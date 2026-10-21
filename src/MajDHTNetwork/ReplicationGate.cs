using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// Admits record replications into a fixed number of slots and lets maintenance reannouncements yield to publications.
    /// A publication, import, renewal or withdrawal that a caller waits for counts as publication activity from the moment it
    /// asks for a slot until it returns the slot. Before a reannouncement asks for a slot it waits until no publication has
    /// been active for a quiet period, which also covers the short gaps in which a bulk publisher prepares its next file, or
    /// until its deadline passes; slots themselves are granted in arrival order.
    /// </summary>
    internal sealed class ReplicationGate
    {
        /// <summary>Serializes the publication activity state.</summary>
        private readonly object _sync = new object();
        /// <summary>The replication slots, granted in arrival order.</summary>
        private readonly SemaphoreSlim _slots;
        /// <summary>How long, in <see cref="Stopwatch"/> ticks, no publication must have been active before a reannouncement proceeds.</summary>
        private readonly long _quietPeriod;
        /// <summary>The publications waiting for or holding a slot.</summary>
        private int _publications;
        /// <summary>The <see cref="Stopwatch"/> timestamp at which the last active publication ended.</summary>
        private long _lastPublication;
        /// <summary>Completes when the active publications have ended; replaced when a publication starts while none is active.</summary>
        private TaskCompletionSource<bool> _publicationsEnded = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Creates a gate with every slot free and no recent publication.</summary>
        /// <param name="slots">The replications admitted at once, at least one.</param>
        /// <param name="quietPeriod">How long no publication must have been active before a reannouncement proceeds.</param>
        /// <exception cref="ArgumentOutOfRangeException">The slot count is not positive or the quiet period is negative.</exception>
        internal ReplicationGate(int slots, TimeSpan quietPeriod)
        {
            if (slots < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(slots), "At least one replication slot is required.");
            }
            if (quietPeriod < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(quietPeriod), "The quiet period must not be negative.");
            }
            _slots = new SemaphoreSlim(slots, slots);
            _quietPeriod = (long)(quietPeriod.TotalSeconds * Stopwatch.Frequency);
            _lastPublication = Stopwatch.GetTimestamp() - _quietPeriod;
            _publicationsEnded.SetResult(true);
        }

        /// <summary>Waits for a replication slot; the caller returns it with <see cref="Exit"/>.</summary>
        /// <param name="publication">
        /// Whether the replication is a publication, import, renewal or withdrawal that a caller waits for, which makes
        /// reannouncements yield from now until <see cref="Exit"/>; false for a maintenance reannouncement.
        /// </param>
        /// <param name="cancellationToken">Cancels waiting for the slot.</param>
        /// <returns>Completion once the caller holds a slot.</returns>
        /// <exception cref="OperationCanceledException">Waiting was cancelled; the caller holds no slot.</exception>
        internal async Task EnterAsync(bool publication, CancellationToken cancellationToken)
        {
            if (publication)
            {
                BeginPublication();
            }
            try
            {
                await _slots.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                if (publication)
                {
                    EndPublication();
                }
                throw;
            }
        }

        /// <summary>Returns a slot taken with <see cref="EnterAsync"/>.</summary>
        /// <param name="publication">The value passed to <see cref="EnterAsync"/>.</param>
        internal void Exit(bool publication)
        {
            _slots.Release();
            if (publication)
            {
                EndPublication();
            }
        }

        /// <summary>
        /// Waits until no publication has waited for or held a slot during the quiet period, or until a deadline, whichever
        /// comes first. A reannouncement calls it before <see cref="EnterAsync"/>.
        /// </summary>
        /// <param name="deadline">The <see cref="Stopwatch"/> timestamp after which the caller stops yielding.</param>
        /// <param name="cancellationToken">Cancels waiting.</param>
        /// <returns>Completion once the caller may ask for a slot.</returns>
        /// <exception cref="OperationCanceledException">Waiting was cancelled.</exception>
        internal async Task YieldToPublicationsAsync(long deadline, CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var now = Stopwatch.GetTimestamp();
                if (now >= deadline)
                {
                    return;
                }
                Task? publicationsEnded = null;
                long until;
                lock (_sync)
                {
                    if (_publications == 0)
                    {
                        var quiet = _lastPublication + _quietPeriod;
                        if (now >= quiet)
                        {
                            return;
                        }
                        until = Math.Min(deadline, quiet);
                    }
                    else
                    {
                        publicationsEnded = _publicationsEnded.Task;
                        until = deadline;
                    }
                }
                await WaitAsync(publicationsEnded, until - now, cancellationToken).ConfigureAwait(false);
            }
        }

        /// <summary>Counts a publication as active, starting a new activity period when none was active.</summary>
        private void BeginPublication()
        {
            lock (_sync)
            {
                if (_publications == 0)
                {
                    _publicationsEnded = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                }
                _publications++;
            }
        }

        /// <summary>Ends one active publication and, after the last one, starts the quiet period and wakes yielding reannouncements.</summary>
        private void EndPublication()
        {
            TaskCompletionSource<bool>? ended = null;
            lock (_sync)
            {
                _publications--;
                if (_publications == 0)
                {
                    _lastPublication = Stopwatch.GetTimestamp();
                    ended = _publicationsEnded;
                }
            }
            ended?.TrySetResult(true);
        }

        /// <summary>Waits for a signal or a timeout, whichever comes first.</summary>
        /// <param name="signal">A task whose completion ends the wait early, or null to wait for the timeout only.</param>
        /// <param name="ticks">The positive timeout in <see cref="Stopwatch"/> ticks.</param>
        /// <param name="cancellationToken">Cancels waiting.</param>
        /// <returns>Completion after the signal or the timeout.</returns>
        /// <exception cref="OperationCanceledException">Waiting was cancelled.</exception>
        private static async Task WaitAsync(Task? signal, long ticks, CancellationToken cancellationToken)
        {
            // Rounding up keeps the wait from ending just before the moment it waits for; the callers check again anyway.
            var milliseconds = Math.Min(Math.Ceiling(ticks * 1000.0 / Stopwatch.Frequency), int.MaxValue - 1);
            var timeout = TimeSpan.FromMilliseconds(milliseconds);
            if (signal == null)
            {
                await Task.Delay(timeout, cancellationToken).ConfigureAwait(false);
                return;
            }
            using var timer = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            await Task.WhenAny(signal, Task.Delay(timeout, timer.Token)).ConfigureAwait(false);
            timer.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
        }
    }
}
