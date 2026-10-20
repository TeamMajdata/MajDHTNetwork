using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>
        /// Downloads the blocks of one file from several providers concurrently and writes them in order.
        /// </summary>
        /// <remarks>
        /// Up to <see cref="DHTNodeOptions.MaxConcurrentBlockRequests"/> workers each lease the lowest pending block inside a
        /// bounded reorder window, assign it to the best provider that has a free slot and has not failed that block, and
        /// return it to the queue when the provider fails. Providers are ranked local first, then by measured packet loss,
        /// in-flight requests and failures. A block fails the download only after every provider failed it.
        /// </remarks>
        private sealed class BlockDownload : IDisposable
        {
            /// <summary>The owning node.</summary>
            private readonly MajDHTNode _node;
            /// <summary>The trusted manifest.</summary>
            private readonly DHTRecord _record;
            /// <summary>The caller-owned destination stream.</summary>
            private readonly Stream _destination;
            /// <summary>The caller-owned whole-file digest, appended in block order.</summary>
            private readonly IncrementalHash _digest;
            /// <summary>The caller-owned Merkle leaf list, appended in block order.</summary>
            private readonly Wire _leaves;
            /// <summary>The providers and their per-download counters.</summary>
            private readonly List<ProviderSlot> _providers = new List<ProviderSlot>();
            /// <summary>Protects the scheduling state.</summary>
            private readonly object _gate = new object();
            /// <summary>The blocks a provider failed that wait for another provider, lowest first.</summary>
            private readonly SortedSet<int> _returned = new SortedSet<int>();
            /// <summary>The providers already asked for each block, kept only while the block is in flight or returned.</summary>
            private readonly Dictionary<int, HashSet<string>> _attempted = new Dictionary<int, HashSet<string>>();
            /// <summary>The verified blocks waiting to be written in order, each still holding its provider's response frame.</summary>
            private readonly Dictionary<int, OwnedMemory> _completed = new Dictionary<int, OwnedMemory>();
            /// <summary>Serializes ordered writes to the digest, leaves, store and destination.</summary>
            private readonly SemaphoreSlim _writer = new SemaphoreSlim(1, 1);
            /// <summary>Cancels every worker on failure or caller cancellation.</summary>
            private readonly CancellationTokenSource _cancellation;
            /// <summary>The number of blocks that may be leased beyond the next block to write.</summary>
            private readonly int _window;
            /// <summary>The per-provider in-flight limit.</summary>
            private readonly int _perPeerLimit;
            /// <summary>Wakes waiting workers after any scheduling change.</summary>
            private TaskCompletionSource<bool> _changed = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            /// <summary>The next block index to write.</summary>
            private int _nextToWrite;
            /// <summary>The lowest block index that was never leased; every block at or above it is pending in index order.</summary>
            private int _nextToLease;
            /// <summary>The first fatal failure.</summary>
            private Exception? _failure;

            /// <summary>Prepares a download.</summary>
            /// <param name="node">The owning node.</param>
            /// <param name="record">The trusted manifest.</param>
            /// <param name="providers">The distinct candidate providers.</param>
            /// <param name="destination">The caller-owned destination stream.</param>
            /// <param name="digest">The caller-owned whole-file digest.</param>
            /// <param name="leaves">The caller-owned Merkle leaf list.</param>
            /// <param name="cancellationToken">The operation lifetime.</param>
            internal BlockDownload(MajDHTNode node, DHTRecord record, IReadOnlyList<DHTPeer> providers, Stream destination,
                IncrementalHash digest, Wire leaves, CancellationToken cancellationToken)
            {
                _node = node;
                _record = record;
                _destination = destination;
                _digest = digest;
                _leaves = leaves;
                _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                _window = node._options.MaxConcurrentBlockRequests * 2;
                _perPeerLimit = node._options.MaxBlockRequestsPerPeer;
                // A random rotation order keeps equally ranked providers, such as many unmeasured Sybil providers, from being
                // chosen in a predictable discovery order.
                var shuffled = new List<DHTPeer>(providers);
                Crypto.Shuffle(shuffled);
                for (var index = 0; index < shuffled.Count; index++)
                {
                    _providers.Add(new ProviderSlot(shuffled[index], index, shuffled[index].NodeId == node.NodeId));
                }
                _cancellation.Token.Register(Signal);
            }

            /// <summary>Runs the workers until every block is written, a block fails at every provider, or cancellation.</summary>
            /// <returns>Completion after all blocks were written in order.</returns>
            /// <exception cref="IOException">Every provider failed a block, or the store or destination failed.</exception>
            /// <exception cref="InvalidDataException">A store or destination reported invalid data.</exception>
            /// <exception cref="OperationCanceledException">The download was cancelled.</exception>
            internal async Task RunAsync()
            {
                var workers = new Task[Math.Min(_node._options.MaxConcurrentBlockRequests, _record.BlockCount)];
                for (var index = 0; index < workers.Length; index++)
                {
                    workers[index] = WorkAsync();
                }
                await Task.WhenAll(workers).ConfigureAwait(false);
                if (_failure != null)
                {
                    ExceptionDispatchInfo.Capture(_failure).Throw();
                }
                _cancellation.Token.ThrowIfCancellationRequested();
                if (_nextToWrite != _record.BlockCount)
                {
                    throw new IOException("The download ended before every block was written.");
                }
            }

            /// <summary>Leases, downloads and writes blocks until no pending block remains.</summary>
            /// <returns>Completion when the worker has no more work or the download stopped.</returns>
            private async Task WorkAsync()
            {
                await Task.Yield();
                var token = _cancellation.Token;
                try
                {
                    while (true)
                    {
                        var lease = await LeaseAsync().ConfigureAwait(false);
                        if (lease == null)
                        {
                            return;
                        }
                        OwnedMemory bytes;
                        try
                        {
                            // The manifest, index and capability were validated once by DownloadAsync, whose lifetime this token links.
                            bytes = await _node.ReadBlockCoreAsync(_record, lease.Value.Provider.Peer, lease.Value.Index, null, token)
                                .ConfigureAwait(false);
                        }
                        catch (Exception exception) when (IsPeerFailure(exception))
                        {
                            token.ThrowIfCancellationRequested();
                            _node.Log(LogLevel.Warning, "Provider block rejected: ", exception);
                            Reject(lease.Value, exception);
                            continue;
                        }
                        Accept(lease.Value, bytes);
                        await DrainAsync().ConfigureAwait(false);
                    }
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                }
                catch (Exception exception)
                {
                    Fail(exception);
                }
            }

            /// <summary>Waits for the lowest leasable block and its best available provider.</summary>
            /// <returns>The lease, or null when no block is pending.</returns>
            /// <exception cref="OperationCanceledException">The download stopped.</exception>
            /// <remarks>
            /// Returned blocks are tried first because they are always below the lease cursor. A never-leased block has no
            /// attempted providers, so when the cursor block has no free provider, no later block has one either.
            /// </remarks>
            private async Task<Lease?> LeaseAsync()
            {
                while (true)
                {
                    Task wait;
                    lock (_gate)
                    {
                        _cancellation.Token.ThrowIfCancellationRequested();
                        if (_returned.Count == 0 && _nextToLease >= _record.BlockCount)
                        {
                            return null;
                        }
                        var limit = _nextToWrite + _window;
                        foreach (var index in _returned)
                        {
                            if (index >= limit)
                            {
                                break;
                            }
                            var provider = ChooseProviderLocked(index);
                            if (provider != null)
                            {
                                _returned.Remove(index);
                                return LeaseLocked(index, provider);
                            }
                        }
                        if (_nextToLease < _record.BlockCount && _nextToLease < limit)
                        {
                            var provider = ChooseProviderLocked(_nextToLease);
                            if (provider != null)
                            {
                                return LeaseLocked(_nextToLease++, provider);
                            }
                        }
                        wait = _changed.Task;
                    }
                    await wait.ConfigureAwait(false);
                }
            }

            /// <summary>Records that a provider was asked for a block and assigns the lease.</summary>
            /// <param name="index">The block index.</param>
            /// <param name="provider">The chosen provider.</param>
            /// <returns>The lease.</returns>
            /// <remarks>The caller must hold the scheduling lock.</remarks>
            private Lease LeaseLocked(int index, ProviderSlot provider)
            {
                if (!_attempted.TryGetValue(index, out var attempted))
                {
                    attempted = new HashSet<string>(StringComparer.Ordinal);
                    _attempted.Add(index, attempted);
                }
                attempted.Add(provider.Peer.NodeId);
                provider.InFlight++;
                return new Lease(index, provider);
            }

            /// <summary>Chooses the best provider with a free slot that has not been asked for a block.</summary>
            /// <param name="index">The block index.</param>
            /// <returns>The provider, or null when every untried provider is busy.</returns>
            /// <remarks>The caller must hold the scheduling lock.</remarks>
            private ProviderSlot? ChooseProviderLocked(int index)
            {
                ProviderSlot? best = null;
                var bestLoss = 0.0;
                _attempted.TryGetValue(index, out var attempted);
                foreach (var provider in _providers)
                {
                    if (provider.InFlight >= _perPeerLimit || (attempted != null && attempted.Contains(provider.Peer.NodeId)))
                    {
                        continue;
                    }
                    var loss = provider.IsLocal ? 0 : _node.PacketLossRate(provider.Peer.NodeId);
                    if (best == null || Better(provider, loss, best, bestLoss, index))
                    {
                        best = provider;
                        bestLoss = loss;
                    }
                }
                return best;
            }

            /// <summary>Compares two providers: local first, then lower loss, fewer in-flight requests, fewer failures, then rotation.</summary>
            /// <param name="candidate">The candidate provider.</param>
            /// <param name="candidateLoss">The candidate's loss rate.</param>
            /// <param name="current">The current best provider.</param>
            /// <param name="currentLoss">The current best provider's loss rate.</param>
            /// <param name="index">The block index used to rotate otherwise equal providers.</param>
            /// <returns>Whether the candidate is better.</returns>
            private bool Better(ProviderSlot candidate, double candidateLoss, ProviderSlot current, double currentLoss, int index)
            {
                if (candidate.IsLocal != current.IsLocal)
                {
                    return candidate.IsLocal;
                }
                if (candidateLoss != currentLoss)
                {
                    return candidateLoss < currentLoss;
                }
                if (candidate.InFlight != current.InFlight)
                {
                    return candidate.InFlight < current.InFlight;
                }
                if (candidate.Failures != current.Failures)
                {
                    return candidate.Failures < current.Failures;
                }
                var count = _providers.Count;
                return ((candidate.Ordinal - index) % count + count) % count < ((current.Ordinal - index) % count + count) % count;
            }

            /// <summary>Records a verified block and wakes waiting workers.</summary>
            /// <param name="lease">The completed lease.</param>
            /// <param name="bytes">The verified block, whose frame the download now owns until the block is written or the download ends.</param>
            private void Accept(Lease lease, OwnedMemory bytes)
            {
                lock (_gate)
                {
                    lease.Provider.InFlight--;
                    _completed[lease.Index] = bytes;
                    _attempted.Remove(lease.Index);
                }
                Signal();
            }

            /// <summary>Returns a failed block to the queue, or fails the download when every provider failed it.</summary>
            /// <param name="lease">The failed lease.</param>
            /// <param name="failure">The provider failure.</param>
            private void Reject(Lease lease, Exception failure)
            {
                bool exhausted;
                lock (_gate)
                {
                    lease.Provider.InFlight--;
                    lease.Provider.Failures++;
                    exhausted = _attempted[lease.Index].Count >= _providers.Count;
                    if (!exhausted)
                    {
                        _returned.Add(lease.Index);
                    }
                }
                if (exhausted)
                {
                    Fail(new IOException("No provider returned an authenticated block.", failure));
                }
                Signal();
            }

            /// <summary>
            /// Writes every consecutive completed block to the digest, leaves, store and destination, releasing each block's
            /// response frame once the store has copied the block and the destination has received it.
            /// </summary>
            /// <returns>Completion after no further consecutive block is available.</returns>
            /// <exception cref="OperationCanceledException">The download stopped.</exception>
            private async Task DrainAsync()
            {
                var token = _cancellation.Token;
                await _writer.WaitAsync(token).ConfigureAwait(false);
                try
                {
                    while (true)
                    {
                        OwnedMemory block;
                        lock (_gate)
                        {
                            if (!_completed.TryGetValue(_nextToWrite, out block))
                            {
                                return;
                            }
                            _completed.Remove(_nextToWrite);
                        }
                        using (block)
                        {
                            _digest.AppendData(block.Bytes.Span);
                            var leafId = MerkleTree.AppendLeaf(_leaves, block.Bytes.Span);
                            await _node._store.PutAsync(leafId, block.Bytes, token).ConfigureAwait(false);
                            await _destination.WriteAsync(block.Bytes, token).ConfigureAwait(false);
                        }
                        lock (_gate)
                        {
                            _nextToWrite++;
                        }
                        Signal();
                    }
                }
                finally
                {
                    _writer.Release();
                }
            }

            /// <summary>Records the first fatal failure and stops every worker.</summary>
            /// <param name="failure">The failure.</param>
            private void Fail(Exception failure)
            {
                lock (_gate)
                {
                    _failure ??= failure;
                }
                _cancellation.Cancel();
            }

            /// <summary>Wakes every worker waiting for a scheduling change.</summary>
            private void Signal()
            {
                var previous = Interlocked.Exchange(ref _changed,
                    new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously));
                previous.TrySetResult(true);
            }

            /// <summary>Releases the frames of blocks that were never written, the cancellation source and the writer gate.</summary>
            public void Dispose()
            {
                lock (_gate)
                {
                    foreach (var block in _completed.Values)
                    {
                        block.Dispose();
                    }
                    _completed.Clear();
                }
                _cancellation.Dispose();
                _writer.Dispose();
            }

            /// <summary>One block assigned to one provider.</summary>
            private readonly struct Lease
            {
                /// <summary>Gets the block index.</summary>
                internal int Index { get; }
                /// <summary>Gets the provider.</summary>
                internal ProviderSlot Provider { get; }

                /// <summary>Creates a lease.</summary>
                /// <param name="index">The block index.</param>
                /// <param name="provider">The provider.</param>
                internal Lease(int index, ProviderSlot provider)
                {
                    Index = index;
                    Provider = provider;
                }
            }

            /// <summary>Holds one provider's per-download counters under the scheduling lock.</summary>
            private sealed class ProviderSlot
            {
                /// <summary>Gets the provider contact.</summary>
                internal DHTPeer Peer { get; }
                /// <summary>Gets the provider's position in discovery order, used for rotation.</summary>
                internal int Ordinal { get; }
                /// <summary>Gets whether the provider is this node.</summary>
                internal bool IsLocal { get; }
                /// <summary>Gets or sets the number of requests in flight.</summary>
                internal int InFlight { get; set; }
                /// <summary>Gets or sets the number of failed blocks.</summary>
                internal int Failures { get; set; }

                /// <summary>Creates a provider slot.</summary>
                /// <param name="peer">The provider contact.</param>
                /// <param name="ordinal">The discovery order.</param>
                /// <param name="isLocal">Whether the provider is this node.</param>
                internal ProviderSlot(DHTPeer peer, int ordinal, bool isLocal)
                {
                    Peer = peer;
                    Ordinal = ordinal;
                    IsLocal = isLocal;
                }
            }
        }
    }
}
