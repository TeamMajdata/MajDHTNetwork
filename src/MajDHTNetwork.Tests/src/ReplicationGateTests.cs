#nullable enable

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks that maintenance reannouncements yield replication slots to publications without starving.</summary>
    public sealed class ReplicationGateTests
    {
        /// <summary>Gets a reannouncement deadline that no test reaches.</summary>
        private static long FarDeadline => Stopwatch.GetTimestamp() + (Stopwatch.Frequency * 3600);

        /// <summary>Rejects a gate without slots and a negative quiet period.</summary>
        [Fact]
        public void GateRequiresASlotAndANonNegativeQuietPeriod()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new ReplicationGate(0, TimeSpan.Zero));
            Assert.Throws<ArgumentOutOfRangeException>(() => new ReplicationGate(1, TimeSpan.FromTicks(-1)));
        }

        /// <summary>
        /// A reannouncement waits while a publication holds a slot, although another slot is free, and proceeds once the
        /// publication returned its slot.
        /// </summary>
        /// <returns>Completion after the reannouncement took a slot.</returns>
        [Fact]
        public async Task ReannouncementYieldsWhileAPublicationHoldsASlot()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var gate = new ReplicationGate(2, TimeSpan.Zero);
            await gate.EnterAsync(true, token);
            var yielding = gate.YieldToPublicationsAsync(FarDeadline, token);
            Assert.False(yielding.IsCompleted, "A reannouncement must not start while a publication replicates.");
            gate.Exit(true);
            await yielding.WaitAsync(token);
            await gate.EnterAsync(false, token);
            gate.Exit(false);
        }

        /// <summary>
        /// A publication that only waits for a slot already makes reannouncements yield, gets the slot a reannouncement
        /// returns, and keeps them yielding until it returns the slot itself.
        /// </summary>
        /// <returns>Completion after both replications returned their slots.</returns>
        [Fact]
        public async Task WaitingPublicationMakesReannouncementsYield()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var gate = new ReplicationGate(1, TimeSpan.Zero);
            await gate.EnterAsync(false, token);
            var publication = gate.EnterAsync(true, token);
            Assert.False(publication.IsCompleted, "The only slot is held by a reannouncement.");
            var yielding = gate.YieldToPublicationsAsync(FarDeadline, token);
            Assert.False(yielding.IsCompleted, "A waiting publication must make reannouncements yield.");
            gate.Exit(false);
            await publication.WaitAsync(token);
            Assert.False(yielding.IsCompleted, "The publication now replicates, so reannouncements still yield.");
            gate.Exit(true);
            await yielding.WaitAsync(token);
        }

        /// <summary>
        /// After the last publication a reannouncement still waits for the quiet period, so it does not slip into the gap
        /// before a bulk publisher's next replication; it proceeds once the quiet period has passed.
        /// </summary>
        /// <returns>Completion after the quiet periods were checked.</returns>
        [Fact]
        public async Task ReannouncementWaitsForTheQuietPeriodAfterPublications()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var gate = new ReplicationGate(1, TimeSpan.FromHours(1));
            await gate.EnterAsync(true, token);
            gate.Exit(true);
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(token);
            var yielding = gate.YieldToPublicationsAsync(FarDeadline, stop.Token);
            Assert.False(yielding.IsCompleted, "A reannouncement must wait for the quiet period after a publication.");
            await gate.EnterAsync(true, token);
            gate.Exit(true);
            Assert.False(yielding.IsCompleted, "A publication within the quiet period starts it again.");
            stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => yielding);

            var shortGate = new ReplicationGate(1, TimeSpan.FromMilliseconds(200));
            await shortGate.EnterAsync(true, token);
            var ended = Stopwatch.GetTimestamp();
            shortGate.Exit(true);
            await shortGate.YieldToPublicationsAsync(FarDeadline, token).WaitAsync(token);
            Assert.True(Stopwatch.GetElapsedTime(ended) >= TimeSpan.FromMilliseconds(200), "The quiet period must have passed.");
        }

        /// <summary>
        /// A reannouncement stops yielding at its deadline although publications continue, so maintenance cannot starve, and
        /// then takes a free slot next to the publication.
        /// </summary>
        /// <returns>Completion after the reannouncement took a slot.</returns>
        [Fact]
        public async Task ReannouncementStopsYieldingAtItsDeadline()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var gate = new ReplicationGate(2, TimeSpan.FromHours(1));
            await gate.EnterAsync(true, token);
            Assert.True(gate.YieldToPublicationsAsync(Stopwatch.GetTimestamp(), token).IsCompleted,
                "A reannouncement past its deadline must not yield.");
            var soon = Stopwatch.GetTimestamp() + (Stopwatch.Frequency / 5);
            await gate.YieldToPublicationsAsync(soon, token).WaitAsync(token);
            Assert.True(Stopwatch.GetTimestamp() >= soon, "The reannouncement must have yielded until its deadline.");
            await gate.EnterAsync(false, token);
            gate.Exit(false);
            gate.Exit(true);
        }

        /// <summary>
        /// A publication cancelled while it waits for a slot stops counting as active and holds no slot, so reannouncements
        /// proceed and the slot stays usable.
        /// </summary>
        /// <returns>Completion after the slot was taken again.</returns>
        [Fact]
        public async Task CancelledPublicationStopsCountingAsActive()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var gate = new ReplicationGate(1, TimeSpan.Zero);
            await gate.EnterAsync(false, token);
            using var cancel = new CancellationTokenSource();
            var publication = gate.EnterAsync(true, cancel.Token);
            var yielding = gate.YieldToPublicationsAsync(FarDeadline, token);
            Assert.False(yielding.IsCompleted, "A waiting publication must make reannouncements yield.");
            cancel.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => publication);
            await yielding.WaitAsync(token);
            gate.Exit(false);
            await gate.EnterAsync(true, token);
            gate.Exit(true);
        }
    }
}
