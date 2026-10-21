#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks which local records maintenance reannounces, how long each yields to publications, and that it does.</summary>
    public sealed class ReannouncementTests
    {
        /// <summary>Keeps the 30-minute default and accepts republish intervals from one second to 45 minutes only.</summary>
        [Fact]
        public void RepublishIntervalIsValidated()
        {
            Assert.Equal(TimeSpan.FromMinutes(30), new DHTNodeOptions().RepublishInterval);
            Assert.Equal(TimeSpan.FromMinutes(45), new DHTNodeOptions { RepublishInterval = TimeSpan.FromMinutes(45) }.Snapshot().RepublishInterval);
            Assert.Equal(TimeSpan.FromSeconds(1), new DHTNodeOptions { RepublishInterval = TimeSpan.FromSeconds(1) }.Snapshot().RepublishInterval);
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { RepublishInterval = TimeSpan.FromMilliseconds(999) }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { RepublishInterval = TimeSpan.FromMinutes(45).Add(TimeSpan.FromTicks(1)) }.Snapshot());
        }

        /// <summary>
        /// Lists due records earliest deadline first: an accepted record yields until its last accepted announcement is 45
        /// minutes old, a record no replica accepted until 45 minutes after the listing, and after a contact change every
        /// record is listed without yielding.
        /// </summary>
        /// <returns>Completion after the listings were checked.</returns>
        [Fact]
        public async Task ReannouncementsYieldUntilTheirClaimsApproachTheShortestLease()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var maximumDeferral = (long)(TimeSpan.FromMinutes(45).TotalSeconds * Stopwatch.Frequency);
            await using var publisher = new MajDHTNode(ReannouncingOptions());
            await using var peer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), peer.StartAsync(token));
            // Published before joining, so no replica accepts it.
            using var lonelySource = new MemoryStream(Crypto.Random(100));
            var lonely = await publisher.PublishAsync("songs/unaccepted", lonelySource, cancellationToken: token);
            await publisher.JoinAsync(peer.LocalPeer, token);
            using var acceptedSource = new MemoryStream(Crypto.Random(100));
            var beforeAccepted = Stopwatch.GetTimestamp();
            var accepted = await publisher.PublishAsync("songs/accepted", acceptedSource, cancellationToken: token);
            var afterAccepted = Stopwatch.GetTimestamp();
            await WaitUntilDueAsync(publisher, accepted, token);

            var beforeListing = Stopwatch.GetTimestamp();
            var listed = publisher.LocalRecordsToReannounce(true);
            var afterListing = Stopwatch.GetTimestamp();
            Assert.Equal(2, listed.Count);
            Assert.Equal(accepted.Key, listed[0].Record.Key);
            Assert.InRange(listed[0].Deadline, beforeAccepted + maximumDeferral, afterAccepted + maximumDeferral);
            Assert.Equal(lonely.Key, listed[1].Record.Key);
            Assert.InRange(listed[1].Deadline, beforeListing + maximumDeferral, afterListing + maximumDeferral);

            var contactChange = publisher.LocalRecordsToReannounce(false);
            var now = Stopwatch.GetTimestamp();
            Assert.Equal(2, contactChange.Count);
            Assert.All(contactChange, reannouncement => Assert.True(reannouncement.Deadline <= now, "A contact change must not yield."));
        }

        /// <summary>
        /// A scheduled reannouncement waits while a publication holds a replication slot, although another slot is free, lets
        /// new publications replicate meanwhile, and announces its record once publications have been quiet.
        /// </summary>
        /// <returns>Completion after the record was announced again.</returns>
        [Fact]
        public async Task ScheduledReannouncementWaitsForPublications()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var publisher = new MajDHTNode(ReannouncingOptions());
            await using var peer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), peer.StartAsync(token));
            await publisher.JoinAsync(peer.LocalPeer, token);
            using var oldSource = new MemoryStream(Crypto.Random(100));
            var old = await publisher.PublishAsync("songs/old", oldSource, cancellationToken: token);
            var due = await WaitUntilDueAsync(publisher, old, token);

            Task pass;
            await publisher.Replications.EnterAsync(true, token);
            try
            {
                pass = publisher.ReannounceLocalRecordsAsync(true, token);
                using var newSource = new MemoryStream(Crypto.Random(100));
                await publisher.PublishAsync("songs/new", newSource, cancellationToken: token);
                Assert.False(pass.IsCompleted, "A scheduled reannouncement must wait while a publication replicates.");
                Assert.Contains(publisher.LocalRecordsToReannounce(true), listed => listed.Record.Key.Equals(old.Key));
            }
            finally
            {
                publisher.Replications.Exit(true);
            }
            await pass.WaitAsync(token);
            // The record reached the peer again: it is no longer due, or due once more with a later deadline.
            foreach (var listed in publisher.LocalRecordsToReannounce(true))
            {
                Assert.True(!listed.Record.Key.Equals(old.Key) || listed.Deadline > due, "The pass must have announced the record.");
            }
        }

        /// <summary>
        /// While a maintenance pass yields to a long publication, the maintenance loop keeps renewing the local contact on its
        /// interval instead of waiting for the pass, so the contact that provider claims carry never runs out meanwhile.
        /// </summary>
        /// <returns>Completion after the contact was renewed during the yielding pass.</returns>
        [Fact]
        public async Task MaintenanceKeepsRenewingTheContactWhileAPassYields()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var options = ReannouncingOptions();
            options.MaintenanceInterval = TimeSpan.FromSeconds(1);
            await using var publisher = new MajDHTNode(options);
            await using var peer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), peer.StartAsync(token));
            await publisher.JoinAsync(peer.LocalPeer, token);
            using var source = new MemoryStream(Crypto.Random(100));
            var record = await publisher.PublishAsync("songs/held", source, cancellationToken: token);
            await publisher.Replications.EnterAsync(true, token);
            try
            {
                await WaitUntilDueAsync(publisher, record, token);
                // From here every maintenance interval finds the record due, so a pass is running and yielding to the held slot.
                var renewed = publisher.LocalContact.ExpiresAt;
                // Contacts are signed in whole seconds; three more seconds take at least three renewals after the pass began.
                while (publisher.LocalContact.ExpiresAt < renewed.AddSeconds(3))
                {
                    await Task.Delay(100, token);
                }
                Assert.Contains(publisher.LocalRecordsToReannounce(true), listed => listed.Record.Key.Equals(record.Key));
            }
            finally
            {
                publisher.Replications.Exit(true);
            }
        }

        /// <summary>
        /// Creates publisher options with three replication slots, a one-second republish interval and no maintenance pass
        /// during a test unless the test shortens the maintenance interval.
        /// </summary>
        /// <returns>The publisher options.</returns>
        private static DHTNodeOptions ReannouncingOptions()
        {
            var options = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            options.MaxConcurrentRequests = 64;
            options.MaintenanceInterval = TimeSpan.FromHours(1);
            options.RepublishInterval = TimeSpan.FromSeconds(1);
            return options;
        }

        /// <summary>Waits until a scheduled maintenance pass would reannounce a record.</summary>
        /// <param name="node">The publishing node.</param>
        /// <param name="record">The record.</param>
        /// <param name="cancellationToken">Ends the wait with the test.</param>
        /// <returns>The deadline with which the record is listed.</returns>
        /// <exception cref="OperationCanceledException">The record did not become due in time.</exception>
        private static async Task<long> WaitUntilDueAsync(MajDHTNode node, DHTRecord record, CancellationToken cancellationToken)
        {
            while (true)
            {
                foreach (var listed in node.LocalRecordsToReannounce(true))
                {
                    if (listed.Record.Key.Equals(record.Key))
                    {
                        return listed.Deadline;
                    }
                }
                await Task.Delay(100, cancellationToken);
            }
        }
    }
}
