#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks per-peer packet-loss statistics, loss-based route ranking and concurrent multi-provider downloads.</summary>
    public sealed class DownloadStatisticsTests
    {
        /// <summary>Counts a dropped UDP response as one lost transmission for the peer and the route it used.</summary>
        /// <returns>Completion after the statistics assertions.</returns>
        [Fact]
        public async Task LostUdpResponsesAreRecordedPerPeerAndRoute()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            await using var server = new MajDHTNode(Options(DHTTransport.Udp, DHTCapabilities.Download), identity);
            await server.StartAsync(token);
            await using var proxy = new LossyUdpProxy(new IPEndPoint(IPAddress.Loopback, server.LocalPeer.UdpPort()));
            await using var client = new MajDHTNode(Options(DHTTransport.Udp, DHTCapabilities.Download));
            await client.StartAsync(token);
            Assert.Null(client.GetPeerStatistics(server.NodeId));
            await client.JoinAsync(DHTPeer.Create(identity, IPAddress.Loopback, 0, proxy.Port, DHTCapabilities.Download), token);
            var statistics = client.GetPeerStatistics(server.NodeId);
            Assert.NotNull(statistics);
            Assert.Equal(1, statistics!.LostPackets);
            Assert.True(statistics.SentPackets >= 2, "The retransmission must be counted.");
            var route = statistics.GetRoute(new IPEndPoint(IPAddress.Loopback, proxy.Port), DHTTransport.Udp);
            Assert.NotNull(route);
            Assert.Equal(2, route!.SentPackets);
            Assert.Equal(0.5, route.PacketLossRate);
            Assert.Contains(client.PeerStatistics, entry => entry.NodeId == server.NodeId);
        }

        /// <summary>Puts lower-loss routes and relays first within the same tier of the default selector.</summary>
        [Fact]
        public void DefaultSelectorRanksRoutesAndRelaysByPacketLoss()
        {
            var destination = DHTPeer.Create(new DHTIdentity(),
                new[] { new DHTEndpoint(IPAddress.Parse("203.0.113.2"), 1000, 2000, DHTEndpointFlags.Verified) }, DHTCapabilities.Provide,
                DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
            var lossyRelay = PublicRelay("203.0.113.10");
            var cleanRelay = PublicRelay("203.0.113.11");
            var tcp = new IPEndPoint(IPAddress.Parse("203.0.113.2"), 1000);
            var statistics = new Dictionary<string, DHTPeerStatistics>
            {
                [destination.NodeId] = new DHTPeerStatistics(destination.NodeId, 10, 5, DateTimeOffset.UtcNow,
                    new[] { new DHTRouteStatistics(tcp, DHTTransport.Tcp, 10, 5, DateTimeOffset.UtcNow) }),
                [lossyRelay.NodeId] = new DHTPeerStatistics(lossyRelay.NodeId, 10, 9, DateTimeOffset.UtcNow, Array.Empty<DHTRouteStatistics>())
            };
            var context = new DHTRouteContext(DHTTransport.Tcp, true, Array.Empty<IPAddress>(), Array.Empty<string>(), 8,
                nodeId => statistics.TryGetValue(nodeId, out var entry) ? entry : null);
            var selector = new DefaultDHTRouteSelector();
            var routes = selector.SelectDirectRoutes(destination, context);
            Assert.Equal(DHTTransport.Udp, routes[0].Transport);
            Assert.Equal(DHTTransport.Tcp, routes[1].Transport);
            Assert.Equal(0.5, context.PacketLossRate(destination.NodeId, routes[1]));
            var relays = selector.SelectRelayRoutes(destination, new[] { lossyRelay, cleanRelay }, context);
            Assert.Equal(cleanRelay.NodeId, relays[0].Relay.NodeId);
            Assert.Equal(lossyRelay.NodeId, relays[1].Relay.NodeId);
        }

        /// <summary>Downloads one file from two providers concurrently while respecting the per-provider request limit.</summary>
        /// <returns>Completion after the verified concurrent download.</returns>
        [Fact]
        public async Task DownloadsUseSeveralProvidersConcurrently()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            var tracker = new ConcurrencyTracker();
            var firstStore = new TrackingStore(tracker);
            var secondStore = new TrackingStore(tracker);
            var providerOptions = Options(DHTTransport.Udp, DHTCapabilities.Download | DHTCapabilities.Provide);
            providerOptions.BlockSize = 1024;
            await using var first = new MajDHTNode(providerOptions, contentStore: firstStore);
            await using var second = new MajDHTNode(providerOptions, contentStore: secondStore);
            var clientOptions = Options(DHTTransport.Udp, DHTCapabilities.Download);
            clientOptions.MaxConcurrentBlockRequests = 8;
            clientOptions.MaxBlockRequestsPerPeer = 2;
            await using var client = new MajDHTNode(clientOptions);
            await Task.WhenAll(first.StartAsync(token), second.StartAsync(token), client.StartAsync(token));
            var content = Crypto.Random(40 * 1024);
            using var source = new MemoryStream(content);
            var record = await first.PublishAsync("concurrent/file", source, cancellationToken: token);
            await second.JoinAsync(first.LocalPeer, token);
            using (var copy = new MemoryStream())
            {
                await second.DownloadAsync(record, copy, record.FileHash, token);
            }
            await client.JoinAsync(first.LocalPeer, token);
            Assert.Equal(2, (await client.FindProvidersAsync(record.FileHash, token)).Count);
            tracker.Reset();
            firstStore.Reset();
            secondStore.Reset();
            using var destination = new MemoryStream();
            await client.DownloadAsync(record, destination, record.FileHash, token);
            Assert.True(BytesEqual(content, destination.ToArray()), "The concurrent download must deliver the verified file in order.");
            Assert.True(firstStore.Reads > 0 && secondStore.Reads > 0, "Both providers must serve blocks.");
            Assert.True(firstStore.Reads + secondStore.Reads >= record.BlockCount, "Every block must be read from a provider.");
            Assert.True(firstStore.PeakReads <= 2 && secondStore.PeakReads <= 2, "No provider may exceed the per-peer request limit.");
            Assert.True(tracker.Peak >= 2, "Blocks must be requested concurrently.");
        }

        /// <summary>Rejects download concurrency limits outside their ranges.</summary>
        [Fact]
        public void DownloadConcurrencyOptionsAreValidated()
        {
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { MaxConcurrentBlockRequests = 0 }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { MaxConcurrentBlockRequests = 65 }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { MaxBlockRequestsPerPeer = 0 }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { MaxBlockRequestsPerPeer = 17 }.Snapshot());
        }

        /// <summary>Creates a public relay contact with one configured endpoint.</summary>
        /// <param name="address">The relay address.</param>
        /// <returns>The relay contact.</returns>
        private static DHTPeer PublicRelay(string address)
        {
            return DHTPeer.Create(new DHTIdentity(), new[] { new DHTEndpoint(IPAddress.Parse(address), 42000, 0, DHTEndpointFlags.Configured) },
                DHTCapabilities.Relay, DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(2));
        }

        /// <summary>Tracks the peak number of block reads in progress across several stores.</summary>
        private sealed class ConcurrencyTracker
        {
            /// <summary>The reads in progress.</summary>
            private int _active;
            /// <summary>The peak number of reads in progress.</summary>
            private int _peak;

            /// <summary>Gets the peak number of reads in progress.</summary>
            internal int Peak => Volatile.Read(ref _peak);

            /// <summary>Records the start of a read.</summary>
            /// <returns>The number of reads now in progress.</returns>
            internal int Enter()
            {
                var active = Interlocked.Increment(ref _active);
                InterlockedMax(ref _peak, active);
                return active;
            }

            /// <summary>Records the end of a read.</summary>
            internal void Exit()
            {
                Interlocked.Decrement(ref _active);
            }

            /// <summary>Clears the peak.</summary>
            internal void Reset()
            {
                Volatile.Write(ref _peak, 0);
            }
        }

        /// <summary>A memory store that delays reads and records how many run concurrently.</summary>
        private sealed class TrackingStore : IDHTContentStore
        {
            /// <summary>The backing store.</summary>
            private readonly MemoryDHTContentStore _inner = new MemoryDHTContentStore();
            /// <summary>The cross-store concurrency tracker.</summary>
            private readonly ConcurrencyTracker _tracker;
            /// <summary>The reads in progress on this store.</summary>
            private int _active;
            /// <summary>The peak number of reads in progress on this store.</summary>
            private int _peak;
            /// <summary>The number of reads.</summary>
            private int _reads;

            /// <summary>Gets the number of reads since the last reset.</summary>
            internal int Reads => Volatile.Read(ref _reads);
            /// <summary>Gets the peak number of concurrent reads since the last reset.</summary>
            internal int PeakReads => Volatile.Read(ref _peak);

            /// <summary>Creates a tracking store.</summary>
            /// <param name="tracker">The cross-store concurrency tracker.</param>
            internal TrackingStore(ConcurrencyTracker tracker)
            {
                _tracker = tracker;
            }

            /// <summary>Clears the read counters.</summary>
            internal void Reset()
            {
                Volatile.Write(ref _reads, 0);
                Volatile.Write(ref _peak, 0);
            }

            /// <inheritdoc />
            public ValueTask PutAsync(string blockHash, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
            {
                return _inner.PutAsync(blockHash, content, cancellationToken);
            }

            /// <inheritdoc />
            public async ValueTask<ReadOnlyMemory<byte>?> GetAsync(string blockHash, CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref _reads);
                InterlockedMax(ref _peak, Interlocked.Increment(ref _active));
                _tracker.Enter();
                try
                {
                    await Task.Delay(30, cancellationToken).ConfigureAwait(false);
                    return await _inner.GetAsync(blockHash, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    _tracker.Exit();
                    Interlocked.Decrement(ref _active);
                }
            }
        }

        /// <summary>Raises a shared maximum without locks.</summary>
        /// <param name="target">The maximum.</param>
        /// <param name="value">The candidate value.</param>
        private static void InterlockedMax(ref int target, int value)
        {
            var current = Volatile.Read(ref target);
            while (value > current)
            {
                var observed = Interlocked.CompareExchange(ref target, value, current);
                if (observed == current)
                {
                    return;
                }
                current = observed;
            }
        }
    }
}
