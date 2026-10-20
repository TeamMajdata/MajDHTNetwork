#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// Regressions for the Sybil mitigations: identity proof of work, verified routing admission, per-network routing and
    /// provider limits, randomized helper selection and disjoint-path lookups.
    /// </summary>
    [Trait("Category", "Security")]
    public sealed class SybilResistanceTests
    {
        /// <summary>Requires the configured identity work from senders and from lookup referrals.</summary>
        /// <returns>Completion after cheap identities were refused and proven identities accepted.</returns>
        [Fact]
        public async Task IdentityProofOfWorkIsProvenAndEnforced()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            const int bits = 4;
            var options = Options(DHTTransport.Tcp, DHTCapabilities.Download);
            options.IdentityWorkBits = bits;
            await using var node = new MajDHTNode(options);
            await node.StartAsync(token);
            Assert.True(node.LocalPeer.IdentityWork >= bits, "A node must create an identity reaching its configured work.");
            Assert.ThrowsAny<ArgumentException>(() => new MajDHTNode(options, CheapIdentity(bits)));
            await using var cheap = new ScriptedPeer(IPAddress.Parse("127.0.0.6"), DHTCapabilities.Download, DHTReachability.Unknown,
                CheapIdentity(bits));
            await Assert.ThrowsAnyAsync<IOException>(() => cheap.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token));
            await using var worthy = new ScriptedPeer(IPAddress.Parse("127.0.0.7"), DHTCapabilities.Download, DHTReachability.Unknown,
                DHTIdentity.Create(bits, token));
            await using var referred = new ScriptedPeer(IPAddress.Parse("127.0.0.8"), DHTCapabilities.Download, DHTReachability.Unknown,
                DHTIdentity.Create(bits, token));
            await using var unproven = new ScriptedPeer(IPAddress.Parse("127.0.0.9"), DHTCapabilities.Download, DHTReachability.Unknown,
                CheapIdentity(bits));
            worthy.Script((packet, source) =>
                packet.Kind == (byte)Operation.Find ? ((byte)0, FindReply(new[] { referred.Peer, unproven.Peer })) : ((byte)0, Array.Empty<byte>()));
            Assert.Equal(0, (await worthy.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            await WaitUntilAsync(() => Contains(node.KnownPeers, worthy.Peer.NodeId), token);
            await node.FindNodesAsync(NodeHash(), token);
            Assert.True(referred.Received(Operation.Find) > 0, "A referral proving the work must be queried.");
            Assert.Equal(0, unproven.Received(Operation.Find));
        }

        /// <summary>
        /// Binds the work to the identity itself: a key's work is fixed by its node digest and survives a restore from the
        /// seed, so grinding a node identifier towards a position costs a full puzzle per candidate key.
        /// </summary>
        [Fact]
        public void IdentityWorkIsBoundToTheKeyAndSurvivesRestores()
        {
            var identity = DHTIdentity.Create(6, TestContext.Current.CancellationToken);
            Assert.True(identity.IdentityWork >= 6);
            var restored = new DHTIdentity(identity.ExportSeed());
            Assert.Equal(identity.NodeId, restored.NodeId);
            Assert.Equal(identity.IdentityWork, restored.IdentityWork);
            var contact = DHTPeer.Create(restored, IPAddress.Loopback, 1000, 0, DHTCapabilities.Download);
            Assert.Equal(identity.IdentityWork, new DHTPeer(contact.Encoded.ToArray()).IdentityWork);
            Assert.ThrowsAny<ArgumentOutOfRangeException>(() => DHTIdentity.Create(21, TestContext.Current.CancellationToken));
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { IdentityWorkBits = 21 }.Snapshot());
        }

        /// <summary>Limits verified contacts per globally routed network while leaving LAN peers and other networks unaffected.</summary>
        [Fact]
        public void RoutingTableLimitsContactsPerNetwork()
        {
            var table = new KademliaDHTRoutingTable(maxPerNetworkInBucket: 16, maxPerNetwork: 3);
            table.Initialize(new DHTIdentity().NodeId, 16);
            var sybils = Observe(table, 10, index => "203.0.113." + (index + 1));
            var others = Observe(table, 3, index => "198.51." + (100 + index) + ".7");
            var lan = Observe(table, 5, index => "192.168.1." + (index + 1));
            // Distinct /48 networks inside one IPv6 /32 allocation still count as one operator network.
            var allocation = Observe(table, 6, index => "2001:db8:" + (index + 1).ToString("x") + "::1");
            var unverified = DHTPeer.Create(new DHTIdentity(), IPAddress.Parse("198.18.0.1"), 1000, 0, DHTCapabilities.Download);
            table.Observe(unverified, null);
            var routed = table.Closest(NodeHash(), 1000);
            Assert.InRange(CountIn(routed, sybils), 1, 3);
            Assert.Equal(3, CountIn(routed, others));
            Assert.Equal(5, CountIn(routed, lan));
            Assert.InRange(CountIn(routed, allocation), 1, 3);
            Assert.Equal(0, CountIn(routed, new HashSet<string> { unverified.NodeId }));
            var narrow = new KademliaDHTRoutingTable(maxPerNetworkInBucket: 1, maxPerNetwork: 100);
            narrow.Initialize(new DHTIdentity().NodeId, 16);
            var crowded = Observe(narrow, 12, index => "203.0.113." + (index + 1));
            Assert.InRange(CountIn(narrow.Closest(NodeHash(), 1000), crowded), 1, 11);
        }

        /// <summary>Limits provider claims for one file from one globally routed network.</summary>
        [Fact]
        public void ProviderClaimsAreLimitedPerNetwork()
        {
            var claims = new Dictionary<string, MajDHTNode.ProviderClaim>();
            for (var index = 0; index < MajDHTNode.MaxProvidersPerNetwork; index++)
            {
                var peer = DHTPeer.Create(new DHTIdentity(), IPAddress.Parse("203.0.113." + (index + 1)), 1000, 0, DHTCapabilities.Provide);
                claims[peer.NodeId] = new MajDHTNode.ProviderClaim(peer, IPAddress.Parse("203.0.113." + (index + 1)));
            }
            Assert.False(MajDHTNode.HasProviderRoom(claims, IPAddress.Parse("203.0.113.200")));
            Assert.True(MajDHTNode.HasProviderRoom(claims, IPAddress.Parse("198.51.100.1")));
            Assert.True(MajDHTNode.HasProviderRoom(claims, IPAddress.Parse("192.168.1.1")));
            Assert.True(MajDHTNode.HasProviderRoom(claims, null));
        }

        /// <summary>
        /// Admits a sender arriving from its advertised endpoint at once, but never admits senders that advertise someone
        /// else's endpoint, and verifies such claims only a bounded number of times per source network.
        /// </summary>
        /// <returns>Completion after the admission and verification assertions.</returns>
        [Fact]
        public async Task InboundSendersMustProveAnAdvertisedEndpoint()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await node.StartAsync(token);
            await using var honest = new ScriptedPeer(IPAddress.Parse("127.0.0.6"), DHTCapabilities.Download, DHTReachability.Unknown);
            Assert.Equal(0, (await honest.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            await WaitUntilAsync(() => Contains(node.KnownPeers, honest.Peer.NodeId), token);
            await using var victim = new FrameCounter(IPAddress.Parse("127.0.0.8"));
            await using var forger = new ScriptedPeer(IPAddress.Parse("127.0.0.7"), DHTCapabilities.Download, DHTReachability.Unknown);
            var forged = new HashSet<string>();
            for (var index = 0; index < 20; index++)
            {
                var identity = new DHTIdentity();
                forged.Add(identity.NodeId);
                Assert.Equal(0, (await forger.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token, identity,
                    victim.Endpoint)).Status);
            }
            await Task.Delay(TimeSpan.FromSeconds(2), token);
            Assert.Equal(0, CountIn(node.KnownPeers, forged));
            Assert.InRange(victim.Frames, 1, MajDHTNode.VerificationsPerNetwork);
        }

        /// <summary>Draws at most one dial-back helper per network, so one network cannot supply every helper.</summary>
        /// <returns>Completion after three dial-back requests.</returns>
        [Fact]
        public async Task DialBackHelpersAreDrawnOncePerNetwork()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var relayAddress = IPAddress.Loopback;
            var relayOptions = Options(DHTTransport.Tcp, DHTCapabilities.Relay);
            relayOptions.ListenAddresses = new List<IPAddress> { relayAddress };
            relayOptions.AdvertisedAddresses = new List<IPAddress> { relayAddress };
            await using var relay = new MajDHTNode(relayOptions);
            await relay.StartAsync(token);
            await using var first = new ScriptedPeer(IPAddress.Parse("127.0.0.3"), DHTCapabilities.Relay);
            await using var second = new ScriptedPeer(IPAddress.Parse("127.0.0.3"), DHTCapabilities.Relay);
            await using var third = new ScriptedPeer(IPAddress.Parse("127.0.0.4"), DHTCapabilities.Relay);
            foreach (var helper in new[] { first, second, third })
            {
                helper.Script((packet, source) => packet.Kind == (byte)Operation.Rendezvous ? ((byte)1, Array.Empty<byte>()) : ((byte)0, Array.Empty<byte>()));
                Assert.Equal(0, (await helper.SendAsync(relay.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            }
            await WaitUntilAsync(() => relay.KnownPeers.Count >= 3, token);
            await using var requester = new ScriptedPeer(IPAddress.Parse("127.0.0.2"), DHTCapabilities.Download, DHTReachability.Unknown);
            var request = new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0 };
            for (var attempt = 0; attempt < 3; attempt++)
            {
                Assert.Equal(1, (await requester.SendAsync(relay.LocalPeer, Operation.Rendezvous, request, token)).Status);
            }
            Assert.Equal(3, first.Received(Operation.Rendezvous) + second.Received(Operation.Rendezvous));
            Assert.Equal(3, third.Received(Operation.Rendezvous));
        }

        /// <summary>
        /// A Sybil node answers lookups with many unreachable referrals closer to the target than the honest holder; a single
        /// path spends its budget on them, while a disjoint honest path still reaches the record.
        /// </summary>
        /// <param name="paths">The number of disjoint lookup paths.</param>
        /// <param name="expectFound">Whether the record must be found.</param>
        /// <returns>Completion after the lookup assertion.</returns>
        [Theory]
        [InlineData(1, false)]
        [InlineData(2, true)]
        public async Task DisjointLookupsResistSybilReferrals(int paths, bool expectFound)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            await using var gateway = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var holder = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await Task.WhenAll(gateway.StartAsync(token), holder.StartAsync(token));
            using var source = new MemoryStream(Crypto.Random(512));
            var record = await holder.PublishAsync("sybil/target", source, cancellationToken: token);
            await holder.JoinAsync(gateway.LocalPeer, token);
            var fakes = CloserContacts(record.Key.RoutingId, holder.NodeId, 16, ClosedPort());
            await using var sybil = new ScriptedPeer(IPAddress.Parse("127.0.0.5"), DHTCapabilities.Download, DHTReachability.Unknown);
            sybil.Script((packet, origin) => packet.Kind == (byte)Operation.Find ? ((byte)0, FindReply(fakes)) : ((byte)0, Array.Empty<byte>()));
            var clientOptions = Options(DHTTransport.Tcp, DHTCapabilities.Download);
            clientOptions.MaxLookupQueries = 16;
            clientOptions.DisjointLookupPaths = paths;
            var table = new AllowListRoutingTable(sybil.Peer.NodeId, gateway.NodeId);
            await using var client = new MajDHTNode(clientOptions, routingTable: table);
            await client.StartAsync(token);
            await client.JoinAsync(sybil.Peer, token);
            await client.JoinAsync(gateway.LocalPeer, token);
            var resolved = await client.ResolveAsync(record.Key, token);
            Assert.Equal(expectFound, resolved != null);
        }

        /// <summary>Creates a random identity whose work stays below a difficulty.</summary>
        /// <param name="bits">The difficulty the identity must not reach.</param>
        /// <returns>The identity.</returns>
        private static DHTIdentity CheapIdentity(int bits)
        {
            while (true)
            {
                var identity = new DHTIdentity();
                if (identity.IdentityWork < bits)
                {
                    return identity;
                }
            }
        }

        /// <summary>Encodes a Find result without a record, with the given nearest contacts and no providers.</summary>
        /// <param name="peers">The referral contacts.</param>
        /// <returns>The result body.</returns>
        private static byte[] FindReply(IReadOnlyList<DHTPeer> peers)
        {
            using var body = new Wire();
            body.Put(ReadOnlySpan<byte>.Empty);
            body.PutLong(peers.Count);
            foreach (var peer in peers)
            {
                body.Put(peer.Encoded);
            }
            body.PutLong(0);
            return body.ToArray();
        }

        /// <summary>Creates unreachable contacts whose identifiers are closer to a target than a reference node.</summary>
        /// <param name="target">The routing target.</param>
        /// <param name="reference">The node the contacts must be closer than.</param>
        /// <param name="count">The number of contacts.</param>
        /// <param name="port">A closed TCP port.</param>
        /// <returns>The contacts.</returns>
        private static List<DHTPeer> CloserContacts(string target, string reference, int count, int port)
        {
            var targetBytes = Crypto.ParseHash(target);
            var referenceBytes = Crypto.ParseHash(reference);
            var result = new List<DHTPeer>();
            while (result.Count < count)
            {
                var identity = new DHTIdentity();
                if (Closer(Crypto.ParseHash(identity.NodeId), referenceBytes, targetBytes))
                {
                    result.Add(DHTPeer.Create(identity, IPAddress.Parse("127.0.0.9"), port, 0, DHTCapabilities.Download));
                }
            }
            return result;
        }

        /// <summary>Checks whether one identifier is closer to a target than another by XOR distance.</summary>
        /// <param name="candidate">The candidate digest.</param>
        /// <param name="reference">The reference digest.</param>
        /// <param name="target">The target digest.</param>
        /// <returns>Whether the candidate is strictly closer.</returns>
        private static bool Closer(byte[] candidate, byte[] reference, byte[] target)
        {
            for (var index = 0; index < target.Length; index++)
            {
                var left = candidate[index] ^ target[index];
                var right = reference[index] ^ target[index];
                if (left != right)
                {
                    return left < right;
                }
            }
            return false;
        }

        /// <summary>Finds a TCP port with no listener on 127.0.0.9.</summary>
        /// <returns>The closed port.</returns>
        private static int ClosedPort()
        {
            using var listener = new TcpListener(IPAddress.Parse("127.0.0.9"), 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        /// <summary>Observes generated contacts with verified addresses.</summary>
        /// <param name="table">The routing table.</param>
        /// <param name="count">The number of contacts.</param>
        /// <param name="address">Selects the verified address of each contact.</param>
        /// <returns>The generated node identifiers.</returns>
        private static HashSet<string> Observe(IDHTRoutingTable table, int count, Func<int, string> address)
        {
            var result = new HashSet<string>();
            for (var index = 0; index < count; index++)
            {
                var ip = IPAddress.Parse(address(index));
                var peer = DHTPeer.Create(new DHTIdentity(), ip, 1000, 0, DHTCapabilities.Download);
                table.Observe(peer, ip);
                result.Add(peer.NodeId);
            }
            return result;
        }

        /// <summary>Counts contacts whose identifiers are in a set.</summary>
        /// <param name="peers">The contacts.</param>
        /// <param name="ids">The identifiers.</param>
        /// <returns>The count.</returns>
        private static int CountIn(IReadOnlyList<DHTPeer> peers, HashSet<string> ids)
        {
            var count = 0;
            foreach (var peer in peers)
            {
                if (ids.Contains(peer.NodeId))
                {
                    count++;
                }
            }
            return count;
        }

        /// <summary>Checks whether a contact list contains a node.</summary>
        /// <param name="peers">The contacts.</param>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>Whether the node is present.</returns>
        private static bool Contains(IReadOnlyList<DHTPeer> peers, string nodeId)
        {
            return CountIn(peers, new HashSet<string> { nodeId }) != 0;
        }

        /// <summary>Polls a condition until it holds.</summary>
        /// <param name="condition">The condition.</param>
        /// <param name="token">The test deadline.</param>
        /// <returns>Completion once the condition holds.</returns>
        private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken token)
        {
            while (!condition())
            {
                await Task.Delay(25, token);
            }
        }

        /// <summary>A routing table that only admits an allow list, pinning a client's lookup seeds.</summary>
        private sealed class AllowListRoutingTable : IDHTRoutingTable
        {
            /// <summary>The wrapped default table.</summary>
            private readonly KademliaDHTRoutingTable _inner = new KademliaDHTRoutingTable();
            /// <summary>The admitted node identifiers.</summary>
            private readonly HashSet<string> _allowed;

            /// <summary>Creates the table.</summary>
            /// <param name="allowed">The admitted node identifiers.</param>
            internal AllowListRoutingTable(params string[] allowed)
            {
                _allowed = new HashSet<string>(allowed);
            }

            /// <inheritdoc />
            public void Initialize(string localNodeId, int bucketSize)
            {
                _inner.Initialize(localNodeId, bucketSize);
            }

            /// <inheritdoc />
            public void Observe(DHTPeer peer, IPAddress? verifiedAddress)
            {
                if (_allowed.Contains(peer.NodeId))
                {
                    _inner.Observe(peer, verifiedAddress);
                }
            }

            /// <inheritdoc />
            public void Remove(string nodeId)
            {
            }

            /// <inheritdoc />
            public IReadOnlyList<DHTPeer> Closest(string routingId, int count)
            {
                return _inner.Closest(routingId, count);
            }
        }

        /// <summary>A TCP listener that counts complete length-prefixed frames without answering them.</summary>
        private sealed class FrameCounter : IAsyncDisposable
        {
            /// <summary>The listener.</summary>
            private readonly TcpListener _listener;
            /// <summary>The accept loop.</summary>
            private readonly Task _loop;
            /// <summary>Stops the accepted connections.</summary>
            private readonly CancellationTokenSource _stop = new CancellationTokenSource();
            /// <summary>The number of frames received.</summary>
            private int _frames;

            /// <summary>Gets the listening endpoint.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the number of frames received.</summary>
            internal int Frames => Volatile.Read(ref _frames);

            /// <summary>Starts counting.</summary>
            /// <param name="address">The listener address.</param>
            internal FrameCounter(IPAddress address)
            {
                _listener = new TcpListener(address, 0);
                _listener.Start();
                Endpoint = (IPEndPoint)_listener.LocalEndpoint;
                _loop = AcceptAsync();
            }

            /// <summary>Accepts connections until disposal.</summary>
            /// <returns>Completion after the listener stops.</returns>
            private async Task AcceptAsync()
            {
                var readers = new List<Task>();
                try
                {
                    while (!_stop.IsCancellationRequested)
                    {
                        var client = await _listener.AcceptTcpClientAsync();
                        readers.Add(ReadAsync(client));
                    }
                }
                catch (Exception exception) when (exception is SocketException || exception is ObjectDisposedException)
                {
                }
                await Task.WhenAll(readers);
            }

            /// <summary>Counts the frames of one connection.</summary>
            /// <param name="client">The accepted connection.</param>
            /// <returns>Completion after the connection closes.</returns>
            private async Task ReadAsync(TcpClient client)
            {
                using (client)
                {
                    try
                    {
                        var stream = client.GetStream();
                        var prefix = new byte[4];
                        while (true)
                        {
                            await stream.ReadExactlyAsync(prefix, _stop.Token);
                            var length = (prefix[0] << 24) | (prefix[1] << 16) | (prefix[2] << 8) | prefix[3];
                            await stream.ReadExactlyAsync(new byte[length], _stop.Token);
                            Interlocked.Increment(ref _frames);
                        }
                    }
                    catch (Exception exception) when (exception is IOException || exception is OperationCanceledException
                        || exception is ObjectDisposedException)
                    {
                    }
                }
            }

            /// <summary>Stops the listener and every reader.</summary>
            /// <returns>Completion after shutdown.</returns>
            public async ValueTask DisposeAsync()
            {
                _stop.Cancel();
                _listener.Stop();
                await _loop;
                _stop.Dispose();
            }
        }
    }
}
