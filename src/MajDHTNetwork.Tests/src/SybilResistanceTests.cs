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
            Assert.Equal(identity.IdentityWork, new DHTContact(contact.Contact.Encoded.ToArray()).IdentityWork);
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
            table.Observe(unverified.Contact, null);
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
        /// Admits an inbound sender only after it answered a Ping at the source its request came from, and verifies senders
        /// only a bounded number of times per source network, so one host cannot flood the table with minted identities.
        /// </summary>
        /// <returns>Completion after the admission and verification assertions.</returns>
        [Fact]
        public async Task InboundSendersAreVerifiedAtTheirObservedSource()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await node.StartAsync(token);
            await using var honest = new ScriptedPeer(IPAddress.Parse("127.0.0.6"), DHTCapabilities.Download, DHTReachability.Unknown);
            Assert.Equal(0, (await honest.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            await WaitUntilAsync(() => Contains(node.KnownPeers, honest.Peer.NodeId), token);
            var admitted = node.KnownPeers[0];
            Assert.True(admitted.WasObservedAt(DHTTransport.Tcp, honest.Endpoint), "The sender must be admitted at the source it sent from.");
            // The forger mints identities; the verification pings sealed to them cannot be answered by its own identity.
            await using var forger = new ScriptedPeer(IPAddress.Parse("127.0.0.7"), DHTCapabilities.Download, DHTReachability.Unknown);
            var forged = new HashSet<string>();
            for (var index = 0; index < 20; index++)
            {
                var identity = new DHTIdentity();
                forged.Add(identity.NodeId);
                Assert.Equal(0, (await forger.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token, identity)).Status);
            }
            await Task.Delay(TimeSpan.FromSeconds(2), token);
            Assert.Equal(0, CountIn(node.KnownPeers, forged));
            var verifications = 0;
            foreach (var identity in forged)
            {
                verifications += node.GetPeerStatistics(identity) == null ? 0 : 1;
            }
            Assert.InRange(verifications, 1, MajDHTNode.VerificationsPerNetwork);
        }

        /// <summary>
        /// Re-verifies a routed sender that sends from a source it was never observed at, such as after a restart on another
        /// port: the new source replaces the old port once it answers a Ping, and stays out of the table while it does not.
        /// </summary>
        /// <returns>Completion after the moved sender was admitted and the unverifiable one was not.</returns>
        [Fact]
        public async Task KnownSendersAreReverifiedAtANewSource()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await node.StartAsync(token);
            var address = IPAddress.Parse("127.0.0.6");
            IPEndPoint original;
            DHTIdentity identity;
            await using (var honest = new ScriptedPeer(address, DHTCapabilities.Download, DHTReachability.Unknown))
            {
                original = honest.Endpoint;
                identity = honest.Identity;
                Assert.Equal(0, (await honest.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
                await WaitUntilAsync(() => Contains(node.KnownPeers, identity.NodeId), token);
            }
            // The same node restarts on another port of the same address and answers the verification Ping there.
            await using var moved = new ScriptedPeer(address, DHTCapabilities.Download, DHTReachability.Unknown, identity);
            Assert.Equal(0, (await moved.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            await WaitUntilAsync(() => RoutedAt(node, identity.NodeId, moved.Endpoint), token);
            Assert.True(moved.Received(Operation.Ping) > 0, "The moved sender must be verified at its new source.");
            Assert.False(RoutedAt(node, identity.NodeId, original), "A port replaced at the same address must not linger.");
            // A source that does not answer the verification Ping under the routed identity never replaces the admitted one.
            await using var silent = new ScriptedPeer(address, DHTCapabilities.Download, DHTReachability.Unknown, identity);
            silent.Script((packet, source) => ((byte)1, Array.Empty<byte>()));
            Assert.Equal(0, (await silent.SendAsync(node.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            await WaitUntilAsync(() => silent.Received(Operation.Ping) > 0, token);
            await Task.Delay(TimeSpan.FromSeconds(1), token);
            Assert.True(RoutedAt(node, identity.NodeId, moved.Endpoint), "A failed verification must keep the verified source.");
            Assert.False(RoutedAt(node, identity.NodeId, silent.Endpoint));
        }

        /// <summary>Checks whether a node's routing table holds a peer observed at a TCP endpoint.</summary>
        /// <param name="node">The node.</param>
        /// <param name="nodeId">The peer identifier.</param>
        /// <param name="endpoint">The TCP endpoint.</param>
        /// <returns>Whether the peer is known and was observed there.</returns>
        private static bool RoutedAt(MajDHTNode node, string nodeId, IPEndPoint endpoint)
        {
            foreach (var peer in node.KnownPeers)
            {
                if (peer.NodeId == nodeId)
                {
                    return peer.WasObservedAt(DHTTransport.Tcp, endpoint);
                }
            }
            return false;
        }

        /// <summary>Draws at most one dial-back helper per network, so one network cannot supply every helper.</summary>
        /// <returns>Completion after three dial-back requests.</returns>
        [Fact]
        public async Task DialBackHelpersAreDrawnOncePerNetwork()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var relayOptions = Options(DHTTransport.Tcp, DHTCapabilities.Traversal);
            relayOptions.ListenAddresses = new List<IPAddress> { IPAddress.Loopback };
            relayOptions.PubliclyReachable = true;
            await using var relay = new MajDHTNode(relayOptions);
            await relay.StartAsync(token);
            await using var first = new ScriptedPeer(IPAddress.Parse("127.0.0.3"), DHTCapabilities.Traversal);
            await using var second = new ScriptedPeer(IPAddress.Parse("127.0.0.3"), DHTCapabilities.Traversal);
            await using var third = new ScriptedPeer(IPAddress.Parse("127.0.0.4"), DHTCapabilities.Traversal);
            foreach (var helper in new[] { first, second, third })
            {
                helper.Script((packet, source) => packet.Kind == (byte)Operation.Traversal ? ((byte)1, Array.Empty<byte>()) : ((byte)0, Array.Empty<byte>()));
                Assert.Equal(0, (await helper.SendAsync(relay.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            }
            await WaitUntilAsync(() => relay.KnownPeers.Count >= 3, token);
            await using var requester = new ScriptedPeer(IPAddress.Parse("127.0.0.2"), DHTCapabilities.Download, DHTReachability.Unknown);
            var request = new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0 };
            for (var attempt = 0; attempt < 3; attempt++)
            {
                Assert.Equal(1, (await requester.SendAsync(relay.LocalPeer, Operation.Traversal, request, token)).Status);
            }
            Assert.Equal(3, first.Received(Operation.Traversal) + second.Received(Operation.Traversal));
            Assert.Equal(3, third.Received(Operation.Traversal));
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

        /// <summary>Encodes a Find result without a record, with the given nearest peers and no providers.</summary>
        /// <param name="peers">The referred peers at the endpoints the referrer claims for them.</param>
        /// <returns>The result body.</returns>
        private static byte[] FindReply(IReadOnlyList<DHTPeer> peers)
        {
            using var body = new Wire();
            body.Put(ReadOnlySpan<byte>.Empty);
            body.PutLong(peers.Count);
            foreach (var peer in peers)
            {
                peer.Write(body);
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

        /// <summary>Observes generated contacts at observed endpoints.</summary>
        /// <param name="table">The routing table.</param>
        /// <param name="count">The number of contacts.</param>
        /// <param name="address">Selects the observed address of each contact.</param>
        /// <returns>The generated node identifiers.</returns>
        private static HashSet<string> Observe(IDHTRoutingTable table, int count, Func<int, string> address)
        {
            var result = new HashSet<string>();
            for (var index = 0; index < count; index++)
            {
                var peer = DHTPeer.Create(new DHTIdentity(), IPAddress.Parse(address(index)), 1000, 0, DHTCapabilities.Download);
                table.Observe(peer.Contact, peer.Endpoints[0]);
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
            public void Observe(DHTContact contact, DHTEndpoint? observed)
            {
                if (_allowed.Contains(contact.NodeId))
                {
                    _inner.Observe(contact, observed);
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
    }
}
