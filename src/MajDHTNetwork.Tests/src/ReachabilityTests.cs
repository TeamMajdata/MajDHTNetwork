#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises external-address voting, independent dial-backs, private contacts and relay hints over distinct loopback hosts.</summary>
    [Trait("Category", "NAT")]
    public sealed class ReachabilityTests
    {
        /// <summary>Verifies a public endpoint after an independent helper dials the observed address back.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after the owner advertises a verified public endpoint.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task IndependentDialBackVerifiesAPublicEndpoint(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(Options("127.0.0.1", transport, DHTCapabilities.Relay, advertise: true));
            await using var helper = new MajDHTNode(Options("127.0.0.3", transport, DHTCapabilities.Relay, advertise: true));
            await using var owner = new MajDHTNode(Options("127.0.0.2", transport, DHTCapabilities.Download | DHTCapabilities.Provide, advertise: false));
            await Task.WhenAll(relay.StartAsync(token), helper.StartAsync(token), owner.StartAsync(token));
            Assert.Equal(DHTReachability.Unknown, owner.LocalPeer.Reachability);
            Assert.Equal(DHTEndpointFlags.Local, Assert.Single(owner.LocalPeer.Endpoints).Flags);
            await helper.JoinAsync(relay.LocalPeer, token);
            await owner.JoinAsync(relay.LocalPeer, token);
            await owner.JoinAsync(helper.LocalPeer, token);
            await WaitUntilAsync(() => owner.LocalPeer.Reachability == DHTReachability.Public && owner.LocalPeer.ExternalAddress != null, token);
            var contact = owner.LocalPeer;
            var endpoint = Assert.Single(contact.Endpoints);
            Assert.Equal(DHTEndpointFlags.Verified, endpoint.Flags);
            Assert.Equal(IPAddress.Parse("127.0.0.2"), endpoint.Address);
            Assert.NotEqual(0, transport == DHTTransport.Tcp ? endpoint.TcpPort : endpoint.UdpPort);
            Assert.Equal(IPAddress.Parse("127.0.0.2"), contact.ExternalAddress);
            Assert.Empty(contact.RelayHints);
        }

        /// <summary>
        /// Marks a node private after dial-backs from two relay networks time out, excludes it from routing tables and
        /// downloads from it through a relay hint.
        /// </summary>
        /// <returns>Completion after the verified download through the hinted relay.</returns>
        [Fact]
        public async Task FailedDialBacksMakeAPrivateNodeReachableThroughRelayHints()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            await using var first = new MajDHTNode(Options("127.0.0.1", DHTTransport.Tcp, DHTCapabilities.Relay, advertise: true));
            await using var second = new MajDHTNode(Options("127.0.0.4", DHTTransport.Tcp, DHTCapabilities.Relay, advertise: true));
            await using var owner = new MajDHTNode(Options("127.0.0.2", DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide,
                advertise: false));
            var clientOptions = Options("127.0.0.1", DHTTransport.Tcp, DHTCapabilities.Download, advertise: false);
            clientOptions.EnableNatTraversal = false;
            await using var client = new MajDHTNode(clientOptions);
            await Task.WhenAll(first.StartAsync(token), second.StartAsync(token), owner.StartAsync(token), client.StartAsync(token));
            await using var helper = await SilentHelper.StartAsync(IPAddress.Parse("127.0.0.3"), token);
            await helper.PingAsync(first.LocalPeer, token);
            await helper.PingAsync(second.LocalPeer, token);
            await owner.JoinAsync(first.LocalPeer, token);
            await owner.JoinAsync(second.LocalPeer, token);
            await WaitUntilAsync(() => owner.LocalPeer.Reachability == DHTReachability.Private, token);
            var contact = owner.LocalPeer;
            Assert.True(helper.Delegations >= 2, "Each relay must delegate the dial-back to an independent helper.");
            Assert.Equal(2, contact.RelayHints.Count);
            Assert.All(contact.Endpoints, endpoint => Assert.Equal(DHTEndpointFlags.Local, endpoint.Flags));
            Assert.Equal(IPAddress.Parse("127.0.0.2"), contact.ExternalAddress);
            await WaitUntilAsync(() => !Contains(first.KnownPeers, owner.NodeId), token);
            var content = Crypto.Random(20000);
            using var source = new MemoryStream(content);
            var record = await owner.PublishAsync("private/file", source, cancellationToken: token);
            await client.JoinAsync(first.LocalPeer, token);
            using var destination = new MemoryStream();
            await client.DownloadAsync(record.Key, destination, record.FileHash, token);
            Assert.True(TestSupport.BytesEqual(content, destination.ToArray()), "The hinted relay must deliver the verified file.");
            Assert.False(Contains(client.KnownPeers, owner.NodeId), "A private node must never enter routing tables.");
        }

        /// <summary>Creates fast single-transport options bound to one loopback host.</summary>
        /// <param name="address">The loopback address that models a distinct host.</param>
        /// <param name="transport">The only transport to bind.</param>
        /// <param name="capabilities">The advertised services.</param>
        /// <param name="advertise">Whether the listener address is configured as directly reachable.</param>
        /// <returns>Independent node options.</returns>
        private static DHTNodeOptions Options(string address, DHTTransport transport, DHTCapabilities capabilities, bool advertise)
        {
            var listen = IPAddress.Parse(address);
            return new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { listen },
                AdvertisedAddresses = advertise ? new List<IPAddress> { listen } : new List<IPAddress>(),
                TcpPort = transport == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = transport == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = transport,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(700),
                UdpAttempts = 2,
                NatTraversalTimeout = TimeSpan.FromSeconds(1.5),
                NatPollInterval = TimeSpan.FromMilliseconds(75),
                NatRegistrationLifetime = TimeSpan.FromSeconds(3)
            };
        }

        /// <summary>Checks whether a contact list contains a node.</summary>
        /// <param name="peers">The contacts.</param>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>Whether the node is present.</returns>
        private static bool Contains(IReadOnlyList<DHTPeer> peers, string nodeId)
        {
            foreach (var peer in peers)
            {
                if (peer.NodeId == nodeId)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Polls a condition until it holds.</summary>
        /// <param name="condition">The condition.</param>
        /// <param name="token">The test deadline.</param>
        /// <returns>Completion once the condition holds.</returns>
        /// <exception cref="OperationCanceledException">The deadline expired first.</exception>
        private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken token)
        {
            while (!condition())
            {
                await Task.Delay(50, token);
            }
        }

        /// <summary>A public relay-capable helper that accepts dial-back delegations but never sends probes.</summary>
        private sealed class SilentHelper : IAsyncDisposable
        {
            /// <summary>The helper identity.</summary>
            private readonly DHTIdentity _identity;
            /// <summary>The raw transport.</summary>
            private readonly SocketTransport _transport;
            /// <summary>The number of accepted dial-back delegations.</summary>
            private int _delegations;

            /// <summary>Gets the signed public helper contact.</summary>
            internal DHTPeer Peer { get; private set; }
            /// <summary>Gets the number of accepted dial-back delegations.</summary>
            internal int Delegations => Volatile.Read(ref _delegations);

            /// <summary>Creates an unbound helper.</summary>
            /// <param name="address">The loopback listener address.</param>
            private SilentHelper(IPAddress address)
            {
                _identity = new DHTIdentity();
                var options = new DHTNodeOptions
                {
                    ListenAddresses = new List<IPAddress> { address },
                    UdpPort = null,
                    RequestTimeout = TimeSpan.FromMilliseconds(700)
                }.Snapshot();
                _transport = new SocketTransport(options, Handle, NullLogger.Instance);
                Peer = null!;
            }

            /// <summary>Binds the helper and signs a public relay contact for its listener.</summary>
            /// <param name="address">The loopback listener address.</param>
            /// <param name="token">The test deadline.</param>
            /// <returns>The running helper.</returns>
            internal static Task<SilentHelper> StartAsync(IPAddress address, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                var helper = new SilentHelper(address);
                helper._transport.Bind();
                helper.Peer = DHTPeer.Create(helper._identity,
                    new[] { new DHTEndpoint(address, helper._transport.TcpPort, 0, DHTEndpointFlags.Configured) }, DHTCapabilities.Relay,
                    DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
                helper._transport.Run();
                return Task.FromResult(helper);
            }

            /// <summary>Introduces the helper to a relay through an authenticated Ping.</summary>
            /// <param name="relay">The relay that should learn the helper.</param>
            /// <param name="token">The test deadline.</param>
            /// <returns>Completion after the authenticated response.</returns>
            internal async Task PingAsync(DHTPeer relay, CancellationToken token)
            {
                var request = new Packet(Peer, Crypto.Random(16), (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty);
                var response = Packet.Open(_identity, await _transport.ExchangeAsync(relay, request.Seal(_identity, relay), token));
                Assert.Equal(relay.NodeId, response.Sender.NodeId);
            }

            /// <summary>Accepts every request with an empty result and counts dial-back delegations.</summary>
            /// <param name="encoded">The sealed request.</param>
            /// <param name="transport">The receiving transport.</param>
            /// <param name="source">The observed source.</param>
            /// <param name="token">The handler lifetime.</param>
            /// <returns>The sealed response.</returns>
            private Task<ReadOnlyMemory<byte>> Handle(ReadOnlyMemory<byte> encoded, DHTTransport transport, IPEndPoint source, CancellationToken token)
            {
                var request = Packet.Open(_identity, encoded);
                if (request.Kind == (byte)Operation.Rendezvous && request.Body.Length != 0 && request.Body.Span[0] == 3)
                {
                    Interlocked.Increment(ref _delegations);
                }
                using var body = new Wire();
                body.PutByte(0);
                body.Put(ReadOnlySpan<byte>.Empty);
                var response = new Packet(Peer, request.RequestId, (byte)(request.Kind | 0x80), body.ToArray());
                return Task.FromResult<ReadOnlyMemory<byte>>(response.Seal(_identity, request.Sender));
            }

            /// <summary>Stops the helper transport.</summary>
            /// <returns>Completion after the transport drains.</returns>
            public ValueTask DisposeAsync()
            {
                return _transport.DisposeAsync();
            }
        }
    }
}
