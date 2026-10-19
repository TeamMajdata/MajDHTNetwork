using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Xunit;

#nullable enable

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises relay registry quotas, observed socket endpoints and server-side capability enforcement.</summary>
    public sealed class NatQuotaTests
    {
        /// <summary>Rejects a second identity while full and reclaims an expired registration without trusting advertised ports.</summary>
        /// <param name="protocol">The transport whose actual source port must be registered.</param>
        /// <returns>Completion after both registrations and expiry reclamation.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task RegistryUsesObservedPortsAndReclaimsExpiredQuota(DHTTransport protocol)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var options = RelayOptions(protocol, DHTCapabilities.Relay);
            options.MaxNatRegistrations = 1;
            options.NatRegistrationLifetime = TimeSpan.FromSeconds(1);
            await using var relay = new MajDHTNode(options);
            await relay.StartAsync(deadline.Token);
            var firstIdentity = new DHTIdentity();
            var secondIdentity = new DHTIdentity();
            await using var first = CreateClient(protocol);
            await using var second = CreateClient(protocol);
            var registered = await RegisterAsync(first, firstIdentity, relay.LocalPeer, protocol, deadline.Token);
            using (var response = new Wire(registered.Body))
            {
                Assert.Equal(0, response.Byte());
                using var payload = new Wire(response.Bytes(Wire.MaxPacket));
                Assert.Equal(IPAddress.Loopback.ToString(), payload.Text(96));
                Assert.Equal(protocol == DHTTransport.Tcp ? first.TcpPort : first.UdpPort, payload.Long());
                Assert.Equal(0, payload.Byte());
                payload.End();
                response.End();
            }
            var rejected = await RegisterAsync(second, secondIdentity, relay.LocalPeer, protocol, deadline.Token);
            Assert.Equal(1, Status(rejected));
            await Task.Delay(TimeSpan.FromMilliseconds(1200), deadline.Token);
            var reclaimed = await RegisterAsync(second, secondIdentity, relay.LocalPeer, protocol, deadline.Token);
            Assert.Equal(0, Status(reclaimed));
        }

        /// <summary>Rejects an authenticated rendezvous request at a server without relay capability.</summary>
        /// <param name="protocol">The receiving transport.</param>
        /// <returns>Completion after the authenticated rejection.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ServerRequiresRelayCapabilityForRendezvous(DHTTransport protocol)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var server = new MajDHTNode(RelayOptions(protocol, DHTCapabilities.Download));
            await server.StartAsync(deadline.Token);
            await using var client = CreateClient(protocol);
            var result = await RegisterAsync(client, new DHTIdentity(), server.LocalPeer, protocol, deadline.Token);
            Assert.Equal(1, Status(result));
        }

        /// <summary>Retries TCP registration after an initial UDP-only success supplies the relay's corrected contact.</summary>
        /// <returns>Completion after an authenticated TCP introduction through the recovered registration.</returns>
        [Fact]
        public async Task PartialRegistrationRetriesTheInitiallyUnavailableTransport()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var relayIdentity = new DHTIdentity();
            var options = new DHTNodeOptions
            {
                RequestTimeout = TimeSpan.FromMilliseconds(600),
                NatPollInterval = TimeSpan.FromMilliseconds(50),
                NatTraversalTimeout = TimeSpan.FromSeconds(2),
                Capabilities = DHTCapabilities.Relay
            };
            await using var relay = new MajDHTNode(options, relayIdentity);
            await relay.StartAsync(deadline.Token);
            options.Capabilities = DHTCapabilities.Download;
            options.AdvertisedAddress = IPAddress.Parse("127.0.0.2");
            await using var target = new MajDHTNode(options);
            await using var requester = new MajDHTNode(options);
            await Task.WhenAll(target.StartAsync(deadline.Token), requester.StartAsync(deadline.Token));
            var initiallyUdpOnly = DHTPeer.Create(relayIdentity, IPAddress.Loopback, 1, relay.LocalPeer.UdpPort, DHTCapabilities.Relay);
            await target.RegisterRelayAsync(initiallyUdpOnly, deadline.Token);
            await requester.RegisterRelayAsync(relay.LocalPeer, deadline.Token);
            var punched = false;
            while (!punched)
            {
                deadline.Token.ThrowIfCancellationRequested();
                punched = await requester.TryPunchAsync(target.LocalPeer, relay.LocalPeer, DHTTransport.Tcp, deadline.Token);
                if (!punched)
                {
                    await Task.Delay(50, deadline.Token);
                }
            }
            Assert.True(punched, "Polling must register TCP even when only UDP succeeded initially.");
        }

        /// <summary>Creates isolated options without automatic client registration.</summary>
        /// <param name="protocol">The enabled transport.</param>
        /// <param name="capabilities">The advertised services.</param>
        /// <returns>Short-timeout node options.</returns>
        private static DHTNodeOptions RelayOptions(DHTTransport protocol, DHTCapabilities capabilities)
        {
            return new DHTNodeOptions
            {
                TcpPort = protocol == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = protocol == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = protocol,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(600),
                NatPollInterval = TimeSpan.FromMilliseconds(50),
                EnableNatTraversal = false
            };
        }

        /// <summary>Creates a bound client transport while rejecting unsolicited application requests.</summary>
        /// <param name="protocol">The enabled transport.</param>
        /// <returns>The caller-owned running transport.</returns>
        private static SocketTransport CreateClient(DHTTransport protocol)
        {
            var client = new SocketTransport(RelayOptions(protocol, DHTCapabilities.Download).Snapshot(),
                (packet, token) => Task.FromException<ReadOnlyMemory<byte>>(new IOException("Unexpected incoming test request.")));
            client.Bind();
            client.Run();
            return client;
        }

        /// <summary>Sends a signed registration advertising an intentionally incorrect port.</summary>
        /// <param name="client">The bound source transport.</param>
        /// <param name="identity">The registrant's signing identity.</param>
        /// <param name="relay">The authenticated server contact.</param>
        /// <param name="protocol">The source mapping to register.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>The authenticated and correlated response.</returns>
        private static async Task<Packet> RegisterAsync(SocketTransport client, DHTIdentity identity, DHTPeer relay,
            DHTTransport protocol, CancellationToken cancellationToken)
        {
            var sender = DHTPeer.Create(identity, IPAddress.Loopback, protocol == DHTTransport.Tcp ? 1 : 0,
                protocol == DHTTransport.Udp ? 1 : 0, DHTCapabilities.Download);
            var request = new Packet(sender, Crypto.Random(16), (byte)Operation.Rendezvous, new byte[] { 0 });
            var endpoint = new IPEndPoint(relay.Address, protocol == DHTTransport.Tcp ? relay.TcpPort : relay.UdpPort);
            var result = await client.ExchangeAtAsync(relay, protocol, endpoint, request.Seal(identity, relay), cancellationToken);
            var response = Packet.Open(identity, result);
            Assert.Equal(relay.NodeId, response.Sender.NodeId);
            Assert.True(request.RequestId.Span.SequenceEqual(response.RequestId.Span));
            Assert.Equal((byte)(request.Kind | 0x80), response.Kind);
            return response;
        }

        /// <summary>Reads an operation status while validating its complete response framing.</summary>
        /// <param name="packet">The authenticated server response.</param>
        /// <returns>The success or rejection status.</returns>
        private static byte Status(Packet packet)
        {
            using var response = new Wire(packet.Body);
            var status = response.Byte();
            response.Bytes(Wire.MaxPacket);
            response.End();
            return status;
        }
    }
}
