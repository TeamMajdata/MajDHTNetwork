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
    /// <summary>
    /// Exercises the hosted registry quotas, observed socket endpoints and server-side capability enforcement of traversal
    /// registrations and forwarding sessions.
    /// </summary>
    public sealed class NatQuotaTests
    {
        /// <summary>Rejects a second identity while full and reclaims an expired registration, binding the observed source port.</summary>
        /// <param name="protocol">The transport whose actual source port must be registered.</param>
        /// <param name="operation">The Traversal registration or the Forward session.</param>
        /// <returns>Completion after both registrations and expiry reclamation.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp, Operation.Traversal)]
        [InlineData(DHTTransport.Udp, Operation.Traversal)]
        [InlineData(DHTTransport.Tcp, Operation.Forward)]
        [InlineData(DHTTransport.Udp, Operation.Forward)]
        public async Task RegistryUsesObservedPortsAndReclaimsExpiredQuota(DHTTransport protocol, Operation operation)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var options = HostOptions(protocol, DHTCapabilities.Traversal | DHTCapabilities.Forwarder);
            options.MaxNatRegistrations = 1;
            options.NatRegistrationLifetime = TimeSpan.FromSeconds(1);
            await using var host = new MajDHTNode(options);
            await host.StartAsync(deadline.Token);
            var firstIdentity = new DHTIdentity();
            var secondIdentity = new DHTIdentity();
            await using var first = CreateClient(protocol);
            await using var second = CreateClient(protocol);
            using var registered = await RegisterAsync(first, firstIdentity, host.LocalPeer, protocol, operation, deadline.Token);
            using (var response = new Wire(registered.Packet.Body))
            {
                Assert.Equal(0, response.Byte());
                using var payload = new Wire(response.Bytes(Wire.MaxPacket));
                Assert.Equal(IPAddress.Loopback.ToString(), payload.Text(96));
                Assert.Equal(protocol == DHTTransport.Tcp ? first.TcpPort : first.UdpPort, payload.Long());
                if (operation == Operation.Traversal)
                {
                    Assert.Equal(0, payload.Byte());
                }
                payload.End();
                response.End();
            }
            using var rejected = await RegisterAsync(second, secondIdentity, host.LocalPeer, protocol, operation, deadline.Token);
            Assert.Equal(1, Status(rejected.Packet));
            await Task.Delay(TimeSpan.FromMilliseconds(1200), deadline.Token);
            using var reclaimed = await RegisterAsync(second, secondIdentity, host.LocalPeer, protocol, operation, deadline.Token);
            Assert.Equal(0, Status(reclaimed.Packet));
        }

        /// <summary>Rejects an authenticated registration at a node that lacks the role's capability, even when it serves the other role.</summary>
        /// <param name="protocol">The receiving transport.</param>
        /// <param name="operation">The Traversal registration or the Forward session.</param>
        /// <param name="hostCapabilities">The capabilities of the node that must refuse.</param>
        /// <returns>Completion after the authenticated rejection.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp, Operation.Traversal, DHTCapabilities.Download)]
        [InlineData(DHTTransport.Udp, Operation.Traversal, DHTCapabilities.Forwarder)]
        [InlineData(DHTTransport.Tcp, Operation.Forward, DHTCapabilities.Traversal)]
        [InlineData(DHTTransport.Udp, Operation.Forward, DHTCapabilities.Download)]
        public async Task HostsRequireTheMatchingCapability(DHTTransport protocol, Operation operation, DHTCapabilities hostCapabilities)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var server = new MajDHTNode(HostOptions(protocol, hostCapabilities));
            await server.StartAsync(deadline.Token);
            await using var client = CreateClient(protocol);
            using var result = await RegisterAsync(client, new DHTIdentity(), server.LocalPeer, protocol, operation, deadline.Token);
            Assert.Equal(1, Status(result.Packet));
        }

        /// <summary>Introduces two registrants over the one transport both registered, while the other transport cannot be punched.</summary>
        /// <returns>Completion after the TCP introduction and the UDP refusal.</returns>
        [Fact]
        public async Task IntroductionsRequireRegistrationsOnTheRequestedTransport()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var traversalIdentity = new DHTIdentity();
            var options = new DHTNodeOptions
            {
                RequestTimeout = TimeSpan.FromMilliseconds(600),
                NatPollInterval = TimeSpan.FromMilliseconds(50),
                NatTraversalTimeout = TimeSpan.FromSeconds(2),
                Capabilities = DHTCapabilities.Traversal
            };
            await using var traversal = new MajDHTNode(options, traversalIdentity);
            await traversal.StartAsync(deadline.Token);
            options.Capabilities = DHTCapabilities.Download;
            await using var target = new MajDHTNode(options);
            await using var requester = new MajDHTNode(options);
            await Task.WhenAll(target.StartAsync(deadline.Token), requester.StartAsync(deadline.Token));
            // The target observed the Traversal node over TCP only, so it registers TCP only; UDP cannot be introduced to it.
            var tcpOnly = DHTPeer.Create(traversalIdentity, IPAddress.Loopback, traversal.LocalPeer.TcpPort(), 0, DHTCapabilities.Traversal);
            await target.RegisterTraversalAsync(tcpOnly, deadline.Token);
            await requester.RegisterTraversalAsync(traversal.LocalPeer, deadline.Token);
            Assert.True(await requester.TryPunchAsync(target.LocalPeer, traversal.LocalPeer, DHTTransport.Tcp, deadline.Token),
                "Both sides registered TCP, so the TCP introduction must succeed.");
            Assert.False(await requester.TryPunchAsync(target.LocalPeer, traversal.LocalPeer, DHTTransport.Udp, deadline.Token),
                "The target never registered UDP, so the Traversal node must refuse the UDP introduction.");
        }

        /// <summary>Creates isolated options without automatic client registration.</summary>
        /// <param name="protocol">The enabled transport.</param>
        /// <param name="capabilities">The advertised services.</param>
        /// <returns>Short-timeout node options.</returns>
        private static DHTNodeOptions HostOptions(DHTTransport protocol, DHTCapabilities capabilities)
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
            var client = new SocketTransport(HostOptions(protocol, DHTCapabilities.Download).Snapshot(),
                (packet, token) => Task.FromException<ReadOnlyMemory<byte>>(new IOException("Unexpected incoming test request.")));
            client.Bind();
            client.Run();
            return client;
        }

        /// <summary>Sends a signed registration or session request from a contact that names no endpoint of its own.</summary>
        /// <param name="client">The bound source transport.</param>
        /// <param name="identity">The registrant's signing identity.</param>
        /// <param name="host">The authenticated server at its listener endpoint.</param>
        /// <param name="protocol">The source mapping to register.</param>
        /// <param name="operation">The Traversal registration or the Forward session; both start with action byte zero.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>The authenticated and correlated response, still holding its received frame until disposed.</returns>
        private static async Task<OwnedPacket> RegisterAsync(SocketTransport client, DHTIdentity identity, DHTPeer host, DHTTransport protocol,
            Operation operation, CancellationToken cancellationToken)
        {
            var sender = DHTContact.Create(identity, DHTCapabilities.Download);
            var request = new Packet(sender, Crypto.Random(16), (byte)operation, new byte[] { 0 });
            var endpoint = new IPEndPoint(host.Address(), protocol == DHTTransport.Tcp ? host.TcpPort() : host.UdpPort());
            var result = await client.ExchangeAtAsync(protocol, endpoint, request.Seal(identity, host), cancellationToken);
            var response = Packet.Open(identity, result.Bytes);
            Assert.Equal(host.NodeId, response.Sender.NodeId);
            Assert.True(request.RequestId.Span.SequenceEqual(response.RequestId.Span));
            Assert.Equal((byte)(request.Kind | 0x80), response.Kind);
            return new OwnedPacket(response, result);
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
