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
    /// <summary>Checks that a successful small probe does not suppress a usable opaque forwarding route.</summary>
    public sealed class NatFallbackTests
    {
        /// <summary>Falls back through the sole assisting relay when the introduced endpoint accepts probes but drops subsequent direct RPCs.</summary>
        /// <returns>Completion after bootstrap through the opaque route and authenticated private-endpoint registration.</returns>
        [Fact]
        public async Task FailedRpcAfterSuccessfulPunchStillUsesTheSameRelay()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var relayOptions = Options(DHTCapabilities.Relay);
            await using var relay = new MajDHTNode(relayOptions);
            await relay.StartAsync(deadline.Token);
            var identity = new DHTIdentity();
            DHTPeer? providerPeer = null;
            var probes = 0;
            var droppedDirectRequests = 0;
            var forwardedRequests = 0;
            await using var provider = new SocketTransport(Options(DHTCapabilities.Provide).Snapshot(),
                (encoded, protocol, source, token) =>
                {
                    var request = Packet.Open(identity, encoded);
                    if (request.Kind == (byte)Operation.Punch)
                    {
                        Interlocked.Increment(ref probes);
                    }
                    else if (source.Port != relay.LocalPeer.UdpPort())
                    {
                        Interlocked.Increment(ref droppedDirectRequests);
                        return Task.FromException<ReadOnlyMemory<byte>>(new IOException("The simulated direct data path drops this request."));
                    }
                    else
                    {
                        Interlocked.Increment(ref forwardedRequests);
                    }
                    using var payload = new Wire();
                    if (request.Kind == (byte)Operation.Find)
                    {
                        payload.Put(ReadOnlySpan<byte>.Empty);
                        payload.PutLong(0);
                        payload.PutLong(0);
                    }
                    using var body = new Wire();
                    body.PutByte(0);
                    body.Put(payload.WrittenSpan);
                    var response = new Packet(providerPeer!, request.RequestId, (byte)(request.Kind | 0x80), body.WrittenMemory);
                    return Task.FromResult<ReadOnlyMemory<byte>>(response.Seal(identity, request.Sender));
                });
            provider.Bind();
            // A relay must use its observed registration; this signed endpoint cannot receive any traffic.
            providerPeer = DHTPeer.Create(identity, IPAddress.Parse("127.0.0.2"), 0, 1, DHTCapabilities.Provide);
            provider.Run();
            var registration = new Packet(providerPeer, Crypto.Random(16), (byte)Operation.Rendezvous, new byte[] { 0 });
            var registrationBytes = await provider.ExchangeAtAsync(DHTTransport.Udp,
                new IPEndPoint(IPAddress.Loopback, relay.LocalPeer.UdpPort()), registration.Seal(identity, relay.LocalPeer), deadline.Token);
            var registered = Packet.Open(identity, registrationBytes);
            Assert.Equal(relay.NodeId, registered.Sender.NodeId);
            using (var reply = new Wire(registered.Body))
            {
                Assert.Equal(0, reply.Byte());
            }
            var clientOptions = Options(DHTCapabilities.Download);
            clientOptions.EnableNatTraversal = true;
            await using var client = new MajDHTNode(clientOptions);
            await client.StartAsync(deadline.Token);
            await client.RegisterRelayAsync(relay.LocalPeer, deadline.Token);
            await client.JoinAsync(providerPeer, deadline.Token);
            Assert.True(Volatile.Read(ref probes) > 0, "The introduced path must first accept an authenticated probe.");
            Assert.True(Volatile.Read(ref droppedDirectRequests) > 0, "The subsequent ordinary direct RPC must fail.");
            Assert.True(Volatile.Read(ref forwardedRequests) > 0, "The same relay must still forward after the direct failure.");
            Assert.Contains(client.KnownPeers, peer => peer.NodeId == providerPeer.NodeId);
        }

        /// <summary>Creates a short-budget UDP-only participant configuration.</summary>
        /// <param name="capabilities">The advertised services.</param>
        /// <returns>Independent options for this controlled packet-loss scenario.</returns>
        private static DHTNodeOptions Options(DHTCapabilities capabilities)
        {
            return new DHTNodeOptions
            {
                TcpPort = null,
                PreferredTransport = DHTTransport.Udp,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(300),
                UdpAttempts = 1,
                NatPollInterval = TimeSpan.FromMilliseconds(50),
                NatTraversalTimeout = TimeSpan.FromSeconds(2),
                EnableNatTraversal = false
            };
        }
    }
}
