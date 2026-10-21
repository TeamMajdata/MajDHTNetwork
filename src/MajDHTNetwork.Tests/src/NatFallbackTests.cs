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
    /// <summary>Checks that a successful small probe does not suppress a usable forwarding route through the same assistant.</summary>
    public sealed class NatFallbackTests
    {
        /// <summary>
        /// Falls back to forwarding through the sole assistant, a Traversal node that is also a Forwarder, when the introduced
        /// endpoint accepts probes but drops subsequent direct RPCs; the Forwarder delivers over the provider's session binding.
        /// </summary>
        /// <returns>Completion after bootstrap through the forwarded route.</returns>
        [Fact]
        public async Task FailedRpcAfterSuccessfulPunchStillForwardsThroughTheSameAssistant()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            await using var assistant = new MajDHTNode(Options(DHTCapabilities.Traversal | DHTCapabilities.Forwarder));
            await assistant.StartAsync(deadline.Token);
            var identity = new DHTIdentity();
            DHTContact? providerContact = null;
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
                        return Task.FromResult(Answer(request, Array.Empty<byte>()));
                    }
                    if (request.Kind == (byte)Operation.Forward && source.Port == assistant.LocalPeer.UdpPort())
                    {
                        // The Forwarder delivers the origin's envelope inside its own request; the inner reply goes back the same way.
                        Interlocked.Increment(ref forwardedRequests);
                        using var body = new Wire(request.Body);
                        Assert.Equal(ForwardAction.Deliver, ForwardMessage.ReadAction(body));
                        var inner = Packet.Open(identity, ForwardMessage.ReadDeliverRequest(body, identity.NodeId));
                        using var result = new Wire();
                        ForwardMessage.WriteEnvelopeResponse(result, Answer(inner, DataResult(inner)).Span);
                        return Task.FromResult(Answer(request, result.ToArray()));
                    }
                    Interlocked.Increment(ref droppedDirectRequests);
                    return Task.FromException<ReadOnlyMemory<byte>>(new IOException("The simulated direct data path drops this request."));
                });
            provider.Bind();
            providerContact = DHTContact.Create(identity, DHTCapabilities.Provide);
            provider.Run();
            // The provider registers for traversal and opens a forwarding session, so the assistant holds its observed bindings.
            await RegisterAsync(provider, identity, providerContact, assistant.LocalPeer, Operation.Traversal, deadline.Token);
            await RegisterAsync(provider, identity, providerContact, assistant.LocalPeer, Operation.Forward, deadline.Token);
            var clientOptions = Options(DHTCapabilities.Download);
            clientOptions.EnableNatTraversal = true;
            await using var client = new MajDHTNode(clientOptions);
            await client.StartAsync(deadline.Token);
            await client.RegisterTraversalAsync(assistant.LocalPeer, deadline.Token);
            // The client knows the provider only at an address where nothing listens.
            var providerPeer = new DHTPeer(providerContact, new[] { new DHTEndpoint(IPAddress.Parse("127.0.0.2"), 0, 1) });
            await client.JoinAsync(providerPeer, deadline.Token);
            Assert.True(Volatile.Read(ref probes) > 0, "The introduced path must first accept an authenticated probe.");
            Assert.True(Volatile.Read(ref droppedDirectRequests) > 0, "The subsequent ordinary direct RPC must fail.");
            Assert.True(Volatile.Read(ref forwardedRequests) > 0, "The same assistant must still forward after the direct failure.");
            // The provider never answered at a selected direct route, so it must not be referred to other nodes.
            Assert.DoesNotContain(client.KnownPeers, peer => peer.NodeId == providerContact.NodeId);

            ReadOnlyMemory<byte> Answer(Packet request, ReadOnlySpan<byte> result)
            {
                using var body = new Wire();
                ResponseStatus.WriteSuccess(body, result);
                return new Packet(providerContact!, request.RequestId, (byte)(request.Kind | 0x80), body.WrittenMemory).Seal(identity, request.Sender);
            }
        }

        /// <summary>Builds the successful result of a data request: an empty Find result, or nothing for every other operation.</summary>
        /// <param name="request">The authenticated inner request.</param>
        /// <returns>The result bytes.</returns>
        private static byte[] DataResult(Packet request)
        {
            using var payload = new Wire();
            if (request.Kind == (byte)Operation.Find)
            {
                payload.Put(ReadOnlySpan<byte>.Empty);
                payload.PutLong(0);
                payload.PutLong(0);
            }
            return payload.ToArray();
        }

        /// <summary>Registers the provider transport with the assistant over UDP through one action-zero request.</summary>
        /// <param name="transport">The provider's bound transport.</param>
        /// <param name="identity">The provider identity.</param>
        /// <param name="contact">The provider contact.</param>
        /// <param name="assistant">The assistant at its listener endpoint.</param>
        /// <param name="operation">The Traversal registration or the Forward session.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>Completion after the assistant accepted the registration.</returns>
        private static async Task RegisterAsync(SocketTransport transport, DHTIdentity identity, DHTContact contact, DHTPeer assistant,
            Operation operation, CancellationToken cancellationToken)
        {
            var registration = new Packet(contact, Crypto.Random(16), (byte)operation, new byte[] { 0 });
            using var encoded = await transport.ExchangeAtAsync(DHTTransport.Udp, new IPEndPoint(IPAddress.Loopback, assistant.UdpPort()),
                registration.Seal(identity, assistant), cancellationToken);
            var registered = Packet.Open(identity, encoded.Bytes);
            Assert.Equal(assistant.NodeId, registered.Sender.NodeId);
            using var reply = new Wire(registered.Body);
            Assert.Equal(0, reply.Byte());
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
