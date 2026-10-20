using System;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Xunit;

#nullable enable

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises persistent duplex TCP sessions and endpoint-pinned concurrent UDP exchanges over real sockets.</summary>
    public sealed class TransportSessionTests
    {
        /// <summary>Serves an incoming request during an outstanding punch and completes 24 later RPCs after the remote listener closes.</summary>
        /// <returns>Completion after authenticated traffic in both directions on the original TCP connection.</returns>
        [Fact]
        [Trait("Category", "NAT")]
        public async Task PunchedTcpSessionServesBothDirectionsAndReusesConnectionForTwentyFourRpcs()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var endpoint = (IPEndPoint)listener.LocalEndpoint;
            var localIdentity = new DHTIdentity();
            var remoteIdentity = new DHTIdentity();
            var remote = DHTPeer.Create(remoteIdentity, IPAddress.Loopback, endpoint.Port, 0, DHTCapabilities.Download);
            DHTPeer? local = null;
            var entered = new TaskCompletionSource<Packet>(TaskCreationOptions.RunContinuationsAsynchronously);
            var releaseHandler = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var incomingCount = 0;
            await using var transport = new SocketTransport(ClientOptions(DHTTransport.Tcp).Snapshot(),
                async (bytes, protocol, source, cancellationToken) =>
                {
                    var request = Packet.Open(localIdentity, bytes);
                    Assert.Equal(DHTTransport.Tcp, protocol);
                    Assert.Equal(endpoint, source);
                    Assert.Equal(remote.NodeId, request.Sender.NodeId);
                    Assert.Equal((byte)Operation.Ping, request.Kind);
                    Interlocked.Increment(ref incomingCount);
                    entered.TrySetResult(request);
                    await releaseHandler.Task.WaitAsync(cancellationToken);
                    return Response(request, local!).Seal(localIdentity, remote);
                });
            transport.Bind();
            local = DHTPeer.Create(localIdentity, IPAddress.Loopback, transport.TcpPort, 0, DHTCapabilities.Download);
            transport.Run();
            var punch = Request(local, Operation.Punch, 0);
            var punching = transport.PunchAsync(DHTTransport.Tcp, endpoint, punch.Seal(localIdentity, remote), token);
            using var connection = await listener.AcceptTcpClientAsync(token);
            Assert.Equal(transport.TcpPort, Assert.IsType<IPEndPoint>(connection.Client.RemoteEndPoint).Port);

            // Further active opens cannot succeed; all subsequent RPCs must reuse this accepted connection.
            listener.Stop();
            var stream = connection.GetStream();
            AssertRequest(remoteIdentity, local, punch, await ReadTcpFrameAsync(stream, token));
            var remotePing = Request(remote, Operation.Ping, 1);
            await WriteTcpFrameAsync(stream, remotePing.Seal(remoteIdentity, local), token);
            var incoming = await entered.Task.WaitAsync(token);
            Assert.True(remotePing.RequestId.Span.SequenceEqual(incoming.RequestId.Span));
            Assert.False(punching.IsCompleted, "An incoming request must not complete the outgoing response slot.");

            // The reader must consume the punch response while the incoming handler is still blocked.
            await WriteTcpFrameAsync(stream, Response(punch, remote).Seal(remoteIdentity, local), token);
            AssertResponse(localIdentity, remote, punch, await punching);
            Assert.False(releaseHandler.Task.IsCompleted);
            releaseHandler.TrySetResult(true);
            AssertResponse(remoteIdentity, local, remotePing, await ReadTcpFrameAsync(stream, token));

            for (var round = 0; round < 12; round++)
            {
                var localRequest = Request(local, Operation.Ping, (byte)(round + 2));
                var remoteRequest = Request(remote, Operation.Ping, (byte)(round + 32));
                var outgoing = transport.ExchangeAtAsync(DHTTransport.Tcp, endpoint,
                    localRequest.Seal(localIdentity, remote), token);
                AssertRequest(remoteIdentity, local, localRequest, await ReadTcpFrameAsync(stream, token));
                await WriteTcpFrameAsync(stream, remoteRequest.Seal(remoteIdentity, local), token);
                await WriteTcpFrameAsync(stream, Response(localRequest, remote).Seal(remoteIdentity, local), token);
                AssertResponse(localIdentity, remote, localRequest, await outgoing);
                AssertResponse(remoteIdentity, local, remoteRequest, await ReadTcpFrameAsync(stream, token));
            }
            Assert.Equal(13, Volatile.Read(ref incomingCount));
        }

        /// <summary>Keeps the outstanding exchange and the connection alive after the local handler rejects an incoming request.</summary>
        /// <returns>Completion after the pending response and one further exchange arrive on the same accepted connection.</returns>
        [Fact]
        [Trait("Category", "NAT")]
        public async Task RejectedIncomingTcpRequestDoesNotAbortOutstandingExchangeOrCloseSession()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var token = deadline.Token;
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var endpoint = (IPEndPoint)listener.LocalEndpoint;
            var localIdentity = new DHTIdentity();
            var remoteIdentity = new DHTIdentity();
            var remote = DHTPeer.Create(remoteIdentity, IPAddress.Loopback, endpoint.Port, 0, DHTCapabilities.Download);
            var rejected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var incomingCount = 0;
            await using var transport = new SocketTransport(ClientOptions(DHTTransport.Tcp).Snapshot(),
                (bytes, protocol, source, cancellationToken) =>
                {
                    Interlocked.Increment(ref incomingCount);
                    rejected.TrySetResult(true);
                    return Task.FromException<ReadOnlyMemory<byte>>(new IOException("This peer serves no requests."));
                });
            transport.Bind();
            var local = DHTPeer.Create(localIdentity, IPAddress.Loopback, transport.TcpPort, 0, DHTCapabilities.Download);
            transport.Run();
            var first = Request(local, Operation.Ping, 1);
            var firstExchange = transport.ExchangeAtAsync(DHTTransport.Tcp, endpoint, first.Seal(localIdentity, remote), token);
            using var connection = await listener.AcceptTcpClientAsync(token);

            // Further active opens cannot succeed; both exchanges must complete on this accepted connection.
            listener.Stop();
            var stream = connection.GetStream();
            AssertRequest(remoteIdentity, local, first, await ReadTcpFrameAsync(stream, token));

            // Like a relay verifying a registrant, the remote asks its own question before it answers ours.
            var remoteRequest = Request(remote, Operation.Ping, 2);
            await WriteTcpFrameAsync(stream, remoteRequest.Seal(remoteIdentity, local), token);
            await rejected.Task.WaitAsync(token);
            await WriteTcpFrameAsync(stream, Response(first, remote).Seal(remoteIdentity, local), token);
            AssertResponse(localIdentity, remote, first, await firstExchange);

            var second = Request(local, Operation.Ping, 3);
            var secondExchange = transport.ExchangeAtAsync(DHTTransport.Tcp, endpoint, second.Seal(localIdentity, remote), token);
            AssertRequest(remoteIdentity, local, second, await ReadTcpFrameAsync(stream, token));
            await WriteTcpFrameAsync(stream, Response(second, remote).Seal(remoteIdentity, local), token);
            AssertResponse(localIdentity, remote, second, await secondExchange);
            Assert.Equal(1, Volatile.Read(ref incomingCount));
        }

        /// <summary>Routes reversed UDP replies by request digest and discards a reply carrying an unrelated digest.</summary>
        /// <returns>Completion after two concurrent authenticated exchanges from the listener's source port.</returns>
        [Fact]
        [Trait("Category", "NAT")]
        public async Task ConcurrentUdpExchangesRouteReversedRepliesAndRejectUnrelatedDigest()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var token = deadline.Token;
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var endpoint = Assert.IsType<IPEndPoint>(server.Client.LocalEndPoint);
            var localIdentity = new DHTIdentity();
            var remoteIdentity = new DHTIdentity();
            var remote = DHTPeer.Create(remoteIdentity, IPAddress.Loopback, 0, endpoint.Port, DHTCapabilities.Download);
            await using var transport = CreateUdpTransport();
            var local = DHTPeer.Create(localIdentity, IPAddress.Loopback, 0, transport.UdpPort, DHTCapabilities.Download);
            var first = Request(local, Operation.Ping, 11);
            var second = Request(local, Operation.Ping, 22);
            var firstBytes = first.Seal(localIdentity, remote);
            var secondBytes = second.Seal(localIdentity, remote);
            var firstExchange = transport.ExchangeAtAsync(DHTTransport.Udp, endpoint, firstBytes, token);
            var secondExchange = transport.ExchangeAtAsync(DHTTransport.Udp, endpoint, secondBytes, token);
            var cookies = new UdpCookies();
            var firstReceived = await ReceiveUdpRequestAsync(server, cookies, transport.UdpPort, token);
            var secondReceived = await ReceiveUdpRequestAsync(server, cookies, transport.UdpPort, token);
            var firstArrivedFirst = firstReceived.Packet.Span.SequenceEqual(firstBytes);
            Assert.True(firstReceived.Packet.Span.SequenceEqual(firstArrivedFirst ? firstBytes : secondBytes));
            Assert.True(secondReceived.Packet.Span.SequenceEqual(firstArrivedFirst ? secondBytes : firstBytes));
            Assert.Equal(firstReceived.Source, secondReceived.Source);
            var firstReply = Response(first, remote).Seal(remoteIdentity, local);
            var secondReply = Response(second, remote).Seal(remoteIdentity, local);

            await SendUdpReplyAsync(server, firstReceived.Source, firstReply, Crypto.Random(32), token);
            await Task.Delay(TimeSpan.FromMilliseconds(75), token);
            Assert.False(firstExchange.IsCompleted, "An unrelated digest must not complete the first pending request.");
            Assert.False(secondExchange.IsCompleted, "An unrelated digest must not complete the second pending request.");

            await SendUdpReplyAsync(server, firstReceived.Source, secondReply, Crypto.Hash(secondBytes), token);
            AssertResponse(localIdentity, remote, second, await secondExchange);
            Assert.False(firstExchange.IsCompleted, "The second response must not occupy the first request's response slot.");
            await SendUdpReplyAsync(server, firstReceived.Source, firstReply, Crypto.Hash(firstBytes), token);
            AssertResponse(localIdentity, remote, first, await firstExchange);
        }

        /// <summary>Rejects an otherwise authentic and digest-matching UDP reply sent from a different source port.</summary>
        /// <returns>Completion only after the pinned endpoint sends the correct response.</returns>
        [Fact]
        [Trait("Category", "NAT")]
        public async Task UdpExchangeRejectsAuthenticReplyFromUnpinnedSource()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var token = deadline.Token;
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            using var otherSource = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var endpoint = Assert.IsType<IPEndPoint>(server.Client.LocalEndPoint);
            Assert.NotEqual(endpoint.Port, Assert.IsType<IPEndPoint>(otherSource.Client.LocalEndPoint).Port);
            var localIdentity = new DHTIdentity();
            var remoteIdentity = new DHTIdentity();
            var remote = DHTPeer.Create(remoteIdentity, IPAddress.Loopback, 0, endpoint.Port, DHTCapabilities.Download);
            await using var transport = CreateUdpTransport();
            var local = DHTPeer.Create(localIdentity, IPAddress.Loopback, 0, transport.UdpPort, DHTCapabilities.Download);
            var request = Request(local, Operation.Ping, 33);
            var requestBytes = request.Seal(localIdentity, remote);
            var exchange = transport.ExchangeAtAsync(DHTTransport.Udp, endpoint, requestBytes, token);
            var received = await ReceiveUdpRequestAsync(server, new UdpCookies(), transport.UdpPort, token);
            AssertRequest(remoteIdentity, local, request, received.Packet);
            var digest = Crypto.Hash(requestBytes);
            var substituted = new Packet(remote, request.RequestId, (byte)(request.Kind | 0x80), new byte[] { 99 });
            var substitutedBytes = substituted.Seal(remoteIdentity, local);
            var authenticated = Packet.Open(localIdentity, substitutedBytes);
            Assert.Equal(remote.NodeId, authenticated.Sender.NodeId);
            Assert.True(request.RequestId.Span.SequenceEqual(authenticated.RequestId.Span));

            await SendUdpReplyAsync(otherSource, received.Source, substitutedBytes, digest, token);
            await Task.Delay(TimeSpan.FromMilliseconds(75), token);
            Assert.False(exchange.IsCompleted, "A valid signature and request digest must not bypass endpoint pinning.");

            await SendUdpReplyAsync(server, received.Source, Response(request, remote).Seal(remoteIdentity, local), digest, token);
            AssertResponse(localIdentity, remote, request, await exchange);
        }

        /// <summary>Creates listener options with enough time for deliberate response ordering and handler gates.</summary>
        /// <param name="protocol">The only enabled protocol.</param>
        /// <returns>Independent node options for the socket cases.</returns>
        private static DHTNodeOptions ClientOptions(DHTTransport protocol)
        {
            return new DHTNodeOptions
            {
                TcpPort = protocol == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = protocol == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = protocol,
                RequestTimeout = TimeSpan.FromSeconds(5),
                UdpAttempts = 1,
                MaxConcurrentRequests = 4,
                EnableNatTraversal = false
            };
        }

        /// <summary>Creates a running UDP client that fails unsolicited application dispatch.</summary>
        /// <returns>A caller-owned bound transport.</returns>
        private static SocketTransport CreateUdpTransport()
        {
            var transport = new SocketTransport(ClientOptions(DHTTransport.Udp).Snapshot(),
                (bytes, token) => Task.FromException<ReadOnlyMemory<byte>>(new InvalidOperationException("Unexpected incoming UDP request.")));
            transport.Bind();
            transport.Run();
            return transport;
        }

        /// <summary>Creates a uniquely correlated request with a small observable body.</summary>
        /// <param name="sender">The signed sending contact.</param>
        /// <param name="operation">The request operation.</param>
        /// <param name="value">The echoed application value.</param>
        /// <returns>An unsealed request with a fresh identifier.</returns>
        private static Packet Request(DHTPeer sender, Operation operation, byte value)
        {
            return new Packet(sender, Crypto.Random(16), (byte)operation, new byte[] { value });
        }

        /// <summary>Creates the authenticated echo response to a received request.</summary>
        /// <param name="request">The original request.</param>
        /// <param name="sender">The responder's signed contact.</param>
        /// <returns>A response carrying the original identifier and body.</returns>
        private static Packet Response(Packet request, DHTPeer sender)
        {
            return new Packet(sender, request.RequestId, (byte)(request.Kind | 0x80), request.Body);
        }

        /// <summary>Authenticates a request observed by the real remote socket.</summary>
        /// <param name="identity">The recipient's private identity.</param>
        /// <param name="sender">The expected sending contact.</param>
        /// <param name="expected">The exact expected request metadata and body.</param>
        /// <param name="encoded">The received encrypted envelope.</param>
        private static void AssertRequest(DHTIdentity identity, DHTPeer sender, Packet expected, ReadOnlyMemory<byte> encoded)
        {
            var actual = Packet.Open(identity, encoded);
            Assert.Equal(sender.NodeId, actual.Sender.NodeId);
            Assert.Equal(expected.Kind, actual.Kind);
            Assert.True(expected.RequestId.Span.SequenceEqual(actual.RequestId.Span));
            Assert.True(expected.Body.Span.SequenceEqual(actual.Body.Span));
        }

        /// <summary>Authenticates a response and verifies that it belongs to the intended request.</summary>
        /// <param name="identity">The original requester's private identity.</param>
        /// <param name="sender">The expected responder.</param>
        /// <param name="request">The request whose slot must receive this response.</param>
        /// <param name="encoded">The received encrypted response.</param>
        private static void AssertResponse(DHTIdentity identity, DHTPeer sender, Packet request, ReadOnlyMemory<byte> encoded)
        {
            AssertRequest(identity, sender, Response(request, sender), encoded);
        }

        /// <summary>Authenticates a response delivered by the transport in its pooled frame, then releases the frame.</summary>
        /// <param name="identity">The original requester's private identity.</param>
        /// <param name="sender">The expected responder.</param>
        /// <param name="request">The request whose slot must receive this response.</param>
        /// <param name="encoded">The received encrypted response in its frame.</param>
        private static void AssertResponse(DHTIdentity identity, DHTPeer sender, Packet request, OwnedMemory encoded)
        {
            using (encoded)
            {
                AssertResponse(identity, sender, request, encoded.Bytes);
            }
        }

        /// <summary>Reads one bounded envelope from the external TCP peer's connection.</summary>
        /// <param name="stream">The real connected peer stream.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>An independently owned encrypted frame.</returns>
        private static async Task<ReadOnlyMemory<byte>> ReadTcpFrameAsync(Stream stream, CancellationToken cancellationToken)
        {
            var prefix = new byte[4];
            await stream.ReadExactlyAsync(prefix, cancellationToken);
            var length = BinaryPrimitives.ReadInt32BigEndian(prefix);
            Assert.InRange(length, 1, Wire.MaxPacket);
            var bytes = new byte[length];
            await stream.ReadExactlyAsync(bytes, cancellationToken);
            return bytes;
        }

        /// <summary>Writes one framed envelope from the external TCP peer.</summary>
        /// <param name="stream">The real connected peer stream.</param>
        /// <param name="packet">The sealed request or response.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>Completion after transmitting the complete frame.</returns>
        private static async Task WriteTcpFrameAsync(Stream stream, ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
        {
            var prefix = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(prefix, packet.Length);
            await stream.WriteAsync(prefix, cancellationToken);
            await stream.WriteAsync(packet, cancellationToken);
        }

        /// <summary>Completes real cookie handshakes until one request arrives on the pinned listener port.</summary>
        /// <param name="server">The external UDP peer socket.</param>
        /// <param name="cookies">The peer's stateless cookie service shared by its concurrent handshakes.</param>
        /// <param name="expectedPort">The transport's advertised listener port.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>The cookie-authenticated request and observed source endpoint.</returns>
        /// <exception cref="InvalidDataException">The sender transmits a frame without a valid source cookie.</exception>
        private static async Task<(ReadOnlyMemory<byte> Packet, IPEndPoint Source)> ReceiveUdpRequestAsync(
            UdpClient server, UdpCookies cookies, int expectedPort, CancellationToken cancellationToken)
        {
            while (true)
            {
                var incoming = await server.ReceiveAsync(cancellationToken);
                Assert.Equal(expectedPort, incoming.RemoteEndPoint.Port);
                var challenge = cookies.Challenge(incoming.Buffer, incoming.RemoteEndPoint);
                if (challenge != null)
                {
                    await server.SendAsync(challenge, incoming.RemoteEndPoint, cancellationToken);
                    continue;
                }
                var request = cookies.OpenRequest(incoming.Buffer, incoming.RemoteEndPoint);
                if (!request.HasValue)
                {
                    throw new InvalidDataException("The peer expected a cookie-authenticated UDP request.");
                }
                return (request.Value, incoming.RemoteEndPoint);
            }
        }

        /// <summary>Sends a correlated response from a deliberately selected real UDP source socket.</summary>
        /// <param name="source">The source socket, which may intentionally differ from the pinned peer.</param>
        /// <param name="destination">The observed transport listener endpoint.</param>
        /// <param name="packet">The sealed response.</param>
        /// <param name="digest">The request digest to place in the transport frame.</param>
        /// <param name="cancellationToken">The test deadline.</param>
        /// <returns>Completion after transmitting the datagram.</returns>
        private static async Task SendUdpReplyAsync(UdpClient source, IPEndPoint destination, ReadOnlyMemory<byte> packet,
            byte[] digest, CancellationToken cancellationToken)
        {
            var frame = new byte[packet.Length + UdpCookies.CorrelatedPrefixLength];
            UdpCookies.WriteReply(packet.Span, digest, frame);
            await source.SendAsync(frame, destination, cancellationToken);
        }
    }
}
