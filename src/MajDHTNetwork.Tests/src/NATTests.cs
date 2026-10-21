#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises real Traversal-assisted direct routes, authenticated probes, quotas and cancellation.</summary>
    [Trait("Category", "NAT")]
    public sealed class NATTests
    {
        /// <summary>Transfers in both directions over punched routes after the Traversal node stops.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after repeated concurrent direct requests and full verified downloads.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task PunchedRoutesSupportRepeatedBidirectionalTransfersAfterTraversalNodeStops(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var traversal = new MajDHTNode(NatOptions(transport, DHTCapabilities.Traversal));
            await using var left = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var right = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download | DHTCapabilities.Provide));
            await Task.WhenAll(traversal.StartAsync(token), left.StartAsync(token), right.StartAsync(token));
            var leftBytes = Crypto.Random(40001);
            var rightBytes = Crypto.Random(35003);
            using var leftSource = new MemoryStream(leftBytes);
            using var rightSource = new MemoryStream(rightBytes);
            var leftRecord = await left.PublishAsync("nat/left", leftSource, cancellationToken: token);
            var rightRecord = await right.PublishAsync("nat/right", rightSource, cancellationToken: token);
            await left.JoinAsync(traversal.LocalPeer, token);
            await right.JoinAsync(traversal.LocalPeer, token);
            // Each side knows the other only at an address where nothing listens, so only the punched route can carry traffic.
            var hiddenLeft = Hidden(left);
            var hiddenRight = Hidden(right);
            Assert.True(await left.TryPunchAsync(hiddenRight, traversal.LocalPeer, transport, token));
            await traversal.StopAsync();
            for (var round = 0; round < 3; round++)
            {
                var index = round % leftRecord.BlockCount;
                var reads = await Task.WhenAll(
                    left.ReadBlockAsync(rightRecord, hiddenRight, index, cancellationToken: token),
                    right.ReadBlockAsync(leftRecord, hiddenLeft, index, cancellationToken: token),
                    left.ReadBlockAsync(rightRecord, hiddenRight, index, cancellationToken: token),
                    right.ReadBlockAsync(leftRecord, hiddenLeft, index, cancellationToken: token));
                AssertBlock(rightBytes, rightRecord.BlockSize, index, reads[0]);
                AssertBlock(leftBytes, leftRecord.BlockSize, index, reads[1]);
                AssertBlock(rightBytes, rightRecord.BlockSize, index, reads[2]);
                AssertBlock(leftBytes, leftRecord.BlockSize, index, reads[3]);
            }
            var leftFile = await ReadWholeFileAsync(left, rightRecord, hiddenRight, token);
            var rightFile = await ReadWholeFileAsync(right, leftRecord, hiddenLeft, token);
            Assert.Equal(rightBytes, leftFile);
            Assert.Equal(leftBytes, rightFile);
        }

        /// <summary>Pairs a node's contact with an address where nothing listens, so only punched or hosted routes can reach it.</summary>
        /// <param name="node">The running node.</param>
        /// <returns>The node's contact at an unreachable endpoint with the node's real ports.</returns>
        private static DHTPeer Hidden(MajDHTNode node)
        {
            var listener = node.LocalPeer.Endpoints[0];
            return new DHTPeer(node.LocalContact, new[] { new DHTEndpoint(IPAddress.Parse("127.0.0.2"), listener.TcpPort, listener.UdpPort) });
        }

        /// <summary>Reads every verified block of a record from one provider and concatenates them.</summary>
        /// <param name="reader">The reading node.</param>
        /// <param name="record">The signed manifest.</param>
        /// <param name="provider">The provider contact.</param>
        /// <param name="token">The test deadline.</param>
        /// <returns>The complete file.</returns>
        private static async Task<byte[]> ReadWholeFileAsync(MajDHTNode reader, DHTRecord record, DHTPeer provider, CancellationToken token)
        {
            using var file = new MemoryStream();
            for (var index = 0; index < record.BlockCount; index++)
            {
                var block = await reader.ReadBlockAsync(record, provider, index, cancellationToken: token);
                file.Write(block.Span);
            }
            return file.ToArray();
        }

        /// <summary>Keeps a registration alive on the transport that works when the other observed transport port is stale.</summary>
        /// <returns>Completion after an introduced TCP peer transfers content without the Traversal node.</returns>
        [Fact]
        public async Task RegistrationSurvivesAStaleTransportPort()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var traversalIdentity = new DHTIdentity();
            var traversalOptions = NatOptions(DHTTransport.Tcp, DHTCapabilities.Traversal);
            traversalOptions.UdpPort = 0;
            var dualOptions = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            dualOptions.UdpPort = 0;
            await using var traversal = new MajDHTNode(traversalOptions, traversalIdentity);
            await using var dual = new MajDHTNode(dualOptions);
            await using var tcpOnly = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(traversal.StartAsync(token), dual.StartAsync(token), tcpOnly.StartAsync(token));
            var content = Crypto.Random(2049);
            using var source = new MemoryStream(content);
            var record = await dual.PublishAsync("nat/stale-udp", source, cancellationToken: token);
            // The Traversal node was observed at a UDP port where nothing listens; the TCP registration must still carry the session.
            var stale = DHTPeer.Create(traversalIdentity, IPAddress.Loopback, traversal.LocalPeer.TcpPort(), 1, DHTCapabilities.Traversal);
            await dual.RegisterTraversalAsync(stale, token);
            await tcpOnly.RegisterTraversalAsync(traversal.LocalPeer, token);
            await Task.Delay(TimeSpan.FromMilliseconds(300), token);
            Assert.True(await tcpOnly.TryPunchAsync(dual.LocalPeer, traversal.LocalPeer, DHTTransport.Tcp, token),
                "The registration over the working transport must survive the failing refreshes of the stale one.");
            await traversal.StopAsync();
            var block = await tcpOnly.ReadBlockAsync(record, Hidden(dual), 0, cancellationToken: token);
            Assert.Equal(content, block.ToArray());
        }

        /// <summary>Rejects assistance from a peer that does not advertise the Traversal capability.</summary>
        /// <returns>Completion after both public APIs reject the incapable peer.</returns>
        [Fact]
        public async Task NonTraversalPeersCannotRegisterOrIntroducePeers()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var client = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var ordinary = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(client.StartAsync(token), ordinary.StartAsync(token));
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.RegisterTraversalAsync(ordinary.LocalPeer, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.TryPunchAsync(target, ordinary.LocalPeer, DHTTransport.Tcp, token));
        }

        /// <summary>Returns false when the requested peer has no live registration at the Traversal node.</summary>
        /// <param name="transport">The only enabled transport.</param>
        /// <returns>Completion after the unregistered-target lookup.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task UnregisteredTargetsDoNotCreateDirectRoutes(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NatOptions(transport, DHTCapabilities.Traversal));
            await using var client = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await using var target = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await Task.WhenAll(relay.StartAsync(token), client.StartAsync(token), target.StartAsync(token));
            await client.RegisterTraversalAsync(relay.LocalPeer, token);
            Assert.False(await client.TryPunchAsync(target.LocalPeer, relay.LocalPeer, transport, token));
        }

        /// <summary>Propagates already-cancelled tokens through registration and traversal.</summary>
        /// <returns>Completion after both cancellation contracts are checked.</returns>
        [Fact]
        public async Task PrecancelledRegistrationAndPunchRequestsAreRejected()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Traversal));
            await using var client = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(relay.StartAsync(token), client.StartAsync(token));
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.RegisterTraversalAsync(relay.LocalPeer, cancelled.Token));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.TryPunchAsync(target, relay.LocalPeer, DHTTransport.Tcp, cancelled.Token));
        }

        /// <summary>Cancels an active real-socket traversal while the Traversal node withholds a response.</summary>
        /// <param name="transport">The only enabled transport.</param>
        /// <returns>Completion after cancellation reaches the outstanding network operation.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task CallerCancellationInterruptsAnOutstandingPunch(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new StallingRelay(transport);
            await using var client = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await client.StartAsync(token);
            await client.RegisterTraversalAsync(relay.Peer, token);
            relay.Stall();
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback,
                transport == DHTTransport.Tcp ? 22000 : 0, transport == DHTTransport.Udp ? 22000 : 0, DHTCapabilities.Download);
            using var caller = CancellationTokenSource.CreateLinkedTokenSource(token);
            var punch = client.TryPunchAsync(target, relay.Peer, transport, caller.Token);
            await relay.Entered.Task.WaitAsync(token);
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => punch);
        }

        /// <summary>Stops registration polling and cancels an outstanding traversal before returning.</summary>
        /// <param name="transport">The only enabled transport.</param>
        /// <returns>Completion after node shutdown and cancelled traversal drainage.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task StopDrainsPollingAndOutstandingPunches(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new StallingRelay(transport);
            await using var client = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await client.StartAsync(token);
            await client.RegisterTraversalAsync(relay.Peer, token);
            relay.Stall();
            await relay.Entered.Task.WaitAsync(token);
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback,
                transport == DHTTransport.Tcp ? 22000 : 0, transport == DHTTransport.Udp ? 22000 : 0, DHTCapabilities.Download);
            var punch = client.TryPunchAsync(target, relay.Peer, transport, token);
            await client.StopAsync().WaitAsync(token);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => punch);
            await client.StopAsync().WaitAsync(token);
        }

        /// <summary>Rejects invalid traversal limits before a node can start background work.</summary>
        /// <param name="option">The option property being checked.</param>
        /// <param name="value">The invalid limit, or duration in milliseconds.</param>
        [Theory]
        [InlineData(nameof(DHTNodeOptions.NatTraversalTimeout), 49)]
        [InlineData(nameof(DHTNodeOptions.NatTraversalTimeout), 120001)]
        [InlineData(nameof(DHTNodeOptions.NatPollInterval), 49)]
        [InlineData(nameof(DHTNodeOptions.NatPollInterval), 60001)]
        [InlineData(nameof(DHTNodeOptions.NatRegistrationLifetime), 999)]
        [InlineData(nameof(DHTNodeOptions.NatRegistrationLifetime), 300001)]
        [InlineData(nameof(DHTNodeOptions.MaxNatRegistrations), 0)]
        [InlineData(nameof(DHTNodeOptions.MaxNatRegistrations), 65537)]
        [InlineData(nameof(DHTNodeOptions.MaxTraversalNodes), 0)]
        [InlineData(nameof(DHTNodeOptions.MaxTraversalNodes), 17)]
        [InlineData(nameof(DHTNodeOptions.MaxForwarders), 0)]
        [InlineData(nameof(DHTNodeOptions.MaxForwarders), 17)]
        [InlineData(nameof(DHTNodeOptions.NatKeepAliveInterval), 49)]
        [InlineData(nameof(DHTNodeOptions.NatKeepAliveInterval), 25001)]
        public void InvalidNatLimitsAreRejected(string option, int value)
        {
            var options = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download);
            switch (option)
            {
                case nameof(DHTNodeOptions.NatKeepAliveInterval):
                    options.NatKeepAliveInterval = TimeSpan.FromMilliseconds(value);
                    break;
                case nameof(DHTNodeOptions.NatTraversalTimeout):
                    options.NatTraversalTimeout = TimeSpan.FromMilliseconds(value);
                    break;
                case nameof(DHTNodeOptions.NatPollInterval):
                    options.NatPollInterval = TimeSpan.FromMilliseconds(value);
                    break;
                case nameof(DHTNodeOptions.NatRegistrationLifetime):
                    options.NatRegistrationLifetime = TimeSpan.FromMilliseconds(value);
                    break;
                case nameof(DHTNodeOptions.MaxNatRegistrations):
                    options.MaxNatRegistrations = value;
                    break;
                case nameof(DHTNodeOptions.MaxTraversalNodes):
                    options.MaxTraversalNodes = value;
                    break;
                case nameof(DHTNodeOptions.MaxForwarders):
                    options.MaxForwarders = value;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(option));
            }
            Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());
        }

        /// <summary>Requires registration leases to cover at least three complete poll intervals.</summary>
        [Fact]
        public void RegistrationLifetimeMustCoverThreePollIntervals()
        {
            var options = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download);
            options.NatPollInterval = TimeSpan.FromMilliseconds(400);
            options.NatRegistrationLifetime = TimeSpan.FromSeconds(1);
            Assert.ThrowsAny<ArgumentException>(() => options.Snapshot());
        }

        /// <summary>Enforces the disabled state, distinct peer identity and valid transport contracts.</summary>
        /// <returns>Completion after invalid public operations are rejected.</returns>
        [Fact]
        public async Task DisabledTraversalAndInvalidPeersCannotRegisterPaths()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var options = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download);
            options.EnableNatTraversal = false;
            await using var client = new MajDHTNode(options);
            await using var relay = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Traversal));
            await Task.WhenAll(client.StartAsync(token), relay.StartAsync(token));
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => client.RegisterTraversalAsync(relay.LocalPeer, token));
            Assert.False(await client.TryPunchAsync(target, relay.LocalPeer, DHTTransport.Tcp, token));
            await Assert.ThrowsAnyAsync<ArgumentNullException>(() => client.TryPunchAsync(null!, relay.LocalPeer, DHTTransport.Tcp, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.TryPunchAsync(client.LocalPeer, relay.LocalPeer, DHTTransport.Tcp, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.TryPunchAsync(target, relay.LocalPeer, (DHTTransport)255, token));
        }

        /// <summary>Rejects modified tickets and the correct ticket sent from an unintroduced third-party endpoint.</summary>
        /// <param name="transport">The only enabled transport.</param>
        /// <returns>Completion after negative replies and an ordinary transfer prove no route was retained.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ForgedTokensAndSubstitutedSourceEndpointsCannotCreateRoutes(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NatOptions(transport, DHTCapabilities.Traversal));
            await using var target = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await using var introduced = new NATProtocolPeer(transport);
            await using var substituted = new NATProtocolPeer(transport, introduced.Identity, introduced.Content);
            await Task.WhenAll(relay.StartAsync(token), target.StartAsync(token));
            await target.RegisterTraversalAsync(relay.LocalPeer, token);
            AssertStatus(await introduced.ExchangeAsync(relay.LocalPeer, Operation.Traversal, new byte[] { 0 }, token), 0);
            using var introduction = new Wire();
            introduction.PutByte(1);
            introduction.PutText(target.NodeId);
            var response = await introduced.ExchangeAsync(relay.LocalPeer, Operation.Traversal, introduction.WrittenMemory, token);
            byte[] ticket;
            using (var envelope = new Wire(response))
            {
                Assert.Equal((byte)0, envelope.Byte());
                using var invitation = new Wire(envelope.Bytes(4096));
                _ = DHTContact.Parse(invitation.Bytes(2048));
                _ = invitation.Text(96);
                _ = invitation.Long();
                ticket = invitation.Bytes(16).ToArray();
                _ = invitation.Long();
                invitation.End();
                envelope.End();
            }
            await introduced.PunchObserved.Task.WaitAsync(token);
            var forged = (byte[])ticket.Clone();
            forged[0] ^= 1;
            AssertStatus(await introduced.ExchangeAsync(target.LocalPeer, Operation.Punch, forged, token), 1);
            AssertStatus(await substituted.ExchangeAsync(target.LocalPeer, Operation.Punch, ticket, token), 1);
            await relay.StopAsync();
            var failure = await Xunit.Record.ExceptionAsync(() => target.ReadBlockAsync(introduced.Record, introduced.Peer, 0, cancellationToken: token));
            Assert.NotNull(failure);
            Assert.True(failure is IOException || failure is SocketException || failure is TimeoutException,
                "An invalid ticket or endpoint must not install a route to the otherwise valid content provider.");
            var reachable = DHTPeer.Create(introduced.Identity, IPAddress.Loopback, introduced.Peer.TcpPort(), introduced.Peer.UdpPort(), DHTCapabilities.Provide);
            var direct = await target.ReadBlockAsync(introduced.Record, reachable, 0, cancellationToken: token);
            Assert.Equal(introduced.Content, direct.ToArray());
        }

        /// <summary>Rejects raw probe tokens with invalid lengths before any introduction exists.</summary>
        /// <param name="transport">The only enabled transport.</param>
        /// <param name="length">The malformed token length.</param>
        /// <returns>Completion after the authenticated error response is checked.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp, 0)]
        [InlineData(DHTTransport.Tcp, 15)]
        [InlineData(DHTTransport.Tcp, 17)]
        [InlineData(DHTTransport.Udp, 0)]
        [InlineData(DHTTransport.Udp, 15)]
        [InlineData(DHTTransport.Udp, 17)]
        public async Task MalformedProbeTokenLengthsAreRejected(DHTTransport transport, int length)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var target = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await using var sender = new NATProtocolPeer(transport);
            await target.StartAsync(token);
            AssertStatus(await sender.ExchangeAsync(target.LocalPeer, Operation.Punch, new byte[length], token), 1);
        }

        /// <summary>Bounds maintained Traversal nodes without counting a duplicate registration twice.</summary>
        /// <returns>Completion after duplicate registration and the full-quota rejection are checked.</returns>
        [Fact]
        public async Task MaintainedTraversalQuotaRejectsAdditionalNodesButAllowsRefresh()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var options = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download);
            options.MaxTraversalNodes = 1;
            await using var client = new MajDHTNode(options);
            await using var first = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Traversal));
            await using var second = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Traversal));
            await Task.WhenAll(client.StartAsync(token), first.StartAsync(token), second.StartAsync(token));
            await client.RegisterTraversalAsync(first.LocalPeer, token);
            await client.RegisterTraversalAsync(first.LocalPeer, token);
            await Assert.ThrowsAnyAsync<IOException>(() => client.RegisterTraversalAsync(second.LocalPeer, token));
        }

        /// <summary>Checks the authenticated outer status of a raw protocol response.</summary>
        /// <param name="response">The decrypted response body.</param>
        /// <param name="expected">The required success or rejection status.</param>
        private static void AssertStatus(ReadOnlyMemory<byte> response, byte expected)
        {
            using var reader = new Wire(response);
            Assert.Equal(expected, reader.Byte());
        }

        /// <summary>Creates fast real-loopback NAT options.</summary>
        /// <param name="transport">The only transport to bind.</param>
        /// <param name="capabilities">The services advertised by the test node.</param>
        /// <returns>Independent options whose observed socket address is 127.0.0.1.</returns>
        private static DHTNodeOptions NatOptions(DHTTransport transport, DHTCapabilities capabilities)
        {
            return new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { IPAddress.Loopback },
                TcpPort = transport == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = transport == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = transport,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(700),
                UdpAttempts = 2,
                NatTraversalTimeout = TimeSpan.FromSeconds(3),
                NatPollInterval = TimeSpan.FromMilliseconds(75),
                NatRegistrationLifetime = TimeSpan.FromSeconds(3)
            };
        }

        /// <summary>Compares a received authenticated block with its exact source-file slice.</summary>
        /// <param name="content">The complete original file.</param>
        /// <param name="blockSize">The signed block size.</param>
        /// <param name="index">The signed block position.</param>
        /// <param name="actual">The received block bytes.</param>
        private static void AssertBlock(byte[] content, int blockSize, int index, ReadOnlyMemory<byte> actual)
        {
            var offset = index * blockSize;
            var length = Math.Min(blockSize, content.Length - offset);
            Assert.True(actual.Span.SequenceEqual(content.AsSpan(offset, length)), "The authenticated direct block differs from its original file slice.");
        }

        /// <summary>Authenticates registration once and can then stall subsequent traversal RPCs.</summary>
        private sealed class StallingRelay : IAsyncDisposable
        {
            /// <summary>The identity signing the Traversal node's authenticated responses.</summary>
            private readonly DHTIdentity _identity = new DHTIdentity();
            /// <summary>The real transport that captures source endpoint metadata.</summary>
            private readonly SocketTransport _transport;
            /// <summary>Whether subsequent requests wait for their transport cancellation.</summary>
            private bool _stall;
            /// <summary>Gets the Traversal-capable contact at the listener endpoint.</summary>
            internal DHTPeer Peer { get; }
            /// <summary>Signals entry into a deliberately withheld network response.</summary>
            internal TaskCompletionSource<bool> Entered { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Binds a real Traversal listener for a single transport.</summary>
            /// <param name="transport">The only transport to enable.</param>
            internal StallingRelay(DHTTransport transport)
            {
                _transport = new SocketTransport(NatOptions(transport, DHTCapabilities.Traversal).Snapshot(), HandleAsync, NullLogger.Instance);
                _transport.Bind();
                Peer = DHTPeer.Create(_identity, IPAddress.Loopback, _transport.TcpPort, _transport.UdpPort, DHTCapabilities.Traversal);
                _transport.Run();
            }

            /// <summary>Makes later registration refreshes wait for cancellation.</summary>
            internal void Stall()
            {
                Volatile.Write(ref _stall, true);
            }

            /// <summary>Returns an authenticated observed endpoint or holds the response until cancelled.</summary>
            /// <param name="encoded">The encrypted traversal request.</param>
            /// <param name="transport">The transport carrying the authenticated request.</param>
            /// <param name="source">The real remote socket endpoint.</param>
            /// <param name="token">The server request lifetime.</param>
            /// <returns>The authenticated registration response.</returns>
            /// <exception cref="OperationCanceledException">The deliberately stalled request was cancelled.</exception>
            private async Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, DHTTransport transport, IPEndPoint source, CancellationToken token)
            {
                var request = Packet.Open(_identity, encoded);
                if (Volatile.Read(ref _stall))
                {
                    Entered.TrySetResult(true);
                    await Task.Delay(Timeout.Infinite, token);
                }
                using var body = new Wire();
                body.PutText(source.Address.ToString());
                body.PutLong(source.Port);
                body.PutByte(0);
                using var response = new Wire();
                response.PutByte(0);
                response.Put(body.WrittenSpan);
                return new Packet(Peer, request.RequestId, (byte)(request.Kind | 128), response.WrittenMemory).Seal(_identity, request.Sender);
            }

            /// <summary>Cancels all held requests and drains the real transport.</summary>
            /// <returns>Completion after all listener and request tasks stop.</returns>
            public async ValueTask DisposeAsync()
            {
                await _transport.DisposeAsync();
            }
        }
    }
}
