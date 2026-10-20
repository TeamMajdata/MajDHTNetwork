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
    /// <summary>Exercises real relay-assisted direct routes, authenticated probes, quotas and cancellation.</summary>
    [Trait("Category", "NAT")]
    public sealed class NATTests
    {
        /// <summary>Transfers in both directions over observed endpoints after the assisting relay stops.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after repeated concurrent direct requests and full verified downloads.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ObservedRoutesSupportRepeatedBidirectionalTransfersAfterRelayStops(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NatOptions(transport, DHTCapabilities.Relay));
            await using var left = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download | DHTCapabilities.Provide, hidden: true));
            await using var right = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download | DHTCapabilities.Provide, hidden: true));
            await Task.WhenAll(relay.StartAsync(token), left.StartAsync(token), right.StartAsync(token));
            var leftBytes = Crypto.Random(40001);
            var rightBytes = Crypto.Random(35003);
            using var leftSource = new MemoryStream(leftBytes);
            using var rightSource = new MemoryStream(rightBytes);
            var leftRecord = await left.PublishAsync("nat/left", leftSource, cancellationToken: token);
            var rightRecord = await right.PublishAsync("nat/right", rightSource, cancellationToken: token);
            await left.JoinAsync(relay.LocalPeer, token);
            await right.JoinAsync(relay.LocalPeer, token);
            Assert.Equal(IPAddress.Parse("127.0.0.2"), left.LocalPeer.Address());
            Assert.Equal(IPAddress.Parse("127.0.0.2"), right.LocalPeer.Address());
            Assert.True(await left.TryPunchAsync(right.LocalPeer, relay.LocalPeer, transport, token));
            await relay.StopAsync();
            for (var round = 0; round < 3; round++)
            {
                var index = round % leftRecord.BlockCount;
                var reads = await Task.WhenAll(
                    left.ReadBlockAsync(rightRecord, right.LocalPeer, index, cancellationToken: token),
                    right.ReadBlockAsync(leftRecord, left.LocalPeer, index, cancellationToken: token),
                    left.ReadBlockAsync(rightRecord, right.LocalPeer, index, cancellationToken: token),
                    right.ReadBlockAsync(leftRecord, left.LocalPeer, index, cancellationToken: token));
                AssertBlock(rightBytes, rightRecord.BlockSize, index, reads[0]);
                AssertBlock(leftBytes, leftRecord.BlockSize, index, reads[1]);
                AssertBlock(rightBytes, rightRecord.BlockSize, index, reads[2]);
                AssertBlock(leftBytes, leftRecord.BlockSize, index, reads[3]);
            }
            // Peers whose advertised endpoints never answer stay out of routing tables, so the whole files are read
            // block by block over the punched routes rather than through DHT provider discovery.
            var leftFile = await ReadWholeFileAsync(left, rightRecord, right.LocalPeer, token);
            var rightFile = await ReadWholeFileAsync(right, leftRecord, left.LocalPeer, token);
            Assert.Equal(rightBytes, leftFile);
            Assert.Equal(leftBytes, rightFile);
            Assert.DoesNotContain(left.KnownPeers, peer => peer.NodeId == right.NodeId);
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

        /// <summary>Retries an initially failed common transport while maintaining an existing relay registration.</summary>
        /// <returns>Completion after an independently introduced UDP peer transfers content without the relay.</returns>
        [Fact]
        public async Task PollingRecoversAnInitiallyFailedCommonTransport()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var relayIdentity = new DHTIdentity();
            var relayOptions = NatOptions(DHTTransport.Tcp, DHTCapabilities.Relay);
            relayOptions.UdpPort = 0;
            var dualOptions = NatOptions(DHTTransport.Udp, DHTCapabilities.Download | DHTCapabilities.Provide, hidden: true);
            dualOptions.TcpPort = 0;
            await using var relay = new MajDHTNode(relayOptions, relayIdentity);
            await using var dual = new MajDHTNode(dualOptions);
            await using var udpOnly = new MajDHTNode(NatOptions(DHTTransport.Udp, DHTCapabilities.Download, hidden: true));
            await Task.WhenAll(relay.StartAsync(token), dual.StartAsync(token), udpOnly.StartAsync(token));
            var content = Crypto.Random(2049);
            using var source = new MemoryStream(content);
            var record = await dual.PublishAsync("nat/recovered-udp", source, cancellationToken: token);
            var stale = DHTPeer.Create(relayIdentity, IPAddress.Loopback, relay.LocalPeer.TcpPort(), 1, DHTCapabilities.Relay);
            await dual.RegisterRelayAsync(stale, token);
            await udpOnly.RegisterRelayAsync(relay.LocalPeer, token);
            var punched = false;
            for (var attempt = 0; attempt < 20 && !punched; attempt++)
            {
                punched = await udpOnly.TryPunchAsync(dual.LocalPeer, relay.LocalPeer, DHTTransport.Udp, token);
                if (!punched)
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(75), token);
                }
            }
            Assert.True(punched, "Polling must register UDP even when only TCP succeeded during initial registration.");
            await relay.StopAsync();
            var block = await udpOnly.ReadBlockAsync(record, dual.LocalPeer, 0, cancellationToken: token);
            Assert.Equal(content, block.ToArray());
        }

        /// <summary>Rejects assistance from a contact that does not advertise relay capability.</summary>
        /// <returns>Completion after both public APIs reject the incapable relay.</returns>
        [Fact]
        public async Task NonRelayContactsCannotRegisterOrIntroducePeers()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var client = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var ordinary = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(client.StartAsync(token), ordinary.StartAsync(token));
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.RegisterRelayAsync(ordinary.LocalPeer, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => client.TryPunchAsync(target, ordinary.LocalPeer, DHTTransport.Tcp, token));
        }

        /// <summary>Returns false when the requested peer has no live registration at the relay.</summary>
        /// <param name="transport">The only enabled transport.</param>
        /// <returns>Completion after the unregistered-target lookup.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task UnregisteredTargetsDoNotCreateDirectRoutes(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NatOptions(transport, DHTCapabilities.Relay));
            await using var client = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download));
            await using var target = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download, hidden: true));
            await Task.WhenAll(relay.StartAsync(token), client.StartAsync(token), target.StartAsync(token));
            await client.RegisterRelayAsync(relay.LocalPeer, token);
            Assert.False(await client.TryPunchAsync(target.LocalPeer, relay.LocalPeer, transport, token));
        }

        /// <summary>Propagates already-cancelled tokens through registration and traversal.</summary>
        /// <returns>Completion after both cancellation contracts are checked.</returns>
        [Fact]
        public async Task PrecancelledRegistrationAndPunchRequestsAreRejected()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Relay));
            await using var client = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(relay.StartAsync(token), client.StartAsync(token));
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.RegisterRelayAsync(relay.LocalPeer, cancelled.Token));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.TryPunchAsync(target, relay.LocalPeer, DHTTransport.Tcp, cancelled.Token));
        }

        /// <summary>Cancels an active real-socket traversal while the relay withholds a response.</summary>
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
            await client.RegisterRelayAsync(relay.Peer, token);
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
            await client.RegisterRelayAsync(relay.Peer, token);
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
        [InlineData(nameof(DHTNodeOptions.MaxNatRelays), 0)]
        [InlineData(nameof(DHTNodeOptions.MaxNatRelays), 17)]
        public void InvalidNatLimitsAreRejected(string option, int value)
        {
            var options = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download);
            switch (option)
            {
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
                case nameof(DHTNodeOptions.MaxNatRelays):
                    options.MaxNatRelays = value;
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
            await using var relay = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Relay));
            await Task.WhenAll(client.StartAsync(token), relay.StartAsync(token));
            var target = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => client.RegisterRelayAsync(relay.LocalPeer, token));
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
            await using var relay = new MajDHTNode(NatOptions(transport, DHTCapabilities.Relay));
            await using var target = new MajDHTNode(NatOptions(transport, DHTCapabilities.Download, hidden: true));
            await using var introduced = new NATProtocolPeer(transport);
            await using var substituted = new NATProtocolPeer(transport, introduced.Identity, introduced.Content);
            await Task.WhenAll(relay.StartAsync(token), target.StartAsync(token));
            await target.RegisterRelayAsync(relay.LocalPeer, token);
            AssertStatus(await introduced.ExchangeAsync(relay.LocalPeer, Operation.Rendezvous, new byte[] { 0 }, token), 0);
            using var introduction = new Wire();
            introduction.PutByte(1);
            introduction.PutText(target.NodeId);
            var response = await introduced.ExchangeAsync(relay.LocalPeer, Operation.Rendezvous, introduction.WrittenMemory, token);
            byte[] ticket;
            using (var envelope = new Wire(response))
            {
                Assert.Equal((byte)0, envelope.Byte());
                using var invitation = new Wire(envelope.Bytes(4096));
                _ = new DHTPeer(invitation.Bytes(2048));
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

        /// <summary>Bounds maintained assisting relays without counting a duplicate registration twice.</summary>
        /// <returns>Completion after duplicate registration and the full-quota rejection are checked.</returns>
        [Fact]
        public async Task MaintainedRelayQuotaRejectsAdditionalRelaysButAllowsRefresh()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var options = NatOptions(DHTTransport.Tcp, DHTCapabilities.Download);
            options.MaxNatRelays = 1;
            await using var client = new MajDHTNode(options);
            await using var first = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Relay));
            await using var second = new MajDHTNode(NatOptions(DHTTransport.Tcp, DHTCapabilities.Relay));
            await Task.WhenAll(client.StartAsync(token), first.StartAsync(token), second.StartAsync(token));
            await client.RegisterRelayAsync(first.LocalPeer, token);
            await client.RegisterRelayAsync(first.LocalPeer, token);
            await Assert.ThrowsAnyAsync<IOException>(() => client.RegisterRelayAsync(second.LocalPeer, token));
        }

        /// <summary>Checks the authenticated outer status of a raw protocol response.</summary>
        /// <param name="response">The decrypted response body.</param>
        /// <param name="expected">The required success or rejection status.</param>
        private static void AssertStatus(ReadOnlyMemory<byte> response, byte expected)
        {
            using var reader = new Wire(response);
            Assert.Equal(expected, reader.Byte());
        }

        /// <summary>Creates fast real-loopback NAT options with optional unreachable advertised addresses.</summary>
        /// <param name="transport">The only transport to bind.</param>
        /// <param name="capabilities">The services advertised by the test node.</param>
        /// <param name="hidden">Whether the signed contact should use an address with no matching listener.</param>
        /// <returns>Independent options whose observed socket address remains 127.0.0.1.</returns>
        private static DHTNodeOptions NatOptions(DHTTransport transport, DHTCapabilities capabilities, bool hidden = false)
        {
            return new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { IPAddress.Loopback },
                AdvertisedAddresses = new List<IPAddress> { hidden ? IPAddress.Parse("127.0.0.2") : IPAddress.Loopback },
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

        /// <summary>Authenticates registration once and can then stall subsequent rendezvous RPCs.</summary>
        private sealed class StallingRelay : IAsyncDisposable
        {
            /// <summary>The identity signing the relay's authenticated responses.</summary>
            private readonly DHTIdentity _identity = new DHTIdentity();
            /// <summary>The real transport that captures source endpoint metadata.</summary>
            private readonly SocketTransport _transport;
            /// <summary>Whether subsequent requests wait for their transport cancellation.</summary>
            private bool _stall;
            /// <summary>Gets the relay-capable signed listener contact.</summary>
            internal DHTPeer Peer { get; }
            /// <summary>Signals entry into a deliberately withheld network response.</summary>
            internal TaskCompletionSource<bool> Entered { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Binds a real relay listener for a single transport.</summary>
            /// <param name="transport">The only transport to enable.</param>
            internal StallingRelay(DHTTransport transport)
            {
                _transport = new SocketTransport(NatOptions(transport, DHTCapabilities.Relay).Snapshot(), HandleAsync, NullLogger.Instance);
                _transport.Bind();
                Peer = DHTPeer.Create(_identity, IPAddress.Loopback, _transport.TcpPort, _transport.UdpPort, DHTCapabilities.Relay);
                _transport.Run();
            }

            /// <summary>Makes later registration refreshes wait for cancellation.</summary>
            internal void Stall()
            {
                Volatile.Write(ref _stall, true);
            }

            /// <summary>Returns an authenticated observed endpoint or holds the response until cancelled.</summary>
            /// <param name="encoded">The encrypted rendezvous request.</param>
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

            /// <summary>Cancels all held requests and drains the real relay transport.</summary>
            /// <returns>Completion after all listener and request tasks stop.</returns>
            public async ValueTask DisposeAsync()
            {
                await _transport.DisposeAsync();
            }
        }
    }
}
