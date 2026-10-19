#nullable enable

using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Microsoft.Extensions.Logging.Abstractions;

namespace MajDHTNetwork.Tests
{
    /// <summary>Serves valid one-block content but deliberately rejects direct probes for adversarial NAT tests.</summary>
    internal sealed class NATProtocolPeer : IAsyncDisposable
    {
        /// <summary>The real single-transport listener and outbound exchange socket.</summary>
        private readonly SocketTransport _transport;
        /// <summary>The transport used for every observed-endpoint exchange.</summary>
        private readonly DHTTransport _kind;
        /// <summary>Gets the identity shared with a deliberately substituted source endpoint when needed.</summary>
        internal DHTIdentity Identity { get; }
        /// <summary>Gets the immutable-by-convention file bytes served by this test peer.</summary>
        internal byte[] Content { get; }
        /// <summary>Gets the signed contact whose advertised address has no matching listener.</summary>
        internal DHTPeer Peer { get; }
        /// <summary>Gets the valid signed manifest for the single content block.</summary>
        internal DHTRecord Record { get; }
        /// <summary>Signals that an introduced real node attempted its outgoing authenticated probe.</summary>
        internal TaskCompletionSource<bool> PunchObserved { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <summary>Binds a test peer with valid content and a deliberately unreachable advertised address.</summary>
        /// <param name="transport">The only transport to bind.</param>
        /// <param name="identity">An existing identity to reuse at a different observed endpoint, if required.</param>
        /// <param name="content">The original peer's content to retain across endpoint substitution, if required.</param>
        internal NATProtocolPeer(DHTTransport transport, DHTIdentity? identity = null, byte[]? content = null)
        {
            Identity = identity ?? new DHTIdentity();
            Content = content == null ? new byte[] { 2, 4, 6, 8 } : (byte[])content.Clone();
            _kind = transport;
            Record = DHTRecord.Create(Identity, "nat/authenticated-provider", Crypto.Hex(Crypto.Hash(Content)),
                Crypto.Hex(MerkleTree.Leaf(Content)), Content.Length, 1024, 1, DateTimeOffset.UtcNow.AddHours(1));
            var options = new DHTNodeOptions
            {
                TcpPort = transport == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = transport == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = transport,
                RequestTimeout = TimeSpan.FromMilliseconds(700),
                UdpAttempts = 2,
                EnableNatTraversal = false
            };
            _transport = new SocketTransport(options.Snapshot(), HandleAsync, NullLogger.Instance);
            _transport.Bind();
            Peer = DHTPeer.Create(Identity, IPAddress.Parse("127.0.0.2"), _transport.TcpPort, _transport.UdpPort, DHTCapabilities.Provide);
            _transport.Run();
        }

        /// <summary>Sends an authenticated operation to a node's actual loopback listener.</summary>
        /// <param name="receiver">The signed remote node contact.</param>
        /// <param name="operation">The raw protocol operation to send.</param>
        /// <param name="body">The operation arguments, retained until request sealing completes.</param>
        /// <param name="token">The bounded operation lifetime.</param>
        /// <returns>The authenticated outer response body, including its success byte.</returns>
        /// <exception cref="OperationCanceledException">The caller cancelled the socket exchange.</exception>
        internal async Task<ReadOnlyMemory<byte>> ExchangeAsync(DHTPeer receiver, Operation operation, ReadOnlyMemory<byte> body, CancellationToken token)
        {
            var packet = new Packet(Peer, Crypto.Random(16), (byte)operation, body);
            var endpoint = new IPEndPoint(IPAddress.Loopback, _kind == DHTTransport.Tcp ? receiver.TcpPort : receiver.UdpPort);
            var encoded = await _transport.ExchangeAtAsync(receiver, _kind, endpoint, packet.Seal(Identity, receiver), token);
            var response = Packet.Open(Identity, encoded);
            if (response.Sender.NodeId != receiver.NodeId || !response.RequestId.Span.SequenceEqual(packet.RequestId.Span)
                || response.Kind != (byte)(packet.Kind | 128))
            {
                throw new InvalidDataException("The injected operation received an unauthenticated or mismatched response.");
            }
            return response.Body;
        }

        /// <summary>Answers valid block requests while declining every incoming probe.</summary>
        /// <param name="encoded">The encrypted request from the real node under test.</param>
        /// <param name="token">The incoming transport request lifetime.</param>
        /// <returns>A correctly signed and encrypted success or rejection response.</returns>
        private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var packet = Packet.Open(Identity, encoded);
            using var response = new Wire();
            if (packet.Kind == (byte)Operation.Block)
            {
                using var block = new Wire();
                block.Put(Content);
                block.Put(Array.Empty<byte>());
                response.PutByte(0);
                response.Put(block.WrittenSpan);
            }
            else
            {
                if (packet.Kind == (byte)Operation.Punch)
                {
                    PunchObserved.TrySetResult(true);
                }
                response.PutByte(1);
                response.PutText("This adversarial peer deliberately rejects direct probes.");
            }
            ReadOnlyMemory<byte> result = new Packet(Peer, packet.RequestId, (byte)(packet.Kind | 128), response.WrittenMemory).Seal(Identity, packet.Sender);
            return Task.FromResult(result);
        }

        /// <summary>Closes sockets and drains all incoming protocol operations.</summary>
        /// <returns>Completion after the protocol peer transport stops.</returns>
        public async ValueTask DisposeAsync()
        {
            await _transport.DisposeAsync();
        }
    }
}
