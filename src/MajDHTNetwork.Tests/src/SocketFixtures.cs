#nullable enable

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Transport;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>A cancellation-aware storage double that blocks server reads.</summary>
    internal sealed class BlockingStore : IDHTContentStore
    {
        /// <summary>Signals when a serving request reaches storage.</summary>
        internal TaskCompletionSource<bool> Entered { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        /// <inheritdoc />
        public ValueTask PutAsync(string blockHash, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            return default;
        }

        /// <inheritdoc />
        public async ValueTask<ReadOnlyMemory<byte>?> GetAsync(string blockHash, CancellationToken cancellationToken)
        {
            Entered.TrySetResult(true);
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
            return null;
        }
    }

    /// <summary>
    /// A real UDP proxy that drops the first reply from the node and checks replay-cached retransmission. Both directions are
    /// pumped independently, because the node also sends its own requests, such as admission verifications, towards the
    /// client's observed source, which is the proxy.
    /// </summary>
    internal sealed class LossyUdpProxy : IAsyncDisposable
    {
        /// <summary>The public proxy socket.</summary>
        private readonly UdpClient _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        /// <summary>The socket towards the actual node.</summary>
        private readonly UdpClient _outgoing = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        /// <summary>The actual node endpoint.</summary>
        private readonly IPEndPoint _destination;
        /// <summary>The active receive tasks.</summary>
        private readonly Task _loop;
        /// <summary>The first encrypted reply.</summary>
        private byte[]? _first;
        /// <summary>The client endpoint seen most recently, which receives everything the node sends.</summary>
        private IPEndPoint? _client;
        /// <summary>The shutdown marker.</summary>
        private volatile bool _stopped;
        /// <summary>Gets the number of replies received from the node.</summary>
        internal int Responses { get; private set; }
        /// <summary>Gets whether a later reply repeated the dropped ciphertext, served from the replay cache.</summary>
        internal bool DuplicateReplyMatched { get; private set; }
        /// <summary>Gets the public proxy port.</summary>
        internal int Port
        {
            get
            {
                return ((IPEndPoint)_listener.Client.LocalEndPoint!).Port;
            }
        }

        /// <summary>Starts a UDP proxy targeting a real node.</summary>
        /// <param name="destination">The actual node endpoint.</param>
        internal LossyUdpProxy(IPEndPoint destination)
        {
            _destination = destination;
            _loop = RunAsync();
        }

        /// <summary>Pumps both directions until shutdown.</summary>
        /// <returns>Completion after proxy shutdown.</returns>
        private Task RunAsync()
        {
            return Task.WhenAll(ForwardClientFramesAsync(), ForwardNodeFramesAsync());
        }

        /// <summary>Forwards everything the client sends to the node and remembers the client endpoint.</summary>
        /// <returns>Completion after proxy shutdown.</returns>
        private async Task ForwardClientFramesAsync()
        {
            try
            {
                while (!_stopped)
                {
                    var incoming = await _listener.ReceiveAsync().ConfigureAwait(false);
                    Volatile.Write(ref _client, incoming.RemoteEndPoint);
                    await _outgoing.SendAsync(incoming.Buffer, incoming.Buffer.Length, _destination).ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (_stopped && (exception is ObjectDisposedException || exception is SocketException))
            {
            }
        }

        /// <summary>Forwards what the node sends to the client, discarding the node's first reply.</summary>
        /// <returns>Completion after proxy shutdown.</returns>
        private async Task ForwardNodeFramesAsync()
        {
            try
            {
                while (!_stopped)
                {
                    var response = await _outgoing.ReceiveAsync().ConfigureAwait(false);
                    var client = Volatile.Read(ref _client);
                    if (client == null)
                    {
                        continue;
                    }
                    // Challenges and the node's own requests pass through; only replies take part in the loss experiment.
                    if (UdpCookies.IsFrame(response.Buffer, 3) || UdpCookies.ReplyDigest(response.Buffer).HasValue)
                    {
                        Responses++;
                        if (_first == null)
                        {
                            _first = response.Buffer;
                            continue;
                        }
                        DuplicateReplyMatched |= BytesEqual(_first, response.Buffer);
                    }
                    await _listener.SendAsync(response.Buffer, response.Buffer.Length, client).ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (_stopped && (exception is ObjectDisposedException || exception is SocketException))
            {
            }
        }

        /// <summary>Closes the proxy sockets and drains the receive tasks.</summary>
        /// <returns>Completion after proxy cleanup.</returns>
        public async ValueTask DisposeAsync()
        {
            _stopped = true;
            _listener.Dispose();
            _outgoing.Dispose();
            await _loop.ConfigureAwait(false);
        }
    }
}
