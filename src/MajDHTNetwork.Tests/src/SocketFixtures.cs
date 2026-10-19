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

    /// <summary>A real UDP proxy that drops the first response and checks replay-cached retransmission.</summary>
    internal sealed class LossyUdpProxy : IAsyncDisposable
    {
        /// <summary>The public proxy socket.</summary>
        private readonly UdpClient _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        /// <summary>The actual node endpoint.</summary>
        private readonly IPEndPoint _destination;
        /// <summary>The active receive task.</summary>
        private readonly Task _loop;
        /// <summary>The first encrypted response.</summary>
        private byte[]? _first;
        /// <summary>The shutdown marker.</summary>
        private bool _stopped;
        /// <summary>Gets the number of forwarded valid responses.</summary>
        internal int Responses { get; private set; }
        /// <summary>Gets whether duplicate ciphertext was served from the replay cache.</summary>
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

        /// <summary>Forwards requests, discarding the first reply.</summary>
        /// <returns>Completion after proxy shutdown.</returns>
        private async Task RunAsync()
        {
            try
            {
                using var outgoing = new UdpClient();
                outgoing.Connect(_destination);
                while (!_stopped)
                {
                    var incoming = await _listener.ReceiveAsync().ConfigureAwait(false);
                    await outgoing.SendAsync(incoming.Buffer, incoming.Buffer.Length).ConfigureAwait(false);
                    var response = await outgoing.ReceiveAsync().ConfigureAwait(false);
                    if (!UdpCookies.IsFrame(response.Buffer, 3) && !UdpCookies.ReplyDigest(response.Buffer).HasValue)
                    {
                        await _listener.SendAsync(response.Buffer, response.Buffer.Length, incoming.RemoteEndPoint).ConfigureAwait(false);
                        continue;
                    }
                    Responses++;
                    if (_first == null)
                    {
                        _first = response.Buffer;
                        continue;
                    }
                    DuplicateReplyMatched = BytesEqual(_first, response.Buffer);
                    await _listener.SendAsync(response.Buffer, response.Buffer.Length, incoming.RemoteEndPoint).ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (_stopped && (exception is ObjectDisposedException || exception is SocketException))
            {
            }
        }

        /// <summary>Closes the proxy socket and drains the receive task.</summary>
        /// <returns>Completion after proxy cleanup.</returns>
        public async ValueTask DisposeAsync()
        {
            _stopped = true;
            _listener.Dispose();
            await _loop.ConfigureAwait(false);
        }
    }
}
