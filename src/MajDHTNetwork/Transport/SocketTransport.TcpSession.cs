using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork.Transport
{
    internal sealed partial class SocketTransport
    {
        /// <summary>Enables a TCP listener and its active-open sockets to share a local endpoint.</summary>
        /// <param name="socket">The unbound TCP socket.</param>
        /// <exception cref="SocketException">The platform rejects endpoint reuse.</exception>
        private static void ConfigureReusableTcp(Socket socket)
        {
            socket.ExclusiveAddressUse = false;
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        }

        /// <summary>Finds a live pinned session or actively opens one from the listener's local port.</summary>
        /// <param name="endpoint">The exact remote endpoint.</param>
        /// <param name="connectTimeout">The maximum lifetime of a connecting socket.</param>
        /// <returns>A cached or newly connecting session.</returns>
        /// <exception cref="IOException">The bounded cache is busy or address families do not match.</exception>
        /// <exception cref="SocketException">The reusable source endpoint cannot bind.</exception>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        private TcpSession GetTcpSession(IPEndPoint endpoint, TimeSpan connectTimeout)
        {
            lock (_sessionSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                if (_sessionsByEndpoint.TryGetValue(endpoint, out var existing) && !existing.IsClosed)
                {
                    return existing;
                }
                if (!MakeSessionSpace())
                {
                    throw new IOException("The bounded TCP session cache is busy.");
                }
                var client = new TcpClient(endpoint.AddressFamily);
                try
                {
                    if (_tcpEndpoint != null)
                    {
                        if (_tcpEndpoint.AddressFamily != endpoint.AddressFamily)
                        {
                            throw new IOException("The TCP listener and destination address families differ.");
                        }
                        ConfigureReusableTcp(client.Client);
                        client.Client.Bind(_tcpEndpoint);
                    }
                    return AddSession(client, endpoint, false, connectTimeout);
                }
                catch
                {
                    client.Dispose();
                    throw;
                }
            }
        }

        /// <summary>Adds and starts a session while holding the session cache lock.</summary>
        /// <param name="client">The accepted or newly bound socket transferred to the session.</param>
        /// <param name="endpoint">The immutable pinned destination.</param>
        /// <param name="connected">Whether the socket was accepted already connected.</param>
        /// <param name="connectTimeout">The active-open attempt budget.</param>
        /// <returns>The owned live session.</returns>
        private TcpSession AddSession(TcpClient client, IPEndPoint endpoint, bool connected, TimeSpan connectTimeout)
        {
            var id = Interlocked.Increment(ref _sequence);
            var session = new TcpSession(this, id, client, endpoint, connected, connectTimeout);
            _sessions.Add(id, session);
            if (!_sessionsByEndpoint.TryGetValue(endpoint, out var existing) || existing.IsClosed
                || (connected && !existing.IsConnected))
            {
                _sessionsByEndpoint[endpoint] = session;
            }
            Track(session.RunAsync());
            return session;
        }

        /// <summary>Evicts one idle connection when the bounded session cache is full.</summary>
        /// <returns>Whether a new socket may be retained.</returns>
        private bool MakeSessionSpace()
        {
            if (_sessions.Count < _options.MaxConcurrentRequests)
            {
                return true;
            }
            TcpSession? oldest = null;
            foreach (var session in _sessions.Values)
            {
                if (session.IsClosed || (session.IsIdle && (oldest == null || session.LastActivity < oldest.LastActivity)))
                {
                    oldest = session;
                    if (session.IsClosed)
                    {
                        break;
                    }
                }
            }
            if (oldest == null)
            {
                return false;
            }
            RemoveSession(oldest);
            oldest.Stop();
            return true;
        }

        /// <summary>Removes a closed or evicted session without discarding a replacement connection.</summary>
        /// <param name="session">The session relinquishing its cache entry.</param>
        private void RemoveSession(TcpSession session)
        {
            lock (_sessionSync)
            {
                _sessions.Remove(session.Id);
                if (_sessionsByEndpoint.TryGetValue(session.Endpoint, out var existing) && ReferenceEquals(existing, session))
                {
                    _sessionsByEndpoint.Remove(session.Endpoint);
                    foreach (var candidate in _sessions.Values)
                    {
                        if (!candidate.IsClosed && candidate.Endpoint.Equals(session.Endpoint))
                        {
                            _sessionsByEndpoint[session.Endpoint] = candidate;
                            break;
                        }
                    }
                }
            }
        }

        /// <summary>Reads only bounded envelope metadata to route requests and responses without decrypting.</summary>
        /// <param name="encoded">The opaque frame.</param>
        /// <returns>The untrusted visible kind or null for an alternate frame encoding.</returns>
        private static byte? ReadEnvelopeKind(ReadOnlyMemory<byte> encoded)
        {
            try
            {
                using var outer = new Wire(encoded);
                var header = outer.Bytes(256);
                var cipher = outer.Bytes(Wire.MaxPacket);
                outer.End();
                using var reader = new Wire(header);
                if (reader.Text(32) != "MajDHT/1/envelope")
                {
                    return null;
                }
                var kind = reader.Byte();
                var recipient = reader.Text(64);
                var key = reader.Bytes(32);
                var nonce = reader.Bytes(12);
                reader.End();
                if ((kind & 0x7f) == 0 || recipient.Length != 64 || key.Length != 32 || nonce.Length != 12 || cipher.Length < 16)
                {
                    return null;
                }
                for (var index = 0; index < recipient.Length; index++)
                {
                    var character = recipient[index];
                    if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
                    {
                        return null;
                    }
                }
                return kind;
            }
            catch (Exception exception) when (exception is InvalidDataException || exception is DecoderFallbackException)
            {
                return null;
            }
        }

        /// <summary>Owns a persistent, endpoint-pinned duplex TCP connection with one outbound response slot.</summary>
        private sealed class TcpSession
        {
            /// <summary>The owning transport and handler dispatcher.</summary>
            private readonly SocketTransport _owner;
            /// <summary>The owned accepted or actively connecting socket.</summary>
            private readonly TcpClient _client;
            /// <summary>The linked connection lifetime, also enforcing an idle timeout.</summary>
            private readonly CancellationTokenSource _lifetime;
            /// <summary>The stable token, valid even after the source is disposed.</summary>
            private readonly CancellationToken _token;
            /// <summary>The budget for an active-open attempt.</summary>
            private readonly TimeSpan _connectTimeout;
            /// <summary>The finite idle lifetime after connection succeeds.</summary>
            private readonly TimeSpan _idleTimeout;
            /// <summary>Serializes outbound requests and their response slot.</summary>
            private readonly SemaphoreSlim _exchangeGate = new SemaphoreSlim(1, 1);
            /// <summary>Serializes request and response writes into complete frames.</summary>
            private readonly SemaphoreSlim _sendGate = new SemaphoreSlim(1, 1);
            /// <summary>Protects the outbound response slot.</summary>
            private readonly object _responseSync = new object();
            /// <summary>The connection establishment result.</summary>
            private readonly TaskCompletionSource<bool> _ready =
                new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            /// <summary>The response to the one currently outstanding outbound request.</summary>
            private TaskCompletionSource<ReadOnlyMemory<byte>>? _response;
            /// <summary>The expected untrusted response operation when the request has a known header.</summary>
            private byte? _expectedKind;
            /// <summary>The last read or write timestamp used for idle eviction.</summary>
            private long _lastActivity = Stopwatch.GetTimestamp();
            /// <summary>The number of active or queued outgoing requests.</summary>
            private int _outgoing;
            /// <summary>The number of dispatched incoming handlers.</summary>
            private int _incoming;
            /// <summary>The successful connection marker.</summary>
            private int _connected;
            /// <summary>The idempotent connection close marker.</summary>
            private int _closed;
            /// <summary>Gets the unique transport-owned session identifier.</summary>
            internal long Id { get; }
            /// <summary>Gets the pinned remote endpoint, never supplied directly to a user handler.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the connection lifetime.</summary>
            internal CancellationToken Token => _token;
            /// <summary>Gets whether the connection is closing or closed.</summary>
            internal bool IsClosed => Volatile.Read(ref _closed) != 0 || _token.IsCancellationRequested;
            /// <summary>Gets whether the active open or accept has completed.</summary>
            internal bool IsConnected => Volatile.Read(ref _connected) != 0;
            /// <summary>Gets whether an established session can be safely evicted.</summary>
            internal bool IsIdle => IsConnected && Volatile.Read(ref _outgoing) == 0 && Volatile.Read(ref _incoming) == 0;
            /// <summary>Gets the monotonic last-activity timestamp.</summary>
            internal long LastActivity => Interlocked.Read(ref _lastActivity);

            /// <summary>Takes ownership of one socket and its pinned endpoint.</summary>
            /// <param name="owner">The transport owning the cache and incoming concurrency limiter.</param>
            /// <param name="id">The unique session identifier.</param>
            /// <param name="client">The owned connected or unconnected socket.</param>
            /// <param name="endpoint">The immutable remote endpoint.</param>
            /// <param name="connected">Whether this socket was accepted already connected.</param>
            /// <param name="connectTimeout">The maximum duration of an active-open attempt.</param>
            internal TcpSession(SocketTransport owner, long id, TcpClient client, IPEndPoint endpoint,
                bool connected, TimeSpan connectTimeout)
            {
                _owner = owner;
                Id = id;
                _client = client;
                Endpoint = endpoint;
                _connected = connected ? 1 : 0;
                _connectTimeout = connectTimeout;
                _idleTimeout = TimeSpan.FromTicks(Math.Max(TimeSpan.FromSeconds(30).Ticks, owner._options.RequestTimeout.Ticks * 4));
                _lifetime = CancellationTokenSource.CreateLinkedTokenSource(owner._shutdownToken);
                _token = _lifetime.Token;
                _ = _ready.Task.ContinueWith(completed =>
                {
                    var ignored = completed.Exception;
                }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }

            /// <summary>Connects when necessary, then continuously receives requests and responses.</summary>
            /// <returns>Completion after socket closure and response-slot cleanup.</returns>
            internal async Task RunAsync()
            {
                using var registration = _token.Register(_client.Dispose);
                Exception failure = new IOException("The TCP session closed.");
                try
                {
                    if (!IsConnected)
                    {
                        _lifetime.CancelAfter(_connectTimeout);
                        await _client.ConnectAsync(Endpoint.Address, Endpoint.Port).ConfigureAwait(false);
                        Volatile.Write(ref _connected, 1);
                    }
                    _token.ThrowIfCancellationRequested();
                    _client.NoDelay = true;
                    Touch();
                    _ready.TrySetResult(true);
                    var stream = _client.GetStream();
                    while (!_token.IsCancellationRequested)
                    {
                        var frame = await ReadFrameAsync(stream, _token).ConfigureAwait(false);
                        Touch();
                        var kind = ReadEnvelopeKind(frame);
                        bool response;
                        lock (_responseSync)
                        {
                            response = _owner._responseClassifier != null
                                ? _owner._responseClassifier(frame)
                                : kind.HasValue ? (kind.Value & 0x80) != 0 : _response != null;
                            if (response)
                            {
                                if (_response != null && (!_expectedKind.HasValue || !kind.HasValue || kind == _expectedKind))
                                {
                                    _response.TrySetResult(frame);
                                }
                            }
                        }
                        if (!response)
                        {
                            Interlocked.Increment(ref _incoming);
                            _owner.DispatchTcp(this, frame);
                        }
                    }
                }
                catch (Exception exception)
                {
                    failure = exception;
                    if (!_token.IsCancellationRequested)
                    {
                        DHTLog.Write(_owner._logger, LogLevel.Debug, "TCP session closed: ", exception);
                    }
                }
                finally
                {
                    Stop();
                    _ready.TrySetException(new IOException("TCP connection failed or closed.", failure));
                    lock (_responseSync)
                    {
                        _response?.TrySetException(new IOException("TCP response was interrupted.", failure));
                    }
                    _owner.RemoveSession(this);
                    _lifetime.Dispose();
                }
            }

            /// <summary>Serializes one outgoing request while the independent reader serves incoming frames.</summary>
            /// <param name="packet">The encrypted request.</param>
            /// <param name="cancellationToken">The caller and exchange budget.</param>
            /// <returns>The opaque response, requiring caller authentication.</returns>
            /// <exception cref="IOException">The connection closes before its response arrives.</exception>
            /// <exception cref="OperationCanceledException">The exchange is cancelled.</exception>
            internal async Task<ReadOnlyMemory<byte>> ExchangeAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref _outgoing);
                var entered = false;
                try
                {
                    await _exchangeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
                    entered = true;
                    await AwaitCancellableAsync(_ready.Task, cancellationToken).ConfigureAwait(false);
                    var response = new TaskCompletionSource<ReadOnlyMemory<byte>>(TaskCreationOptions.RunContinuationsAsynchronously);
                    ObserveFault(response.Task);
                    var kind = ReadEnvelopeKind(packet);
                    lock (_responseSync)
                    {
                        if (IsClosed)
                        {
                            throw new IOException("The cached TCP session has closed.");
                        }
                        _expectedKind = kind.HasValue ? (byte?)(kind.Value | 0x80) : null;
                        _response = response;
                    }
                    await SendAsync(packet, cancellationToken).ConfigureAwait(false);
                    return await AwaitCancellableAsync(response.Task, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    if (entered)
                    {
                        // Closing prevents a delayed response from occupying a later request's slot.
                        Stop();
                    }
                    throw;
                }
                finally
                {
                    if (entered)
                    {
                        lock (_responseSync)
                        {
                            _response = null;
                            _expectedKind = null;
                        }
                        _exchangeGate.Release();
                    }
                    Interlocked.Decrement(ref _outgoing);
                }
            }

            /// <summary>Writes a complete frame without interleaving simultaneous requests and responses.</summary>
            /// <param name="packet">The encrypted request or response.</param>
            /// <param name="cancellationToken">The frame lifetime.</param>
            /// <returns>Completion after the frame is written.</returns>
            /// <exception cref="IOException">The connection has closed or writing fails.</exception>
            /// <exception cref="OperationCanceledException">The frame or connection is cancelled.</exception>
            internal async Task SendAsync(ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
            {
                using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _token);
                await _sendGate.WaitAsync(lifetime.Token).ConfigureAwait(false);
                try
                {
                    if (IsClosed)
                    {
                        throw new IOException("The TCP session has closed.");
                    }
                    await WriteFrameAsync(_client.GetStream(), packet, lifetime.Token).ConfigureAwait(false);
                    Touch();
                }
                finally
                {
                    _sendGate.Release();
                }
            }

            /// <summary>Releases the incoming activity marker after dispatch or rejection.</summary>
            internal void CompleteIncoming()
            {
                Interlocked.Decrement(ref _incoming);
            }

            /// <summary>Renews the finite idle lifetime after a complete read or write.</summary>
            private void Touch()
            {
                Interlocked.Exchange(ref _lastActivity, Stopwatch.GetTimestamp());
                if (!IsClosed)
                {
                    _lifetime.CancelAfter(_idleTimeout);
                }
            }

            /// <summary>Closes the socket promptly and cancels the read loop.</summary>
            internal void Stop()
            {
                if (Interlocked.Exchange(ref _closed, 1) == 0)
                {
                    _lifetime.Cancel();
                    _client.Dispose();
                }
            }
        }
    }
}
