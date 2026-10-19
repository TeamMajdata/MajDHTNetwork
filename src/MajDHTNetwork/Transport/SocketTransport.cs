using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork.Transport
{
    /// <summary>Exchanges bounded envelopes through shared UDP sockets and reusable TCP sessions.</summary>
    internal sealed partial class SocketTransport : IAsyncDisposable
    {
        /// <summary>The interval between simultaneous-open attempts.</summary>
        private static readonly TimeSpan s_punchInterval = TimeSpan.FromMilliseconds(200);
        /// <summary>The immutable node options.</summary>
        private readonly DHTNodeOptions _options;
        /// <summary>The dispatcher receiving the transport and observed source.</summary>
        private readonly Func<ReadOnlyMemory<byte>, DHTTransport, IPEndPoint, CancellationToken, Task<ReadOnlyMemory<byte>>> _handler;
        /// <summary>An optional response-bit classifier for alternate envelope encodings.</summary>
        private readonly Func<ReadOnlyMemory<byte>, bool>? _responseClassifier;
        /// <summary>The isolated diagnostic sink.</summary>
        private readonly ILogger _logger;
        /// <summary>The transport shutdown signal.</summary>
        private readonly CancellationTokenSource _shutdown = new CancellationTokenSource();
        /// <summary>The stable shutdown token, available after resource disposal.</summary>
        private readonly CancellationToken _shutdownToken;
        /// <summary>The stateless UDP source-address validation service.</summary>
        private readonly UdpCookies _cookies = new UdpCookies();
        /// <summary>The incoming concurrency limiter.</summary>
        private readonly SemaphoreSlim _slots;
        /// <summary>The outgoing exchange and pending-state limiter.</summary>
        private readonly SemaphoreSlim _outgoingSlots;
        /// <summary>Serializes sends on the shared UDP socket.</summary>
        private readonly SemaphoreSlim _udpSend = new SemaphoreSlim(1, 1);
        /// <summary>The live handlers, exchanges and session loops.</summary>
        private readonly ConcurrentDictionary<long, Task> _requests = new ConcurrentDictionary<long, Task>();
        /// <summary>The bounded pending UDP exchanges indexed by pinned endpoint and request digest.</summary>
        private readonly ConcurrentDictionary<UdpExchangeKey, UdpPendingExchange> _udpPending = new ConcurrentDictionary<UdpExchangeKey, UdpPendingExchange>();
        /// <summary>Serializes listener startup and shutdown against new exchanges.</summary>
        private readonly object _lifecycleSync = new object();
        /// <summary>Serializes TCP session cache updates.</summary>
        private readonly object _sessionSync = new object();
        /// <summary>All live TCP sessions, including accepted simultaneous connections.</summary>
        private readonly Dictionary<long, TcpSession> _sessions = new Dictionary<long, TcpSession>();
        /// <summary>The preferred live session for each exact remote endpoint.</summary>
        private readonly Dictionary<IPEndPoint, TcpSession> _sessionsByEndpoint = new Dictionary<IPEndPoint, TcpSession>();
        /// <summary>The TCP acceptor when enabled.</summary>
        private TcpListener? _tcp;
        /// <summary>The immutable bound TCP address and port.</summary>
        private IPEndPoint? _tcpEndpoint;
        /// <summary>The single UDP socket, including an outbound-only fallback if needed.</summary>
        private UdpClient? _udp;
        /// <summary>The immutable bound UDP address and port.</summary>
        private IPEndPoint? _udpEndpoint;
        /// <summary>The accept loop task.</summary>
        private Task _tcpLoop = Task.CompletedTask;
        /// <summary>The datagram loop task.</summary>
        private Task _udpLoop = Task.CompletedTask;
        /// <summary>The request and session sequence.</summary>
        private long _sequence;
        /// <summary>Whether listener binding completed.</summary>
        private bool _bound;
        /// <summary>Whether new inbound UDP requests may be dispatched.</summary>
        private bool _acceptUdpRequests;
        /// <summary>Whether the UDP receive loop has started.</summary>
        private bool _udpRunning;
        /// <summary>Whether the TCP accept loop has started.</summary>
        private bool _tcpRunning;
        /// <summary>The idempotent stop marker.</summary>
        private int _stopped;
        /// <summary>Gets the assigned TCP listener port or zero.</summary>
        internal int TcpPort => _tcpEndpoint?.Port ?? 0;
        /// <summary>Gets the assigned UDP listener port, excluding the outbound-only fallback.</summary>
        internal int UdpPort => _bound && _options.UdpPort.HasValue ? _udpEndpoint?.Port ?? 0 : 0;

        /// <summary>Creates an unbound transport that exposes observed endpoints to its handler.</summary>
        /// <param name="options">The validated options.</param>
        /// <param name="handler">The envelope handler, including transport and observed source.</param>
        /// <param name="logger">An optional standard logger override.</param>
        /// <param name="responseClassifier">An optional response-bit classifier; authentication remains the handler's responsibility.</param>
        internal SocketTransport(DHTNodeOptions options,
            Func<ReadOnlyMemory<byte>, DHTTransport, IPEndPoint, CancellationToken, Task<ReadOnlyMemory<byte>>> handler,
            ILogger? logger = null, Func<ReadOnlyMemory<byte>, bool>? responseClassifier = null)
        {
            _shutdownToken = _shutdown.Token;
            _options = options;
            _handler = handler;
            _logger = logger ?? options.Logger;
            _responseClassifier = responseClassifier;
            _slots = new SemaphoreSlim(options.MaxConcurrentRequests, options.MaxConcurrentRequests);
            _outgoingSlots = new SemaphoreSlim(options.MaxConcurrentRequests, options.MaxConcurrentRequests);
        }

        /// <summary>Creates a transport for legacy handlers that do not consume endpoint metadata.</summary>
        /// <param name="options">The validated options.</param>
        /// <param name="handler">The legacy envelope handler.</param>
        /// <param name="logger">An optional standard logger override.</param>
        internal SocketTransport(DHTNodeOptions options,
            Func<ReadOnlyMemory<byte>, CancellationToken, Task<ReadOnlyMemory<byte>>> handler, ILogger? logger = null)
            : this(options, (packet, transport, endpoint, token) => handler(packet, token), logger)
        {
        }

        /// <summary>Binds requested listeners with reusable TCP source ports.</summary>
        /// <exception cref="InvalidOperationException">The listeners have already been bound.</exception>
        /// <exception cref="SocketException">A requested listener cannot bind.</exception>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        internal void Bind()
        {
            lock (_lifecycleSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                if (_bound)
                {
                    throw new InvalidOperationException("The transport is already bound.");
                }
                if (_options.TcpPort.HasValue)
                {
                    _tcp = new TcpListener(_options.ListenAddress, _options.TcpPort.Value);
                    ConfigureReusableTcp(_tcp.Server);
                    _tcp.Start(_options.MaxConcurrentRequests);
                    _tcpEndpoint = CopyEndpoint((IPEndPoint)_tcp.LocalEndpoint);
                }
                if (_options.UdpPort.HasValue)
                {
                    if (_udp != null)
                    {
                        throw new InvalidOperationException("Bind must precede outbound UDP exchanges when a UDP listener is configured.");
                    }
                    _udp = new UdpClient(new IPEndPoint(_options.ListenAddress, _options.UdpPort.Value));
                    _udpEndpoint = CopyEndpoint((IPEndPoint)_udp.Client.LocalEndPoint!);
                }
                _bound = true;
            }
        }

        /// <summary>Starts listeners after the local signed contact is available.</summary>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        internal void Run()
        {
            lock (_lifecycleSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                if (_tcp != null && !_tcpRunning)
                {
                    _tcpRunning = true;
                    _tcpLoop = AcceptAsync();
                }
                _acceptUdpRequests = _bound && _options.UdpPort.HasValue;
                StartUdpLoop();
            }
        }

        /// <summary>Starts the single receiver if its socket exists and is not already running.</summary>
        private void StartUdpLoop()
        {
            if (_udp != null && !_udpRunning)
            {
                _udpRunning = true;
                _udpLoop = ReceiveAsync();
            }
        }

        /// <summary>Ensures ordinary outbound UDP works even when no UDP listener was requested.</summary>
        /// <exception cref="SocketException">The outbound-only socket cannot bind.</exception>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        private void EnsureUdpSocket()
        {
            lock (_lifecycleSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                if (_udp == null)
                {
                    _udp = new UdpClient(new IPEndPoint(_options.ListenAddress, 0));
                    _udpEndpoint = CopyEndpoint((IPEndPoint)_udp.Client.LocalEndPoint!);
                    DHTLog.Write(_logger, LogLevel.Debug, "Created a shared outbound-only UDP socket; inbound UDP punching is unavailable.");
                }
                StartUdpLoop();
            }
        }

        /// <summary>Accepts persistent TCP sessions within the bounded cache.</summary>
        /// <returns>Completion when the listener closes.</returns>
        private async Task AcceptAsync()
        {
            try
            {
                while (!_shutdown.IsCancellationRequested)
                {
                    var client = await _tcp!.AcceptTcpClientAsync().ConfigureAwait(false);
                    if (!(client.Client.RemoteEndPoint is IPEndPoint endpoint))
                    {
                        client.Dispose();
                        continue;
                    }
                    lock (_sessionSync)
                    {
                        if (_shutdown.IsCancellationRequested || !MakeSessionSpace())
                        {
                            client.Dispose();
                            continue;
                        }
                        AddSession(client, CopyEndpoint(endpoint), true, _options.RequestTimeout);
                    }
                }
            }
            catch (Exception exception) when (_shutdown.IsCancellationRequested || exception is SocketException || exception is ObjectDisposedException)
            {
                if (!_shutdown.IsCancellationRequested)
                {
                    DHTLog.Write(_logger, LogLevel.Error, "TCP accept loop stopped: ", exception);
                }
            }
        }

        /// <summary>Demultiplexes replies before applying incoming request concurrency limits.</summary>
        /// <returns>Completion when the shared socket closes.</returns>
        private async Task ReceiveAsync()
        {
            try
            {
                while (!_shutdown.IsCancellationRequested)
                {
                    UdpReceiveResult packet;
                    try
                    {
                        packet = await _udp!.ReceiveAsync().ConfigureAwait(false);
                    }
                    catch (SocketException) when (!_shutdown.IsCancellationRequested)
                    {
                        DHTLog.Write(_logger, LogLevel.Warning, "Transient UDP receive failure.");
                        await Task.Delay(10, _shutdownToken).ConfigureAwait(false);
                        continue;
                    }
                    if (packet.Buffer.Length > UdpCookies.MaxDatagram || RouteUdpReply(packet))
                    {
                        continue;
                    }
                    if (!_acceptUdpRequests || (!IsUdpRequestFrame(packet.Buffer)) || !_slots.Wait(0))
                    {
                        continue;
                    }
                    Track(ServeUdpAsync(packet));
                }
            }
            catch (Exception exception) when (_shutdown.IsCancellationRequested || exception is SocketException || exception is ObjectDisposedException)
            {
                if (!_shutdown.IsCancellationRequested)
                {
                    DHTLog.Write(_logger, LogLevel.Error, "UDP receive loop stopped: ", exception);
                }
            }
        }

        /// <summary>Checks whether a datagram could be an inbound hello or cookie-bearing request.</summary>
        /// <param name="packet">The received datagram.</param>
        /// <returns>Whether incoming dispatch is applicable.</returns>
        private static bool IsUdpRequestFrame(ReadOnlySpan<byte> packet)
        {
            return UdpCookies.IsFrame(packet, 0) || UdpCookies.IsFrame(packet, 2);
        }

        /// <summary>Routes challenges and correlated replies only to their pinned pending exchange.</summary>
        /// <param name="packet">The received datagram and source.</param>
        /// <returns>Whether this is a reply or challenge, including unmatched frames to discard.</returns>
        private bool RouteUdpReply(UdpReceiveResult packet)
        {
            var challengeDigest = UdpCookies.ChallengeDigest(packet.Buffer);
            if (challengeDigest.HasValue)
            {
                if (_udpPending.TryGetValue(new UdpExchangeKey(packet.RemoteEndPoint, challengeDigest.Value.Span), out var pending))
                {
                    pending.Challenge.TrySetResult(packet.Buffer);
                }
                return true;
            }
            var replyDigest = UdpCookies.ReplyDigest(packet.Buffer);
            if (replyDigest.HasValue)
            {
                if (_udpPending.TryGetValue(new UdpExchangeKey(packet.RemoteEndPoint, replyDigest.Value.Span), out var pending)
                    && pending.RequestSent)
                {
                    var response = UdpCookies.OpenReply(packet.Buffer, pending.Digest);
                    if (response.HasValue)
                    {
                        pending.Response.TrySetResult(response.Value);
                    }
                }
                return true;
            }
            if (UdpCookies.IsFrame(packet.Buffer, 3))
            {
                UdpPendingExchange? only = null;
                foreach (var pending in _udpPending.Values)
                {
                    if (!pending.Endpoint.Equals(packet.RemoteEndPoint))
                    {
                        continue;
                    }
                    if (only != null)
                    {
                        return true;
                    }
                    only = pending;
                }
                var response = UdpCookies.OpenReply(packet.Buffer);
                if (only != null && only.RequestSent && response.HasValue)
                {
                    only.Response.TrySetResult(response.Value);
                }
                return true;
            }
            return UdpCookies.IsFrame(packet.Buffer, 1) || UdpCookies.IsFrame(packet.Buffer, 4);
        }

        /// <summary>Tracks work and observes faults without retaining completed tasks.</summary>
        /// <param name="request">The self-contained task.</param>
        /// <param name="reportFailure">Whether an unexpected fault should be logged as an error.</param>
        private void Track(Task request, bool reportFailure = true)
        {
            var id = Interlocked.Increment(ref _sequence);
            _requests[id] = request;
            _ = request.ContinueWith(completed =>
            {
                _requests.TryRemove(id, out var ignored);
                if (completed.IsFaulted)
                {
                    var error = completed.Exception!.GetBaseException();
                    if (reportFailure)
                    {
                        DHTLog.Write(_logger, LogLevel.Error, "Transport task failed: ", error);
                    }
                }
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }

        /// <summary>Schedules a TCP request without blocking the session reader or its response slot.</summary>
        /// <param name="session">The pinned connected session.</param>
        /// <param name="request">The received encrypted envelope.</param>
        private void DispatchTcp(TcpSession session, ReadOnlyMemory<byte> request)
        {
            if (_shutdown.IsCancellationRequested || !_slots.Wait(0))
            {
                session.CompleteIncoming();
                session.Stop();
                return;
            }
            Track(ServeTcpAsync(session, request));
        }

        /// <summary>Serves one frame while the session independently receives other traffic.</summary>
        /// <param name="session">The connection receiving the request.</param>
        /// <param name="request">The received encrypted envelope.</param>
        /// <returns>Completion after response transmission or cancellation.</returns>
        private async Task ServeTcpAsync(TcpSession session, ReadOnlyMemory<byte> request)
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(_shutdownToken, session.Token);
            cancellation.CancelAfter(_options.RequestTimeout + _options.RequestTimeout);
            try
            {
                var response = await InvokeHandlerAsync(request, DHTTransport.Tcp, session.Endpoint, cancellation.Token).ConfigureAwait(false);
                await session.SendAsync(response, cancellation.Token).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                DHTLog.Write(_logger, LogLevel.Debug, "Rejected TCP request: ", exception);
                session.Stop();
            }
            finally
            {
                session.CompleteIncoming();
                _slots.Release();
            }
        }

        /// <summary>Validates a UDP cookie before dispatch and returns a digest-correlated reply.</summary>
        /// <param name="packet">The received datagram and observed source.</param>
        /// <returns>Completion after cleanup.</returns>
        private async Task ServeUdpAsync(UdpReceiveResult packet)
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(_shutdownToken);
            cancellation.CancelAfter(_options.RequestTimeout + _options.RequestTimeout);
            try
            {
                var challenge = _cookies.Challenge(packet.Buffer, packet.RemoteEndPoint);
                if (challenge != null)
                {
                    await SendUdpAsync(challenge, packet.RemoteEndPoint, cancellation.Token).ConfigureAwait(false);
                    return;
                }
                var request = _cookies.OpenRequest(packet.Buffer, packet.RemoteEndPoint);
                if (!request.HasValue)
                {
                    return;
                }
                var digest = Crypto.Hash(request.Value.Span);
                var reply = await InvokeHandlerAsync(request.Value, DHTTransport.Udp, packet.RemoteEndPoint, cancellation.Token).ConfigureAwait(false);
                using var owner = new PooledBuffer(reply.Length + UdpCookies.CorrelatedPrefixLength);
                UdpCookies.WriteReply(reply.Span, digest, owner.Memory.Span);
                await SendUdpAsync(owner.Memory, packet.RemoteEndPoint, cancellation.Token).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                DHTLog.Write(_logger, LogLevel.Debug, "Rejected UDP request: ", exception);
            }
            finally
            {
                _slots.Release();
            }
        }

        /// <summary>Runs user dispatch independently so synchronous handlers cannot block readers or shutdown.</summary>
        /// <param name="packet">The independently owned encrypted request.</param>
        /// <param name="transport">The receiving protocol.</param>
        /// <param name="endpoint">The observed endpoint to copy before exposing it to the handler.</param>
        /// <param name="cancellationToken">The bounded incoming request lifetime.</param>
        /// <returns>The handler response or a cancelled wait.</returns>
        /// <exception cref="OperationCanceledException">The incoming request lifetime ends.</exception>
        private Task<ReadOnlyMemory<byte>> InvokeHandlerAsync(ReadOnlyMemory<byte> packet, DHTTransport transport,
            IPEndPoint endpoint, CancellationToken cancellationToken)
        {
            var source = CopyEndpoint(endpoint);
            var handling = Task.Run(() => _handler(packet, transport, source, cancellationToken), cancellationToken);
            return AwaitCancellableAsync(handling, cancellationToken);
        }

        /// <summary>Sends every UDP frame through the same unconnected bound socket.</summary>
        /// <param name="packet">The complete transport frame.</param>
        /// <param name="destination">The pinned or observed endpoint.</param>
        /// <param name="cancellationToken">The exchange lifetime.</param>
        /// <returns>Completion after the datagram send.</returns>
        private async Task SendUdpAsync(ReadOnlyMemory<byte> packet, IPEndPoint destination, CancellationToken cancellationToken)
        {
            await _udpSend.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _udp!.Client.SendToAsync(Crypto.Array(packet), SocketFlags.None, destination).ConfigureAwait(false);
            }
            finally
            {
                _udpSend.Release();
            }
        }

        /// <summary>Attempts the preferred protocol and then any other advertised protocol.</summary>
        /// <param name="peer">The destination contact.</param>
        /// <param name="packet">The opaque encrypted request.</param>
        /// <param name="cancellationToken">Cancels all connection attempts.</param>
        /// <returns>The opaque encrypted response.</returns>
        /// <exception cref="IOException">No advertised transport returned a response.</exception>
        /// <exception cref="OperationCanceledException">The request or transport was cancelled.</exception>
        internal async Task<ReadOnlyMemory<byte>> ExchangeAsync(DHTPeer peer, ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
        {
            Exception? last = null;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var udp = (_options.PreferredTransport == DHTTransport.Udp) == (attempt == 0);
                var port = udp ? peer.UdpPort : peer.TcpPort;
                if (port == 0)
                {
                    continue;
                }
                try
                {
                    return await ExchangeAtAsync(peer, udp ? DHTTransport.Udp : DHTTransport.Tcp,
                        new IPEndPoint(peer.NetworkAddress, port), packet, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsTransportFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    _shutdownToken.ThrowIfCancellationRequested();
                    last = exception;
                }
            }
            throw new IOException("No advertised transport responded.", last);
        }

        /// <summary>Exchanges directly through one protocol at an explicitly observed endpoint.</summary>
        /// <param name="peer">The destination identity used by the caller to authenticate the response.</param>
        /// <param name="transport">The single protocol to use.</param>
        /// <param name="endpoint">The exact pinned remote endpoint.</param>
        /// <param name="packet">The encrypted request.</param>
        /// <param name="cancellationToken">Cancels queueing and exchange.</param>
        /// <returns>The response; the caller must authenticate its sender and request identifier.</returns>
        /// <exception cref="IOException">The packet, contact, endpoint or transport is invalid, or no response arrives.</exception>
        /// <exception cref="OperationCanceledException">The exchange or transport was cancelled.</exception>
        internal Task<ReadOnlyMemory<byte>> ExchangeAtAsync(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
        {
            return StartExchange(peer, transport, endpoint, packet, cancellationToken, false);
        }

        /// <summary>Retries direct punching within one request budget and retains a successful TCP session.</summary>
        /// <param name="peer">The peer identity authenticated by the caller.</param>
        /// <param name="transport">The protocol whose local listener port must be reused.</param>
        /// <param name="endpoint">The pinned remote endpoint observed by the rendezvous peer.</param>
        /// <param name="packet">The identical signed encrypted punch request on every retry.</param>
        /// <param name="cancellationToken">Cancels the complete punching attempt.</param>
        /// <returns>The encrypted response, requiring caller authentication and token correlation.</returns>
        /// <exception cref="IOException">A matching listener is unavailable or punching fails.</exception>
        /// <exception cref="OperationCanceledException">The exchange or transport was cancelled.</exception>
        internal Task<ReadOnlyMemory<byte>> PunchAsync(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
        {
            return StartExchange(peer, transport, endpoint, packet, cancellationToken, true);
        }

        /// <summary>Registers outgoing work before shutdown can start draining it.</summary>
        /// <param name="peer">The destination contact.</param>
        /// <param name="transport">The selected protocol.</param>
        /// <param name="endpoint">The explicitly pinned endpoint.</param>
        /// <param name="packet">The immutable request for the lifetime of the task.</param>
        /// <param name="cancellationToken">The caller's cancellation.</param>
        /// <param name="punch">Whether a listener and a single short retry budget are required.</param>
        /// <returns>The tracked exchange task.</returns>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        private Task<ReadOnlyMemory<byte>> StartExchange(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> packet, CancellationToken cancellationToken, bool punch)
        {
            lock (_lifecycleSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                var task = ExchangeCoreAsync(peer, transport, CopyEndpoint(endpoint), packet, cancellationToken, punch);
                Track(task, false);
                return task;
            }
        }

        /// <summary>Bounds outgoing state and applies the requested exchange or punching budget.</summary>
        /// <param name="peer">The destination contact.</param>
        /// <param name="transport">The selected protocol.</param>
        /// <param name="endpoint">The pinned endpoint snapshot.</param>
        /// <param name="packet">The immutable encrypted request.</param>
        /// <param name="cancellationToken">The caller's cancellation.</param>
        /// <param name="punch">Whether to require a reusable local listener.</param>
        /// <returns>The opaque response.</returns>
        /// <exception cref="IOException">Validation, connection or response retrieval fails.</exception>
        /// <exception cref="OperationCanceledException">The caller, budget or transport was cancelled.</exception>
        private async Task<ReadOnlyMemory<byte>> ExchangeCoreAsync(DHTPeer peer, DHTTransport transport,
            IPEndPoint endpoint, ReadOnlyMemory<byte> packet, CancellationToken cancellationToken, bool punch)
        {
            if (peer.IsExpired || packet.Length == 0 || packet.Length > Wire.MaxPacket || endpoint.Port == 0
                || (transport != DHTTransport.Tcp && transport != DHTTransport.Udp))
            {
                throw new IOException("Invalid destination, expired contact or invalid encrypted packet size.");
            }
            using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdownToken);
            if (punch || transport == DHTTransport.Tcp)
            {
                lifetime.CancelAfter(_options.RequestTimeout);
            }
            lifetime.Token.ThrowIfCancellationRequested();
            if (!_outgoingSlots.Wait(0))
            {
                throw new IOException("The bounded outgoing exchange limit was reached.");
            }
            try
            {
                if (transport == DHTTransport.Udp)
                {
                    if (punch && (!_bound || !_options.UdpPort.HasValue || !_acceptUdpRequests))
                    {
                        throw new IOException("UDP punching requires an active UDP listener.");
                    }
                    EnsureUdpSocket();
                    if (_udpEndpoint!.AddressFamily != endpoint.AddressFamily)
                    {
                        throw new IOException("The shared UDP socket cannot reach this address family.");
                    }
                    return await ExchangeUdpAsync(endpoint, packet, lifetime.Token, punch).ConfigureAwait(false);
                }
                if (punch && (_tcpEndpoint == null || !_tcpRunning || _tcpEndpoint.AddressFamily != endpoint.AddressFamily))
                {
                    throw new IOException("TCP punching requires an active TCP listener of the destination address family.");
                }
                Exception? last = null;
                do
                {
                    try
                    {
                        var session = GetTcpSession(endpoint, punch ? s_punchInterval : _options.RequestTimeout);
                        return await session.ExchangeAsync(packet, lifetime.Token).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (IsTransportFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        _shutdownToken.ThrowIfCancellationRequested();
                        lifetime.Token.ThrowIfCancellationRequested();
                        if (!punch)
                        {
                            throw new IOException("TCP exchange failed.", exception);
                        }
                        last = exception;
                    }
                    await Task.Delay(25, lifetime.Token).ConfigureAwait(false);
                }
                while (!lifetime.IsCancellationRequested);
                throw new IOException("TCP punching budget exhausted.", last);
            }
            catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested && !_shutdown.IsCancellationRequested)
            {
                throw new IOException("The transport request budget expired.", exception);
            }
            finally
            {
                _outgoingSlots.Release();
            }
        }

        /// <summary>Retries UDP through one socket, preserving the request and source port after packet loss.</summary>
        /// <param name="endpoint">The pinned destination.</param>
        /// <param name="packet">The identical sealed request for every retransmission.</param>
        /// <param name="cancellationToken">The overall exchange lifetime.</param>
        /// <param name="punch">Whether retries use short intervals within one parent budget.</param>
        /// <returns>The correlated sealed response from the pinned endpoint.</returns>
        /// <exception cref="IOException">The pending entry conflicts or all retries expire.</exception>
        /// <exception cref="OperationCanceledException">The overall lifetime is cancelled.</exception>
        private async Task<ReadOnlyMemory<byte>> ExchangeUdpAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> packet,
            CancellationToken cancellationToken, bool punch)
        {
            var digest = Crypto.Hash(packet.Span);
            var key = new UdpExchangeKey(endpoint, digest);
            var pending = new UdpPendingExchange(endpoint, digest);
            if (!_udpPending.TryAdd(key, pending))
            {
                throw new IOException("An identical UDP request is already pending for this endpoint.");
            }
            try
            {
                var hello = UdpCookies.Hello(digest);
                using var request = new PooledBuffer(packet.Length + UdpCookies.CorrelatedPrefixLength);
                var hasRequest = false;
                for (var attempt = 0; punch || attempt < _options.UdpAttempts; attempt++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    timeout.CancelAfter(punch ? s_punchInterval : _options.RequestTimeout);
                    try
                    {
                        if (!hasRequest)
                        {
                            await SendUdpAsync(hello, endpoint, timeout.Token).ConfigureAwait(false);
                            var challenge = await AwaitCancellableAsync(pending.Challenge.Task, timeout.Token).ConfigureAwait(false);
                            if (!UdpCookies.WriteRequest(challenge.Span, packet.Span, digest, request.Memory.Span))
                            {
                                throw new InvalidDataException("Invalid UDP return-reachability challenge.");
                            }
                            hasRequest = true;
                        }
                        pending.MarkRequestSent();
                        await SendUdpAsync(request.Memory, endpoint, timeout.Token).ConfigureAwait(false);
                        return await AwaitCancellableAsync(pending.Response.Task, timeout.Token).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (IsTransportFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                    }
                }
                throw new IOException("UDP retry budget exhausted.");
            }
            finally
            {
                _udpPending.TryRemove(key, out var ignored);
            }
        }

        /// <summary>Waits for cooperative work while observing faults even if cancellation wins.</summary>
        /// <typeparam name="T">The operation result.</typeparam>
        /// <param name="task">The operation whose exceptions must remain observed.</param>
        /// <param name="cancellationToken">Cancels the wait without waiting for an uncooperative handler.</param>
        /// <returns>The completed result.</returns>
        /// <exception cref="OperationCanceledException">Cancellation wins the race.</exception>
        private static async Task<T> AwaitCancellableAsync<T>(Task<T> task, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                ObserveFault(task);
                cancellationToken.ThrowIfCancellationRequested();
            }
            if (task.IsCompleted)
            {
                return await task.ConfigureAwait(false);
            }
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = cancellationToken.Register(() => cancelled.TrySetResult(true));
            if (await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false) != task)
            {
                ObserveFault(task);
                cancellationToken.ThrowIfCancellationRequested();
            }
            return await task.ConfigureAwait(false);
        }

        /// <summary>Observes eventual errors when cancellation detaches an operation from its caller.</summary>
        /// <param name="task">The operation that may outlive its cancelled wait.</param>
        private static void ObserveFault(Task task)
        {
            _ = task.ContinueWith(completed =>
            {
                var ignored = completed.Exception;
            }, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        /// <summary>Identifies failures that permit a transport fallback or punch retry.</summary>
        /// <param name="exception">The observed failure.</param>
        /// <returns>Whether the failure is a transport or lifetime failure.</returns>
        private static bool IsTransportFailure(Exception exception)
        {
            return exception is SocketException || exception is IOException
                || exception is OperationCanceledException || exception is ObjectDisposedException;
        }

        /// <summary>Copies an endpoint so callers and handlers cannot mutate cache keys.</summary>
        /// <param name="endpoint">The endpoint to snapshot.</param>
        /// <returns>An independent endpoint.</returns>
        private static IPEndPoint CopyEndpoint(IPEndPoint endpoint)
        {
            var original = endpoint.Address;
            var address = original.AddressFamily == AddressFamily.InterNetworkV6
                ? new IPAddress(original.GetAddressBytes(), original.ScopeId)
                : new IPAddress(original.GetAddressBytes());
            return new IPEndPoint(address, endpoint.Port);
        }

        /// <summary>Reads an exact byte count without accepting partial or truncated frames.</summary>
        /// <param name="stream">The connected stream.</param>
        /// <param name="bytes">The destination buffer.</param>
        /// <param name="cancellationToken">Cancels the read.</param>
        /// <returns>Completion after the buffer is filled.</returns>
        /// <exception cref="EndOfStreamException">The connection ends during a frame.</exception>
        private static async Task ReadExactlyAsync(Stream stream, byte[] bytes, CancellationToken cancellationToken)
        {
            var offset = 0;
            while (offset < bytes.Length)
            {
                var count = await stream.ReadAsync(bytes, offset, bytes.Length - offset, cancellationToken).ConfigureAwait(false);
                if (count == 0)
                {
                    throw new EndOfStreamException("Truncated TCP frame.");
                }
                offset += count;
            }
        }

        /// <summary>Reads a bounded big-endian length-prefixed envelope.</summary>
        /// <param name="stream">The connected stream.</param>
        /// <param name="cancellationToken">Cancels the read.</param>
        /// <returns>The encrypted envelope.</returns>
        /// <exception cref="InvalidDataException">The declared frame size is invalid.</exception>
        /// <exception cref="EndOfStreamException">The frame is truncated.</exception>
        private static async Task<ReadOnlyMemory<byte>> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
        {
            var prefix = new byte[4];
            await ReadExactlyAsync(stream, prefix, cancellationToken).ConfigureAwait(false);
            var length = ((uint)prefix[0] << 24) | ((uint)prefix[1] << 16) | ((uint)prefix[2] << 8) | prefix[3];
            if (length == 0 || length > Wire.MaxPacket)
            {
                throw new InvalidDataException("Invalid TCP frame size.");
            }
            var packet = new byte[(int)length];
            await ReadExactlyAsync(stream, packet, cancellationToken).ConfigureAwait(false);
            return packet;
        }

        /// <summary>Writes one big-endian length-prefixed encrypted envelope.</summary>
        /// <param name="stream">The connected stream.</param>
        /// <param name="packet">The encrypted envelope.</param>
        /// <param name="cancellationToken">Cancels the write.</param>
        /// <returns>Completion after the frame is written.</returns>
        /// <exception cref="InvalidDataException">The frame size is invalid.</exception>
        private static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
        {
            var length = packet.Length;
            if (length == 0 || length > Wire.MaxPacket)
            {
                throw new InvalidDataException("Invalid TCP frame size.");
            }
            var prefix = new[] { (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length };
            await stream.WriteAsync(prefix, 0, prefix.Length, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Cancels all pending operations and closes every listener and TCP session.</summary>
        internal void Stop()
        {
            lock (_lifecycleSync)
            {
                if (Interlocked.Exchange(ref _stopped, 1) != 0)
                {
                    return;
                }
                _shutdown.Cancel();
                _tcp?.Stop();
                _udp?.Dispose();
                lock (_sessionSync)
                {
                    foreach (var session in new List<TcpSession>(_sessions.Values))
                    {
                        session.Stop();
                    }
                }
            }
        }

        /// <summary>Stops listeners and drains all tracked exchanges, handlers and session readers.</summary>
        /// <returns>Completion after transport-owned work is drained.</returns>
        public async ValueTask DisposeAsync()
        {
            Stop();
            await Task.WhenAll(_tcpLoop, _udpLoop).ConfigureAwait(false);
            while (!_requests.IsEmpty)
            {
                try
                {
                    await Task.WhenAll(_requests.Values).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    // Each tracked fault is observed by Track; cancellation is expected during shutdown.
                }
            }
            _slots.Dispose();
            _outgoingSlots.Dispose();
            _udpSend.Dispose();
            _shutdown.Dispose();
        }
    }
}
