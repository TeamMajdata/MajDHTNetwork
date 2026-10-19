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
        /// <summary>The TCP acceptors, at most one per address family.</summary>
        private readonly List<TcpListener> _tcpListeners = new List<TcpListener>();
        /// <summary>The immutable bound TCP endpoints indexed by address family.</summary>
        private readonly ConcurrentDictionary<AddressFamily, IPEndPoint> _tcpEndpoints = new ConcurrentDictionary<AddressFamily, IPEndPoint>();
        /// <summary>The UDP sockets indexed by address family, including outbound-only fallbacks.</summary>
        private readonly ConcurrentDictionary<AddressFamily, UdpChannel> _udpChannels = new ConcurrentDictionary<AddressFamily, UdpChannel>();
        /// <summary>The accept loop tasks.</summary>
        private readonly List<Task> _tcpLoops = new List<Task>();
        /// <summary>The address family of the first configured listener.</summary>
        private readonly AddressFamily _primaryFamily;
        /// <summary>The request and session sequence.</summary>
        private long _sequence;
        /// <summary>Whether listener binding completed.</summary>
        private bool _bound;
        /// <summary>Whether new inbound UDP requests may be dispatched.</summary>
        private bool _acceptUdpRequests;
        /// <summary>Whether the UDP receive loops may start.</summary>
        private bool _udpRunning;
        /// <summary>Whether the TCP accept loops have started.</summary>
        private bool _tcpRunning;
        /// <summary>The idempotent stop marker.</summary>
        private int _stopped;
        /// <summary>Gets the assigned TCP listener port of the first configured address family, or zero.</summary>
        internal int TcpPort => TcpPortFor(_primaryFamily);
        /// <summary>Gets the assigned UDP listener port of the first configured address family, excluding outbound-only sockets.</summary>
        internal int UdpPort => UdpPortFor(_primaryFamily);

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
            _primaryFamily = options.ListenAddresses[0].AddressFamily;
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

        /// <summary>Gets the assigned TCP listener port for an address family.</summary>
        /// <param name="family">The address family.</param>
        /// <returns>The bound port, or zero when no TCP listener exists for the family.</returns>
        internal int TcpPortFor(AddressFamily family)
        {
            return _tcpEndpoints.TryGetValue(family, out var endpoint) ? endpoint.Port : 0;
        }

        /// <summary>Gets the assigned UDP listener port for an address family, excluding outbound-only sockets.</summary>
        /// <param name="family">The address family.</param>
        /// <returns>The bound port, or zero when no UDP listener exists for the family.</returns>
        internal int UdpPortFor(AddressFamily family)
        {
            return _bound && _udpChannels.TryGetValue(family, out var channel) && channel.Listening ? channel.Endpoint.Port : 0;
        }

        /// <summary>Gets the assigned listener port for a transport and address family.</summary>
        /// <param name="transport">The transport.</param>
        /// <param name="family">The address family.</param>
        /// <returns>The bound port, or zero when no listener exists.</returns>
        internal int PortFor(DHTTransport transport, AddressFamily family)
        {
            return transport == DHTTransport.Tcp ? TcpPortFor(family) : UdpPortFor(family);
        }

        /// <summary>Binds requested listeners for every configured address family with reusable TCP source ports.</summary>
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
                foreach (var address in _options.ListenAddresses)
                {
                    if (_options.TcpPort.HasValue)
                    {
                        var listener = new TcpListener(address, _options.TcpPort.Value);
                        _tcpListeners.Add(listener);
                        DisableDualMode(listener.Server);
                        ConfigureReusableTcp(listener.Server);
                        listener.Start(_options.MaxConcurrentRequests);
                        _tcpEndpoints[address.AddressFamily] = CopyEndpoint((IPEndPoint)listener.LocalEndpoint);
                    }
                    if (_options.UdpPort.HasValue)
                    {
                        if (_udpChannels.ContainsKey(address.AddressFamily))
                        {
                            throw new InvalidOperationException("Bind must precede outbound UDP exchanges when a UDP listener is configured.");
                        }
                        _udpChannels[address.AddressFamily] = CreateUdpChannel(new IPEndPoint(address, _options.UdpPort.Value), true);
                    }
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
                if (!_tcpRunning)
                {
                    _tcpRunning = true;
                    foreach (var listener in _tcpListeners)
                    {
                        _tcpLoops.Add(AcceptAsync(listener));
                    }
                }
                _acceptUdpRequests = _bound && _options.UdpPort.HasValue;
                _udpRunning = true;
                foreach (var channel in _udpChannels.Values)
                {
                    StartUdpLoop(channel);
                }
            }
        }

        /// <summary>Creates and binds one UDP socket without accepting IPv4-mapped traffic on IPv6 sockets.</summary>
        /// <param name="endpoint">The local endpoint.</param>
        /// <param name="listening">Whether the socket is a configured listener.</param>
        /// <returns>The bound socket state.</returns>
        /// <exception cref="SocketException">The socket cannot bind.</exception>
        private static UdpChannel CreateUdpChannel(IPEndPoint endpoint, bool listening)
        {
            var client = new UdpClient(endpoint.AddressFamily);
            try
            {
                DisableDualMode(client.Client);
                client.Client.Bind(endpoint);
                return new UdpChannel(client, CopyEndpoint((IPEndPoint)client.Client.LocalEndPoint!), listening);
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        /// <summary>Keeps IPv6 sockets IPv6-only so that separate IPv4 and IPv6 listeners can share a port number.</summary>
        /// <param name="socket">The unbound socket.</param>
        private static void DisableDualMode(Socket socket)
        {
            if (socket.AddressFamily == AddressFamily.InterNetworkV6)
            {
                socket.DualMode = false;
            }
        }

        /// <summary>Starts a socket's receiver once loops are allowed and it is not already running.</summary>
        /// <param name="channel">The UDP socket state.</param>
        private void StartUdpLoop(UdpChannel channel)
        {
            if (_udpRunning && !channel.Running)
            {
                channel.Running = true;
                channel.Loop = ReceiveAsync(channel);
            }
        }

        /// <summary>Ensures ordinary outbound UDP works for an address family even when no UDP listener exists for it.</summary>
        /// <param name="family">The destination address family.</param>
        /// <returns>The listener or outbound-only socket for the family.</returns>
        /// <exception cref="SocketException">The outbound-only socket cannot bind.</exception>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        private UdpChannel EnsureUdpSocket(AddressFamily family)
        {
            lock (_lifecycleSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                if (!_udpChannels.TryGetValue(family, out var channel))
                {
                    var address = _options.ListenAddress(family)
                        ?? (family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any);
                    channel = CreateUdpChannel(new IPEndPoint(address, 0), false);
                    _udpChannels[family] = channel;
                    DHTLog.Write(_logger, LogLevel.Debug, "Created a shared outbound-only UDP socket; inbound UDP punching is unavailable.");
                }
                _udpRunning = true;
                StartUdpLoop(channel);
                return channel;
            }
        }

        /// <summary>Accepts persistent TCP sessions within the bounded cache.</summary>
        /// <param name="listener">The bound listener.</param>
        /// <returns>Completion when the listener closes.</returns>
        private async Task AcceptAsync(TcpListener listener)
        {
            try
            {
                while (!_shutdown.IsCancellationRequested)
                {
                    var client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
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
        /// <param name="channel">The receiving UDP socket.</param>
        /// <returns>Completion when the socket closes.</returns>
        private async Task ReceiveAsync(UdpChannel channel)
        {
            try
            {
                while (!_shutdown.IsCancellationRequested)
                {
                    UdpReceiveResult packet;
                    try
                    {
                        packet = await channel.Client.ReceiveAsync().ConfigureAwait(false);
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
                    if (!_acceptUdpRequests || !channel.Listening || (!IsUdpRequestFrame(packet.Buffer)) || !_slots.Wait(0))
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

        /// <summary>Sends a UDP frame through the bound socket of the destination's address family.</summary>
        /// <param name="packet">The complete transport frame.</param>
        /// <param name="destination">The pinned or observed endpoint.</param>
        /// <param name="cancellationToken">The exchange lifetime.</param>
        /// <returns>Completion after the datagram send.</returns>
        /// <exception cref="IOException">No socket exists for the destination address family.</exception>
        private async Task SendUdpAsync(ReadOnlyMemory<byte> packet, IPEndPoint destination, CancellationToken cancellationToken)
        {
            if (!_udpChannels.TryGetValue(destination.AddressFamily, out var channel))
            {
                throw new IOException("No UDP socket exists for the destination address family.");
            }
            await channel.Send.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                await channel.Client.Client.SendToAsync(Crypto.Array(packet), SocketFlags.None, destination).ConfigureAwait(false);
            }
            finally
            {
                channel.Send.Release();
            }
        }

        /// <summary>Exchanges directly through one protocol at an explicitly selected endpoint.</summary>
        /// <param name="transport">The single protocol to use.</param>
        /// <param name="endpoint">The exact pinned remote endpoint.</param>
        /// <param name="packet">The sealed request.</param>
        /// <param name="cancellationToken">Cancels queueing and exchange.</param>
        /// <param name="counter">An optional counter of transmissions and unanswered transmissions for packet-loss statistics.</param>
        /// <returns>The response; the caller must authenticate its sender and request identifier.</returns>
        /// <exception cref="IOException">The packet, endpoint or transport is invalid, or no response arrives.</exception>
        /// <exception cref="OperationCanceledException">The exchange or transport was cancelled.</exception>
        internal Task<ReadOnlyMemory<byte>> ExchangeAtAsync(DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> packet, CancellationToken cancellationToken, TransmissionCounter? counter = null)
        {
            return StartExchange(transport, endpoint, packet, cancellationToken, false, counter);
        }

        /// <summary>Retries direct punching within one request budget and retains a successful TCP session.</summary>
        /// <param name="transport">The protocol whose local listener port must be reused.</param>
        /// <param name="endpoint">The pinned remote endpoint observed by the rendezvous peer.</param>
        /// <param name="packet">The identical signed encrypted punch request on every retry.</param>
        /// <param name="cancellationToken">Cancels the complete punching attempt.</param>
        /// <returns>The encrypted response, requiring caller authentication and token correlation.</returns>
        /// <exception cref="IOException">A matching listener is unavailable or punching fails.</exception>
        /// <exception cref="OperationCanceledException">The exchange or transport was cancelled.</exception>
        internal Task<ReadOnlyMemory<byte>> PunchAsync(DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> packet, CancellationToken cancellationToken)
        {
            return StartExchange(transport, endpoint, packet, cancellationToken, true, null);
        }

        /// <summary>Registers outgoing work before shutdown can start draining it.</summary>
        /// <param name="transport">The selected protocol.</param>
        /// <param name="endpoint">The explicitly pinned endpoint.</param>
        /// <param name="packet">The immutable request for the lifetime of the task.</param>
        /// <param name="cancellationToken">The caller's cancellation.</param>
        /// <param name="punch">Whether a listener and a single short retry budget are required.</param>
        /// <param name="counter">An optional transmission counter; punching is never counted.</param>
        /// <returns>The tracked exchange task.</returns>
        /// <exception cref="OperationCanceledException">The transport has stopped.</exception>
        private Task<ReadOnlyMemory<byte>> StartExchange(DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> packet, CancellationToken cancellationToken, bool punch, TransmissionCounter? counter)
        {
            lock (_lifecycleSync)
            {
                _shutdownToken.ThrowIfCancellationRequested();
                var task = ExchangeCoreAsync(transport, CopyEndpoint(endpoint), packet, cancellationToken, punch, counter);
                Track(task, false);
                return task;
            }
        }

        /// <summary>Bounds outgoing state and applies the requested exchange or punching budget.</summary>
        /// <param name="transport">The selected protocol.</param>
        /// <param name="endpoint">The pinned endpoint snapshot.</param>
        /// <param name="packet">The immutable encrypted request.</param>
        /// <param name="cancellationToken">The caller's cancellation.</param>
        /// <param name="punch">Whether to require a reusable local listener.</param>
        /// <param name="counter">An optional transmission counter.</param>
        /// <returns>The opaque response.</returns>
        /// <exception cref="IOException">Validation, connection or response retrieval fails.</exception>
        /// <exception cref="OperationCanceledException">The caller, budget or transport was cancelled.</exception>
        private async Task<ReadOnlyMemory<byte>> ExchangeCoreAsync(DHTTransport transport,
            IPEndPoint endpoint, ReadOnlyMemory<byte> packet, CancellationToken cancellationToken, bool punch, TransmissionCounter? counter)
        {
            if (packet.Length == 0 || packet.Length > Wire.MaxPacket || endpoint.Port == 0
                || (transport != DHTTransport.Tcp && transport != DHTTransport.Udp))
            {
                throw new IOException("Invalid destination or invalid encrypted packet size.");
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
                    if (punch && (!_acceptUdpRequests || UdpPortFor(endpoint.AddressFamily) == 0))
                    {
                        throw new IOException("UDP punching requires an active UDP listener of the destination address family.");
                    }
                    EnsureUdpSocket(endpoint.AddressFamily);
                    return await ExchangeUdpAsync(endpoint, packet, lifetime.Token, punch, counter).ConfigureAwait(false);
                }
                if (punch && (!_tcpRunning || TcpPortFor(endpoint.AddressFamily) == 0))
                {
                    throw new IOException("TCP punching requires an active TCP listener of the destination address family.");
                }
                Exception? last = null;
                do
                {
                    try
                    {
                        var session = GetTcpSession(endpoint, punch ? s_punchInterval : _options.RequestTimeout);
                        var response = await session.ExchangeAsync(packet, lifetime.Token).ConfigureAwait(false);
                        counter?.Delivered();
                        return response;
                    }
                    catch (Exception exception) when (IsTransportFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        _shutdownToken.ThrowIfCancellationRequested();
                        counter?.Dropped();
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
        /// <param name="counter">An optional counter receiving one entry per completed attempt.</param>
        /// <returns>The correlated sealed response from the pinned endpoint.</returns>
        /// <exception cref="IOException">The pending entry conflicts or all retries expire.</exception>
        /// <exception cref="OperationCanceledException">The overall lifetime is cancelled.</exception>
        private async Task<ReadOnlyMemory<byte>> ExchangeUdpAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> packet,
            CancellationToken cancellationToken, bool punch, TransmissionCounter? counter)
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
                        var response = await AwaitCancellableAsync(pending.Response.Task, timeout.Token).ConfigureAwait(false);
                        counter?.Delivered();
                        return response;
                    }
                    catch (Exception exception) when (IsTransportFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        // A lost hello, challenge, request or response all leave this attempt unanswered.
                        counter?.Dropped();
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
                foreach (var listener in _tcpListeners)
                {
                    listener.Stop();
                }
                foreach (var channel in _udpChannels.Values)
                {
                    channel.Client.Dispose();
                }
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
            var loops = new List<Task>(_tcpLoops);
            foreach (var channel in _udpChannels.Values)
            {
                loops.Add(channel.Loop);
            }
            await Task.WhenAll(loops).ConfigureAwait(false);
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
            foreach (var channel in _udpChannels.Values)
            {
                channel.Send.Dispose();
            }
            _shutdown.Dispose();
        }

        /// <summary>Owns one bound UDP socket, its send serialization and its receive loop.</summary>
        private sealed class UdpChannel
        {
            /// <summary>Gets the owned bound socket.</summary>
            internal UdpClient Client { get; }
            /// <summary>Gets the immutable bound local endpoint.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets whether the socket is a configured listener rather than an outbound-only fallback.</summary>
            internal bool Listening { get; }
            /// <summary>Gets the serialization of sends on this socket.</summary>
            internal SemaphoreSlim Send { get; } = new SemaphoreSlim(1, 1);
            /// <summary>Gets or sets whether the receive loop has started.</summary>
            internal bool Running { get; set; }
            /// <summary>Gets or sets the receive loop task.</summary>
            internal Task Loop { get; set; } = Task.CompletedTask;

            /// <summary>Takes ownership of a bound socket.</summary>
            /// <param name="client">The bound socket.</param>
            /// <param name="endpoint">The bound local endpoint.</param>
            /// <param name="listening">Whether the socket accepts inbound requests.</param>
            internal UdpChannel(UdpClient client, IPEndPoint endpoint, bool listening)
            {
                Client = client;
                Endpoint = endpoint;
                Listening = listening;
            }
        }
    }
}
