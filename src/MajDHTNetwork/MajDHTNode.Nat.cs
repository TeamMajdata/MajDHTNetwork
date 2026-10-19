using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The immutable empty-poll arguments reused by every registration refresh.</summary>
        private static readonly byte[] s_natRegistration = new byte[] { 0 };
        /// <summary>The bounded observed registrations hosted by a relay.</summary>
        private readonly Dictionary<string, NatRegistration> _natRegistrations = new Dictionary<string, NatRegistration>();
        /// <summary>The bounded client registration loops owned by this node.</summary>
        private readonly Dictionary<string, NatRelay> _natRelays = new Dictionary<string, NatRelay>();
        /// <summary>The authenticated, short-lived introduction tickets.</summary>
        private readonly Dictionary<string, NatSession> _natSessions = new Dictionary<string, NatSession>();
        /// <summary>The recently authenticated direct endpoints indexed by peer and transport.</summary>
        private readonly Dictionary<(string, DHTTransport), NatRoute> _natRoutes = new Dictionary<(string, DHTTransport), NatRoute>();

        /// <summary>Registers the node's bound TCP and UDP endpoints with an authenticated relay and maintains their leases until shutdown.</summary>
        /// <param name="relay">A reachable signed contact advertising relay capability.</param>
        /// <param name="cancellationToken">Cancels initial registration; successful registrations subsequently follow the node lifetime.</param>
        /// <returns>Completion after at least one common transport has registered.</returns>
        /// <exception cref="ArgumentException">The contact cannot provide rendezvous assistance.</exception>
        /// <exception cref="InvalidOperationException">The node is not running or traversal is disabled.</exception>
        /// <exception cref="IOException">No common transport could register or the relay limit was reached.</exception>
        /// <exception cref="OperationCanceledException">Registration was cancelled.</exception>
        public async Task RegisterRelayAsync(DHTPeer relay, CancellationToken cancellationToken = default)
        {
            ValidateNatPeers(relay, null);
            using var cancellation = OperationCancellation(cancellationToken);
            if (!_options.EnableNatTraversal)
            {
                throw new InvalidOperationException("NAT traversal is disabled.");
            }
            lock (_gate)
            {
                if (_natRelays.TryGetValue(relay.NodeId, out var existing))
                {
                    if (relay.ExpiresAt >= existing.Peer.ExpiresAt)
                    {
                        existing.Peer = relay;
                    }
                    if (!existing.Work.IsCompleted)
                    {
                        return;
                    }
                    _natRelays.Remove(relay.NodeId);
                }
                if (_natRelays.Count >= _options.MaxNatRelays)
                {
                    throw new IOException("The rendezvous relay limit was reached.");
                }
            }
            var registrations = 0;
            foreach (var transport in new[] { _options.PreferredTransport, OtherTransport(_options.PreferredTransport) })
            {
                if (!SupportsNatTransport(relay, transport))
                {
                    continue;
                }
                try
                {
                    relay = await RegisterNatTransportAsync(relay, transport, cancellation.Token).ConfigureAwait(false);
                    registrations++;
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Rendezvous transport registration failed: ", exception);
                }
            }
            if (registrations == 0)
            {
                throw new IOException("No common transport registered with the relay.");
            }
            lock (_gate)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                if (_natRelays.ContainsKey(relay.NodeId))
                {
                    return;
                }
                if (_natRelays.Count >= _options.MaxNatRelays)
                {
                    throw new IOException("The rendezvous relay limit was reached.");
                }
                var registration = new NatRelay(relay);
                _natRelays.Add(relay.NodeId, registration);
                registration.Work = PollNatRelayAsync(registration);
            }
            Log(LogLevel.Information, "Rendezvous registration established.");
        }

        /// <summary>Asks a relay to introduce two registered peers, probes simultaneously, and retains an authenticated direct route.</summary>
        /// <param name="peer">The signed final peer, which must also have registered with the relay.</param>
        /// <param name="relay">The common authenticated rendezvous relay.</param>
        /// <param name="transport">The TCP or UDP transport to punch.</param>
        /// <param name="cancellationToken">Cancels negotiation and the local probe.</param>
        /// <returns>True when a direct probe or incoming peer probe was authenticated; otherwise false when negotiation or probing timed out.</returns>
        /// <exception cref="ArgumentException">The peer, relay or transport is invalid.</exception>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        /// <exception cref="OperationCanceledException">The caller or node lifetime was cancelled.</exception>
        public async Task<bool> TryPunchAsync(DHTPeer peer, DHTPeer relay, DHTTransport transport, CancellationToken cancellationToken = default)
        {
            if (peer == null)
            {
                throw new ArgumentNullException(nameof(peer));
            }
            ValidateNatPeers(relay, peer);
            if (transport != DHTTransport.Tcp && transport != DHTTransport.Udp)
            {
                throw new ArgumentException("A TCP or UDP transport is required.", nameof(transport));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            if (!_options.EnableNatTraversal || !SupportsNatTransport(peer, transport) || !SupportsNatTransport(relay, transport))
            {
                return false;
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            timeout.CancelAfter(_options.NatTraversalTimeout);
            try
            {
                await RegisterRelayAsync(relay, timeout.Token).ConfigureAwait(false);
                // Refresh this exact mapping before asking the relay to distribute it.
                await RegisterNatTransportAsync(relay, transport, timeout.Token).ConfigureAwait(false);
                using var body = new Wire();
                body.PutByte(1);
                body.PutText(peer.NodeId);
                var response = await RequestNatAsync(relay, transport, body.WrittenMemory, timeout.Token).ConfigureAwait(false);
                using var reader = new Wire(response.Body);
                var invitation = ReadNatInvitation(reader, transport);
                reader.End();
                if (invitation.Peer.NodeId != peer.NodeId)
                {
                    throw new InvalidDataException("The rendezvous target was substituted.");
                }
                var session = StartNatSession(invitation, timeout.Token);
                var succeeded = await session.Work.ConfigureAwait(false);
                cancellation.Token.ThrowIfCancellationRequested();
                return succeeded;
            }
            catch (OperationCanceledException)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                Log(LogLevel.Debug, "Direct NAT traversal timed out.");
                return false;
            }
            catch (Exception exception) when (IsPeerFailure(exception))
            {
                cancellation.Token.ThrowIfCancellationRequested();
                Log(LogLevel.Debug, "Direct NAT traversal failed: ", exception);
                return false;
            }
        }

        /// <summary>Validates identities before allocating rendezvous state.</summary>
        /// <param name="relay">The assisting peer.</param>
        /// <param name="peer">The optional final peer.</param>
        /// <exception cref="ArgumentException">A contact is absent, expired, local, or lacks relay capability.</exception>
        private void ValidateNatPeers(DHTPeer relay, DHTPeer? peer)
        {
            if (relay == null || relay.IsExpired || relay.NodeId == NodeId || (relay.Capabilities & DHTCapabilities.Relay) == 0)
            {
                throw new ArgumentException("An unexpired remote relay contact is required.", nameof(relay));
            }
            if (peer != null && (peer.IsExpired || peer.NodeId == NodeId || peer.NodeId == relay.NodeId))
            {
                throw new ArgumentException("An unexpired distinct remote peer is required.", nameof(peer));
            }
        }

        /// <summary>Checks whether both ends have a listener for a transport.</summary>
        /// <param name="peer">The remote contact.</param>
        /// <param name="transport">The transport to check.</param>
        /// <returns>Whether both endpoints support the transport.</returns>
        private bool SupportsNatTransport(DHTPeer peer, DHTTransport transport)
        {
            return transport == DHTTransport.Tcp
                ? _transport.TcpPort != 0 && peer.TcpPort != 0
                : _transport.UdpPort != 0 && peer.UdpPort != 0;
        }

        /// <summary>Gets the alternate wire transport.</summary>
        /// <param name="transport">The first transport.</param>
        /// <returns>The other transport.</returns>
        private static DHTTransport OtherTransport(DHTTransport transport)
        {
            return transport == DHTTransport.Tcp ? DHTTransport.Udp : DHTTransport.Tcp;
        }

        /// <summary>Performs a pinned, authenticated rendezvous RPC without relaying or recursive traversal.</summary>
        /// <param name="relay">The assisting relay.</param>
        /// <param name="transport">The mapping being observed.</param>
        /// <param name="body">The rendezvous operation arguments.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>The refreshed relay contact and decoded response body.</returns>
        private async Task<(DHTPeer Peer, ReadOnlyMemory<byte> Body)> RequestNatAsync(DHTPeer relay, DHTTransport transport,
            ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        {
            var packet = new Packet(LocalPeer, Crypto.Random(16), (byte)Operation.Rendezvous, body);
            var endpoint = new IPEndPoint(relay.NetworkAddress, transport == DHTTransport.Tcp ? relay.TcpPort : relay.UdpPort);
            var result = await _transport.ExchangeAtAsync(relay, transport, endpoint, packet.Seal(_identity, relay), cancellationToken).ConfigureAwait(false);
            var response = AuthenticateResponse(result, relay, packet);
            _routing.Observe(response.Sender);
            return (response.Sender, ReadResponseBody(response));
        }

        /// <summary>Refreshes an observed mapping and starts a queued peer introduction, if present.</summary>
        /// <param name="relay">The assisting relay.</param>
        /// <param name="transport">The mapping to register.</param>
        /// <param name="cancellationToken">The bounded registration lifetime.</param>
        /// <returns>The freshly authenticated relay contact.</returns>
        private async Task<DHTPeer> RegisterNatTransportAsync(DHTPeer relay, DHTTransport transport, CancellationToken cancellationToken)
        {
            var response = await RequestNatAsync(relay, transport, s_natRegistration, cancellationToken).ConfigureAwait(false);
            using var reader = new Wire(response.Body);
            ReadNatEndpoint(reader);
            var hasInvitation = reader.Byte();
            if (hasInvitation > 1)
            {
                throw new InvalidDataException("Invalid rendezvous poll response.");
            }
            NatInvitation? invitation = hasInvitation == 0 ? null : ReadNatInvitation(reader, transport);
            reader.End();
            if (invitation.HasValue)
            {
                StartNatSession(invitation.Value, _lifetime.Token);
            }
            return response.Peer;
        }

        /// <summary>Maintains bounded registration leases and polls queued introductions.</summary>
        /// <param name="registration">The relay and supported transports owned by this loop.</param>
        /// <returns>Completion after node shutdown.</returns>
        private async Task PollNatRelayAsync(NatRelay registration)
        {
            try
            {
                while (!_lifetime.IsCancellationRequested)
                {
                    await Task.Delay(_options.NatPollInterval, _lifetime.Token).ConfigureAwait(false);
                    for (var attempt = 0; attempt < 2; attempt++)
                    {
                        var transport = attempt == 0 ? _options.PreferredTransport : OtherTransport(_options.PreferredTransport);
                        DHTPeer peer;
                        lock (_gate)
                        {
                            peer = registration.Peer;
                        }
                        if (!SupportsNatTransport(peer, transport))
                        {
                            continue;
                        }
                        try
                        {
                            var refreshed = await RegisterNatTransportAsync(peer, transport, _lifetime.Token).ConfigureAwait(false);
                            lock (_gate)
                            {
                                if (refreshed.ExpiresAt >= registration.Peer.ExpiresAt)
                                {
                                    registration.Peer = refreshed;
                                }
                            }
                        }
                        catch (Exception exception) when (IsPeerFailure(exception))
                        {
                            _lifetime.Token.ThrowIfCancellationRequested();
                            Log(LogLevel.Debug, "Rendezvous lease refresh failed: ", exception);
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Log(LogLevel.Warning, "Rendezvous registration loop stopped: ", exception);
            }
        }

        /// <summary>Executes authenticated relay registration or introduction using the actual transport source.</summary>
        /// <param name="packet">The authenticated requester.</param>
        /// <param name="request">The operation arguments.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The socket's validated remote endpoint.</param>
        /// <returns>The observed mapping or peer introduction.</returns>
        /// <exception cref="IOException">Relaying is disabled, a mapping is absent, or a quota was reached.</exception>
        /// <exception cref="InvalidDataException">The request is invalid.</exception>
        private ReadOnlyMemory<byte> DispatchRendezvous(Packet packet, Wire request, DHTTransport transport, IPEndPoint source)
        {
            if ((_options.Capabilities & DHTCapabilities.Relay) == 0)
            {
                throw new IOException("Rendezvous assistance requires relay capability.");
            }
            var action = request.Byte();
            var targetId = action == 1 ? request.Text(64) : string.Empty;
            request.End();
            if (action > 1 || targetId == packet.Sender.NodeId)
            {
                throw new InvalidDataException("Invalid rendezvous action or target.");
            }
            using var response = new Wire();
            lock (_gate)
            {
                PruneNatState();
                var now = DateTimeOffset.UtcNow;
                var expiry = now + _options.NatRegistrationLifetime;
                if (expiry > packet.Sender.ExpiresAt)
                {
                    expiry = packet.Sender.ExpiresAt;
                }
                if (!_natRegistrations.TryGetValue(packet.Sender.NodeId, out var sender))
                {
                    if (action != 0 || _natRegistrations.Count >= _options.MaxNatRegistrations)
                    {
                        throw new IOException("Rendezvous registration is absent or the registry is full.");
                    }
                    sender = new NatRegistration(packet.Sender);
                    _natRegistrations.Add(packet.Sender.NodeId, sender);
                }
                sender.Peer = packet.Sender;
                sender.Bindings[transport] = new NatRoute(CopyEndpoint(source), expiry);
                if (action == 0)
                {
                    PutNatEndpoint(response, source);
                    var inbox = sender.Inbox(transport);
                    while (inbox.Count != 0 && inbox.Peek().ExpiresAt <= now)
                    {
                        inbox.Dequeue();
                    }
                    response.PutByte((byte)(inbox.Count == 0 ? 0 : 1));
                    if (inbox.Count != 0)
                    {
                        PutNatInvitation(response, inbox.Dequeue());
                    }
                }
                else
                {
                    Crypto.ParseHash(targetId);
                    if (!_natRegistrations.TryGetValue(targetId, out var target)
                        || !target.Bindings.TryGetValue(transport, out var binding) || binding.ExpiresAt <= now)
                    {
                        throw new IOException("The target has no live registration for this transport.");
                    }
                    var inbox = target.Inbox(transport);
                    while (inbox.Count != 0 && inbox.Peek().ExpiresAt <= now)
                    {
                        inbox.Dequeue();
                    }
                    if (inbox.Count >= _options.MaxConcurrentRequests)
                    {
                        throw new IOException("The target introduction queue is full.");
                    }
                    var token = Crypto.Random(16);
                    var ticketExpiry = now + _options.NatTraversalTimeout;
                    if (ticketExpiry > expiry)
                    {
                        ticketExpiry = expiry;
                    }
                    if (ticketExpiry > binding.ExpiresAt)
                    {
                        ticketExpiry = binding.ExpiresAt;
                    }
                    inbox.Enqueue(new NatInvitation(packet.Sender, transport, CopyEndpoint(source), token, ticketExpiry));
                    PutNatInvitation(response, new NatInvitation(target.Peer, transport, binding.Endpoint, token, ticketExpiry));
                }
            }
            return response.ToArray();
        }

        /// <summary>Validates an introduced peer's probe and records its direct source endpoint.</summary>
        /// <param name="packet">The authenticated direct probe.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The socket's observed remote endpoint.</param>
        /// <returns>An empty successful response body.</returns>
        /// <exception cref="InvalidDataException">The ticket, identity, transport or source endpoint does not match.</exception>
        private ReadOnlyMemory<byte> DispatchPunch(Packet packet, DHTTransport transport, IPEndPoint source)
        {
            if (packet.Body.Length != 16)
            {
                throw new InvalidDataException("A direct probe requires a 128-bit introduction ticket.");
            }
            lock (_gate)
            {
                if (!_natSessions.TryGetValue(Crypto.Hex(packet.Body.Span), out var session)
                    || session.Invitation.ExpiresAt <= DateTimeOffset.UtcNow || session.Invitation.Peer.NodeId != packet.Sender.NodeId
                    || session.Invitation.Transport != transport || !session.Invitation.Endpoint.Equals(source))
                {
                    throw new InvalidDataException("The direct probe does not match an active introduction.");
                }
                RememberNatRoute(packet.Sender, transport, source);
                session.Success.TrySetResult(true);
            }
            return Array.Empty<byte>();
        }

        /// <summary>Starts or coalesces a bounded introduction while retaining its work for shutdown.</summary>
        /// <param name="invitation">The authenticated relay ticket.</param>
        /// <param name="cancellationToken">The initiating caller or node lifetime.</param>
        /// <returns>The shared probe state.</returns>
        /// <exception cref="IOException">The local introduction limit was reached.</exception>
        private NatSession StartNatSession(NatInvitation invitation, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                _lifetime.Token.ThrowIfCancellationRequested();
                PruneNatState();
                var id = Crypto.Hex(invitation.Token.Span);
                if (_natSessions.TryGetValue(id, out var existing))
                {
                    if (existing.Invitation.Peer.NodeId != invitation.Peer.NodeId || existing.Invitation.Transport != invitation.Transport
                        || !existing.Invitation.Endpoint.Equals(invitation.Endpoint))
                    {
                        throw new InvalidDataException("An introduction ticket was reused for another peer or endpoint.");
                    }
                    return existing;
                }
                if (_natSessions.Count >= _options.MaxConcurrentRequests * 4)
                {
                    throw new IOException("The direct introduction limit was reached.");
                }
                var session = new NatSession(invitation);
                _natSessions.Add(id, session);
                session.Work = RunNatSessionAsync(session, cancellationToken);
                return session;
            }
        }

        /// <summary>Sends authenticated probes while the other peer opens its matching mapping.</summary>
        /// <param name="session">The active ticket and completion signal.</param>
        /// <param name="cancellationToken">The initiating operation lifetime.</param>
        /// <returns>Whether either direction authenticated the introduced path.</returns>
        private async Task<bool> RunNatSessionAsync(NatSession session, CancellationToken cancellationToken)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            var remaining = session.Invitation.ExpiresAt - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                return false;
            }
            timeout.CancelAfter(remaining < _options.NatTraversalTimeout ? remaining : _options.NatTraversalTimeout);
            try
            {
                while (!timeout.IsCancellationRequested)
                {
                    var invitation = session.Invitation;
                    var request = new Packet(LocalPeer, Crypto.Random(16), (byte)Operation.Punch, invitation.Token);
                    try
                    {
                        var encoded = await _transport.PunchAsync(invitation.Peer, invitation.Transport, invitation.Endpoint,
                            request.Seal(_identity, invitation.Peer), timeout.Token).ConfigureAwait(false);
                        ReadResponseBody(AuthenticateResponse(encoded, invitation.Peer, request));
                        lock (_gate)
                        {
                            RememberNatRoute(invitation.Peer, invitation.Transport, invitation.Endpoint);
                            session.Success.TrySetResult(true);
                        }
                        Log(LogLevel.Information, "Authenticated direct NAT path established.");
                        return true;
                    }
                    catch (Exception exception) when (IsPeerFailure(exception))
                    {
                        timeout.Token.ThrowIfCancellationRequested();
                        // A ticket can arrive at the other peer slightly later; a retry needs a fresh replay identifier.
                        if (session.Success.Task.IsCompletedSuccessfully)
                        {
                            return true;
                        }
                        await Task.Delay(50, timeout.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Log(LogLevel.Warning, "Direct NAT probe stopped: ", exception);
            }
            return session.Success.Task.IsCompletedSuccessfully;
        }

        /// <summary>Records an authenticated route while bounding cache retention.</summary>
        /// <param name="peer">The authenticated final peer.</param>
        /// <param name="transport">The transport that reached it.</param>
        /// <param name="endpoint">Its verified socket endpoint.</param>
        private void RememberNatRoute(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint)
        {
            var key = (peer.NodeId, transport);
            if (!_natRoutes.ContainsKey(key) && _natRoutes.Count >= _options.MaxNatRegistrations)
            {
                (string, DHTTransport)? oldest = null;
                var expiry = DateTimeOffset.MaxValue;
                foreach (var entry in _natRoutes)
                {
                    if (entry.Value.ExpiresAt < expiry)
                    {
                        oldest = entry.Key;
                        expiry = entry.Value.ExpiresAt;
                    }
                }
                if (oldest.HasValue)
                {
                    _natRoutes.Remove(oldest.Value);
                }
            }
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
            _natRoutes[key] = new NatRoute(CopyEndpoint(endpoint), expiresAt < peer.ExpiresAt ? expiresAt : peer.ExpiresAt);
        }

        /// <summary>Uses an authenticated punched route or relay registration before trying advertised endpoints.</summary>
        /// <param name="peer">The final peer.</param>
        /// <param name="envelope">The sealed request.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>The encrypted direct response.</returns>
        private async Task<ReadOnlyMemory<byte>> ExchangeDirectAsync(DHTPeer peer, ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var transport = attempt == 0 ? _options.PreferredTransport : OtherTransport(_options.PreferredTransport);
                NatRoute route;
                var key = (peer.NodeId, transport);
                lock (_gate)
                {
                    if (!_natRoutes.TryGetValue(key, out route) || route.ExpiresAt <= DateTimeOffset.UtcNow)
                    {
                        _natRoutes.Remove(key);
                        if (!_natRegistrations.TryGetValue(peer.NodeId, out var registration) || registration.Peer.IsExpired
                            || !registration.Bindings.TryGetValue(transport, out route) || route.ExpiresAt <= DateTimeOffset.UtcNow)
                        {
                            continue;
                        }
                    }
                }
                try
                {
                    return await _transport.ExchangeAtAsync(peer, transport, route.Endpoint, envelope, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    lock (_gate)
                    {
                        if (_natRoutes.TryGetValue(key, out var current) && current.Endpoint.Equals(route.Endpoint))
                        {
                            _natRoutes.Remove(key);
                        }
                    }
                    Log(LogLevel.Debug, "Previously introduced direct route failed: ", exception);
                }
            }
            return await _transport.ExchangeAsync(peer, envelope, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Reclaims expired relay bindings, introduction tickets and direct routes under the state lock.</summary>
        private void PruneNatState()
        {
            var now = DateTimeOffset.UtcNow;
            var removed = new List<string>();
            foreach (var entry in _natRegistrations)
            {
                for (var index = 0; index < 2; index++)
                {
                    var transport = index == 0 ? DHTTransport.Tcp : DHTTransport.Udp;
                    if (entry.Value.Bindings.TryGetValue(transport, out var binding) && binding.ExpiresAt <= now)
                    {
                        entry.Value.Bindings.Remove(transport);
                    }
                }
                if (entry.Value.Peer.IsExpired || entry.Value.Bindings.Count == 0)
                {
                    removed.Add(entry.Key);
                }
            }
            foreach (var id in removed)
            {
                _natRegistrations.Remove(id);
            }
            removed.Clear();
            foreach (var entry in _natSessions)
            {
                if (entry.Value.Invitation.ExpiresAt <= now && entry.Value.Work.IsCompleted)
                {
                    removed.Add(entry.Key);
                }
            }
            foreach (var id in removed)
            {
                _natSessions.Remove(id);
            }
            var routes = new List<(string, DHTTransport)>();
            foreach (var entry in _natRoutes)
            {
                if (entry.Value.ExpiresAt <= now)
                {
                    routes.Add(entry.Key);
                }
            }
            foreach (var key in routes)
            {
                _natRoutes.Remove(key);
            }
        }

        /// <summary>Waits for every retained rendezvous loop and probe after lifetime cancellation.</summary>
        /// <returns>Completion after all background traversal work has drained.</returns>
        private Task DrainNatAsync()
        {
            lock (_gate)
            {
                var work = new List<Task>(_natRelays.Count + _natSessions.Count);
                foreach (var relay in _natRelays.Values)
                {
                    work.Add(relay.Work);
                }
                foreach (var session in _natSessions.Values)
                {
                    work.Add(session.Work);
                }
                return Task.WhenAll(work);
            }
        }

        /// <summary>Copies a mutable socket endpoint before retaining it.</summary>
        /// <param name="endpoint">The socket-owned endpoint.</param>
        /// <returns>An independent endpoint and address.</returns>
        private static IPEndPoint CopyEndpoint(IPEndPoint endpoint)
        {
            return new IPEndPoint(IPAddress.Parse(endpoint.Address.ToString()), endpoint.Port);
        }

        /// <summary>Encodes a relay-observed endpoint.</summary>
        /// <param name="writer">The operation encoder.</param>
        /// <param name="endpoint">The validated endpoint.</param>
        private static void PutNatEndpoint(Wire writer, IPEndPoint endpoint)
        {
            writer.PutText(endpoint.Address.ToString());
            writer.PutLong(endpoint.Port);
        }

        /// <summary>Decodes a bounded canonical unicast endpoint.</summary>
        /// <param name="reader">The operation decoder.</param>
        /// <returns>The observed endpoint.</returns>
        /// <exception cref="InvalidDataException">The address or port is invalid.</exception>
        private static IPEndPoint ReadNatEndpoint(Wire reader)
        {
            var text = reader.Text(96);
            var port = reader.Long();
            if (!IPAddress.TryParse(text, out var address) || address.ToString() != text || address.IsIPv6Multicast
                || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.None)
                || address.Equals(IPAddress.Broadcast) || port < 1 || port > 65535)
            {
                throw new InvalidDataException("Invalid rendezvous endpoint.");
            }
            return new IPEndPoint(address, (int)port);
        }

        /// <summary>Encodes a short-lived introduction shared by exactly two peer identities.</summary>
        /// <param name="writer">The operation encoder.</param>
        /// <param name="invitation">The bounded ticket.</param>
        private static void PutNatInvitation(Wire writer, NatInvitation invitation)
        {
            writer.Put(invitation.Peer.Encoded);
            PutNatEndpoint(writer, invitation.Endpoint);
            writer.Put(invitation.Token.Span);
            writer.PutLong(invitation.ExpiresAt.ToUnixTimeMilliseconds());
        }

        /// <summary>Decodes and validates an introduction from an authenticated relay.</summary>
        /// <param name="reader">The operation decoder.</param>
        /// <param name="transport">The transport observed by this registration.</param>
        /// <returns>An owned ticket and verified peer contact.</returns>
        /// <exception cref="InvalidDataException">The ticket is expired, malformed, local, or uses another address family.</exception>
        private NatInvitation ReadNatInvitation(Wire reader, DHTTransport transport)
        {
            var peer = new DHTPeer(reader.Bytes(2048));
            var endpoint = ReadNatEndpoint(reader);
            var token = reader.Bytes(16);
            var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.Long());
            if (token.Length != 16 || peer.NodeId == NodeId || endpoint.AddressFamily != _options.ListenAddress.AddressFamily
                || expiresAt <= DateTimeOffset.UtcNow || expiresAt > DateTimeOffset.UtcNow.AddMinutes(2)
                || expiresAt > peer.ExpiresAt || !SupportsNatTransport(peer, transport))
            {
                throw new InvalidDataException("Invalid or expired rendezvous introduction.");
            }
            return new NatInvitation(peer, transport, endpoint, token.ToArray(), expiresAt);
        }

        /// <summary>Owns a relay's mutable registration lease and bounded transport inboxes.</summary>
        private sealed class NatRegistration
        {
            /// <summary>Gets or sets the latest signed registrant contact.</summary>
            internal DHTPeer Peer { get; set; }
            /// <summary>Gets the at most two independently observed transport bindings.</summary>
            internal Dictionary<DHTTransport, NatRoute> Bindings { get; } = new Dictionary<DHTTransport, NatRoute>();
            /// <summary>The pending TCP introductions.</summary>
            private readonly Queue<NatInvitation> _tcp = new Queue<NatInvitation>();
            /// <summary>The pending UDP introductions.</summary>
            private readonly Queue<NatInvitation> _udp = new Queue<NatInvitation>();

            /// <summary>Creates a registrant with no unverified endpoints.</summary>
            /// <param name="peer">The authenticated contact.</param>
            internal NatRegistration(DHTPeer peer)
            {
                Peer = peer;
            }

            /// <summary>Gets the bounded inbox for one transport.</summary>
            /// <param name="transport">The transport whose inbox is needed.</param>
            /// <returns>The corresponding introduction queue.</returns>
            internal Queue<NatInvitation> Inbox(DHTTransport transport)
            {
                return transport == DHTTransport.Tcp ? _tcp : _udp;
            }
        }

        /// <summary>Owns a client's ongoing registration with one assisting relay.</summary>
        private sealed class NatRelay
        {
            /// <summary>Gets or sets the latest authenticated relay contact.</summary>
            internal DHTPeer Peer { get; set; }
            /// <summary>Gets or sets the observed background polling task.</summary>
            internal Task Work { get; set; } = Task.CompletedTask;

            /// <summary>Creates the lifetime-owned registration state.</summary>
            /// <param name="peer">The authenticated assisting relay.</param>
            internal NatRelay(DHTPeer peer)
            {
                Peer = peer;
            }
        }

        /// <summary>Owns one cancellable probe and its incoming success signal.</summary>
        private sealed class NatSession
        {
            /// <summary>Gets the authenticated relay introduction.</summary>
            internal NatInvitation Invitation { get; }
            /// <summary>Gets the signal set only by an authenticated matching direct probe.</summary>
            internal TaskCompletionSource<bool> Success { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            /// <summary>Gets or sets the retained probe task.</summary>
            internal Task<bool> Work { get; set; } = Task.FromResult(false);

            /// <summary>Creates a pending direct probe.</summary>
            /// <param name="invitation">The authenticated relay ticket.</param>
            internal NatSession(NatInvitation invitation)
            {
                Invitation = invitation;
            }
        }

        /// <summary>Stores a bounded observed endpoint without an additional object allocation.</summary>
        private readonly struct NatRoute
        {
            /// <summary>Gets the privately owned observed endpoint.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the endpoint lease expiry.</summary>
            internal DateTimeOffset ExpiresAt { get; }

            /// <summary>Associates an endpoint with its retention deadline.</summary>
            /// <param name="endpoint">The privately owned endpoint.</param>
            /// <param name="expiresAt">The retention deadline.</param>
            internal NatRoute(IPEndPoint endpoint, DateTimeOffset expiresAt)
            {
                Endpoint = endpoint;
                ExpiresAt = expiresAt;
            }
        }

        /// <summary>Stores an immutable introduction while retaining its owned contact and token memory.</summary>
        private readonly struct NatInvitation
        {
            /// <summary>Gets the verified final peer.</summary>
            internal DHTPeer Peer { get; }
            /// <summary>Gets the transport to punch.</summary>
            internal DHTTransport Transport { get; }
            /// <summary>Gets the privately owned relay-observed endpoint.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the shared random 128-bit ticket.</summary>
            internal ReadOnlyMemory<byte> Token { get; }
            /// <summary>Gets the ticket's absolute expiry.</summary>
            internal DateTimeOffset ExpiresAt { get; }

            /// <summary>Creates an introduction from authenticated relay data.</summary>
            /// <param name="peer">The verified final peer.</param>
            /// <param name="transport">The transport to punch.</param>
            /// <param name="endpoint">The relay-observed endpoint.</param>
            /// <param name="token">The owned random ticket.</param>
            /// <param name="expiresAt">The absolute ticket expiry.</param>
            internal NatInvitation(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint, ReadOnlyMemory<byte> token, DateTimeOffset expiresAt)
            {
                Peer = peer;
                Transport = transport;
                Endpoint = endpoint;
                Token = token;
                ExpiresAt = expiresAt;
            }
        }
    }
}
