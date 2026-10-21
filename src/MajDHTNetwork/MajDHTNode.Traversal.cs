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
        private static readonly byte[] s_traversalRegistration = new byte[] { (byte)TraversalAction.Register };
        /// <summary>The bounded registrations hosted by this Traversal node, keyed by registrant identifier.</summary>
        private readonly Dictionary<string, HostedRegistration> _traversalRegistrations = new Dictionary<string, HostedRegistration>();
        /// <summary>The Traversal nodes this node stays registered with, keyed by their identifier.</summary>
        private readonly Dictionary<string, AssistantSession> _traversalNodes = new Dictionary<string, AssistantSession>();
        /// <summary>The authenticated, short-lived introduction tickets.</summary>
        private readonly Dictionary<string, PunchSession> _punchSessions = new Dictionary<string, PunchSession>();
        /// <summary>The recently authenticated direct endpoints indexed by peer and transport.</summary>
        private readonly Dictionary<(string, DHTTransport), ObservedRoute> _directRoutes = new Dictionary<(string, DHTTransport), ObservedRoute>();

        /// <summary>Registers the node's bound TCP and UDP endpoints with a Traversal node and maintains the leases until shutdown.</summary>
        /// <param name="traversal">A Traversal node at the endpoints observed for it.</param>
        /// <param name="cancellationToken">Cancels initial registration; successful registrations subsequently follow the node lifetime.</param>
        /// <returns>Completion after at least one common transport has registered.</returns>
        /// <exception cref="ArgumentException">The peer cannot coordinate traversal or has no observed endpoint.</exception>
        /// <exception cref="InvalidOperationException">The node is not running or traversal is disabled.</exception>
        /// <exception cref="IOException">No common transport could register or the Traversal node limit was reached.</exception>
        /// <exception cref="OperationCanceledException">Registration was cancelled.</exception>
        public async Task RegisterTraversalAsync(DHTPeer traversal, CancellationToken cancellationToken = default)
        {
            ValidateAssistant(traversal, DHTCapabilities.Traversal);
            using var cancellation = OperationCancellation(cancellationToken);
            if (!_options.EnableNatTraversal)
            {
                throw new InvalidOperationException("NAT traversal is disabled.");
            }
            if (!ReserveAssistantSessionLocked(_traversalNodes, traversal, _options.MaxTraversalNodes))
            {
                return;
            }
            var registrations = 0;
            foreach (var transport in new[] { _options.PreferredTransport, OtherTransport(_options.PreferredTransport) })
            {
                if (!SupportsAssistantTransport(traversal, transport))
                {
                    continue;
                }
                try
                {
                    traversal = await RegisterTraversalTransportAsync(traversal, transport, cancellation.Token).ConfigureAwait(false);
                    registrations++;
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Traversal transport registration failed: ", exception);
                }
            }
            if (registrations == 0)
            {
                throw new IOException("No common transport registered with the Traversal node.");
            }
            lock (_gate)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                if (_traversalNodes.ContainsKey(traversal.NodeId))
                {
                    return;
                }
                if (_traversalNodes.Count >= _options.MaxTraversalNodes)
                {
                    throw new IOException("The Traversal node limit was reached.");
                }
                var session = new AssistantSession(traversal);
                _traversalNodes.Add(traversal.NodeId, session);
                session.Work = PollTraversalNodeAsync(session);
                RefreshLocalContactLocked();
            }
            Log(LogLevel.Information, "Traversal registration established.");
            TriggerReachabilityCheck();
        }

        /// <summary>Asks a Traversal node to introduce two registered peers, probes simultaneously, and retains an authenticated direct route.</summary>
        /// <param name="peer">The final peer, which must also have registered with the Traversal node.</param>
        /// <param name="traversal">The common Traversal node.</param>
        /// <param name="transport">The TCP or UDP transport to punch.</param>
        /// <param name="cancellationToken">Cancels negotiation and the local probe.</param>
        /// <returns>True when a direct probe or incoming peer probe was authenticated; otherwise false when negotiation or probing timed out.</returns>
        /// <exception cref="ArgumentException">The peer, Traversal node or transport is invalid.</exception>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        /// <exception cref="OperationCanceledException">The caller or node lifetime was cancelled.</exception>
        public async Task<bool> TryPunchAsync(DHTPeer peer, DHTPeer traversal, DHTTransport transport, CancellationToken cancellationToken = default)
        {
            if (peer == null)
            {
                throw new ArgumentNullException(nameof(peer));
            }
            ValidateAssistant(traversal, DHTCapabilities.Traversal);
            if (peer.IsExpired || peer.NodeId == NodeId || peer.NodeId == traversal.NodeId)
            {
                throw new ArgumentException("An unexpired distinct remote peer is required.", nameof(peer));
            }
            if (transport != DHTTransport.Tcp && transport != DHTTransport.Udp)
            {
                throw new ArgumentException("A TCP or UDP transport is required.", nameof(transport));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            if (!_options.EnableNatTraversal || !MaySupportTransport(peer, transport) || !SupportsAssistantTransport(traversal, transport))
            {
                return false;
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token);
            timeout.CancelAfter(_options.NatTraversalTimeout);
            try
            {
                await RegisterTraversalAsync(traversal, timeout.Token).ConfigureAwait(false);
                // Refresh this exact mapping before asking the Traversal node to distribute it.
                await RegisterTraversalTransportAsync(traversal, transport, timeout.Token).ConfigureAwait(false);
                using var body = new Wire();
                TraversalMessage.WriteIntroduceRequest(body, peer.NodeId);
                var response = await RequestAssistantAsync(traversal, Operation.Traversal, transport, body.WrittenMemory, timeout.Token).ConfigureAwait(false);
                using var introduction = response.Body;
                using var reader = new Wire(introduction.Bytes);
                var invitation = ToPunchInvitation(TraversalMessage.ReadIntroduceResponse(reader), transport);
                if (invitation.Peer.NodeId != peer.NodeId)
                {
                    throw new InvalidDataException("The traversal target was substituted.");
                }
                var session = StartPunchSession(invitation, timeout.Token);
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

        /// <summary>Validates a Traversal node or Forwarder before this node asks it for assistance.</summary>
        /// <param name="assistant">The assisting peer.</param>
        /// <param name="capability">The capability the assistant must advertise.</param>
        /// <exception cref="ArgumentException">The peer is absent, expired, local, lacks the capability or has no observed endpoint.</exception>
        private void ValidateAssistant(DHTPeer assistant, DHTCapabilities capability)
        {
            if (assistant == null || assistant.IsExpired || assistant.NodeId == NodeId || (assistant.Capabilities & capability) == 0
                || assistant.Endpoints.Count == 0)
            {
                throw new ArgumentException("An unexpired remote " + capability + " node with an observed endpoint is required.", nameof(assistant));
            }
        }

        /// <summary>
        /// Checks whether a session with an assistant must be opened: an existing live session only takes the newer contact, while
        /// a finished one is discarded and the registry must have room for a new one.
        /// </summary>
        /// <param name="sessions">The sessions of one assistant role.</param>
        /// <param name="assistant">The assisting peer.</param>
        /// <param name="limit">The maximum sessions of that role.</param>
        /// <returns>Whether the caller should open a new session.</returns>
        /// <exception cref="IOException">The registry is full.</exception>
        private bool ReserveAssistantSessionLocked(Dictionary<string, AssistantSession> sessions, DHTPeer assistant, int limit)
        {
            lock (_gate)
            {
                if (sessions.TryGetValue(assistant.NodeId, out var existing))
                {
                    if (assistant.Sequence >= existing.Peer.Sequence)
                    {
                        existing.Peer = assistant;
                    }
                    if (!existing.Work.IsCompleted)
                    {
                        return false;
                    }
                    sessions.Remove(assistant.NodeId);
                }
                if (sessions.Count >= limit)
                {
                    throw new IOException("The assistant session limit was reached.");
                }
                return true;
            }
        }

        /// <summary>Checks whether an assistant was observed at an endpoint that a local listener of the same family can reach.</summary>
        /// <param name="assistant">The assisting peer.</param>
        /// <param name="transport">The transport to check.</param>
        /// <returns>Whether both ends support the transport in a common address family.</returns>
        private bool SupportsAssistantTransport(DHTPeer assistant, DHTTransport transport)
        {
            return AssistantEndpoint(assistant, transport) != null;
        }

        /// <summary>Selects an assistant's observed endpoint whose address family has a local listener for the transport.</summary>
        /// <param name="assistant">The assisting peer.</param>
        /// <param name="transport">The transport to use.</param>
        /// <returns>The remote endpoint, or null when no common address family exists.</returns>
        private IPEndPoint? AssistantEndpoint(DHTPeer assistant, DHTTransport transport)
        {
            for (var index = assistant.Endpoints.Count - 1; index >= 0; index--)
            {
                var endpoint = assistant.Endpoints[index];
                var port = endpoint.Port(transport);
                if (port != 0 && _transport.PortFor(transport, endpoint.NetworkAddress.AddressFamily) != 0)
                {
                    return new IPEndPoint(endpoint.NetworkAddress, port);
                }
            }
            return null;
        }

        /// <summary>Checks whether this node listens on a transport in any address family.</summary>
        /// <param name="transport">The transport.</param>
        /// <returns>Whether a listener exists.</returns>
        private bool HasListener(DHTTransport transport)
        {
            foreach (var address in _options.ListenAddresses)
            {
                if (_transport.PortFor(transport, address.AddressFamily) != 0)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Checks whether a punch target may listen on a transport; a peer without observed endpoints leaves the decision to the Traversal node.</summary>
        /// <param name="peer">The punch target.</param>
        /// <param name="transport">The transport to check.</param>
        /// <returns>Whether this node listens on the transport and the target does not rule it out.</returns>
        private bool MaySupportTransport(DHTPeer peer, DHTTransport transport)
        {
            if (!HasListener(transport))
            {
                return false;
            }
            if (peer.Endpoints.Count == 0)
            {
                return true;
            }
            foreach (var endpoint in peer.Endpoints)
            {
                if (endpoint.Port(transport) != 0)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Gets the alternate wire transport.</summary>
        /// <param name="transport">The first transport.</param>
        /// <returns>The other transport.</returns>
        private static DHTTransport OtherTransport(DHTTransport transport)
        {
            return transport == DHTTransport.Tcp ? DHTTransport.Udp : DHTTransport.Tcp;
        }

        /// <summary>Performs a pinned, authenticated RPC to an assistant without forwarding or recursive traversal.</summary>
        /// <param name="assistant">The Traversal node or Forwarder.</param>
        /// <param name="operation">The Traversal or Forward operation.</param>
        /// <param name="transport">The mapping being observed.</param>
        /// <param name="body">The operation arguments.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>
        /// The refreshed assistant contact, the decoded response body, which the caller releases by disposing it, and the assistant
        /// endpoint that was used.
        /// </returns>
        /// <exception cref="IOException">No common address family exists or the assistant rejected the request.</exception>
        private async Task<(DHTContact Peer, OwnedMemory Body, IPEndPoint Endpoint)> RequestAssistantAsync(DHTPeer assistant, Operation operation,
            DHTTransport transport, ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
        {
            if (assistant.IsExpired)
            {
                throw new IOException("The assistant contact has expired.");
            }
            var endpoint = AssistantEndpoint(assistant, transport) ?? throw new IOException("The assistant has no endpoint in a listened address family.");
            var packet = new Packet(LocalContact, Crypto.Random(16), (byte)operation, body);
            var result = await ExchangeCountedAsync(assistant, transport, endpoint, packet.Seal(_identity, assistant.Contact), cancellationToken).ConfigureAwait(false);
            var response = AuthenticateResponse(result, assistant.Contact, packet);
            try
            {
                ObservePeer(response.Packet.Sender, DHTEndpoint.Observed(transport, endpoint));
            }
            catch
            {
                response.Dispose();
                throw;
            }
            return (response.Packet.Sender, TakeResponseBody(response), endpoint);
        }

        /// <summary>Refreshes an observed mapping, records it for the external-address vote and starts a queued introduction.</summary>
        /// <param name="traversal">The Traversal node.</param>
        /// <param name="transport">The mapping to register.</param>
        /// <param name="cancellationToken">The bounded registration lifetime.</param>
        /// <returns>The Traversal node with its freshly authenticated contact.</returns>
        private async Task<DHTPeer> RegisterTraversalTransportAsync(DHTPeer traversal, DHTTransport transport, CancellationToken cancellationToken)
        {
            var response = await RequestAssistantAsync(traversal, Operation.Traversal, transport, s_traversalRegistration, cancellationToken).ConfigureAwait(false);
            using var body = response.Body;
            using var reader = new Wire(body.Bytes);
            var poll = TraversalMessage.ReadPollResponse(reader);
            RecordObservation(response.Peer, response.Endpoint.Address, transport, poll.Observed);
            PunchInvitation? invitation = poll.Introduction.HasValue ? ToPunchInvitation(poll.Introduction.Value, transport) : null;
            if (invitation.HasValue)
            {
                StartPunchSession(invitation.Value, _lifetime.Token);
            }
            return traversal.WithContact(response.Peer);
        }

        /// <summary>Maintains bounded registration leases and polls queued introductions.</summary>
        /// <param name="session">The Traversal node and supported transports owned by this loop.</param>
        /// <returns>Completion after node shutdown.</returns>
        private Task PollTraversalNodeAsync(AssistantSession session)
        {
            return MaintainAssistantSessionAsync(session, "Traversal lease refresh failed: ", RegisterTraversalTransportAsync);
        }

        /// <summary>Refreshes a session with an assistant on every poll interval and tracks whether its lease is live.</summary>
        /// <param name="session">The session owned by this loop.</param>
        /// <param name="failureMessage">The log context of a failed refresh.</param>
        /// <param name="refresh">Refreshes the session over one transport and returns the assistant with its fresh contact.</param>
        /// <returns>Completion after node shutdown.</returns>
        private async Task MaintainAssistantSessionAsync(AssistantSession session, string failureMessage,
            Func<DHTPeer, DHTTransport, CancellationToken, Task<DHTPeer>> refresh)
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
                            peer = session.Peer;
                        }
                        if (!SupportsAssistantTransport(peer, transport))
                        {
                            continue;
                        }
                        try
                        {
                            var refreshed = await refresh(peer, transport, _lifetime.Token).ConfigureAwait(false);
                            lock (_gate)
                            {
                                if (refreshed.Sequence >= session.Peer.Sequence)
                                {
                                    session.Peer = refreshed;
                                }
                                session.LastSuccess = DateTimeOffset.UtcNow;
                            }
                        }
                        catch (Exception exception) when (IsPeerFailure(exception))
                        {
                            _lifetime.Token.ThrowIfCancellationRequested();
                            Log(LogLevel.Debug, failureMessage, exception);
                        }
                    }
                    lock (_gate)
                    {
                        // A lapsed or restored session adds or removes this assistant from the local contact's hints.
                        var live = session.LastSuccess + _options.NatRegistrationLifetime > DateTimeOffset.UtcNow;
                        if (live != session.Live)
                        {
                            session.Live = live;
                            RefreshLocalContactLocked();
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Log(LogLevel.Warning, "Assistant session loop stopped: ", exception);
            }
        }

        /// <summary>Executes an authenticated traversal action using the actual transport source.</summary>
        /// <param name="packet">The authenticated requester.</param>
        /// <param name="request">The operation arguments.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The socket's validated remote endpoint.</param>
        /// <param name="response">The encoder receiving the action result.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>Completion after the action result was written.</returns>
        /// <exception cref="IOException">This node is not a Traversal node, a mapping or helper is absent, or a quota was reached.</exception>
        /// <exception cref="InvalidDataException">The request is invalid.</exception>
        private async Task DispatchTraversalAsync(Packet packet, Wire request, DHTTransport transport, IPEndPoint source, Wire response,
            CancellationToken cancellationToken)
        {
            if ((_options.Capabilities & DHTCapabilities.Traversal) == 0)
            {
                throw new IOException("Traversal assistance requires the Traversal capability.");
            }
            var action = TraversalMessage.ReadAction(request);
            switch (action)
            {
                case TraversalAction.DialBack:
                    await DispatchDialBackAsync(packet, request, transport, source, response, cancellationToken).ConfigureAwait(false);
                    return;
                case TraversalAction.DialBackAssist:
                    DispatchDialBackAssist(packet, request);
                    return;
                default:
                    DispatchTraversal(packet, request, action, transport, source, response);
                    return;
            }
        }

        /// <summary>Executes authenticated registration or introduction using the actual transport source.</summary>
        /// <param name="packet">The authenticated requester.</param>
        /// <param name="request">The operation arguments after the action byte.</param>
        /// <param name="action">Register to refresh and poll, or Introduce to request an introduction.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The socket's validated remote endpoint.</param>
        /// <param name="response">The encoder receiving the observed mapping or peer introduction.</param>
        /// <exception cref="IOException">A mapping is absent, or a quota was reached.</exception>
        /// <exception cref="InvalidDataException">The request is invalid.</exception>
        private void DispatchTraversal(Packet packet, Wire request, TraversalAction action, DHTTransport transport, IPEndPoint source, Wire response)
        {
            var targetId = string.Empty;
            if (action == TraversalAction.Introduce)
            {
                targetId = TraversalMessage.ReadIntroduceRequest(request);
            }
            else
            {
                TraversalMessage.ReadRegisterRequest(request);
            }
            if (targetId == packet.Sender.NodeId)
            {
                throw new InvalidDataException("Invalid traversal target.");
            }
            lock (_gate)
            {
                PruneAssistanceStateLocked();
                var now = DateTimeOffset.UtcNow;
                var sender = RegisterHostedLocked(_traversalRegistrations, packet.Sender, transport, source, action == TraversalAction.Register);
                var expiry = sender.Bindings[transport].ExpiresAt;
                if (action == TraversalAction.Register)
                {
                    var inbox = sender.Inbox(transport);
                    while (inbox.Count != 0 && inbox.Peek().ExpiresAt <= now)
                    {
                        inbox.Dequeue();
                    }
                    TraversalIntroduction? pending = inbox.Count == 0 ? null : ToIntroduction(inbox.Dequeue());
                    TraversalMessage.WritePollResponse(response, source, pending);
                }
                else
                {
                    if (!_traversalRegistrations.TryGetValue(targetId, out var target)
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
                    inbox.Enqueue(new PunchInvitation(packet.Sender, transport, CopyEndpoint(source), token, ticketExpiry));
                    TraversalMessage.WriteIntroduction(response, new TraversalIntroduction(target.Peer, binding.Endpoint, token, ticketExpiry));
                }
            }
        }

        /// <summary>
        /// Records the observed source of an authenticated registrant in one hosted registry, admitting a new registrant only
        /// when the action opens a registration and the registry has room.
        /// </summary>
        /// <param name="registry">The traversal registrations or the forwarding sessions.</param>
        /// <param name="registrant">The authenticated registrant.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <param name="admit">Whether an unknown registrant may be added.</param>
        /// <returns>The registration with the refreshed binding.</returns>
        /// <exception cref="IOException">The registrant is unknown and cannot be admitted, or the registry is full.</exception>
        /// <remarks>The caller must hold the state lock.</remarks>
        private HostedRegistration RegisterHostedLocked(Dictionary<string, HostedRegistration> registry, DHTContact registrant, DHTTransport transport,
            IPEndPoint source, bool admit)
        {
            var expiry = DateTimeOffset.UtcNow + _options.NatRegistrationLifetime;
            if (expiry > registrant.ExpiresAt)
            {
                expiry = registrant.ExpiresAt;
            }
            if (!registry.TryGetValue(registrant.NodeId, out var registration))
            {
                if (!admit || registry.Count >= _options.MaxNatRegistrations)
                {
                    throw new IOException("The registration is absent or the registry is full.");
                }
                registration = new HostedRegistration(registrant);
                registry.Add(registrant.NodeId, registration);
            }
            registration.Peer = registrant;
            registration.Bindings[transport] = new ObservedRoute(CopyEndpoint(source), expiry);
            return registration;
        }

        /// <summary>Validates an introduced peer's probe and records its direct source endpoint; the response body stays empty.</summary>
        /// <param name="packet">The authenticated direct probe.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The socket's observed remote endpoint.</param>
        /// <exception cref="InvalidDataException">The ticket, identity, transport or source endpoint does not match.</exception>
        private void DispatchPunch(Packet packet, DHTTransport transport, IPEndPoint source)
        {
            var ticket = PunchMessage.ReadRequest(packet.Body);
            lock (_gate)
            {
                if (!_punchSessions.TryGetValue(Crypto.Hex(ticket.Span), out var session)
                    || session.Invitation.ExpiresAt <= DateTimeOffset.UtcNow || session.Invitation.Peer.NodeId != packet.Sender.NodeId
                    || session.Invitation.Transport != transport || !session.Invitation.Endpoint.Equals(source))
                {
                    throw new InvalidDataException("The direct probe does not match an active introduction.");
                }
                RememberDirectRoute(packet.Sender, transport, source);
                session.Success.TrySetResult(true);
            }
        }

        /// <summary>Starts or coalesces a bounded introduction while retaining its work for shutdown.</summary>
        /// <param name="invitation">The authenticated ticket.</param>
        /// <param name="cancellationToken">The initiating caller or node lifetime.</param>
        /// <returns>The shared probe state.</returns>
        /// <exception cref="IOException">The local introduction limit was reached.</exception>
        private PunchSession StartPunchSession(PunchInvitation invitation, CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                _lifetime.Token.ThrowIfCancellationRequested();
                PruneAssistanceStateLocked();
                var id = Crypto.Hex(invitation.Token.Span);
                if (_punchSessions.TryGetValue(id, out var existing))
                {
                    if (existing.Invitation.Peer.NodeId != invitation.Peer.NodeId || existing.Invitation.Transport != invitation.Transport
                        || !existing.Invitation.Endpoint.Equals(invitation.Endpoint))
                    {
                        throw new InvalidDataException("An introduction ticket was reused for another peer or endpoint.");
                    }
                    return existing;
                }
                if (_punchSessions.Count >= _options.MaxConcurrentRequests * 4)
                {
                    throw new IOException("The direct introduction limit was reached.");
                }
                var session = new PunchSession(invitation);
                _punchSessions.Add(id, session);
                session.Work = RunPunchSessionAsync(session, cancellationToken);
                return session;
            }
        }

        /// <summary>Sends authenticated probes while the other peer opens its matching mapping.</summary>
        /// <param name="session">The active ticket and completion signal.</param>
        /// <param name="cancellationToken">The initiating operation lifetime.</param>
        /// <returns>Whether either direction authenticated the introduced path.</returns>
        private async Task<bool> RunPunchSessionAsync(PunchSession session, CancellationToken cancellationToken)
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
                    var request = new Packet(LocalContact, Crypto.Random(16), (byte)Operation.Punch, invitation.Token);
                    try
                    {
                        var encoded = await _transport.PunchAsync(invitation.Transport, invitation.Endpoint,
                            request.Seal(_identity, invitation.Peer), timeout.Token).ConfigureAwait(false);
                        using var response = AuthenticateResponse(encoded, invitation.Peer, request);
                        ResponseStatus.ReadResult(response.Packet.Body);
                        lock (_gate)
                        {
                            RememberDirectRoute(invitation.Peer, invitation.Transport, invitation.Endpoint);
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
        private void RememberDirectRoute(DHTContact peer, DHTTransport transport, IPEndPoint endpoint)
        {
            var key = (peer.NodeId, transport);
            if (!_directRoutes.ContainsKey(key) && _directRoutes.Count >= _options.MaxNatRegistrations)
            {
                (string, DHTTransport)? oldest = null;
                var expiry = DateTimeOffset.MaxValue;
                foreach (var entry in _directRoutes)
                {
                    if (entry.Value.ExpiresAt < expiry)
                    {
                        oldest = entry.Key;
                        expiry = entry.Value.ExpiresAt;
                    }
                }
                if (oldest.HasValue)
                {
                    _directRoutes.Remove(oldest.Value);
                }
            }
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(5);
            _directRoutes[key] = new ObservedRoute(CopyEndpoint(endpoint), expiresAt < peer.ExpiresAt ? expiresAt : peer.ExpiresAt);
        }

        /// <summary>Uses an authenticated punched route or a hosted registration or session before trying the peer's observed endpoints.</summary>
        /// <param name="peer">The final peer at its observed endpoints.</param>
        /// <param name="envelope">The sealed request.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>
        /// The encrypted direct response and, when it arrived over one of the peer's observed endpoints, that endpoint.
        /// </returns>
        /// <exception cref="IOException">The contact expired or no route answered.</exception>
        /// <exception cref="OperationCanceledException">The request or node lifetime was cancelled.</exception>
        private async Task<DirectExchange> ExchangeDirectAsync(DHTPeer peer, ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            if (peer.IsExpired)
            {
                throw new IOException("The destination contact has expired.");
            }
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var transport = attempt == 0 ? _options.PreferredTransport : OtherTransport(_options.PreferredTransport);
                ObservedRoute route;
                var key = (peer.NodeId, transport);
                lock (_gate)
                {
                    if (!_directRoutes.TryGetValue(key, out route) || route.ExpiresAt <= DateTimeOffset.UtcNow)
                    {
                        _directRoutes.Remove(key);
                        if (!TryGetHostedBindingLocked(peer.NodeId, transport, out route))
                        {
                            continue;
                        }
                    }
                }
                try
                {
                    // Punched routes and hosted bindings are mappings towards this node; they are not referred to others.
                    return new DirectExchange(
                        await ExchangeCountedAsync(peer, transport, route.Endpoint, envelope, cancellationToken).ConfigureAwait(false), null);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    lock (_gate)
                    {
                        if (_directRoutes.TryGetValue(key, out var current) && current.Endpoint.Equals(route.Endpoint))
                        {
                            _directRoutes.Remove(key);
                        }
                    }
                    Log(LogLevel.Debug, "Previously introduced direct route failed: ", exception);
                }
            }
            Exception? last = null;
            foreach (var route in SelectDirectRoutes(peer))
            {
                try
                {
                    var response = await ExchangeCountedAsync(peer, route.Transport, route.NetworkEndpoint, envelope, cancellationToken)
                        .ConfigureAwait(false);
                    return new DirectExchange(response, DHTEndpoint.Observed(route.Transport, route.NetworkEndpoint));
                }
                catch (Exception exception) when (IsPeerFailure(exception) || exception is OperationCanceledException
                    || exception is ObjectDisposedException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    _lifetime.Token.ThrowIfCancellationRequested();
                    last = exception;
                }
            }
            throw new IOException("No selected direct route responded.", last);
        }

        /// <summary>Finds the live binding of a node that holds a traversal registration or forwarding session with this node.</summary>
        /// <param name="nodeId">The registrant identifier.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="route">The live binding.</param>
        /// <returns>Whether a live binding exists.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private bool TryGetHostedBindingLocked(string nodeId, DHTTransport transport, out ObservedRoute route)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var registry in new[] { _traversalRegistrations, _forwardSessions })
            {
                if (registry.TryGetValue(nodeId, out var registration) && !registration.Peer.IsExpired
                    && registration.Bindings.TryGetValue(transport, out route) && route.ExpiresAt > now)
                {
                    return true;
                }
            }
            route = default;
            return false;
        }

        /// <summary>Checks whether a node holds a live traversal registration or forwarding session with this node.</summary>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>Whether a live binding exists on any transport.</returns>
        private bool HoldsHostedSession(string nodeId)
        {
            lock (_gate)
            {
                return TryGetHostedBindingLocked(nodeId, DHTTransport.Tcp, out _) || TryGetHostedBindingLocked(nodeId, DHTTransport.Udp, out _);
            }
        }

        /// <summary>The response of a direct exchange and the observed endpoint it proved, if any.</summary>
        private readonly struct DirectExchange
        {
            /// <summary>Gets the encrypted response in its received frame, which the consumer releases.</summary>
            internal OwnedMemory Response { get; }
            /// <summary>Gets the observed endpoint that answered, or null for punched routes and hosted bindings.</summary>
            internal DHTEndpoint? Observed { get; }

            /// <summary>Creates a direct exchange result.</summary>
            /// <param name="response">The encrypted response in its received frame.</param>
            /// <param name="observed">The observed endpoint that answered, or null.</param>
            internal DirectExchange(OwnedMemory response, DHTEndpoint? observed)
            {
                Response = response;
                Observed = observed;
            }
        }

        /// <summary>Reclaims expired hosted bindings, introduction tickets and direct routes.</summary>
        /// <remarks>The caller must hold the state lock.</remarks>
        private void PruneAssistanceStateLocked()
        {
            var now = DateTimeOffset.UtcNow;
            PruneHostedLocked(_traversalRegistrations, now);
            PruneHostedLocked(_forwardSessions, now);
            var removed = new List<string>();
            foreach (var entry in _punchSessions)
            {
                if (entry.Value.Invitation.ExpiresAt <= now && entry.Value.Work.IsCompleted)
                {
                    removed.Add(entry.Key);
                }
            }
            foreach (var id in removed)
            {
                _punchSessions.Remove(id);
            }
            var routes = new List<(string, DHTTransport)>();
            foreach (var entry in _directRoutes)
            {
                if (entry.Value.ExpiresAt <= now)
                {
                    routes.Add(entry.Key);
                }
            }
            foreach (var key in routes)
            {
                _directRoutes.Remove(key);
            }
        }

        /// <summary>Reclaims expired bindings and registrants of one hosted registry.</summary>
        /// <param name="registry">The traversal registrations or the forwarding sessions.</param>
        /// <param name="now">The current time.</param>
        /// <remarks>The caller must hold the state lock.</remarks>
        private static void PruneHostedLocked(Dictionary<string, HostedRegistration> registry, DateTimeOffset now)
        {
            var removed = new List<string>();
            foreach (var entry in registry)
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
                registry.Remove(id);
            }
        }

        /// <summary>Waits for every retained session loop, probe, reachability check and contact announcement after lifetime cancellation.</summary>
        /// <returns>Completion after all background assistance work has drained.</returns>
        private Task DrainAssistanceAsync()
        {
            lock (_gate)
            {
                var work = ReachabilityWorkLocked();
                foreach (var session in _traversalNodes.Values)
                {
                    work.Add(session.Work);
                }
                foreach (var session in _forwarders.Values)
                {
                    work.Add(session.Work);
                }
                foreach (var session in _punchSessions.Values)
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
            return NetworkScope.CopyEndpoint(endpoint);
        }

        /// <summary>Converts a queued introduction into its wire form.</summary>
        /// <param name="invitation">The queued introduction.</param>
        /// <returns>The introduction as the requester reads it.</returns>
        private static TraversalIntroduction ToIntroduction(PunchInvitation invitation)
        {
            return new TraversalIntroduction(invitation.Peer, invitation.Endpoint, invitation.Token, invitation.ExpiresAt);
        }

        /// <summary>Validates an introduction from an authenticated Traversal node against this node's identity, listeners and policies.</summary>
        /// <param name="introduction">The decoded introduction.</param>
        /// <param name="transport">The transport observed by this registration.</param>
        /// <returns>An owned ticket and verified peer contact.</returns>
        /// <exception cref="InvalidDataException">The ticket is expired, local, below the required work, or uses another address family.</exception>
        private PunchInvitation ToPunchInvitation(TraversalIntroduction introduction, DHTTransport transport)
        {
            var peer = introduction.Peer;
            var expiresAt = introduction.ExpiresAt;
            if (peer.NodeId == NodeId || !HasRequiredWork(peer) || _transport.PortFor(transport, introduction.Endpoint.AddressFamily) == 0
                || expiresAt <= DateTimeOffset.UtcNow || expiresAt > DateTimeOffset.UtcNow.AddMinutes(2)
                || expiresAt > peer.ExpiresAt)
            {
                throw new InvalidDataException("Invalid or expired traversal introduction.");
            }
            return new PunchInvitation(peer, transport, introduction.Endpoint, introduction.Ticket.ToArray(), expiresAt);
        }

        /// <summary>Owns a registrant's mutable lease and bounded transport inboxes in a hosted registry.</summary>
        private sealed class HostedRegistration
        {
            /// <summary>Gets or sets the latest signed registrant contact.</summary>
            internal DHTContact Peer { get; set; }
            /// <summary>Gets the at most two independently observed transport bindings.</summary>
            internal Dictionary<DHTTransport, ObservedRoute> Bindings { get; } = new Dictionary<DHTTransport, ObservedRoute>();
            /// <summary>The pending TCP introductions.</summary>
            private readonly Queue<PunchInvitation> _tcp = new Queue<PunchInvitation>();
            /// <summary>The pending UDP introductions.</summary>
            private readonly Queue<PunchInvitation> _udp = new Queue<PunchInvitation>();

            /// <summary>Creates a registrant without bindings.</summary>
            /// <param name="peer">The authenticated contact.</param>
            internal HostedRegistration(DHTContact peer)
            {
                Peer = peer;
            }

            /// <summary>Gets the bounded inbox for one transport.</summary>
            /// <param name="transport">The transport whose inbox is needed.</param>
            /// <returns>The corresponding introduction queue.</returns>
            internal Queue<PunchInvitation> Inbox(DHTTransport transport)
            {
                return transport == DHTTransport.Tcp ? _tcp : _udp;
            }
        }

        /// <summary>Owns this node's ongoing session with one Traversal node or Forwarder.</summary>
        private sealed class AssistantSession
        {
            /// <summary>Gets or sets the assistant with its latest authenticated contact.</summary>
            internal DHTPeer Peer { get; set; }
            /// <summary>Gets or sets the observed background polling task.</summary>
            internal Task Work { get; set; } = Task.CompletedTask;
            /// <summary>Gets or sets the time of the most recent successful refresh.</summary>
            internal DateTimeOffset LastSuccess { get; set; }
            /// <summary>Gets or sets whether the session was live when last evaluated for hints.</summary>
            internal bool Live { get; set; } = true;

            /// <summary>Creates the lifetime-owned session state.</summary>
            /// <param name="peer">The authenticated assistant.</param>
            internal AssistantSession(DHTPeer peer)
            {
                Peer = peer;
                LastSuccess = DateTimeOffset.UtcNow;
            }
        }

        /// <summary>Owns one cancellable probe and its incoming success signal.</summary>
        private sealed class PunchSession
        {
            /// <summary>Gets the authenticated introduction.</summary>
            internal PunchInvitation Invitation { get; }
            /// <summary>Gets the signal set only by an authenticated matching direct probe.</summary>
            internal TaskCompletionSource<bool> Success { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            /// <summary>Gets or sets the retained probe task.</summary>
            internal Task<bool> Work { get; set; } = Task.FromResult(false);

            /// <summary>Creates a pending direct probe.</summary>
            /// <param name="invitation">The authenticated ticket.</param>
            internal PunchSession(PunchInvitation invitation)
            {
                Invitation = invitation;
            }
        }

        /// <summary>Stores a bounded observed endpoint without an additional object allocation.</summary>
        private readonly struct ObservedRoute
        {
            /// <summary>Gets the privately owned observed endpoint.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the endpoint lease expiry.</summary>
            internal DateTimeOffset ExpiresAt { get; }

            /// <summary>Associates an endpoint with its retention deadline.</summary>
            /// <param name="endpoint">The privately owned endpoint.</param>
            /// <param name="expiresAt">The retention deadline.</param>
            internal ObservedRoute(IPEndPoint endpoint, DateTimeOffset expiresAt)
            {
                Endpoint = endpoint;
                ExpiresAt = expiresAt;
            }
        }

        /// <summary>Stores an immutable introduction while retaining its owned contact and token memory.</summary>
        private readonly struct PunchInvitation
        {
            /// <summary>Gets the verified final peer.</summary>
            internal DHTContact Peer { get; }
            /// <summary>Gets the transport to punch.</summary>
            internal DHTTransport Transport { get; }
            /// <summary>Gets the privately owned observed endpoint.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the shared random 128-bit ticket.</summary>
            internal ReadOnlyMemory<byte> Token { get; }
            /// <summary>Gets the ticket's absolute expiry.</summary>
            internal DateTimeOffset ExpiresAt { get; }

            /// <summary>Creates an introduction from authenticated Traversal data.</summary>
            /// <param name="peer">The verified final peer.</param>
            /// <param name="transport">The transport to punch.</param>
            /// <param name="endpoint">The observed endpoint.</param>
            /// <param name="token">The owned random ticket.</param>
            /// <param name="expiresAt">The absolute ticket expiry.</param>
            internal PunchInvitation(DHTContact peer, DHTTransport transport, IPEndPoint endpoint, ReadOnlyMemory<byte> token, DateTimeOffset expiresAt)
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
