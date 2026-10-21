using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The immutable session arguments reused by every forwarding session refresh.</summary>
        private static readonly byte[] s_forwardSession = new byte[] { (byte)ForwardAction.Session };
        /// <summary>The bounded forwarding sessions hosted by this Forwarder, keyed by the node that opened them.</summary>
        private readonly Dictionary<string, HostedRegistration> _forwardSessions = new Dictionary<string, HostedRegistration>();
        /// <summary>The Forwarders this node keeps forwarding sessions with, keyed by their identifier.</summary>
        private readonly Dictionary<string, AssistantSession> _forwarders = new Dictionary<string, AssistantSession>();

        /// <summary>
        /// Opens a forwarding session with a Forwarder over every common transport and keeps it alive until shutdown, so the
        /// Forwarder can deliver traffic from other peers to this node at the endpoint it observed.
        /// </summary>
        /// <param name="forwarder">A Forwarder at the endpoints observed for it.</param>
        /// <param name="cancellationToken">Cancels the initial session; successful sessions subsequently follow the node lifetime.</param>
        /// <returns>Completion after at least one common transport has opened a session.</returns>
        /// <exception cref="ArgumentException">The peer does not forward traffic or has no observed endpoint.</exception>
        /// <exception cref="InvalidOperationException">The node is not running or NAT traversal is disabled.</exception>
        /// <exception cref="IOException">No common transport opened a session or the Forwarder limit was reached.</exception>
        /// <exception cref="OperationCanceledException">The session was cancelled.</exception>
        public async Task RegisterForwarderAsync(DHTPeer forwarder, CancellationToken cancellationToken = default)
        {
            ValidateAssistant(forwarder, DHTCapabilities.Forwarder);
            using var cancellation = OperationCancellation(cancellationToken);
            if (!_options.EnableNatTraversal)
            {
                throw new InvalidOperationException("NAT traversal is disabled.");
            }
            if (!ReserveAssistantSessionLocked(_forwarders, forwarder, _options.MaxForwarders))
            {
                return;
            }
            var sessions = 0;
            foreach (var transport in new[] { _options.PreferredTransport, OtherTransport(_options.PreferredTransport) })
            {
                if (!SupportsAssistantTransport(forwarder, transport))
                {
                    continue;
                }
                try
                {
                    forwarder = await OpenForwardSessionAsync(forwarder, transport, cancellation.Token).ConfigureAwait(false);
                    sessions++;
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Forwarding session transport failed: ", exception);
                }
            }
            if (sessions == 0)
            {
                throw new IOException("No common transport opened a forwarding session.");
            }
            lock (_gate)
            {
                cancellation.Token.ThrowIfCancellationRequested();
                if (_forwarders.ContainsKey(forwarder.NodeId))
                {
                    return;
                }
                if (_forwarders.Count >= _options.MaxForwarders)
                {
                    throw new IOException("The Forwarder limit was reached.");
                }
                var session = new AssistantSession(forwarder);
                _forwarders.Add(forwarder.NodeId, session);
                session.Work = MaintainAssistantSessionAsync(session, "Forwarding session refresh failed: ", OpenForwardSessionAsync);
                RefreshLocalContactLocked();
            }
            Log(LogLevel.Information, "Forwarding session established.");
        }

        /// <summary>Opens or refreshes the forwarding session over one transport and records the endpoint the Forwarder observed.</summary>
        /// <param name="forwarder">The Forwarder.</param>
        /// <param name="transport">The transport whose mapping the session keeps.</param>
        /// <param name="cancellationToken">The bounded session lifetime.</param>
        /// <returns>The Forwarder with its freshly authenticated contact.</returns>
        private async Task<DHTPeer> OpenForwardSessionAsync(DHTPeer forwarder, DHTTransport transport, CancellationToken cancellationToken)
        {
            var response = await RequestAssistantAsync(forwarder, Operation.Forward, transport, s_forwardSession, cancellationToken).ConfigureAwait(false);
            using var body = response.Body;
            using var reader = new Wire(body.Bytes);
            RecordObservation(response.Peer, response.Endpoint.Address, transport, ForwardMessage.ReadSessionResponse(reader));
            return forwarder.WithContact(response.Peer);
        }

        /// <summary>Checks whether this node may still register with another Traversal node.</summary>
        /// <returns>Whether NAT traversal is enabled and the Traversal node limit is not reached.</returns>
        private bool HasTraversalRoom()
        {
            lock (_gate)
            {
                return _options.EnableNatTraversal && _traversalNodes.Count < _options.MaxTraversalNodes;
            }
        }

        /// <summary>Checks whether this node may still open a session with another Forwarder.</summary>
        /// <returns>Whether NAT traversal is enabled and the Forwarder limit is not reached.</returns>
        private bool HasForwarderRoom()
        {
            lock (_gate)
            {
                return _options.EnableNatTraversal && _forwarders.Count < _options.MaxForwarders;
            }
        }

        /// <summary>Executes an authenticated Forward action: hosts a session, relays an envelope or accepts a delivered one.</summary>
        /// <param name="packet">The authenticated requester.</param>
        /// <param name="request">The operation arguments.</param>
        /// <param name="origin">The transport, socket source and delivering Forwarder of the request.</param>
        /// <param name="response">The encoder receiving the action result.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>Completion after the action result was written.</returns>
        /// <exception cref="IOException">This node is not a Forwarder, the destination is unknown or a quota was reached.</exception>
        /// <exception cref="InvalidDataException">The request is invalid or was not sent directly.</exception>
        private async Task DispatchForwardAsync(Packet packet, Wire request, RequestOrigin origin, Wire response, CancellationToken cancellationToken)
        {
            var action = ForwardMessage.ReadAction(request);
            switch (action)
            {
                case ForwardAction.Session:
                    RequireDirect(origin);
                    RequireForwarding();
                    ForwardMessage.ReadSessionRequest(request);
                    lock (_gate)
                    {
                        PruneAssistanceStateLocked();
                        RegisterHostedLocked(_forwardSessions, packet.Sender, origin.Transport, origin.Endpoint, true);
                    }
                    ForwardMessage.WriteSessionResponse(response, origin.Endpoint);
                    return;
                case ForwardAction.Relay:
                {
                    RequireForwarding();
                    var relay = ForwardMessage.ReadRelayRequest(request);
                    var destination = ForwardDestination(relay.DestinationId);
                    if (destination == null || destination.NodeId == packet.Sender.NodeId)
                    {
                        throw new IOException("The destination must hold a forwarding session or be an already known peer.");
                    }
                    using var relayed = await DeliverAsync(destination, relay.Envelope, cancellationToken).ConfigureAwait(false);
                    ForwardMessage.WriteEnvelopeResponse(response, relayed.Bytes.Span);
                    return;
                }
                case ForwardAction.Deliver:
                {
                    RequireDirect(origin);
                    if ((packet.Sender.Capabilities & DHTCapabilities.Forwarder) == 0)
                    {
                        throw new InvalidDataException("Only Forwarders may deliver relayed envelopes.");
                    }
                    var inner = ForwardMessage.ReadDeliverRequest(request, NodeId);
                    // The inner request is handled as its origin's own request, with the Forwarder as its socket source.
                    var reply = await HandleAsync(inner, new RequestOrigin(origin.Transport, origin.Endpoint, packet.Sender), cancellationToken)
                        .ConfigureAwait(false);
                    ForwardMessage.WriteEnvelopeResponse(response, reply.Span);
                    return;
                }
                default:
                    throw new InvalidDataException("Invalid forward action.");
            }
        }

        /// <summary>Rejects session and relay requests when this node does not forward traffic.</summary>
        /// <exception cref="IOException">The Forwarder capability is disabled.</exception>
        private void RequireForwarding()
        {
            if ((_options.Capabilities & DHTCapabilities.Forwarder) == 0)
            {
                throw new IOException("Forwarding is disabled.");
            }
        }

        /// <summary>Finds the destination of a relayed envelope among the hosted forwarding sessions and the routed peers.</summary>
        /// <param name="target">The destination node identifier.</param>
        /// <returns>The destination at its session bindings or observed endpoints, or null when it is unknown.</returns>
        private DHTPeer? ForwardDestination(string target)
        {
            lock (_gate)
            {
                PruneAssistanceStateLocked();
                if (_forwardSessions.TryGetValue(target, out var session))
                {
                    var endpoints = new List<DHTEndpoint>();
                    foreach (var binding in session.Bindings)
                    {
                        endpoints = new List<DHTEndpoint>(DHTPeer.Merge(endpoints, DHTEndpoint.Observed(binding.Key, binding.Value.Endpoint)));
                    }
                    return new DHTPeer(session.Peer, endpoints);
                }
            }
            foreach (var peer in RoutedPeers(target, _options.BucketSize))
            {
                if (peer.NodeId == target)
                {
                    return peer;
                }
            }
            return null;
        }

        /// <summary>Delivers a relayed envelope to its destination inside this Forwarder's own authenticated request.</summary>
        /// <param name="destination">The destination at its session bindings or observed endpoints.</param>
        /// <param name="envelope">The origin's envelope, sealed to the destination.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>The destination's opaque response envelope, a view inside the response frame that releases the frame.</returns>
        /// <exception cref="IOException">The destination did not answer or rejected the delivery.</exception>
        private async Task<OwnedMemory> DeliverAsync(DHTPeer destination, ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            using var body = new Wire();
            ForwardMessage.WriteDeliverRequest(body, envelope.Span);
            var response = await RequestAsync(destination, Operation.Forward, body.WrittenMemory, cancellationToken, allowAssisted: false).ConfigureAwait(false);
            return NarrowEnvelope(response);
        }

        /// <summary>Wraps an already sealed request in a Relay action to a Forwarder.</summary>
        /// <param name="forwarder">The Forwarder.</param>
        /// <param name="destination">The final recipient.</param>
        /// <param name="envelope">The end-to-end encrypted inner request.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>The opaque end-to-end encrypted reply, a view inside the Forwarder's response frame that releases the frame.</returns>
        /// <exception cref="IOException">The peer cannot forward this request or did not answer.</exception>
        private async Task<OwnedMemory> RelayThroughAsync(DHTPeer forwarder, DHTPeer destination, ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            if (forwarder.NodeId == destination.NodeId || forwarder.NodeId == NodeId || (forwarder.Capabilities & DHTCapabilities.Forwarder) == 0)
            {
                throw new IOException("The selected peer cannot forward this request.");
            }
            using var body = new Wire();
            ForwardMessage.WriteRelayRequest(body, destination.NodeId, envelope.Span);
            var response = await RequestAsync(forwarder, Operation.Forward, body.WrittenMemory, cancellationToken, allowAssisted: false).ConfigureAwait(false);
            return NarrowEnvelope(response);
        }

        /// <summary>Takes the opaque envelope out of a Forward result, releasing the frame when the result is malformed.</summary>
        /// <param name="response">The authenticated result body, which must not be disposed afterwards.</param>
        /// <returns>The envelope view, releasing the frame when disposed.</returns>
        /// <exception cref="InvalidDataException">The result is malformed; the frame has been released.</exception>
        private static OwnedMemory NarrowEnvelope(OwnedMemory response)
        {
            try
            {
                using var reader = new Wire(response.Bytes);
                return response.Narrow(ForwardMessage.ReadEnvelopeResponse(reader));
            }
            catch
            {
                response.Dispose();
                throw;
            }
        }
    }
}
