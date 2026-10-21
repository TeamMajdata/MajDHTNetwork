using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The maximum direct routes attempted for one request.</summary>
        private const int MaxDirectRoutes = 16;
        /// <summary>The maximum assisted routes attempted for one request.</summary>
        private const int MaxAssistedRoutes = 32;
        /// <summary>The maximum inbound senders verified concurrently.</summary>
        private const int MaxPendingVerifications = 16;
        /// <summary>The maximum inbound senders verified per source network and quota window.</summary>
        internal const int VerificationsPerNetwork = 8;
        /// <summary>The node identifiers whose verification is in progress.</summary>
        private readonly HashSet<string> _verifying = new HashSet<string>(StringComparer.Ordinal);
        /// <summary>The verification tasks still running.</summary>
        private readonly List<Task> _verificationWork = new List<Task>();

        /// <summary>Checks whether a contact proves the identity work this node requires.</summary>
        /// <param name="contact">The contact.</param>
        /// <returns>Whether the contact's proof of work reaches <see cref="DHTNodeOptions.IdentityWorkBits"/>.</returns>
        private bool HasRequiredWork(DHTContact contact)
        {
            return _options.IdentityWorkBits == 0 || contact.IdentityWork >= _options.IdentityWorkBits;
        }

        /// <summary>Queries the routing table and discards entries that must never be used as lookup hops.</summary>
        /// <param name="routingId">The lowercase SHA-256 target identifier.</param>
        /// <param name="count">The maximum number of peers.</param>
        /// <returns>Distinct live non-private remote peers in the table's order, each at the endpoints observed for it.</returns>
        private List<DHTPeer> RoutedPeers(string routingId, int count)
        {
            var result = new List<DHTPeer>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var peer in _routing.Closest(routingId, count) ?? Array.Empty<DHTPeer>())
            {
                if (result.Count >= count)
                {
                    break;
                }
                if (peer == null || peer.IsExpired || peer.NodeId == NodeId || peer.Reachability == DHTReachability.Private
                    || !seen.Add(peer.NodeId))
                {
                    continue;
                }
                result.Add(peer);
            }
            return result;
        }

        /// <summary>Offers an authenticated contact to the routing table unless it can only be reached through forwarders.</summary>
        /// <param name="contact">The authenticated contact.</param>
        /// <param name="observed">
        /// The endpoint this node exchanged an authenticated packet with, or null to refresh a known contact only, such as after a
        /// response over a punched route, a hosted registration or a Forwarder.
        /// </param>
        /// <remarks>
        /// Private nodes participate as clients: they are never returned as lookup hops, and a node that becomes private
        /// is removed together with its earlier contact.
        /// </remarks>
        private void ObservePeer(DHTContact contact, DHTEndpoint? observed)
        {
            if (contact.Reachability == DHTReachability.Private)
            {
                _routing.Remove(contact.NodeId);
            }
            else
            {
                _routing.Observe(contact, observed);
            }
        }

        /// <summary>
        /// Handles the sender of an inbound request: a known contact is refreshed, and an unknown one is queued for a bounded
        /// verification at its observed source before it can occupy the routing table.
        /// </summary>
        /// <param name="sender">The authenticated sender.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <remarks>
        /// Nodes send from their listening ports, so an honest directly reachable node answers a Ping at the endpoint its
        /// request came from. A sender with unknown reachability that holds a traversal registration or forwarding session with
        /// this node asked for NAT assistance, so its source stays unverified until a dial-back makes its contact public.
        /// </remarks>
        private void AdmitInbound(DHTContact sender, DHTTransport transport, IPEndPoint source)
        {
            if (sender.Reachability == DHTReachability.Private)
            {
                _routing.Remove(sender.NodeId);
                return;
            }
            _routing.Observe(sender, null);
            if (sender.Reachability == DHTReachability.Unknown && HoldsHostedSession(sender.NodeId))
            {
                return;
            }
            ScheduleVerification(DHTPeer.Observed(sender, transport, source));
        }

        /// <summary>Starts a bounded, rate-limited verification of an inbound sender at its observed source endpoint.</summary>
        /// <param name="candidate">The candidate at its observed source.</param>
        private void ScheduleVerification(DHTPeer candidate)
        {
            foreach (var routed in _routing.Closest(candidate.NodeId, 1) ?? Array.Empty<DHTPeer>())
            {
                if (routed?.NodeId == candidate.NodeId)
                {
                    return;
                }
            }
            var source = candidate.Endpoints[0].NetworkAddress;
            lock (_gate)
            {
                if (!_started || _stopped || _lifetime.IsCancellationRequested || _verifying.Count >= MaxPendingVerifications
                    || _verifying.Contains(candidate.NodeId)
                    || !TakeProbeQuotaLocked("verify:" + NetworkScope.NetworkKey(source), VerificationsPerNetwork))
                {
                    return;
                }
                _verifying.Add(candidate.NodeId);
                _verificationWork.RemoveAll(work => work.IsCompleted);
                _verificationWork.Add(VerifyCandidateAsync(candidate));
            }
        }

        /// <summary>Pings a candidate at its observed source; an authenticated answer admits it there through <see cref="ObservePeer"/>.</summary>
        /// <param name="candidate">The candidate at its observed source.</param>
        /// <returns>Completion after the verification attempt.</returns>
        private async Task VerifyCandidateAsync(DHTPeer candidate)
        {
            await Task.Yield();
            try
            {
                var observed = candidate.Endpoints[0];
                var transport = observed.TcpPort != 0 ? DHTTransport.Tcp : DHTTransport.Udp;
                var request = new Packet(LocalContact, Crypto.Random(16), (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty);
                // The exchange is pinned to the observed source, so a hosted registration or punched route cannot stand in for it.
                var encoded = await ExchangeCountedAsync(candidate, transport, observed.ToIPEndPoint(transport)!, request.Seal(_identity, candidate.Contact),
                    _lifetime.Token).ConfigureAwait(false);
                using var response = AuthenticateResponse(encoded, candidate.Contact, request);
                ResponseStatus.ReadResult(response.Packet.Body);
                ObservePeer(response.Packet.Sender, observed);
            }
            catch (Exception exception) when (IsPeerFailure(exception) || exception is OperationCanceledException
                || exception is InvalidOperationException)
            {
                Log(LogLevel.Debug, "Candidate verification failed: ", exception);
            }
            finally
            {
                lock (_gate)
                {
                    _verifying.Remove(candidate.NodeId);
                }
            }
        }

        /// <summary>Captures the routing state passed to the route selector.</summary>
        /// <returns>A snapshot of the preferred transport and live traversal registrations.</returns>
        private DHTRouteContext RouteContext()
        {
            lock (_gate)
            {
                return new DHTRouteContext(_options.PreferredTransport, _options.EnableNatTraversal, _traversalNodes.Keys, _options.BucketSize,
                    GetPeerStatistics);
            }
        }

        /// <summary>Asks the route selector for direct attempts and bounds the result.</summary>
        /// <param name="destination">The destination at its observed endpoints.</param>
        /// <returns>At most sixteen direct routes.</returns>
        private List<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination)
        {
            var result = new List<DHTDirectRoute>();
            foreach (var route in _routeSelector.SelectDirectRoutes(destination, RouteContext()) ?? Array.Empty<DHTDirectRoute>())
            {
                if (result.Count >= MaxDirectRoutes)
                {
                    break;
                }
                if (route != null)
                {
                    result.Add(route);
                }
            }
            return result;
        }

        /// <summary>Asks the route selector for assisted attempts and discards assistants that cannot serve the destination.</summary>
        /// <param name="destination">The destination.</param>
        /// <returns>At most thirty-two distinct usable assisted routes.</returns>
        private List<DHTAssistedRoute> SelectAssistedRoutes(DHTPeer destination)
        {
            const DHTCapabilities assisting = DHTCapabilities.Traversal | DHTCapabilities.Forwarder;
            var known = new List<DHTPeer>();
            foreach (var peer in RoutedPeers(destination.NodeId, 256))
            {
                if (peer.NodeId != destination.NodeId && (peer.Capabilities & assisting) != 0)
                {
                    known.Add(peer);
                }
            }
            var result = new List<DHTAssistedRoute>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var route in _routeSelector.SelectAssistedRoutes(destination, known.AsReadOnly(), RouteContext()) ?? Array.Empty<DHTAssistedRoute>())
            {
                if (result.Count >= MaxAssistedRoutes)
                {
                    break;
                }
                var assistant = route?.Assistant;
                if (assistant == null || assistant.IsExpired || assistant.NodeId == NodeId || assistant.NodeId == destination.NodeId
                    || (assistant.Capabilities & assisting) == 0 || !HasRequiredWork(assistant.Contact) || !seen.Add(assistant.NodeId))
                {
                    continue;
                }
                result.Add(route!);
            }
            return result;
        }
    }
}
