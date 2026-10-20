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
        /// <summary>The maximum relay routes attempted for one request.</summary>
        private const int MaxRelayRoutes = 32;
        /// <summary>The maximum inbound senders verified concurrently.</summary>
        private const int MaxPendingVerifications = 16;
        /// <summary>The maximum inbound senders verified per source network and quota window.</summary>
        internal const int VerificationsPerNetwork = 8;
        /// <summary>The node identifiers whose verification is in progress.</summary>
        private readonly HashSet<string> _verifying = new HashSet<string>(StringComparer.Ordinal);
        /// <summary>The verification tasks still running.</summary>
        private readonly List<Task> _verificationWork = new List<Task>();

        /// <summary>Checks whether a contact proves the identity work this node requires.</summary>
        /// <param name="peer">The contact.</param>
        /// <returns>Whether the contact's proof of work reaches <see cref="DHTNodeOptions.IdentityWorkBits"/>.</returns>
        private bool HasRequiredWork(DHTPeer peer)
        {
            return _options.IdentityWorkBits == 0 || peer.IdentityWork >= _options.IdentityWorkBits;
        }

        /// <summary>Queries the routing table and discards entries that must never be used as lookup hops.</summary>
        /// <param name="routingId">The lowercase SHA-256 target identifier.</param>
        /// <param name="count">The maximum number of contacts.</param>
        /// <returns>Distinct live non-private remote contacts in the table's order.</returns>
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

        /// <summary>Offers an authenticated contact to the routing table unless it can only be reached through relays.</summary>
        /// <param name="peer">The authenticated contact.</param>
        /// <param name="verifiedAddress">The advertised address the exchange proved, or null to refresh a known contact only.</param>
        /// <remarks>
        /// Private nodes participate as clients: they are never returned as lookup hops, and a node that becomes private
        /// is removed together with its earlier contact.
        /// </remarks>
        private void ObservePeer(DHTPeer peer, IPAddress? verifiedAddress)
        {
            if (peer.Reachability == DHTReachability.Private)
            {
                _routing.Remove(peer.NodeId);
            }
            else
            {
                _routing.Observe(peer, verifiedAddress);
            }
        }

        /// <summary>
        /// Handles the sender of an inbound request: it is admitted at once when the request came from one of its advertised
        /// endpoints, and otherwise only refreshed and queued for an outbound verification.
        /// </summary>
        /// <param name="sender">The authenticated sender.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <remarks>
        /// Nodes send from their listening ports, so an honest directly reachable node arrives from an advertised endpoint.
        /// Anything else, including a contact advertising someone else's address, must answer at an advertised endpoint
        /// before it can occupy the routing table.
        /// </remarks>
        private void AdmitInbound(DHTPeer sender, DHTTransport transport, IPEndPoint source)
        {
            if (sender.Reachability == DHTReachability.Private)
            {
                _routing.Remove(sender.NodeId);
                return;
            }
            foreach (var endpoint in sender.Endpoints)
            {
                if (endpoint.NetworkAddress.Equals(source.Address) && endpoint.Port(transport) == source.Port)
                {
                    _routing.Observe(sender, source.Address);
                    return;
                }
            }
            _routing.Observe(sender, null);
            if (sender.Endpoints.Count != 0)
            {
                ScheduleVerification(sender, source.Address);
            }
        }

        /// <summary>Starts a bounded, rate-limited verification of an inbound sender's advertised endpoints.</summary>
        /// <param name="candidate">The candidate contact.</param>
        /// <param name="source">The observed source address, used for per-network rate limits.</param>
        private void ScheduleVerification(DHTPeer candidate, IPAddress source)
        {
            foreach (var routed in _routing.Closest(candidate.NodeId, 1) ?? Array.Empty<DHTPeer>())
            {
                if (routed?.NodeId == candidate.NodeId)
                {
                    return;
                }
            }
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

        /// <summary>Pings a candidate directly; an answer from an advertised endpoint admits it through <see cref="ObservePeer"/>.</summary>
        /// <param name="candidate">The candidate contact.</param>
        /// <returns>Completion after the verification attempt.</returns>
        private async Task VerifyCandidateAsync(DHTPeer candidate)
        {
            await Task.Yield();
            try
            {
                using var pong = await RequestAsync(candidate, Operation.Ping, ReadOnlyMemory<byte>.Empty, _lifetime.Token, allowRelay: false)
                    .ConfigureAwait(false);
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
        /// <returns>A snapshot of the preferred transport, external addresses and live relay registrations.</returns>
        private DHTRouteContext RouteContext()
        {
            lock (_gate)
            {
                return new DHTRouteContext(_options.PreferredTransport, _options.EnableNatTraversal, _externalAddresses.Values,
                    _natRelays.Keys, _options.BucketSize, GetPeerStatistics);
            }
        }

        /// <summary>Asks the route selector for direct attempts and bounds the result.</summary>
        /// <param name="destination">The destination contact.</param>
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

        /// <summary>Asks the route selector for relay attempts and discards relays that cannot serve the destination.</summary>
        /// <param name="destination">The destination contact.</param>
        /// <returns>At most thirty-two distinct usable relay routes.</returns>
        private List<DHTRelayRoute> SelectRelayRoutes(DHTPeer destination)
        {
            var known = new List<DHTPeer>();
            foreach (var peer in RoutedPeers(destination.NodeId, 256))
            {
                if (peer.NodeId != destination.NodeId && (peer.Capabilities & DHTCapabilities.Relay) != 0)
                {
                    known.Add(peer);
                }
            }
            var result = new List<DHTRelayRoute>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var route in _routeSelector.SelectRelayRoutes(destination, known.AsReadOnly(), RouteContext()) ?? Array.Empty<DHTRelayRoute>())
            {
                if (result.Count >= MaxRelayRoutes)
                {
                    break;
                }
                var relay = route?.Relay;
                if (relay == null || relay.IsExpired || relay.NodeId == NodeId || relay.NodeId == destination.NodeId
                    || (relay.Capabilities & DHTCapabilities.Relay) == 0 || !HasRequiredWork(relay) || !seen.Add(relay.NodeId))
                {
                    continue;
                }
                result.Add(route!);
            }
            return result;
        }
    }
}
