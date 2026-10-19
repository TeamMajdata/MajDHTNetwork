using System;
using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The maximum direct routes attempted for one request.</summary>
        private const int MaxDirectRoutes = 16;
        /// <summary>The maximum relay routes attempted for one request.</summary>
        private const int MaxRelayRoutes = 32;

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

        /// <summary>Adds an authenticated contact to the routing table unless it can only be reached through relays.</summary>
        /// <param name="peer">The authenticated contact.</param>
        /// <remarks>
        /// Private nodes participate as clients: they are never returned as lookup hops, and a node that becomes private
        /// is removed together with its earlier contact.
        /// </remarks>
        private void ObservePeer(DHTPeer peer)
        {
            if (peer.Reachability == DHTReachability.Private)
            {
                _routing.Remove(peer.NodeId);
            }
            else
            {
                _routing.Observe(peer);
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
                    || (relay.Capabilities & DHTCapabilities.Relay) == 0 || !seen.Add(relay.NodeId))
                {
                    continue;
                }
                result.Add(route!);
            }
            return result;
        }
    }
}
