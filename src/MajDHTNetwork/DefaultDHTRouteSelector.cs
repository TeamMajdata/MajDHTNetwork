using System.Collections.Generic;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// The default route selection: verified or configured endpoints first, then unverified and local endpoints; the
    /// destination's relay hints before other routed relays.
    /// </summary>
    public sealed class DefaultDHTRouteSelector : IDHTRouteSelector
    {
        /// <summary>
        /// Orders configured or verified endpoints, then unverified endpoints, then local endpoints, each with the preferred
        /// transport before the alternate transport. A private destination's local endpoints are only selected when both
        /// nodes share an external address.
        /// </summary>
        /// <param name="destination">The signed destination contact.</param>
        /// <param name="context">The local node's routing state.</param>
        /// <returns>The direct attempts in order.</returns>
        public IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context)
        {
            var result = new List<DHTDirectRoute>();
            var sameNetwork = context.SharesExternalAddress(destination);
            for (var pass = 0; pass < 3; pass++)
            {
                foreach (var endpoint in destination.Endpoints)
                {
                    var local = (endpoint.Flags & DHTEndpointFlags.Local) != 0;
                    var rank = endpoint.IsReachable ? 0 : local ? 2 : 1;
                    if (rank != pass || (local && destination.Reachability == DHTReachability.Private && !sameNetwork))
                    {
                        continue;
                    }
                    AddDirectRoute(result, endpoint, context.PreferredTransport);
                    AddDirectRoute(result, endpoint, context.AlternateTransport);
                }
            }
            return result;
        }

        /// <summary>
        /// Lists the destination's relay hints, then at most <see cref="DHTRouteContext.MaxRelayAttempts"/> other routed relays.
        /// Punching is requested unless the destination reported an endpoint-dependent mapping, and through a hinted relay
        /// only when this node is already registered with it.
        /// </summary>
        /// <param name="destination">The signed destination contact, including its relay hints.</param>
        /// <param name="knownRelays">Routed relay-capable contacts, nearest to the destination first.</param>
        /// <param name="context">The local node's routing state.</param>
        /// <returns>The relay attempts in order.</returns>
        public IReadOnlyList<DHTRelayRoute> SelectRelayRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownRelays, DHTRouteContext context)
        {
            var result = new List<DHTRelayRoute>();
            var selected = new HashSet<string>();
            var punchable = context.NatTraversalEnabled && !destination.HasEndpointDependentMapping;
            foreach (var hint in destination.RelayHints)
            {
                if (selected.Add(hint.NodeId))
                {
                    // Registering with a hinted relay only to punch would consume a relay slot, so forward instead.
                    result.Add(new DHTRelayRoute(hint, punchable && context.IsRegisteredWith(hint.NodeId)));
                }
            }
            var routed = 0;
            foreach (var relay in knownRelays)
            {
                if (routed >= context.MaxRelayAttempts)
                {
                    break;
                }
                if (relay.NodeId != destination.NodeId && (relay.Capabilities & DHTCapabilities.Relay) != 0 && selected.Add(relay.NodeId))
                {
                    result.Add(new DHTRelayRoute(relay, punchable));
                    routed++;
                }
            }
            return result;
        }

        /// <summary>Adds the direct attempt for one transport when the endpoint accepts it.</summary>
        /// <param name="routes">The routes under construction.</param>
        /// <param name="endpoint">The advertised endpoint.</param>
        /// <param name="transport">The transport.</param>
        private static void AddDirectRoute(List<DHTDirectRoute> routes, DHTEndpoint endpoint, DHTTransport transport)
        {
            var port = endpoint.Port(transport);
            if (port != 0)
            {
                routes.Add(new DHTDirectRoute(new IPEndPoint(endpoint.NetworkAddress, port), transport));
            }
        }
    }
}
