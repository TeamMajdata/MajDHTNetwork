using System;
using System.Collections.Generic;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// The default route selection: verified or configured endpoints first, then unverified and local endpoints; the
    /// destination's relay hints before other routed relays. Within each tier, routes and relays with a lower measured
    /// packet loss rate come first, and equal rates keep their natural order.
    /// </summary>
    public sealed class DefaultDHTRouteSelector : IDHTRouteSelector
    {
        /// <summary>
        /// Orders configured or verified endpoints, then unverified endpoints, then local endpoints. Within each tier the
        /// routes with the lowest measured loss come first; untried routes count as lossless, and equal rates keep the
        /// preferred transport before the alternate transport. A private destination's local endpoints are only selected
        /// when both nodes share an external address.
        /// </summary>
        /// <param name="destination">The signed destination contact.</param>
        /// <param name="context">The local node's routing state and loss statistics.</param>
        /// <returns>The direct attempts in order.</returns>
        public IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context)
        {
            var result = new List<DHTDirectRoute>();
            var sameNetwork = context.SharesExternalAddress(destination);
            for (var pass = 0; pass < 3; pass++)
            {
                var tier = new List<DHTDirectRoute>();
                foreach (var endpoint in destination.Endpoints)
                {
                    var local = (endpoint.Flags & DHTEndpointFlags.Local) != 0;
                    var rank = endpoint.IsReachable ? 0 : local ? 2 : 1;
                    if (rank != pass || (local && destination.Reachability == DHTReachability.Private && !sameNetwork))
                    {
                        continue;
                    }
                    AddDirectRoute(tier, endpoint, context.PreferredTransport);
                    AddDirectRoute(tier, endpoint, context.AlternateTransport);
                }
                result.AddRange(OrderByLoss(tier, route => context.PacketLossRate(destination.NodeId, route)));
            }
            return result;
        }

        /// <summary>
        /// Lists the destination's relay hints, then at most <see cref="DHTRouteContext.MaxRelayAttempts"/> other routed relays,
        /// each group ordered by the relays' measured packet loss. Punching is requested unless the destination reported an
        /// endpoint-dependent mapping, and through a hinted relay only when this node is already registered with it.
        /// </summary>
        /// <param name="destination">The signed destination contact, including its relay hints.</param>
        /// <param name="knownRelays">Routed relay-capable contacts, nearest to the destination first.</param>
        /// <param name="context">The local node's routing state and loss statistics.</param>
        /// <returns>The relay attempts in order.</returns>
        public IReadOnlyList<DHTRelayRoute> SelectRelayRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownRelays, DHTRouteContext context)
        {
            var result = new List<DHTRelayRoute>();
            var selected = new HashSet<string>();
            var punchable = context.NatTraversalEnabled && !destination.HasEndpointDependentMapping;
            var hints = new List<DHTPeer>();
            foreach (var hint in destination.RelayHints)
            {
                if (selected.Add(hint.NodeId))
                {
                    hints.Add(hint);
                }
            }
            foreach (var hint in OrderByLoss(hints, relay => context.PacketLossRate(relay.NodeId)))
            {
                // Registering with a hinted relay only to punch would consume a relay slot, so forward instead.
                result.Add(new DHTRelayRoute(hint, punchable && context.IsRegisteredWith(hint.NodeId)));
            }
            var routed = new List<DHTPeer>();
            foreach (var relay in knownRelays)
            {
                if (relay.NodeId != destination.NodeId && (relay.Capabilities & DHTCapabilities.Relay) != 0 && selected.Add(relay.NodeId))
                {
                    routed.Add(relay);
                }
            }
            var ordered = OrderByLoss(routed, relay => context.PacketLossRate(relay.NodeId));
            for (var index = 0; index < ordered.Count && index < context.MaxRelayAttempts; index++)
            {
                result.Add(new DHTRelayRoute(ordered[index], punchable));
            }
            return result;
        }

        /// <summary>Stably orders items by ascending loss rate, so equal rates keep their original order.</summary>
        /// <typeparam name="T">The item type.</typeparam>
        /// <param name="items">The items in their natural order.</param>
        /// <param name="lossRate">Gets an item's loss rate.</param>
        /// <returns>A new ordered list.</returns>
        private static List<T> OrderByLoss<T>(List<T> items, Func<T, double> lossRate)
        {
            var keyed = new List<(double Loss, int Index, T Item)>(items.Count);
            for (var index = 0; index < items.Count; index++)
            {
                keyed.Add((lossRate(items[index]), index, items[index]));
            }
            keyed.Sort((left, right) => left.Loss != right.Loss ? left.Loss.CompareTo(right.Loss) : left.Index.CompareTo(right.Index));
            var result = new List<T>(keyed.Count);
            foreach (var entry in keyed)
            {
                result.Add(entry.Item);
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
