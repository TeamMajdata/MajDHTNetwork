using System;
using System.Collections.Generic;
using System.Net;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// The default route selection: the destination's observed endpoints, most recently observed first, then the destination's
    /// hints before other routed Traversal and Forwarder nodes. Within each tier, routes and assistants with a lower measured
    /// packet loss rate come first, and equal rates keep their natural order.
    /// </summary>
    public sealed class DefaultDHTRouteSelector : IDHTRouteSelector
    {
        /// <summary>
        /// Lists the destination's observed endpoints, most recently observed first, each with the preferred and then the
        /// alternate transport; routes with the lowest measured loss come first and untried routes count as lossless. A private
        /// destination has no direct routes: its observed endpoints are NAT mappings that failed an independent dial-back.
        /// </summary>
        /// <param name="destination">The destination at its observed endpoints.</param>
        /// <param name="context">The local node's routing state and loss statistics.</param>
        /// <returns>The direct attempts in order.</returns>
        public IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context)
        {
            var routes = new List<DHTDirectRoute>();
            if (destination.Reachability == DHTReachability.Private)
            {
                return routes;
            }
            for (var index = destination.Endpoints.Count - 1; index >= 0; index--)
            {
                AddDirectRoute(routes, destination.Endpoints[index], context.PreferredTransport);
                AddDirectRoute(routes, destination.Endpoints[index], context.AlternateTransport);
            }
            return OrderByLoss(routes, route => context.PacketLossRate(destination.NodeId, route));
        }

        /// <summary>
        /// Lists the destination's hints, then at most <see cref="DHTRouteContext.MaxAssistedAttempts"/> assistants drawn from
        /// the nearest twice that many routed assistants in random order, each group ordered by the assistants' measured packet
        /// loss. Punching is requested from Traversal nodes unless the destination reported an endpoint-dependent mapping, and
        /// through a hinted Traversal node only when this node is already registered with it.
        /// </summary>
        /// <param name="destination">The destination, whose contact carries its hints.</param>
        /// <param name="knownAssistants">Routed Traversal or Forwarder nodes, nearest to the destination first.</param>
        /// <param name="context">The local node's routing state and loss statistics.</param>
        /// <returns>The assisted attempts in order.</returns>
        public IReadOnlyList<DHTAssistedRoute> SelectAssistedRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownAssistants, DHTRouteContext context)
        {
            var result = new List<DHTAssistedRoute>();
            var selected = new HashSet<string>(StringComparer.Ordinal);
            var punchable = context.NatTraversalEnabled && !destination.HasEndpointDependentMapping;
            var hints = new List<DHTPeer>();
            foreach (var hint in destination.Hints)
            {
                if (selected.Add(hint.NodeId))
                {
                    hints.Add(hint);
                }
            }
            foreach (var hint in OrderByLoss(hints, assistant => context.PacketLossRate(assistant.NodeId)))
            {
                // Registering with a hinted Traversal node only to punch would consume a registration slot, so forward instead.
                result.Add(new DHTAssistedRoute(hint, punchable && IsTraversal(hint) && context.IsRegisteredWith(hint.NodeId)));
            }
            var routed = new List<DHTPeer>();
            foreach (var assistant in knownAssistants)
            {
                if (routed.Count >= context.MaxAssistedAttempts * 2)
                {
                    break;
                }
                if (assistant.NodeId != destination.NodeId
                    && (assistant.Capabilities & (DHTCapabilities.Traversal | DHTCapabilities.Forwarder)) != 0 && selected.Add(assistant.NodeId))
                {
                    routed.Add(assistant);
                }
            }
            // Shuffling the nearest candidates before the stable loss ordering randomizes ties, so identities minted near a
            // destination cannot predictably capture its assisted traffic.
            Crypto.Shuffle(routed);
            var ordered = OrderByLoss(routed, assistant => context.PacketLossRate(assistant.NodeId));
            for (var index = 0; index < ordered.Count && index < context.MaxAssistedAttempts; index++)
            {
                result.Add(new DHTAssistedRoute(ordered[index], punchable && IsTraversal(ordered[index])));
            }
            return result;
        }

        /// <summary>Checks whether a peer coordinates hole punching.</summary>
        /// <param name="peer">The peer.</param>
        /// <returns>Whether it advertises the Traversal capability.</returns>
        private static bool IsTraversal(DHTPeer peer)
        {
            return (peer.Capabilities & DHTCapabilities.Traversal) != 0;
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

        /// <summary>Adds the direct attempt for one transport when the node was observed over it at the endpoint.</summary>
        /// <param name="routes">The routes under construction.</param>
        /// <param name="endpoint">The observed endpoint.</param>
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
