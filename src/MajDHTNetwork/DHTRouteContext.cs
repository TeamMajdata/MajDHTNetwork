using System;
using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>A snapshot of the local node state that informs route selection.</summary>
    public sealed class DHTRouteContext
    {
        /// <summary>The Traversal nodes this node holds a live registration with.</summary>
        private readonly HashSet<string> _registeredTraversalNodes;
        /// <summary>Looks up the node's lifetime statistics for a peer, or null when statistics are unavailable.</summary>
        private readonly Func<string, DHTPeerStatistics?>? _statistics;

        /// <summary>Gets the transport the node prefers for outgoing requests.</summary>
        public DHTTransport PreferredTransport { get; }
        /// <summary>Gets whether the node may register with Traversal nodes and attempt hole punching.</summary>
        public bool NatTraversalEnabled { get; }
        /// <summary>Gets the configured attempt budget for routed assistants, which is <see cref="DHTNodeOptions.BucketSize"/>.</summary>
        public int MaxAssistedAttempts { get; }

        /// <summary>Creates a routing state snapshot.</summary>
        /// <param name="preferredTransport">The preferred outgoing transport.</param>
        /// <param name="natTraversalEnabled">Whether hole punching is permitted.</param>
        /// <param name="registeredTraversalNodes">The identifiers of Traversal nodes with live registrations; they are copied.</param>
        /// <param name="maxAssistedAttempts">The routed assistant attempt budget.</param>
        /// <param name="statistics">An optional lookup of per-peer statistics, normally <see cref="MajDHTNode.GetPeerStatistics"/>.</param>
        /// <exception cref="ArgumentException">The transport or budget is invalid, or the collection is null.</exception>
        public DHTRouteContext(DHTTransport preferredTransport, bool natTraversalEnabled, IEnumerable<string> registeredTraversalNodes,
            int maxAssistedAttempts, Func<string, DHTPeerStatistics?>? statistics = null)
        {
            if ((preferredTransport != DHTTransport.Tcp && preferredTransport != DHTTransport.Udp) || maxAssistedAttempts < 0
                || registeredTraversalNodes == null)
            {
                throw new ArgumentException("Invalid route selection context.");
            }
            PreferredTransport = preferredTransport;
            NatTraversalEnabled = natTraversalEnabled;
            _registeredTraversalNodes = new HashSet<string>(registeredTraversalNodes, StringComparer.Ordinal);
            MaxAssistedAttempts = maxAssistedAttempts;
            _statistics = statistics;
        }

        /// <summary>Gets the statistics the node collected for a peer during its lifetime.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <returns>The peer and per-route statistics, or null when the peer was never contacted directly.</returns>
        public DHTPeerStatistics? GetPeerStatistics(string nodeId)
        {
            return nodeId == null || _statistics == null ? null : _statistics(nodeId);
        }

        /// <summary>Gets a peer's packet loss rate over all routes.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <returns>The loss rate from zero to one, or zero when the peer was never contacted directly.</returns>
        public double PacketLossRate(string nodeId)
        {
            return GetPeerStatistics(nodeId)?.PacketLossRate ?? 0;
        }

        /// <summary>Gets the packet loss rate of one direct route to a peer.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <param name="route">The direct route.</param>
        /// <returns>The loss rate from zero to one, or zero when the route was never used.</returns>
        public double PacketLossRate(string nodeId, DHTDirectRoute route)
        {
            return route == null ? 0 : GetPeerStatistics(nodeId)?.GetRoute(route.NetworkEndpoint, route.Transport)?.PacketLossRate ?? 0;
        }

        /// <summary>Gets the transport tried after the preferred transport.</summary>
        public DHTTransport AlternateTransport => PreferredTransport == DHTTransport.Tcp ? DHTTransport.Udp : DHTTransport.Tcp;

        /// <summary>Checks whether this node holds a live registration with a Traversal node, which hole punching through it requires.</summary>
        /// <param name="traversalNodeId">The Traversal node identifier.</param>
        /// <returns>Whether a registration exists.</returns>
        public bool IsRegisteredWith(string traversalNodeId)
        {
            return traversalNodeId != null && _registeredTraversalNodes.Contains(traversalNodeId);
        }
    }
}
