using System;
using System.Collections.Generic;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>A snapshot of the local node state that informs route selection.</summary>
    public sealed class DHTRouteContext
    {
        /// <summary>The relays this node holds a live rendezvous registration with.</summary>
        private readonly HashSet<string> _registeredRelays;
        /// <summary>Looks up the node's lifetime statistics for a peer, or null when statistics are unavailable.</summary>
        private readonly Func<string, DHTPeerStatistics?>? _statistics;

        /// <summary>Gets the transport the node prefers for outgoing requests.</summary>
        public DHTTransport PreferredTransport { get; }
        /// <summary>Gets whether the node may register with relays and attempt hole punching.</summary>
        public bool NatTraversalEnabled { get; }
        /// <summary>Gets the external addresses confirmed by independent relays.</summary>
        public IReadOnlyList<IPAddress> ExternalAddresses { get; }
        /// <summary>Gets the configured relay attempt budget for routed relays, which is <see cref="DHTNodeOptions.BucketSize"/>.</summary>
        public int MaxRelayAttempts { get; }

        /// <summary>Creates a routing state snapshot.</summary>
        /// <param name="preferredTransport">The preferred outgoing transport.</param>
        /// <param name="natTraversalEnabled">Whether hole punching is permitted.</param>
        /// <param name="externalAddresses">The confirmed external addresses; they are copied.</param>
        /// <param name="registeredRelays">The identifiers of relays with live registrations; they are copied.</param>
        /// <param name="maxRelayAttempts">The routed relay attempt budget.</param>
        /// <param name="statistics">An optional lookup of per-peer statistics, normally <see cref="MajDHTNode.GetPeerStatistics"/>.</param>
        /// <exception cref="ArgumentException">The transport or budget is invalid, or a collection is null.</exception>
        public DHTRouteContext(DHTTransport preferredTransport, bool natTraversalEnabled, IEnumerable<IPAddress> externalAddresses,
            IEnumerable<string> registeredRelays, int maxRelayAttempts, Func<string, DHTPeerStatistics?>? statistics = null)
        {
            if ((preferredTransport != DHTTransport.Tcp && preferredTransport != DHTTransport.Udp) || maxRelayAttempts < 0
                || externalAddresses == null || registeredRelays == null)
            {
                throw new ArgumentException("Invalid route selection context.");
            }
            var addresses = new List<IPAddress>();
            foreach (var address in externalAddresses)
            {
                addresses.Add(IPAddress.Parse(address.ToString()));
            }
            PreferredTransport = preferredTransport;
            NatTraversalEnabled = natTraversalEnabled;
            ExternalAddresses = addresses;
            _registeredRelays = new HashSet<string>(registeredRelays, StringComparer.Ordinal);
            MaxRelayAttempts = maxRelayAttempts;
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

        /// <summary>Checks whether this node holds a live registration with a relay, which hole punching through it requires.</summary>
        /// <param name="relayNodeId">The relay identifier.</param>
        /// <returns>Whether a registration exists.</returns>
        public bool IsRegisteredWith(string relayNodeId)
        {
            return relayNodeId != null && _registeredRelays.Contains(relayNodeId);
        }

        /// <summary>Checks whether a contact shares one of this node's confirmed external addresses, which implies the same NAT.</summary>
        /// <param name="peer">The remote contact.</param>
        /// <returns>Whether both nodes share an external address.</returns>
        public bool SharesExternalAddress(DHTPeer peer)
        {
            var external = peer?.ExternalNetworkAddress;
            if (external == null)
            {
                return false;
            }
            foreach (var address in ExternalAddresses)
            {
                if (address.Equals(external))
                {
                    return true;
                }
            }
            return false;
        }
    }
}
