using System;
using System.Collections.Generic;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>An immutable snapshot of the traffic statistics a node collected for one peer during its lifetime.</summary>
    /// <remarks>
    /// A transmission is one send of a request directly to the peer, including every UDP retransmission and every TCP
    /// attempt; it is lost when no response arrives before the attempt timeout or the connection fails. Hole-punching and
    /// dial-back probes are not counted, and requests forwarded through a relay count towards the relay.
    /// </remarks>
    public sealed class DHTPeerStatistics
    {
        /// <summary>The per-route breakdown.</summary>
        private readonly DHTRouteStatistics[] _routes;

        /// <summary>Gets the peer's node identifier.</summary>
        public string NodeId { get; }
        /// <summary>Gets the number of request transmissions sent to the peer over all routes.</summary>
        public long SentPackets { get; }
        /// <summary>Gets the number of transmissions that received no response.</summary>
        public long LostPackets { get; }
        /// <summary>Gets the time of the most recent recorded transmission.</summary>
        public DateTimeOffset LastUpdated { get; }
        /// <summary>Gets the fraction of transmissions that were lost, from zero to one; zero when nothing was sent.</summary>
        public double PacketLossRate => SentPackets == 0 ? 0 : (double)LostPackets / SentPackets;
        /// <summary>Gets the statistics of each endpoint and transport used to reach the peer.</summary>
        public IReadOnlyList<DHTRouteStatistics> Routes => _routes;

        /// <summary>Creates a statistics snapshot.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <param name="sentPackets">The number of request transmissions.</param>
        /// <param name="lostPackets">The number of unanswered transmissions, at most <paramref name="sentPackets"/>.</param>
        /// <param name="lastUpdated">The time of the most recent recorded transmission.</param>
        /// <param name="routes">The per-route breakdown; it is copied.</param>
        /// <exception cref="ArgumentException">The identifier is empty, the counters are inconsistent or a route is null.</exception>
        public DHTPeerStatistics(string nodeId, long sentPackets, long lostPackets, DateTimeOffset lastUpdated,
            IEnumerable<DHTRouteStatistics> routes)
        {
            if (string.IsNullOrEmpty(nodeId) || sentPackets < 0 || lostPackets < 0 || lostPackets > sentPackets || routes == null)
            {
                throw new ArgumentException("Invalid peer statistics.");
            }
            var copy = new List<DHTRouteStatistics>();
            foreach (var route in routes)
            {
                copy.Add(route ?? throw new ArgumentException("Peer statistics cannot contain a null route.", nameof(routes)));
            }
            NodeId = nodeId;
            SentPackets = sentPackets;
            LostPackets = lostPackets;
            LastUpdated = lastUpdated;
            _routes = copy.ToArray();
        }

        /// <summary>Finds the statistics of one route.</summary>
        /// <param name="endpoint">The remote endpoint.</param>
        /// <param name="transport">The transport.</param>
        /// <returns>The route statistics, or null when the route was never used.</returns>
        public DHTRouteStatistics? GetRoute(IPEndPoint endpoint, DHTTransport transport)
        {
            if (endpoint == null)
            {
                return null;
            }
            foreach (var route in _routes)
            {
                if (route.Matches(endpoint, transport))
                {
                    return route;
                }
            }
            return null;
        }
    }
}
