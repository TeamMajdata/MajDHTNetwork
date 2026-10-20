using System;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>An immutable snapshot of the transmissions a node sent to a peer over one endpoint and transport.</summary>
    public sealed class DHTRouteStatistics
    {
        /// <summary>The owned remote endpoint.</summary>
        private readonly IPEndPoint _endpoint;

        /// <summary>Gets a copy of the remote endpoint.</summary>
        public IPEndPoint Endpoint => Protocol.NetworkScope.CopyEndpoint(_endpoint);
        /// <summary>Gets the transport.</summary>
        public DHTTransport Transport { get; }
        /// <summary>Gets the number of request transmissions sent over this route.</summary>
        public long SentPackets { get; }
        /// <summary>Gets the number of transmissions over this route that received no response.</summary>
        public long LostPackets { get; }
        /// <summary>Gets the time of the most recent recorded transmission.</summary>
        public DateTimeOffset LastUpdated { get; }
        /// <summary>Gets the fraction of transmissions that were lost, from zero to one; zero when nothing was sent.</summary>
        public double PacketLossRate => SentPackets == 0 ? 0 : (double)LostPackets / SentPackets;

        /// <summary>Creates a route statistics snapshot.</summary>
        /// <param name="endpoint">The remote endpoint; it is copied.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="sentPackets">The number of request transmissions.</param>
        /// <param name="lostPackets">The number of unanswered transmissions, at most <paramref name="sentPackets"/>.</param>
        /// <param name="lastUpdated">The time of the most recent recorded transmission.</param>
        /// <exception cref="ArgumentException">The endpoint, transport or counters are invalid.</exception>
        public DHTRouteStatistics(IPEndPoint endpoint, DHTTransport transport, long sentPackets, long lostPackets, DateTimeOffset lastUpdated)
        {
            if (endpoint == null || (transport != DHTTransport.Tcp && transport != DHTTransport.Udp)
                || sentPackets < 0 || lostPackets < 0 || lostPackets > sentPackets)
            {
                throw new ArgumentException("Invalid route statistics.");
            }
            _endpoint = Protocol.NetworkScope.CopyEndpoint(endpoint);
            Transport = transport;
            SentPackets = sentPackets;
            LostPackets = lostPackets;
            LastUpdated = lastUpdated;
        }

        /// <summary>Checks whether this snapshot describes a route.</summary>
        /// <param name="endpoint">The remote endpoint.</param>
        /// <param name="transport">The transport.</param>
        /// <returns>Whether endpoint and transport match.</returns>
        internal bool Matches(IPEndPoint endpoint, DHTTransport transport)
        {
            return Transport == transport && _endpoint.Equals(endpoint);
        }
    }
}
