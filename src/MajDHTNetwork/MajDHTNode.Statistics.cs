using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The maximum number of peers whose statistics are retained; the least recently updated entry is evicted.</summary>
        private const int MaxPeerStatistics = 4096;
        /// <summary>The maximum number of routes retained per peer; the least recently updated route is evicted.</summary>
        private const int MaxRouteStatistics = 16;
        /// <summary>Protects the statistics ledger independently of the main state lock.</summary>
        private readonly object _statisticsGate = new object();
        /// <summary>The per-peer statistics collected during this node's lifetime.</summary>
        private readonly Dictionary<string, PeerCounters> _peerStatistics = new Dictionary<string, PeerCounters>(StringComparer.Ordinal);

        /// <summary>Gets a snapshot of the statistics of every peer contacted during this node's lifetime.</summary>
        public IReadOnlyList<DHTPeerStatistics> PeerStatistics
        {
            get
            {
                lock (_statisticsGate)
                {
                    var result = new List<DHTPeerStatistics>(_peerStatistics.Count);
                    foreach (var entry in _peerStatistics)
                    {
                        result.Add(entry.Value.Snapshot(entry.Key));
                    }
                    return result.AsReadOnly();
                }
            }
        }

        /// <summary>Gets the statistics collected for one peer during this node's lifetime, including its per-route breakdown.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <returns>The snapshot, or null when no transmission to the peer was recorded.</returns>
        public DHTPeerStatistics? GetPeerStatistics(string nodeId)
        {
            lock (_statisticsGate)
            {
                return nodeId != null && _peerStatistics.TryGetValue(nodeId, out var counters) ? counters.Snapshot(nodeId) : null;
            }
        }

        /// <summary>Gets a peer's packet loss rate for provider ranking.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <returns>The loss rate, or zero for an unmeasured peer.</returns>
        private double PacketLossRate(string nodeId)
        {
            lock (_statisticsGate)
            {
                return _peerStatistics.TryGetValue(nodeId, out var counters) ? counters.Total.LossRate : 0;
            }
        }

        /// <summary>Exchanges directly with a peer and records the exchange's transmissions in the peer's statistics.</summary>
        /// <param name="peer">The destination peer.</param>
        /// <param name="transport">The transport.</param>
        /// <param name="endpoint">The remote endpoint.</param>
        /// <param name="envelope">The sealed request.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>The opaque response in its received frame, still requiring authentication and released by the caller.</returns>
        /// <exception cref="IOException">No response arrived.</exception>
        /// <exception cref="OperationCanceledException">The request or node lifetime was cancelled.</exception>
        private async Task<OwnedMemory> ExchangeCountedAsync(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint,
            ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            var counter = new TransmissionCounter();
            try
            {
                return await _transport.ExchangeAtAsync(transport, endpoint, envelope, cancellationToken, counter).ConfigureAwait(false);
            }
            finally
            {
                RecordTransmissions(peer.NodeId, transport, endpoint, counter);
            }
        }

        /// <summary>Adds the transmissions of one completed exchange to a peer's and a route's statistics.</summary>
        /// <param name="nodeId">The peer's node identifier.</param>
        /// <param name="transport">The transport used.</param>
        /// <param name="endpoint">The remote endpoint used.</param>
        /// <param name="counter">The completed exchange's counter.</param>
        private void RecordTransmissions(string nodeId, DHTTransport transport, IPEndPoint endpoint, TransmissionCounter counter)
        {
            if (counter.Sent == 0)
            {
                return;
            }
            var now = DateTimeOffset.UtcNow;
            lock (_statisticsGate)
            {
                if (!_peerStatistics.TryGetValue(nodeId, out var counters))
                {
                    if (_peerStatistics.Count >= MaxPeerStatistics)
                    {
                        EvictOldestLocked(_peerStatistics, entry => entry.Total.LastUpdated);
                    }
                    counters = new PeerCounters();
                    _peerStatistics.Add(nodeId, counters);
                }
                if (!counters.Routes.TryGetValue((transport, endpoint), out var route))
                {
                    if (counters.Routes.Count >= MaxRouteStatistics)
                    {
                        EvictOldestLocked(counters.Routes, entry => entry.LastUpdated);
                    }
                    route = new LinkCounters();
                    // Only a new route copies its endpoint, so the ledger key can never be mutated through a caller's endpoint.
                    counters.Routes.Add((transport, NetworkScope.CopyEndpoint(endpoint)), route);
                }
                counters.Total.Add(counter, now);
                route.Add(counter, now);
            }
        }

        /// <summary>Removes the least recently updated entry of a bounded statistics dictionary.</summary>
        /// <typeparam name="TKey">The key type.</typeparam>
        /// <typeparam name="TValue">The counter type.</typeparam>
        /// <param name="entries">The dictionary.</param>
        /// <param name="lastUpdated">Selects an entry's last update time.</param>
        /// <remarks>The caller must hold the statistics lock.</remarks>
        private static void EvictOldestLocked<TKey, TValue>(Dictionary<TKey, TValue> entries, Func<TValue, DateTimeOffset> lastUpdated)
            where TKey : notnull
        {
            var found = false;
            var oldest = default(TKey);
            var time = DateTimeOffset.MaxValue;
            foreach (var entry in entries)
            {
                var updated = lastUpdated(entry.Value);
                if (updated < time)
                {
                    found = true;
                    oldest = entry.Key;
                    time = updated;
                }
            }
            if (found)
            {
                entries.Remove(oldest!);
            }
        }

        /// <summary>Holds the mutable counters of one peer and its routes under the statistics lock.</summary>
        private sealed class PeerCounters
        {
            /// <summary>Gets the counters over all routes.</summary>
            internal LinkCounters Total { get; } = new LinkCounters();
            /// <summary>Gets the counters of each transport and endpoint.</summary>
            internal Dictionary<(DHTTransport Transport, IPEndPoint Endpoint), LinkCounters> Routes { get; } =
                new Dictionary<(DHTTransport, IPEndPoint), LinkCounters>();

            /// <summary>Creates an immutable snapshot.</summary>
            /// <param name="nodeId">The peer's node identifier.</param>
            /// <returns>The snapshot.</returns>
            internal DHTPeerStatistics Snapshot(string nodeId)
            {
                var routes = new List<DHTRouteStatistics>(Routes.Count);
                foreach (var entry in Routes)
                {
                    routes.Add(new DHTRouteStatistics(entry.Key.Endpoint, entry.Key.Transport, entry.Value.Sent, entry.Value.Lost,
                        entry.Value.LastUpdated));
                }
                return new DHTPeerStatistics(nodeId, Total.Sent, Total.Lost, Total.LastUpdated, routes);
            }
        }

        /// <summary>Holds the mutable transmission counters of one peer or route.</summary>
        private sealed class LinkCounters
        {
            /// <summary>Gets the number of transmissions.</summary>
            internal long Sent { get; private set; }
            /// <summary>Gets the number of unanswered transmissions.</summary>
            internal long Lost { get; private set; }
            /// <summary>Gets the time of the most recent update.</summary>
            internal DateTimeOffset LastUpdated { get; private set; }
            /// <summary>Gets the loss rate, or zero when nothing was sent.</summary>
            internal double LossRate => Sent == 0 ? 0 : (double)Lost / Sent;

            /// <summary>Adds one exchange's transmissions.</summary>
            /// <param name="counter">The completed exchange's counter.</param>
            /// <param name="now">The update time.</param>
            internal void Add(TransmissionCounter counter, DateTimeOffset now)
            {
                Sent += counter.Sent;
                Lost += counter.Lost;
                LastUpdated = now;
            }
        }
    }
}
