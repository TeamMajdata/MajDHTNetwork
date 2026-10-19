using System;
using System.Buffers;
using System.Collections.Generic;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>The default routing table: bounded Kademlia XOR buckets with lazy allocation and pooled nearest-peer snapshots.</summary>
    public sealed class KademliaDHTRoutingTable : IDHTRoutingTable
    {
        /// <summary>Protects the routing entries and count.</summary>
        private readonly object _gate = new object();
        /// <summary>The sparse distance buckets; empty buckets allocate no lists.</summary>
        private readonly List<DHTPeer>?[] _buckets = new List<DHTPeer>?[256];
        /// <summary>The local routing digest, or null before initialization.</summary>
        private byte[]? _self;
        /// <summary>The per-bucket capacity.</summary>
        private int _capacity;
        /// <summary>The total retained entry count.</summary>
        private int _count;

        /// <inheritdoc />
        /// <exception cref="ArgumentException">The node identifier or bucket size is invalid.</exception>
        public void Initialize(string localNodeId, int bucketSize)
        {
            if (bucketSize < 1)
            {
                throw new ArgumentException("A routing bucket must hold at least one contact.", nameof(bucketSize));
            }
            var self = Crypto.ParseHash(localNodeId);
            lock (_gate)
            {
                if (_self != null)
                {
                    throw new InvalidOperationException("The routing table is already bound to a node.");
                }
                _self = self;
                _capacity = bucketSize;
            }
        }

        /// <summary>Computes the most significant differing bit without temporary identifier arrays.</summary>
        /// <param name="id">The remote node digest.</param>
        /// <returns>The distance bucket, or minus one for self.</returns>
        /// <exception cref="InvalidOperationException">The table has not been initialized.</exception>
        private int Bucket(ReadOnlySpan<byte> id)
        {
            var self = _self ?? throw new InvalidOperationException("The routing table has not been initialized.");
            for (var i = 0; i < id.Length; i++)
            {
                var difference = id[i] ^ self[i];
                if (difference == 0)
                {
                    continue;
                }
                var bit = 7;
                while ((difference & (1 << bit)) == 0)
                {
                    bit--;
                }
                return ((31 - i) * 8) + bit;
            }
            return -1;
        }

        /// <summary>Records an authenticated contact without displacing a live full bucket; a higher sequence replaces a known contact.</summary>
        /// <param name="peer">The verified contact.</param>
        /// <exception cref="InvalidOperationException">The table has not been initialized.</exception>
        public void Observe(DHTPeer peer)
        {
            var index = Bucket(peer.NodeHash);
            if (index < 0 || peer.IsExpired)
            {
                return;
            }
            lock (_gate)
            {
                var bucket = _buckets[index] ??= new List<DHTPeer>(_capacity);
                for (var i = bucket.Count - 1; i >= 0; i--)
                {
                    if (bucket[i].NodeId == peer.NodeId)
                    {
                        if (bucket[i].Sequence > peer.Sequence)
                        {
                            peer = bucket[i];
                        }
                        bucket.RemoveAt(i);
                        _count--;
                    }
                    else if (bucket[i].IsExpired)
                    {
                        bucket.RemoveAt(i);
                        _count--;
                    }
                }
                if (bucket.Count < _capacity)
                {
                    bucket.Add(peer);
                    _count++;
                }
            }
        }

        /// <summary>Removes an unreachable peer using stack-based identifier parsing.</summary>
        /// <param name="nodeId">The canonical peer ID.</param>
        /// <exception cref="InvalidOperationException">The table has not been initialized.</exception>
        public void Remove(string nodeId)
        {
            Span<byte> id = stackalloc byte[32];
            Crypto.ParseHash(nodeId, id);
            var index = Bucket(id);
            if (index < 0)
            {
                return;
            }
            lock (_gate)
            {
                var bucket = _buckets[index];
                if (bucket == null)
                {
                    return;
                }
                for (var i = bucket.Count - 1; i >= 0; i--)
                {
                    if (bucket[i].NodeId == nodeId)
                    {
                        bucket.RemoveAt(i);
                        _count--;
                    }
                }
            }
        }

        /// <summary>Returns the nearest live peers using pooled sorting storage.</summary>
        /// <param name="routingId">The canonical target ID.</param>
        /// <param name="count">The maximum results.</param>
        /// <returns>An owned small peer list.</returns>
        public IReadOnlyList<DHTPeer> Closest(string routingId, int count)
        {
            var comparer = new XorDistanceComparer(routingId);
            DHTPeer[] entries;
            var length = 0;
            lock (_gate)
            {
                if (_count == 0)
                {
                    return new List<DHTPeer>();
                }
                entries = ArrayPool<DHTPeer>.Shared.Rent(_count);
                foreach (var bucket in _buckets)
                {
                    if (bucket == null)
                    {
                        continue;
                    }
                    for (var i = bucket.Count - 1; i >= 0; i--)
                    {
                        if (bucket[i].IsExpired)
                        {
                            bucket.RemoveAt(i);
                            _count--;
                        }
                        else
                        {
                            entries[length++] = bucket[i];
                        }
                    }
                }
            }
            try
            {
                Array.Sort(entries, 0, length, comparer);
                var result = new List<DHTPeer>(Math.Max(0, Math.Min(count, length)));
                for (var i = 0; i < Math.Min(count, length); i++)
                {
                    result.Add(entries[i]);
                }
                return result;
            }
            finally
            {
                ArrayPool<DHTPeer>.Shared.Return(entries, clearArray: true);
            }
        }
    }
}
