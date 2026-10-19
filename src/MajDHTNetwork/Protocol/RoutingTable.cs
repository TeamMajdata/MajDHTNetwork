using System;
using System.Buffers;
using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Maintains bounded XOR buckets with lazy allocation and pooled nearest-peer snapshots.</summary>
    internal sealed class RoutingTable
    {
        /// <summary>Protects the routing entries and count.</summary>
        private readonly object _gate = new object();
        /// <summary>The local routing digest.</summary>
        private readonly byte[] _self;
        /// <summary>The per-bucket capacity.</summary>
        private readonly int _capacity;
        /// <summary>The sparse distance buckets; empty buckets allocate no lists.</summary>
        private readonly List<DHTPeer>?[] _buckets = new List<DHTPeer>?[256];
        /// <summary>The total retained entry count.</summary>
        private int _count;

        /// <summary>Creates an empty routing table.</summary>
        /// <param name="nodeId">The local routing ID.</param>
        /// <param name="capacity">The maximum peers in each bucket.</param>
        internal RoutingTable(string nodeId, int capacity)
        {
            _self = Crypto.ParseHash(nodeId);
            _capacity = capacity;
        }

        /// <summary>Computes the most significant differing bit without temporary identifier arrays.</summary>
        /// <param name="id">The remote node digest.</param>
        /// <returns>The distance bucket, or minus one for self.</returns>
        private int Bucket(ReadOnlySpan<byte> id)
        {
            for (var i = 0; i < id.Length; i++)
            {
                var difference = id[i] ^ _self[i];
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

        /// <summary>Records an authenticated contact without displacing a live full bucket.</summary>
        /// <param name="peer">The verified contact.</param>
        internal void Observe(DHTPeer peer)
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
                        if (bucket[i].ExpiresAt > peer.ExpiresAt)
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
        internal void Remove(string nodeId)
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
        /// <param name="target">The canonical target ID.</param>
        /// <param name="count">The maximum results.</param>
        /// <returns>An owned small peer list.</returns>
        internal List<DHTPeer> Closest(string target, int count)
        {
            var comparer = new DistanceComparer(target);
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
                var result = new List<DHTPeer>(Math.Min(count, length));
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

        /// <summary>Sorts a caller-owned candidate list without parsing each peer ID again.</summary>
        /// <param name="peers">The candidate list.</param>
        /// <param name="target">The routing target.</param>
        internal static void Sort(List<DHTPeer> peers, string target)
        {
            peers.Sort(new DistanceComparer(target));
        }

        /// <summary>Compares cached peer digests against one owned target digest.</summary>
        private sealed class DistanceComparer : IComparer<DHTPeer>
        {
            /// <summary>The target digest reused for every comparison.</summary>
            private readonly byte[] _target;

            /// <summary>Parses a target once for an entire sort.</summary>
            /// <param name="target">The canonical target.</param>
            internal DistanceComparer(string target)
            {
                _target = Crypto.ParseHash(target);
            }

            /// <inheritdoc />
            public int Compare(DHTPeer? left, DHTPeer? right)
            {
                if (ReferenceEquals(left, right))
                {
                    return 0;
                }
                if (left == null)
                {
                    return -1;
                }
                if (right == null)
                {
                    return 1;
                }
                var a = left.NodeHash;
                var b = right.NodeHash;
                for (var i = 0; i < _target.Length; i++)
                {
                    var order = (a[i] ^ _target[i]).CompareTo(b[i] ^ _target[i]);
                    if (order != 0)
                    {
                        return order;
                    }
                }
                return 0;
            }
        }
    }
}
