using System;
using System.Buffers;
using System.Collections.Generic;
using System.Net;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// The default routing table: bounded Kademlia XOR buckets with lazy allocation, pooled nearest-peer snapshots and
    /// per-network admission limits that stop one operator network from filling the table with Sybil identities.
    /// </summary>
    public sealed class KademliaDHTRoutingTable : IDHTRoutingTable
    {
        /// <summary>Protects the routing entries and count.</summary>
        private readonly object _gate = new object();
        /// <summary>The sparse distance buckets; empty buckets allocate no lists.</summary>
        private readonly List<Entry>?[] _buckets = new List<Entry>?[256];
        /// <summary>The maximum contacts from one globally routed network in a bucket.</summary>
        private readonly int _maxPerNetworkInBucket;
        /// <summary>The maximum contacts from one globally routed network in the whole table.</summary>
        private readonly int _maxPerNetwork;
        /// <summary>The local routing digest, or null before initialization.</summary>
        private byte[]? _self;
        /// <summary>The per-bucket capacity.</summary>
        private int _capacity;
        /// <summary>The total retained entry count.</summary>
        private int _count;

        /// <summary>Creates an unbound table.</summary>
        /// <param name="maxPerNetworkInBucket">
        /// The maximum contacts whose admission addresses share one IPv4 /24 or IPv6 /32 in a bucket, from 1; loopback, private
        /// and link-local addresses are not limited.
        /// </param>
        /// <param name="maxPerNetwork">The maximum contacts from one such network in the whole table, from 1.</param>
        /// <exception cref="ArgumentOutOfRangeException">A limit is below one.</exception>
        public KademliaDHTRoutingTable(int maxPerNetworkInBucket = 2, int maxPerNetwork = 10)
        {
            if (maxPerNetworkInBucket < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxPerNetworkInBucket));
            }
            if (maxPerNetwork < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maxPerNetwork));
            }
            _maxPerNetworkInBucket = maxPerNetworkInBucket;
            _maxPerNetwork = maxPerNetwork;
        }

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

        /// <summary>
        /// Refreshes a known contact and merges a newly observed endpoint, or admits a new contact at an observed endpoint when
        /// its bucket has room and its network is below the per-bucket and per-table limits; a full live bucket is never displaced.
        /// </summary>
        /// <param name="contact">The authenticated contact.</param>
        /// <param name="observed">The endpoint this node exchanged an authenticated packet with, or null to refresh only.</param>
        /// <exception cref="InvalidOperationException">The table has not been initialized.</exception>
        public void Observe(DHTContact contact, DHTEndpoint? observed)
        {
            var index = Bucket(contact.NodeHash);
            if (index < 0 || contact.IsExpired)
            {
                return;
            }
            lock (_gate)
            {
                var bucket = _buckets[index] ??= new List<Entry>(_capacity);
                Entry? known = null;
                for (var i = bucket.Count - 1; i >= 0; i--)
                {
                    if (bucket[i].Contact.NodeId == contact.NodeId)
                    {
                        known = bucket[i];
                        bucket.RemoveAt(i);
                        _count--;
                    }
                    else if (bucket[i].Contact.IsExpired)
                    {
                        bucket.RemoveAt(i);
                        _count--;
                    }
                }
                if (known != null)
                {
                    // Keep the newest contact, merge the observation and move the entry to the most recent position.
                    var newest = known.Contact.Sequence > contact.Sequence ? known.Contact : contact;
                    var endpoints = observed == null ? known.Endpoints : DHTPeer.Merge(known.Endpoints, observed);
                    bucket.Add(new Entry(newest, endpoints, known.Address));
                    _count++;
                    return;
                }
                if (observed == null || bucket.Count >= _capacity || !HasNetworkRoomLocked(bucket, observed.NetworkAddress))
                {
                    return;
                }
                bucket.Add(new Entry(contact, new[] { observed }, observed.NetworkAddress));
                _count++;
            }
        }

        /// <summary>Checks the per-bucket and per-table network limits for a new admission address.</summary>
        /// <param name="bucket">The target bucket.</param>
        /// <param name="address">The admission address.</param>
        /// <returns>Whether the network may add another contact.</returns>
        /// <remarks>The caller must hold the table lock.</remarks>
        private bool HasNetworkRoomLocked(List<Entry> bucket, IPAddress address)
        {
            if (!NetworkScope.IsDiversityLimited(address))
            {
                return true;
            }
            if (CountNetwork(bucket, address) >= _maxPerNetworkInBucket)
            {
                return false;
            }
            var total = 0;
            foreach (var other in _buckets)
            {
                if (other != null)
                {
                    total += CountNetwork(other, address);
                }
            }
            return total < _maxPerNetwork;
        }

        /// <summary>Counts the entries of a bucket whose admission address shares a network with an address.</summary>
        /// <param name="bucket">The bucket.</param>
        /// <param name="address">The address.</param>
        /// <returns>The count.</returns>
        private static int CountNetwork(List<Entry> bucket, IPAddress address)
        {
            var count = 0;
            foreach (var entry in bucket)
            {
                if (NetworkScope.SameNetwork(entry.Address, address))
                {
                    count++;
                }
            }
            return count;
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
                    if (bucket[i].Contact.NodeId == nodeId)
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
                        if (bucket[i].Contact.IsExpired)
                        {
                            bucket.RemoveAt(i);
                            _count--;
                        }
                        else
                        {
                            entries[length++] = bucket[i].Peer;
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

        /// <summary>Associates a contact with the endpoints this node observed for it and the address that admitted it.</summary>
        private sealed class Entry
        {
            /// <summary>Gets the contact at its observed endpoints.</summary>
            internal DHTPeer Peer { get; }
            /// <summary>Gets the newest contact.</summary>
            internal DHTContact Contact => Peer.Contact;
            /// <summary>Gets the observed endpoints.</summary>
            internal IReadOnlyList<DHTEndpoint> Endpoints => Peer.Endpoints;
            /// <summary>Gets the address of the first observation, which counts towards the network limits.</summary>
            internal IPAddress Address { get; }

            /// <summary>Creates an entry.</summary>
            /// <param name="contact">The contact.</param>
            /// <param name="endpoints">The observed endpoints.</param>
            /// <param name="address">The admission address.</param>
            internal Entry(DHTContact contact, IReadOnlyList<DHTEndpoint> endpoints, IPAddress address)
            {
                Peer = new DHTPeer(contact, endpoints);
                Address = address;
            }
        }
    }
}
