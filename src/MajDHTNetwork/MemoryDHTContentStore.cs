using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>A bounded least-recently-used store with copied writes and stable read-only block views.</summary>
    public sealed class MemoryDHTContentStore : IDHTContentStore
    {
        /// <summary>Protects the cache and accounting.</summary>
        private readonly object _gate = new object();
        /// <summary>The maximum retained bytes.</summary>
        private readonly long _capacity;
        /// <summary>The entries indexed by leaf identifier.</summary>
        private readonly Dictionary<string, (byte[] Bytes, LinkedListNode<string> Node)> _entries = new Dictionary<string, (byte[], LinkedListNode<string>)>();
        /// <summary>The most recently used leaf first.</summary>
        private readonly LinkedList<string> _lru = new LinkedList<string>();
        /// <summary>The total retained bytes.</summary>
        private long _size;
        /// <summary>The maximum entry count, also bounding empty-block storage.</summary>
        private readonly int _maxEntries;

        /// <summary>Creates an in-memory cache.</summary>
        /// <param name="capacity">The maximum bytes, at least 32 KiB.</param>
        /// <param name="maxEntries">The maximum retained blocks.</param>
        /// <exception cref="ArgumentOutOfRangeException">A bound is invalid.</exception>
        public MemoryDHTContentStore(long capacity = 64L * 1024 * 1024, int maxEntries = 65536)
        {
            if (capacity < 32768 || maxEntries < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(capacity));
            }
            _capacity = capacity;
            _maxEntries = maxEntries;
        }

        /// <inheritdoc />
        public ValueTask PutAsync(string blockHash, ReadOnlyMemory<byte> content, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (content.Length > 32768)
            {
                throw new ArgumentException("A content block cannot exceed 32 KiB.", nameof(content));
            }
            Span<byte> expected = stackalloc byte[32];
            Span<byte> actual = stackalloc byte[32];
            Crypto.ParseHash(blockHash, expected);
            MerkleTree.Leaf(content.Span, actual);
            if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                throw new ArgumentException("The block does not match its leaf identifier.", nameof(content));
            }
            lock (_gate)
            {
                if (_entries.TryGetValue(blockHash, out var existing))
                {
                    _lru.Remove(existing.Node);
                    _lru.AddFirst(existing.Node);
                    return default;
                }
                var bytes = content.ToArray();
                while (_size + bytes.Length > _capacity || _entries.Count >= _maxEntries)
                {
                    var oldest = _lru.Last!;
                    _size -= _entries[oldest.Value].Bytes.Length;
                    _entries.Remove(oldest.Value);
                    _lru.RemoveLast();
                }
                _entries.Add(blockHash, (bytes, _lru.AddFirst(blockHash)));
                _size += bytes.Length;
            }
            return default;
        }

        /// <inheritdoc />
        public ValueTask<ReadOnlyMemory<byte>?> GetAsync(string blockHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (!_entries.TryGetValue(blockHash, out var entry))
                {
                    return new ValueTask<ReadOnlyMemory<byte>?>((ReadOnlyMemory<byte>?)null);
                }
                _lru.Remove(entry.Node);
                _lru.AddFirst(entry.Node);
                return new ValueTask<ReadOnlyMemory<byte>?>(new ReadOnlyMemory<byte>(entry.Bytes));
            }
        }
    }
}
