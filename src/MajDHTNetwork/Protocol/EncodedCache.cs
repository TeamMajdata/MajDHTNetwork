using System;
using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Caches immutable objects parsed and verified from canonical bytes, keyed by the digest of those bytes, so that a
    /// contact or record that arrives repeatedly, for example the sender of every request, is verified and allocated once.
    /// </summary>
    /// <typeparam name="T">The immutable parsed type.</typeparam>
    internal sealed class EncodedCache<T> where T : class
    {
        /// <summary>Parses and verifies canonical bytes into an owned immutable object.</summary>
        /// <param name="encoded">The borrowed canonical bytes.</param>
        /// <returns>The verified object, which must copy any bytes it retains.</returns>
        internal delegate T Parser(ReadOnlyMemory<byte> encoded);

        /// <summary>Checks whether a cached object still represents some canonical bytes.</summary>
        /// <param name="item">The cached object.</param>
        /// <param name="encoded">The canonical bytes being looked up.</param>
        /// <returns>Whether the object was parsed from exactly these bytes and has not become stale, for example by expiring.</returns>
        internal delegate bool Validator(T item, ReadOnlySpan<byte> encoded);

        /// <summary>Protects the entries and the eviction order.</summary>
        private readonly object _gate = new object();
        /// <summary>The cached objects keyed by the digest of their canonical bytes.</summary>
        private readonly Dictionary<DigestKey, T> _entries = new Dictionary<DigestKey, T>();
        /// <summary>The keys in insertion order, for first-in first-out eviction.</summary>
        private readonly Queue<DigestKey> _order = new Queue<DigestKey>();
        /// <summary>The maximum number of cached objects.</summary>
        private readonly int _capacity;
        /// <summary>The parser invoked on a miss.</summary>
        private readonly Parser _parse;
        /// <summary>The validator applied on a hit.</summary>
        private readonly Validator _isCurrent;

        /// <summary>Creates a bounded cache.</summary>
        /// <param name="capacity">The maximum number of cached objects, at least one.</param>
        /// <param name="parse">The parser invoked on a miss; it must verify the bytes and copy what it retains.</param>
        /// <param name="isCurrent">The validator confirming that a hit matches the bytes exactly and is not stale.</param>
        /// <exception cref="ArgumentOutOfRangeException">The capacity is below one.</exception>
        internal EncodedCache(int capacity, Parser parse, Validator isCurrent)
        {
            if (capacity < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(capacity));
            }
            _capacity = capacity;
            _parse = parse;
            _isCurrent = isCurrent;
        }

        /// <summary>Gets the object parsed from canonical bytes, parsing and caching it on a miss.</summary>
        /// <param name="encoded">The borrowed canonical bytes; the cache never retains them.</param>
        /// <returns>The verified object.</returns>
        /// <remarks>Parsing runs outside the lock, so two concurrent misses for the same bytes may both parse; the first result is kept.</remarks>
        internal T Get(ReadOnlyMemory<byte> encoded)
        {
            var key = DigestKey.Of(encoded.Span);
            lock (_gate)
            {
                if (_entries.TryGetValue(key, out var found))
                {
                    if (_isCurrent(found, encoded.Span))
                    {
                        return found;
                    }
                    _entries.Remove(key);
                }
            }
            var item = _parse(encoded);
            lock (_gate)
            {
                if (_entries.TryGetValue(key, out var existing))
                {
                    return existing;
                }
                while (_entries.Count >= _capacity && _order.Count != 0)
                {
                    _entries.Remove(_order.Dequeue());
                }
                _entries.Add(key, item);
                _order.Enqueue(key);
            }
            return item;
        }

        /// <summary>Gets the number of cached objects.</summary>
        internal int Count
        {
            get
            {
                lock (_gate)
                {
                    return _entries.Count;
                }
            }
        }
    }
}
