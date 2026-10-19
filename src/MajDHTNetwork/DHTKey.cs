using System;
using System.Text;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>A publisher-scoped, case-sensitive key whose owner cannot be substituted by a DHT peer.</summary>
    /// <remarks>The default value is uninitialized; use <see cref="IsValid"/> before accessing its components.</remarks>
    public readonly struct DHTKey : IEquatable<DHTKey>
    {
        /// <summary>The strict UTF-8 codec used to validate names and derive routing identifiers.</summary>
        private static readonly UTF8Encoding s_utf8 = new UTF8Encoding(false, true);
        /// <summary>The publisher fingerprint, or null for an uninitialized key.</summary>
        private readonly string? _publisherId;
        /// <summary>The case-sensitive name, or null for an uninitialized key.</summary>
        private readonly string? _name;
        /// <summary>The cached routing identifier, or null for an uninitialized key.</summary>
        private readonly string? _routingId;

        /// <summary>Gets whether this value was initialized with a valid publisher and name.</summary>
        public bool IsValid
        {
            get
            {
                return _routingId != null;
            }
        }

        /// <summary>Gets the publisher signing-key fingerprint.</summary>
        /// <exception cref="InvalidOperationException">The key is uninitialized.</exception>
        public string PublisherId
        {
            get
            {
                return _publisherId ?? throw new InvalidOperationException("An uninitialized key has no publisher.");
            }
        }

        /// <summary>Gets the case-sensitive UTF-8 name in the publisher namespace.</summary>
        /// <exception cref="InvalidOperationException">The key is uninitialized.</exception>
        public string Name
        {
            get
            {
                return _name ?? throw new InvalidOperationException("An uninitialized key has no name.");
            }
        }

        /// <summary>Gets the SHA-256 routing identifier of the canonical key.</summary>
        /// <exception cref="InvalidOperationException">The key is uninitialized.</exception>
        public string RoutingId
        {
            get
            {
                return _routingId ?? throw new InvalidOperationException("An uninitialized key has no routing identifier.");
            }
        }

        /// <summary>Creates an owner-scoped key without retaining temporary encoding buffers.</summary>
        /// <param name="publisherId">The trusted SHA-256 publisher fingerprint.</param>
        /// <param name="name">A nonempty UTF-8 name of at most 256 bytes, with no control characters.</param>
        /// <exception cref="ArgumentException">The identifier or name is invalid.</exception>
        public DHTKey(string publisherId, string name)
        {
            Span<byte> digest = stackalloc byte[32];
            Crypto.ParseHash(publisherId, digest);
            if (string.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("A key name must contain between 1 and 256 UTF-8 bytes.", nameof(name));
            }
            var nameByteCount = s_utf8.GetByteCount(name);
            if (nameByteCount > 256)
            {
                throw new ArgumentException("A key name must contain between 1 and 256 UTF-8 bytes.", nameof(name));
            }
            foreach (var value in name)
            {
                if (char.IsControl(value))
                {
                    throw new ArgumentException("A key name cannot contain control characters.", nameof(name));
                }
            }
            Span<byte> canonical = stackalloc byte[65 + nameByteCount];
            s_utf8.GetBytes(publisherId.AsSpan(), canonical.Slice(0, 64));
            canonical[64] = (byte)':';
            s_utf8.GetBytes(name.AsSpan(), canonical.Slice(65));
            Crypto.Hash(canonical, digest);
            _publisherId = publisherId;
            _name = name;
            _routingId = Crypto.Hex(digest);
        }

        /// <summary>Parses a canonical publisher fingerprint followed by a colon and key name.</summary>
        /// <param name="value">The canonical key.</param>
        /// <returns>The parsed key.</returns>
        /// <exception cref="ArgumentException">The key is invalid or noncanonical.</exception>
        public static DHTKey Parse(string value)
        {
            if (value == null || value.Length < 66 || value[64] != ':')
            {
                throw new ArgumentException("Expected publisher-fingerprint:name.", nameof(value));
            }
            return new DHTKey(value.Substring(0, 64), value.Substring(65));
        }

        /// <summary>Formats the canonical key, or an empty string for an uninitialized value.</summary>
        /// <returns>The publisher fingerprint followed by a colon and the name, or an empty string.</returns>
        public override string ToString()
        {
            if (!IsValid)
            {
                return string.Empty;
            }
            return _publisherId + ":" + _name;
        }

        /// <summary>Compares key components using ordinal equality without allocating.</summary>
        /// <param name="other">The other key, including an uninitialized value.</param>
        /// <returns>Whether both publishers and names match; two uninitialized keys are equal.</returns>
        public bool Equals(DHTKey other)
        {
            return string.Equals(_publisherId, other._publisherId, StringComparison.Ordinal)
                && string.Equals(_name, other._name, StringComparison.Ordinal);
        }

        /// <summary>Compares a key to another object.</summary>
        /// <param name="obj">The other object.</param>
        /// <returns>Whether the object is a key with the same publisher and name.</returns>
        public override bool Equals(object? obj)
        {
            return obj is DHTKey other && Equals(other);
        }

        /// <summary>Hashes key components for in-process collections without formatting or allocating.</summary>
        /// <returns>The combined publisher and name hash, or zero for an uninitialized key.</returns>
        public override int GetHashCode()
        {
            if (!IsValid)
            {
                return 0;
            }
            return HashCode.Combine(_publisherId, _name);
        }

        /// <summary>Compares two key values using ordinal component equality.</summary>
        /// <param name="left">The first key.</param>
        /// <param name="right">The second key.</param>
        /// <returns>Whether the keys have the same publisher and name.</returns>
        public static bool operator ==(DHTKey left, DHTKey right)
        {
            return left.Equals(right);
        }

        /// <summary>Compares two key values for different publishers or names.</summary>
        /// <param name="left">The first key.</param>
        /// <param name="right">The second key.</param>
        /// <returns>Whether the keys have different publishers or names.</returns>
        public static bool operator !=(DHTKey left, DHTKey right)
        {
            return !left.Equals(right);
        }
    }
}
