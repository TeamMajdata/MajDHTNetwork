using System;
using System.Buffers.Binary;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>A 32-byte digest stored inline as four words, so collections can be keyed by content without arrays or strings.</summary>
    internal readonly struct DigestKey : IEquatable<DigestKey>
    {
        /// <summary>The first digest word.</summary>
        private readonly ulong _first;
        /// <summary>The second digest word.</summary>
        private readonly ulong _second;
        /// <summary>The third digest word.</summary>
        private readonly ulong _third;
        /// <summary>The fourth digest word.</summary>
        private readonly ulong _fourth;

        /// <summary>Copies a digest into inline storage.</summary>
        /// <param name="digest">Exactly 32 digest bytes.</param>
        /// <exception cref="ArgumentException">The digest is not 32 bytes long.</exception>
        internal DigestKey(ReadOnlySpan<byte> digest)
        {
            if (digest.Length != Crypto.DigestLength)
            {
                throw new ArgumentException("A digest key requires exactly 32 bytes.", nameof(digest));
            }
            _first = BinaryPrimitives.ReadUInt64BigEndian(digest);
            _second = BinaryPrimitives.ReadUInt64BigEndian(digest.Slice(8));
            _third = BinaryPrimitives.ReadUInt64BigEndian(digest.Slice(16));
            _fourth = BinaryPrimitives.ReadUInt64BigEndian(digest.Slice(24));
        }

        /// <summary>Hashes borrowed bytes into a key without allocating.</summary>
        /// <param name="bytes">The bytes to identify.</param>
        /// <returns>The SHA-256 digest of the bytes as a key.</returns>
        internal static DigestKey Of(ReadOnlySpan<byte> bytes)
        {
            Span<byte> digest = stackalloc byte[Crypto.DigestLength];
            Crypto.Hash(bytes, digest);
            return new DigestKey(digest);
        }

        /// <inheritdoc />
        public bool Equals(DigestKey other)
        {
            return _first == other._first && _second == other._second && _third == other._third && _fourth == other._fourth;
        }

        /// <inheritdoc />
        public override bool Equals(object? obj)
        {
            return obj is DigestKey other && Equals(other);
        }

        /// <summary>Uses the leading digest bits directly, because a cryptographic digest is already uniformly distributed.</summary>
        /// <returns>The hash code.</returns>
        public override int GetHashCode()
        {
            return unchecked((int)_first ^ (int)(_first >> 32));
        }
    }
}
