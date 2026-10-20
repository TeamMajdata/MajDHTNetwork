using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Stores a domain-separated Merkle tree in one contiguous owned node buffer.</summary>
    internal sealed class MerkleTree
    {
        /// <summary>The complete immutable tree, with levels packed from leaves to root.</summary>
        private readonly byte[] _nodes;
        /// <summary>The byte offset of each level.</summary>
        private readonly int[] _offsets;
        /// <summary>Gets the cached canonical root identifier.</summary>
        internal string Root { get; }
        /// <summary>Gets the leaf count.</summary>
        internal int Count { get; }

        /// <summary>Builds a tree from contiguous 32-byte leaf digests.</summary>
        /// <param name="leaves">At least one complete SHA-256 leaf digest.</param>
        /// <exception cref="ArgumentException">The input has no complete leaves.</exception>
        internal MerkleTree(ReadOnlySpan<byte> leaves)
        {
            if (leaves.Length == 0 || (leaves.Length % 32) != 0)
            {
                throw new ArgumentException("Expected contiguous 32-byte Merkle leaves.", nameof(leaves));
            }
            Count = leaves.Length / 32;
            var levels = 1;
            var total = Count;
            for (var count = Count; count > 1;)
            {
                count = (count + 1) / 2;
                total = checked(total + count);
                levels++;
            }
            _offsets = new int[levels];
            _nodes = new byte[checked(total * 32)];
            leaves.CopyTo(_nodes);
            var width = Count;
            for (var level = 1; level < levels; level++)
            {
                _offsets[level] = _offsets[level - 1] + (width * 32);
                var next = (width + 1) / 2;
                for (var index = 0; index < next; index++)
                {
                    Parent(_nodes.AsSpan(_offsets[level - 1] + (index * 64), 32),
                        _nodes.AsSpan(_offsets[level - 1] + (Math.Min((index * 2) + 1, width - 1) * 32), 32),
                        _nodes.AsSpan(_offsets[level] + (index * 32), 32));
                }
                width = next;
            }
            Root = Crypto.Hex(_nodes.AsSpan(_offsets[levels - 1], 32));
        }

        /// <summary>Creates an owned leaf digest for callers needing retained storage.</summary>
        /// <param name="bytes">The raw block.</param>
        /// <returns>The 32-byte leaf.</returns>
        internal static byte[] Leaf(ReadOnlySpan<byte> bytes)
        {
            var digest = new byte[32];
            Leaf(bytes, digest);
            return digest;
        }

        /// <summary>Hashes a domain byte and a borrowed block without concatenating the complete block or allocating a hash instance.</summary>
        /// <param name="bytes">The raw block.</param>
        /// <param name="destination">At least 32 writable digest bytes.</param>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        internal static void Leaf(ReadOnlySpan<byte> bytes, Span<byte> destination)
        {
            Crypto.HashPrefixed(0, bytes, destination);
        }

        /// <summary>Hashes a branch using stack storage and the per-thread hash instance.</summary>
        /// <param name="left">The left digest.</param>
        /// <param name="right">The right digest.</param>
        /// <param name="destination">The output digest.</param>
        private static void Parent(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
        {
            Span<byte> input = stackalloc byte[65];
            input[0] = 1;
            left.CopyTo(input.Slice(1, 32));
            right.CopyTo(input.Slice(33, 32));
            Crypto.Hash(input, destination);
        }

        /// <summary>Appends one leaf to pooled metadata storage and returns its content-store identifier.</summary>
        /// <param name="writer">The contiguous leaf writer.</param>
        /// <param name="block">The borrowed raw block.</param>
        /// <returns>The lowercase leaf hash.</returns>
        internal static string AppendLeaf(Wire writer, ReadOnlySpan<byte> block)
        {
            Span<byte> digest = stackalloc byte[32];
            Leaf(block, digest);
            writer.PutRaw(digest);
            return Crypto.Hex(digest);
        }

        /// <summary>Gets the storage identifier of one retained leaf.</summary>
        /// <param name="index">The block index.</param>
        /// <returns>The lowercase leaf digest.</returns>
        internal string LeafId(int index)
        {
            return Crypto.Hex(_nodes.AsSpan(index * 32, 32));
        }

        /// <summary>Writes an authentication path directly into an operation buffer.</summary>
        /// <param name="writer">The operation writer.</param>
        /// <param name="index">The block index.</param>
        internal void WriteProof(Wire writer, int index)
        {
            writer.PutLong(_offsets.Length - 1);
            var width = Count;
            for (var level = 0; level < _offsets.Length - 1; level++)
            {
                writer.Put(_nodes.AsSpan(_offsets[level] + (Math.Min(index ^ 1, width - 1) * 32), 32));
                index /= 2;
                width = (width + 1) / 2;
            }
        }

        /// <summary>Creates one contiguous proof when a caller needs to retain it.</summary>
        /// <param name="index">The block index.</param>
        /// <returns>The packed sibling digests.</returns>
        internal ReadOnlyMemory<byte> Proof(int index)
        {
            var proof = new byte[(_offsets.Length - 1) * 32];
            var width = Count;
            for (var level = 0; level < _offsets.Length - 1; level++)
            {
                _nodes.AsSpan(_offsets[level] + (Math.Min(index ^ 1, width - 1) * 32), 32).CopyTo(proof.AsSpan(level * 32, 32));
                index /= 2;
                width = (width + 1) / 2;
            }
            return proof;
        }

        /// <summary>Checks exact signed block geometry before content hashing.</summary>
        /// <param name="record">The signed manifest.</param>
        /// <param name="index">The block index.</param>
        /// <param name="length">The returned block length.</param>
        private static void CheckGeometry(DHTRecord record, int index, int length)
        {
            if (index < 0 || index >= record.BlockCount
                || length != (int)Math.Min(record.BlockSize, record.Length - ((long)index * record.BlockSize)))
            {
                throw new InvalidDataException("Block geometry differs from the signed manifest.");
            }
        }

        /// <summary>Reauthenticates a local block against the already verified immutable tree.</summary>
        /// <param name="record">The signed geometry.</param>
        /// <param name="index">The block index.</param>
        /// <param name="bytes">The stored block.</param>
        internal void VerifyLocal(DHTRecord record, int index, ReadOnlySpan<byte> bytes)
        {
            CheckGeometry(record, index, bytes.Length);
            Span<byte> digest = stackalloc byte[32];
            Leaf(bytes, digest);
            if (!CryptographicOperations.FixedTimeEquals(digest, _nodes.AsSpan(index * 32, 32)))
            {
                throw new InvalidDataException("Stored content does not match its Merkle leaf.");
            }
        }

        /// <summary>Authenticates exact block length, position and a contiguous proof without intermediate digest arrays.</summary>
        /// <param name="record">The signed manifest.</param>
        /// <param name="index">The requested block index.</param>
        /// <param name="bytes">The raw block.</param>
        /// <param name="proof">Packed 32-byte sibling digests.</param>
        /// <exception cref="InvalidDataException">The geometry, proof or content is invalid.</exception>
        internal static void Verify(DHTRecord record, int index, ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> proof)
        {
            CheckGeometry(record, index, bytes.Length);
            var levels = 0;
            for (var count = record.BlockCount; count > 1; count = (count + 1) / 2)
            {
                levels++;
            }
            if (proof.Length != levels * 32)
            {
                throw new InvalidDataException("Invalid Merkle proof depth.");
            }
            Span<byte> digest = stackalloc byte[32];
            Span<byte> expected = stackalloc byte[32];
            Leaf(bytes, digest);
            for (var level = 0; level < levels; level++)
            {
                var sibling = proof.Slice(level * 32, 32);
                if ((index & 1) == 0)
                {
                    Parent(digest, sibling, digest);
                }
                else
                {
                    Parent(sibling, digest, digest);
                }
                index /= 2;
            }
            Crypto.ParseHash(record.MerkleRoot, expected);
            if (!CryptographicOperations.FixedTimeEquals(digest, expected))
            {
                throw new InvalidDataException("Block Merkle authentication failed.");
            }
        }
    }
}
