using System;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>The decoded arguments of a Block request.</summary>
    public readonly struct BlockRequest
    {
        /// <summary>Gets the signed record whose block is requested.</summary>
        public DHTRecord Record { get; }
        /// <summary>Gets the block index, within the record's block count.</summary>
        public int Index { get; }

        /// <summary>Creates the arguments of a Block request.</summary>
        /// <param name="record">The signed record.</param>
        /// <param name="index">The block index.</param>
        /// <exception cref="ArgumentNullException">The record is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The index is outside the record's block count.</exception>
        public BlockRequest(DHTRecord record, int index)
        {
            Record = record ?? throw new ArgumentNullException(nameof(record));
            if (index < 0 || index >= record.BlockCount)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }
            Index = index;
        }
    }

    /// <summary>
    /// Encodes the Block operation: the request is a signed record and a block index; the result is the raw block followed by
    /// its Merkle proof, which the requester verifies against its own copy of the record.
    /// </summary>
    public static class BlockMessage
    {
        /// <summary>The maximum proof depth, which covers the largest block count any record can describe.</summary>
        public const int MaxProofDepth = 20;

        /// <summary>Writes a Block request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="record">The signed record.</param>
        /// <param name="index">The block index.</param>
        public static void WriteRequest(Wire writer, DHTRecord record, int index)
        {
            writer.Put(record.Encoded);
            writer.PutLong(index);
        }

        /// <summary>Reads and verifies a complete Block request body.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The authenticated record and a block index within its block count.</returns>
        /// <exception cref="InvalidDataException">The record is invalid, the index is outside its geometry or the body has trailing data.</exception>
        public static BlockRequest ReadRequest(Wire reader)
        {
            var record = DHTRecord.ParseCached(reader.Bytes(DHTRecord.MaxEncodedLength));
            var index = reader.Long();
            reader.End();
            if (index < 0 || index >= record.BlockCount)
            {
                throw new InvalidDataException("Invalid requested block geometry.");
            }
            return new BlockRequest(record, (int)index);
        }

        /// <summary>Writes a successful Block result: the raw block and its authentication path.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="block">The raw block, which the server has already reauthenticated against its tree.</param>
        /// <param name="tree">The Merkle tree of the complete file.</param>
        /// <param name="index">The block index.</param>
        public static void WriteResponse(Wire writer, ReadOnlySpan<byte> block, MerkleTree tree, int index)
        {
            writer.Put(block);
            tree.WriteProof(writer, index);
        }

        /// <summary>Reads a complete Block result and authenticates the block against the requester's signed record.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <param name="record">The requester's own copy of the signed record; server-supplied metadata is never trusted.</param>
        /// <param name="index">The requested block index.</param>
        /// <returns>The verified raw block, borrowing the result memory.</returns>
        /// <exception cref="InvalidDataException">The block length, position, proof or content does not match the record.</exception>
        public static ReadOnlyMemory<byte> ReadResponse(Wire reader, DHTRecord record, int index)
        {
            var block = reader.Bytes(record.BlockSize);
            var depth = reader.Long();
            if (depth < 0 || depth > MaxProofDepth)
            {
                throw new InvalidDataException("Invalid Merkle proof size.");
            }
            Span<byte> proof = stackalloc byte[MaxProofDepth * Crypto.DigestLength];
            for (var level = 0; level < depth; level++)
            {
                var sibling = reader.Bytes(Crypto.DigestLength);
                if (sibling.Length != Crypto.DigestLength)
                {
                    throw new InvalidDataException("Invalid Merkle sibling length.");
                }
                sibling.Span.CopyTo(proof.Slice(level * Crypto.DigestLength, Crypto.DigestLength));
            }
            reader.End();
            MerkleTree.Verify(record, index, block.Span, proof.Slice(0, (int)depth * Crypto.DigestLength));
            return block;
        }
    }
}
