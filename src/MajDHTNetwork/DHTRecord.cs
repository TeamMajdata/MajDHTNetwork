using System;
using System.IO;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>An immutable publisher-signed key binding and Merkle content manifest.</summary>
    public sealed class DHTRecord
    {
        /// <summary>The signed wire representation.</summary>
        private readonly byte[] _encoded;
        /// <summary>Gets the publisher-scoped lookup key.</summary>
        public DHTKey Key { get; }
        /// <summary>Gets the SHA-256 digest of the complete raw file.</summary>
        public string FileHash { get; }
        /// <summary>Gets the domain-separated Merkle root used to verify individual blocks.</summary>
        public string MerkleRoot { get; }
        /// <summary>Gets the complete file length.</summary>
        public long Length { get; }
        /// <summary>Gets the maximum bytes in each block.</summary>
        public int BlockSize { get; }
        /// <summary>Gets the block count, including one empty block for an empty file.</summary>
        public int BlockCount => Math.Max(1, (int)((Length + BlockSize - 1) / BlockSize));
        /// <summary>Gets the strictly positive publisher-assigned revision.</summary>
        public long Revision { get; }
        /// <summary>Gets the absolute publication expiry.</summary>
        public DateTimeOffset ExpiresAt { get; }
        /// <summary>Gets whether the publication has expired.</summary>
        public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;

        /// <summary>Decodes and authenticates a signed publication.</summary>
        /// <param name="encoded">The canonical signed bytes.</param>
        /// <exception cref="InvalidDataException">The record is malformed, expired or forged.</exception>
        private DHTRecord(ReadOnlySpan<byte> encoded)
        {
            _encoded = encoded.ToArray();
            using var wrapper = new Wire(_encoded);
            var payload = wrapper.Bytes(2048);
            var signature = wrapper.Bytes(64);
            wrapper.End();
            using var wire = new Wire(payload);
            if (wire.Text(32) != "MajDHT/1/record")
            {
                throw new InvalidDataException("Unsupported record version.");
            }
            var publicKey = wire.Bytes(32);
            Key = DHTKey.Parse(wire.Text(1024));
            FileHash = wire.Text(64);
            MerkleRoot = wire.Text(64);
            Length = wire.Long();
            var blockSize = wire.Long();
            Revision = wire.Long();
            var expiry = wire.Long();
            wire.End();
            Crypto.ParseHash(FileHash);
            Crypto.ParseHash(MerkleRoot);
            if (Length < 0 || Length > 1024L * 1024 * 1024 || blockSize < 1024 || blockSize > 32768
                || Revision <= 0 || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                || expiry > DateTimeOffset.UtcNow.AddDays(7).ToUnixTimeSeconds()
                || Crypto.Hex(Crypto.Hash(publicKey.Span)) != Key.PublisherId
                || !Crypto.Verify(publicKey, payload, signature))
            {
                throw new InvalidDataException("Invalid, expired or forged publication.");
            }
            BlockSize = (int)blockSize;
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry);
        }

        /// <summary>Signs a content manifest with its owning publisher identity.</summary>
        /// <param name="identity">The key owner.</param>
        /// <param name="name">The owner-scoped name.</param>
        /// <param name="fileHash">The whole-file hash.</param>
        /// <param name="root">The Merkle root.</param>
        /// <param name="length">The file length.</param>
        /// <param name="blockSize">The publication block size.</param>
        /// <param name="revision">The monotonically increasing revision.</param>
        /// <param name="expiresAt">The publication expiry.</param>
        /// <returns>The verified signed record.</returns>
        internal static DHTRecord Create(DHTIdentity identity, string name, string fileHash, string root, long length,
            int blockSize, long revision, DateTimeOffset expiresAt)
        {
            var key = new DHTKey(identity.NodeId, name);
            using var payload = new Wire();
            payload.PutText("MajDHT/1/record");
            payload.Put(identity.PublicKey);
            payload.PutText(key.ToString());
            payload.PutText(fileHash);
            payload.PutText(root);
            payload.PutLong(length);
            payload.PutLong(blockSize);
            payload.PutLong(revision);
            payload.PutLong(expiresAt.ToUnixTimeSeconds());
            using var wrapper = new Wire();
            wrapper.Put(payload.WrittenSpan);
            wrapper.Put(identity.Sign(payload.WrittenMemory));
            return new DHTRecord(wrapper.WrittenSpan);
        }

        /// <summary>Gets the encoded manifest length for caller-owned serialization buffers.</summary>
        public int EncodedLength => _encoded.Length;
        /// <summary>Gets an internal borrowed manifest view without allocating.</summary>
        internal ReadOnlySpan<byte> Encoded => _encoded;

        /// <summary>Copies the signed manifest into caller-owned storage without allocating.</summary>
        /// <param name="destination">At least EncodedLength writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        public void CopyTo(Span<byte> destination)
        {
            _encoded.AsSpan().CopyTo(destination);
        }

        /// <summary>Exports the signed manifest for application persistence or sharing.</summary>
        /// <returns>A copied canonical signed record.</returns>
        public byte[] ToBytes()
        {
            return (byte[])_encoded.Clone();
        }

        /// <summary>Imports and verifies a signed manifest.</summary>
        /// <param name="encoded">The bounded canonical record.</param>
        /// <returns>The authenticated publication.</returns>
        /// <exception cref="ArgumentException">The input is null or too large.</exception>
        /// <exception cref="InvalidDataException">The record cannot be authenticated.</exception>
        public static DHTRecord Parse(ReadOnlySpan<byte> encoded)
        {
            if (encoded.Length > 2200)
            {
                throw new ArgumentException("Invalid record size.", nameof(encoded));
            }
            return new DHTRecord(encoded);
        }

        /// <summary>Checks whether another publication describes identical block geometry and content.</summary>
        /// <param name="other">The comparison publication.</param>
        /// <returns>Whether complete content metadata matches.</returns>
        internal bool SameContent(DHTRecord other)
        {
            return FileHash == other.FileHash && MerkleRoot == other.MerkleRoot
                && Length == other.Length && BlockSize == other.BlockSize;
        }
    }
}
