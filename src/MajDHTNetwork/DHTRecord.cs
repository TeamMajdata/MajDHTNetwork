using System;
using System.IO;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// An immutable publisher-signed key binding: either a Merkle content manifest, or a withdrawal that states the publisher
    /// no longer binds the key to any content.
    /// </summary>
    public sealed class DHTRecord
    {
        /// <summary>The flag marking a withdrawal.</summary>
        private const byte WithdrawnFlag = 1;
        /// <summary>The maximum accepted encoded record length.</summary>
        public const int MaxEncodedLength = 2200;
        /// <summary>The maximum number of distinct records whose verification is cached process-wide.</summary>
        private const int CacheCapacity = 256;
        /// <summary>
        /// The verified records keyed by their exact bytes, so the manifest repeated by every block request of one file and
        /// the records repeated across lookups are parsed, signature-checked and allocated once.
        /// </summary>
        private static readonly EncodedCache<DHTRecord> s_cache = new EncodedCache<DHTRecord>(CacheCapacity,
            static encoded => new DHTRecord(encoded.Span), static (record, encoded) => !record.IsExpired && record.Encoded.SequenceEqual(encoded));
        /// <summary>The signed wire representation.</summary>
        private readonly byte[] _encoded;
        /// <summary>The cached local geometry identifier, formatted on first use.</summary>
        private string? _contentId;
        /// <summary>Gets the publisher-scoped lookup key.</summary>
        public DHTKey Key { get; }
        /// <summary>
        /// Gets whether the publisher withdrew the key. A withdrawal has no content: its file hash and Merkle root are empty and
        /// its length, block size and block count are zero. It supersedes every lower revision of the key.
        /// </summary>
        public bool IsWithdrawn { get; }
        /// <summary>Gets the SHA-256 digest of the complete raw file, or an empty string for a withdrawal.</summary>
        public string FileHash { get; }
        /// <summary>Gets the domain-separated Merkle root used to verify individual blocks, or an empty string for a withdrawal.</summary>
        public string MerkleRoot { get; }
        /// <summary>Gets the complete file length.</summary>
        public long Length { get; }
        /// <summary>Gets the maximum bytes in each block.</summary>
        public int BlockSize { get; }
        /// <summary>Gets the block count, including one empty block for an empty file, or zero for a withdrawal.</summary>
        public int BlockCount => IsWithdrawn ? 0 : Math.Max(1, (int)((Length + BlockSize - 1) / BlockSize));
        /// <summary>Gets the strictly positive publisher-assigned revision.</summary>
        public long Revision { get; }
        /// <summary>Gets the absolute publication expiry.</summary>
        public DateTimeOffset ExpiresAt { get; }
        /// <summary>Gets whether the publication has expired.</summary>
        public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;
        /// <summary>Gets the local geometry identifier: the whole-file hash and canonical block size, formatted once per record.</summary>
        internal string ContentId => _contentId ??= FileHash + ":" + BlockSize.ToString(System.Globalization.CultureInfo.InvariantCulture);

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
            if (!wire.Tag(ProtocolTags.Record))
            {
                throw new InvalidDataException("Unsupported record version.");
            }
            var publicKey = wire.Bytes(32);
            Key = DHTKey.Parse(wire.Text(1024));
            var flags = wire.Byte();
            FileHash = wire.Text(64);
            MerkleRoot = wire.Text(64);
            Length = wire.Long();
            var blockSize = wire.Long();
            Revision = wire.Long();
            var expiry = wire.Long();
            wire.End();
            IsWithdrawn = (flags & WithdrawnFlag) != 0;
            if (IsWithdrawn)
            {
                if (FileHash.Length != 0 || MerkleRoot.Length != 0 || Length != 0 || blockSize != 0)
                {
                    throw new InvalidDataException("A withdrawal must not describe content.");
                }
            }
            else
            {
                Crypto.ParseHash(FileHash);
                Crypto.ParseHash(MerkleRoot);
                if (Length < 0 || Length > 1024L * 1024 * 1024 || blockSize < 1024 || blockSize > 32768)
                {
                    throw new InvalidDataException("Invalid publication geometry.");
                }
            }
            if ((flags & ~WithdrawnFlag) != 0 || Revision <= 0 || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
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
        public static DHTRecord Create(DHTIdentity identity, string name, string fileHash, string root, long length,
            int blockSize, long revision, DateTimeOffset expiresAt)
        {
            return Sign(identity, name, 0, fileHash, root, length, blockSize, revision, expiresAt);
        }

        /// <summary>Signs a withdrawal that supersedes every lower revision of a key without describing content.</summary>
        /// <param name="identity">The key owner.</param>
        /// <param name="name">The owner-scoped name.</param>
        /// <param name="revision">A revision above every revision being withdrawn.</param>
        /// <param name="expiresAt">The withdrawal expiry, which must outlive the withdrawn publications.</param>
        /// <returns>The verified signed withdrawal.</returns>
        public static DHTRecord CreateWithdrawal(DHTIdentity identity, string name, long revision, DateTimeOffset expiresAt)
        {
            return Sign(identity, name, WithdrawnFlag, string.Empty, string.Empty, 0, 0, revision, expiresAt);
        }

        /// <summary>Encodes and signs a record payload.</summary>
        /// <param name="identity">The key owner.</param>
        /// <param name="name">The owner-scoped name.</param>
        /// <param name="flags">The record flags.</param>
        /// <param name="fileHash">The whole-file hash, or empty for a withdrawal.</param>
        /// <param name="root">The Merkle root, or empty for a withdrawal.</param>
        /// <param name="length">The file length.</param>
        /// <param name="blockSize">The block size.</param>
        /// <param name="revision">The revision.</param>
        /// <param name="expiresAt">The expiry.</param>
        /// <returns>The verified signed record.</returns>
        private static DHTRecord Sign(DHTIdentity identity, string name, byte flags, string fileHash, string root, long length,
            int blockSize, long revision, DateTimeOffset expiresAt)
        {
            var key = new DHTKey(identity.NodeId, name);
            using var payload = new Wire();
            payload.Put(ProtocolTags.Record);
            payload.Put(identity.PublicKey);
            payload.PutText(key.ToString());
            payload.PutByte(flags);
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
        public ReadOnlySpan<byte> Encoded => _encoded;

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
            if (encoded.Length > MaxEncodedLength)
            {
                throw new ArgumentException("Invalid record size.", nameof(encoded));
            }
            return new DHTRecord(encoded);
        }

        /// <summary>Gets the verified record for canonical bytes received on the wire, reusing the cached instance for repeated bytes.</summary>
        /// <param name="encoded">The borrowed canonical record; it is never retained.</param>
        /// <returns>The authenticated, unexpired publication.</returns>
        /// <exception cref="InvalidDataException">The record is oversized or cannot be authenticated.</exception>
        public static DHTRecord ParseCached(ReadOnlyMemory<byte> encoded)
        {
            if (encoded.Length > MaxEncodedLength)
            {
                throw new InvalidDataException("Oversized record.");
            }
            return s_cache.Get(encoded);
        }

        /// <summary>Checks whether another publication describes identical block geometry and content, or is also a withdrawal.</summary>
        /// <param name="other">The comparison publication.</param>
        /// <returns>Whether complete content metadata matches.</returns>
        public bool SameContent(DHTRecord other)
        {
            return IsWithdrawn == other.IsWithdrawn && FileHash == other.FileHash && MerkleRoot == other.MerkleRoot
                && Length == other.Length && BlockSize == other.BlockSize;
        }
    }
}
