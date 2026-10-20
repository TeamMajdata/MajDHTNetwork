#nullable enable

using System;
using System.Net;
using System.Runtime.InteropServices;
using MajDHTNetwork.Protocol;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Verifies span exports, memory ownership, cryptographic vectors and public API boundaries.</summary>
    public sealed class MemoryTests
    {
        /// <summary>Preserves zero-copy decoder slices and explicitly owned serialized bytes.</summary>
        [Fact]
        public void DecodedFieldsBorrowTheSourceWhileOwnedSerializationSurvivesDisposal()
        {
            using (var writer = new Wire())
            {
                writer.PutLong(42);
                writer.Put(new byte[] { 1, 3, 5 });
                using var reader = new Wire(writer.WrittenMemory);
                Assert.True(reader.Long() == 42, "Big-endian integer round trip failed.");
                var field = reader.Bytes(3);
                MemoryMarshal.TryGetArray(writer.WrittenMemory, out var source);
                MemoryMarshal.TryGetArray(field, out var view);
                Assert.True(ReferenceEquals(source.Array, view.Array), "Decoded fields must borrow the source buffer.");
                reader.End();
                var retained = writer.ToArray();
                writer.Dispose();
                using var ownedReader = new Wire(retained);
                Assert.True(ownedReader.Long() == 42 && ownedReader.Bytes(3).Span.SequenceEqual(new byte[] { 1, 3, 5 }),
                    "Explicitly owned serialization must survive disposal.");
            }
        }

        /// <summary>Rejects access after disposal while allowing repeated disposal.</summary>
        [Fact]
        public void PooledOwnersExposeLogicalLengthAndDisposeIdempotently()
        {
            using var buffer = new PooledBuffer(33);
            Assert.Equal(33, buffer.Memory.Length);
            buffer.Dispose();
            buffer.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
            {
                _ = buffer.Memory;
            });
        }

        /// <summary>Releases a pooled frame through a narrowed view, preserves pooled bytes by copying and GC-owned bytes as they are.</summary>
        [Fact]
        public void OwnedViewsReleaseTheirFrameOnceAndPreserveBytesBeyondIt()
        {
            var frame = PooledBuffer.Copy(new byte[] { 1, 2, 3, 4, 5 });
            var whole = new OwnedMemory(frame);
            Assert.True(whole.IsPooled);
            var field = whole.Narrow(whole.Bytes.Slice(1, 3));
            Assert.True(field.IsPooled);
            Assert.True(field.Bytes.Span.SequenceEqual(new byte[] { 2, 3, 4 }), "A narrowed view must expose the selected bytes.");
            var preserved = field.Preserve();
            MemoryMarshal.TryGetArray(field.Bytes, out var pooled);
            MemoryMarshal.TryGetArray(preserved, out var copied);
            Assert.False(ReferenceEquals(pooled.Array, copied.Array), "Preserving a pooled view must copy out of the frame.");
            field.Dispose();
            field.Dispose();
            Assert.Throws<ObjectDisposedException>(() =>
            {
                _ = frame.Memory;
            });
            Assert.True(preserved.Span.SequenceEqual(new byte[] { 2, 3, 4 }), "Preserved bytes must survive the frame's release.");
            var stable = new byte[] { 7, 8 };
            var unpooled = new OwnedMemory(stable);
            Assert.False(unpooled.IsPooled);
            MemoryMarshal.TryGetArray(unpooled.Preserve(), out var same);
            Assert.True(ReferenceEquals(stable, same.Array), "GC-owned bytes must be preserved without a copy.");
            unpooled.Dispose();
        }

        /// <summary>Matches the empty-message RFC 8032 vector and verifies a signature at a nonzero array offset.</summary>
        [Fact]
        public void Ed25519MatchesRfc8032AndHonorsSignatureOffsets()
        {
            // RFC 8032 section 7.1, Ed25519 test vector 1 (empty message).
            var vectorIdentity = new DHTIdentity(Convert.FromHexString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
            var vectorSignature = Convert.FromHexString("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
            Assert.True(vectorIdentity.PublicKey.SequenceEqual(Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")),
                "Ed25519 key derivation differs from RFC 8032.");
            Assert.True(vectorIdentity.Sign(ReadOnlyMemory<byte>.Empty).AsSpan().SequenceEqual(vectorSignature),
                "Direct Ed25519 signing differs from RFC 8032.");
            var paddedSignature = new byte[vectorSignature.Length + 4];
            vectorSignature.CopyTo(paddedSignature, 2);
            Assert.True(Crypto.Verify(vectorIdentity.PublicKey.ToArray(), ReadOnlyMemory<byte>.Empty, paddedSignature.AsMemory(2, 64)),
                "Direct signature verification must honor nonzero array offsets.");
        }

        /// <summary>Copies identity seeds into caller-provided span storage.</summary>
        [Fact]
        public void SpanSeedExportsRestoreTheSameIdentity()
        {
            var identity = new DHTIdentity();
            Span<byte> exported = stackalloc byte[32];
            identity.ExportSeed(exported);
            Assert.True(new DHTIdentity(exported).NodeId == identity.NodeId, "Span seed export must restore the same identity.");
        }

        /// <summary>Keeps parsed immutable records valid after the input span is cleared.</summary>
        [Fact]
        public void ImportedRecordsOwnTheirEncodedBytes()
        {
            var identity = new DHTIdentity();
            var content = new byte[] { 2, 4, 6 };
            var record = DHTRecord.Create(identity, "span-api", Crypto.Hex(Crypto.Hash(content)), Crypto.Hex(MerkleTree.Leaf(content)),
                content.Length, 1024, 1, DateTimeOffset.UtcNow.AddHours(1));
            Span<byte> encoded = stackalloc byte[record.EncodedLength];
            record.CopyTo(encoded);
            var imported = DHTRecord.Parse(encoded);
            encoded.Clear();
            Assert.True(imported.FileHash == record.FileHash && imported.ToBytes().AsSpan().SequenceEqual(record.ToBytes()),
                "An imported immutable record must own its bytes.");
        }

        /// <summary>Keeps authenticated decrypted bytes valid after all pooled scratch buffers are reused.</summary>
        [Fact]
        public void DecryptedPayloadOutlivesPooledWriters()
        {
            var identity = new DHTIdentity();
            var content = new byte[] { 2, 4, 6 };
            var sender = DHTPeer.Create(identity, IPAddress.Loopback, 22000, 0, DHTCapabilities.Download);
            var recipientIdentity = new DHTIdentity();
            var recipient = DHTPeer.Create(recipientIdentity, IPAddress.Loopback, 22001, 0, DHTCapabilities.Download);
            Packet opened;
            using (var payload = new Wire())
            {
                payload.Put(content);
                var packet = new Packet(sender, Crypto.Random(16), (byte)Operation.Ping, payload.WrittenMemory);
                opened = Packet.Open(recipientIdentity, packet.Seal(identity, recipient));
            }
            for (var i = 0; i < 32; i++)
            {
                using var churn = new PooledBuffer(32768);
                churn.Memory.Span.Fill(0xff);
            }
            using (var payload = new Wire(opened.Body))
            {
                Assert.True(payload.Bytes(3).Span.SequenceEqual(content), "Decrypted output must outlive all temporary pooled writers.");
            }
        }

        /// <summary>Keeps the complete exported API under the MajDHTNetwork namespace.</summary>
        [Fact]
        public void ExportedTypesUseThePublicRootNamespace()
        {
            foreach (var type in typeof(MajDHTNode).Assembly.GetExportedTypes())
            {
                Assert.True(type.Namespace == "MajDHTNetwork" || type.Namespace?.StartsWith("MajDHTNetwork.", StringComparison.Ordinal) == true,
                    "A public library type leaked the old root namespace.");
            }
        }
    }
}
