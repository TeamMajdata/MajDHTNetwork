#nullable enable

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// Proves that the allocation-free cryptographic paths produce exactly the bytes of the provider-object paths they replaced,
    /// so nodes running the previous implementation interoperate with this one.
    /// </summary>
    public sealed class CryptoCompatibilityTests
    {
        /// <summary>Matches the RFC 5869 HKDF-SHA256 test vectors, including long inputs and empty salt and label.</summary>
        /// <param name="inputKeyMaterial">The hexadecimal input keying material.</param>
        /// <param name="salt">The hexadecimal salt, possibly empty.</param>
        /// <param name="info">The hexadecimal label, possibly empty.</param>
        /// <param name="expected">The hexadecimal expected output keying material.</param>
        [Theory]
        [InlineData("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")]
        [InlineData("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")]
        [InlineData("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")]
        public void HkdfMatchesRfc5869Vectors(string inputKeyMaterial, string salt, string info, string expected)
        {
            var output = new byte[expected.Length / 2];
            Crypto.Hkdf(Convert.FromHexString(inputKeyMaterial), Convert.FromHexString(salt), Convert.FromHexString(info), output);
            Assert.Equal(expected, Crypto.Hex(output));
        }

        /// <summary>Derives the same envelope key as the provider's HKDF generator for random secrets, salts and labels.</summary>
        [Fact]
        public void HkdfMatchesTheProviderGenerator()
        {
            for (var round = 0; round < 32; round++)
            {
                var secret = Crypto.Random(32);
                var salt = Crypto.Random(round % 3 == 0 ? 0 : 32);
                var info = Crypto.Random(round % 5);
                var expected = new byte[32 + (round % 40)];
                var generator = new HkdfBytesGenerator(new Sha256Digest());
                generator.Init(new HkdfParameters(secret, salt, info));
                generator.GenerateBytes(expected, 0, expected.Length);
                var actual = new byte[expected.Length];
                Crypto.Hkdf(secret, salt, info, actual);
                Assert.True(actual.AsSpan().SequenceEqual(expected), "The stack-based HKDF must match the provider for round " + round + ".");
            }
        }

        /// <summary>Computes the same X25519 public key from a raw scalar as the provider's private key object.</summary>
        [Fact]
        public void RawScalarPublicKeysMatchProviderKeyObjects()
        {
            for (var round = 0; round < 16; round++)
            {
                var scalar = Crypto.Random(32);
                var expected = new X25519PrivateKeyParameters(scalar, 0).GeneratePublicKey().GetEncoded();
                var actual = new byte[32];
                Crypto.AgreementPublicKey(scalar, actual);
                Assert.True(actual.AsSpan().SequenceEqual(expected), "Raw scalar public keys must match the provider.");
            }
            var identity = new DHTIdentity();
            var provider = new X25519PrivateKeyParameters(identity.AgreementScalar, 0).GeneratePublicKey().GetEncoded();
            Assert.True(identity.AgreementPublicKey.SequenceEqual(provider), "The identity agreement key must match the provider derivation.");
        }

        /// <summary>
        /// Opens envelopes sealed by the previous implementation and lets it open envelopes sealed now, for every payload
        /// residue of the cipher's 64-byte block and for a full block, so in-place decryption and the single-buffer signing
        /// layout are verified against an independent out-of-place reference.
        /// </summary>
        [Fact]
        public void EnvelopesInteroperateWithThePreviousImplementationAcrossPayloadSizes()
        {
            var senderIdentity = new DHTIdentity();
            var recipientIdentity = new DHTIdentity();
            var sender = Peer(senderIdentity, 30001);
            var recipient = Peer(recipientIdentity, 30002);
            var sizes = new System.Collections.Generic.List<int>();
            for (var size = 0; size <= 200; size++)
            {
                sizes.Add(size);
            }
            sizes.AddRange(new[] { 1023, 1024, 4096, 32768 });
            foreach (var size in sizes)
            {
                var body = Crypto.Random(size);
                var requestId = Crypto.Random(16);
                var modern = new Packet(sender, requestId, (byte)Operation.Block, body).Seal(senderIdentity, recipient);
                var legacy = LegacyOpen(recipientIdentity, modern);
                Assert.True(legacy.Body.AsSpan().SequenceEqual(body) && legacy.RequestId.AsSpan().SequenceEqual(requestId)
                    && legacy.Kind == (byte)Operation.Block && legacy.Sender.NodeId == sender.NodeId,
                    "The previous implementation must open a modern envelope of " + size + " bytes.");
                var sealedByLegacy = LegacySeal(sender, requestId, (byte)Operation.Block, body, senderIdentity, recipient);
                var opened = Packet.Open(recipientIdentity, sealedByLegacy);
                Assert.True(opened.Body.Span.SequenceEqual(body) && opened.RequestId.Span.SequenceEqual(requestId)
                    && opened.Kind == (byte)Operation.Block && opened.Sender.NodeId == sender.NodeId,
                    "A legacy envelope of " + size + " bytes must open in place.");
            }
        }

        /// <summary>Rejects an agreement public key that yields an all-zero shared secret instead of encrypting to it.</summary>
        [Fact]
        public void LowOrderAgreementKeysAreRejected()
        {
            var identity = new DHTIdentity();
            using var writer = new Wire();
            var scalar = Crypto.Random(32);
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() =>
                Crypto.EncryptTo(writer, scalar, new byte[32], new byte[8], new byte[12], ReadOnlyMemory<byte>.Empty));
            var contact = Peer(identity, 30003);
            Assert.True(contact.AgreementKey.Span.SequenceEqual(identity.AgreementPublicKey), "Contacts advertise the identity agreement key.");
        }

        /// <summary>Returns the cached verified contact for repeated bytes and drops it once the lease expires.</summary>
        /// <returns>Completion after the expiry check.</returns>
        [Fact]
        public async Task ContactCacheReusesVerifiedContactsUntilTheyExpire()
        {
            var identity = new DHTIdentity();
            var endpoints = new[] { new DHTEndpoint(IPAddress.Loopback, 30004, 0, DHTEndpointFlags.Configured) };
            var shortLived = DHTPeer.Create(identity, endpoints, DHTCapabilities.Download, DHTReachability.Public, false, null,
                Array.Empty<DHTPeer>(), TimeSpan.FromSeconds(1));
            var encoded = shortLived.Encoded.ToArray();
            var first = DHTPeer.Parse(encoded);
            Assert.Same(first, DHTPeer.Parse((byte[])encoded.Clone()));
            Assert.NotSame(first, new DHTPeer(encoded));
            var record = DHTRecord.Create(identity, "cache/record", Crypto.Hex(Crypto.Hash(encoded)), Crypto.Hex(MerkleTree.Leaf(encoded)),
                encoded.Length, 1024, 1, DateTimeOffset.UtcNow.AddHours(1));
            Assert.Same(DHTRecord.ParseCached(record.ToBytes()), DHTRecord.ParseCached(record.ToBytes()));
            await Task.Delay(TimeSpan.FromMilliseconds(1200), TestContext.Current.CancellationToken);
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Parse(encoded));
        }

        /// <summary>Evicts the oldest entries first and keys entries by the exact bytes.</summary>
        [Fact]
        public void EncodedCacheEvictsOldestEntriesAndKeysByContent()
        {
            var cache = new EncodedCache<object>(2, static encoded => new object(), static (item, encoded) => true);
            var first = cache.Get(new byte[] { 1 });
            var second = cache.Get(new byte[] { 2 });
            Assert.Same(first, cache.Get(new byte[] { 1 }));
            Assert.Same(second, cache.Get(new byte[] { 2 }));
            var third = cache.Get(new byte[] { 3 });
            Assert.Equal(2, cache.Count);
            Assert.NotSame(first, cache.Get(new byte[] { 1 }));
            Assert.Same(third, cache.Get(new byte[] { 3 }));
            Assert.True(DigestKey.Of(new byte[] { 7 }).Equals(DigestKey.Of(new byte[] { 7 })));
            Assert.False(DigestKey.Of(new byte[] { 7 }).Equals(DigestKey.Of(new byte[] { 8 })));
            Assert.ThrowsAny<ArgumentException>(() => new DigestKey(new byte[31]));
        }

        /// <summary>Formats identifiers and compares labels on the wire without strings, matching the text codec.</summary>
        [Fact]
        public void HexadecimalIdentifiersAndLabelsRoundTripWithoutText()
        {
            var digest = Crypto.Random(32);
            using var writer = new Wire();
            writer.PutHex(digest);
            writer.Put(ProtocolTags.Contact);
            writer.PutText("MajDHT/1/record");
            using var reader = new Wire(writer.WrittenMemory);
            var ascii = reader.Bytes(64);
            Assert.Equal(Crypto.Hex(digest), Encoding.ASCII.GetString(ascii.Span));
            Assert.True(Crypto.IsHash(ascii.Span));
            Assert.True(Crypto.AsciiEquals(ascii.Span, Crypto.Hex(digest)));
            Assert.False(Crypto.AsciiEquals(ascii.Span, Crypto.Hex(digest).ToUpperInvariant()));
            Span<byte> parsed = stackalloc byte[32];
            Crypto.ParseHash(ascii.Span, parsed);
            Assert.True(parsed.SequenceEqual(digest));
            Assert.True(reader.Tag(ProtocolTags.Contact));
            Assert.False(reader.Tag(ProtocolTags.Envelope));
            reader.End();
            using var oversized = new Wire(writer.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => oversized.Tag(ProtocolTags.Record));
            Assert.False(Crypto.IsHash(Encoding.ASCII.GetBytes(new string('G', 64))));
        }

        /// <summary>Creates a signed loopback contact.</summary>
        /// <param name="identity">The contact owner.</param>
        /// <param name="port">The advertised TCP and UDP port.</param>
        /// <returns>The verified contact.</returns>
        private static DHTPeer Peer(DHTIdentity identity, int port)
        {
            return DHTPeer.Create(identity, IPAddress.Loopback, port, port, DHTCapabilities.Download | DHTCapabilities.Provide);
        }

        /// <summary>Seals a packet exactly as the previous implementation did, with provider key objects and separate buffers.</summary>
        /// <param name="sender">The sender contact.</param>
        /// <param name="requestId">The correlation identifier.</param>
        /// <param name="kind">The operation.</param>
        /// <param name="body">The operation body.</param>
        /// <param name="identity">The sending identity.</param>
        /// <param name="recipient">The recipient contact.</param>
        /// <returns>The sealed envelope.</returns>
        private static byte[] LegacySeal(DHTPeer sender, byte[] requestId, byte kind, byte[] body, DHTIdentity identity, DHTPeer recipient)
        {
            var ephemeral = new X25519PrivateKeyParameters(Crypto.Random(32), 0);
            var nonce = Crypto.Random(12);
            using var header = new Wire();
            header.PutText("MajDHT/1/envelope");
            header.PutByte(kind);
            header.PutText(recipient.NodeId);
            header.Put(ephemeral.GeneratePublicKey().GetEncoded());
            header.Put(nonce);
            using var plain = new Wire();
            plain.Put(sender.Encoded);
            plain.Put(requestId);
            plain.PutLong(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            plain.Put(body);
            using var signed = new Wire();
            signed.Put(header.WrittenSpan);
            signed.Put(plain.WrittenSpan);
            using var payload = new Wire();
            payload.Put(plain.WrittenSpan);
            payload.Put(identity.Sign(signed.WrittenMemory));
            var key = LegacyDerive(ephemeral, recipient.AgreementKey.ToArray(), header.ToArray());
            using var outer = new Wire();
            outer.Put(header.WrittenSpan);
            outer.Put(LegacyTransform(true, key, nonce, header.ToArray(), payload.ToArray()));
            return outer.ToArray();
        }

        /// <summary>Opens an envelope exactly as the previous implementation did, decrypting into a separate buffer.</summary>
        /// <param name="identity">The receiving identity.</param>
        /// <param name="encoded">The envelope, which is not modified.</param>
        /// <returns>The authenticated fields.</returns>
        private static (DHTPeer Sender, byte[] RequestId, byte Kind, byte[] Body) LegacyOpen(DHTIdentity identity, byte[] encoded)
        {
            using var outer = new Wire(encoded);
            var header = outer.Bytes(256);
            var cipherText = outer.Bytes(Wire.MaxPacket);
            outer.End();
            using var reader = new Wire(header);
            Assert.Equal("MajDHT/1/envelope", reader.Text(32));
            var kind = reader.Byte();
            Assert.Equal(identity.NodeId, reader.Text(64));
            var publicKey = reader.Bytes(32).ToArray();
            var nonce = reader.Bytes(12).ToArray();
            reader.End();
            var key = LegacyDerive(new X25519PrivateKeyParameters(identity.AgreementScalar, 0), publicKey, header.ToArray());
            using var payload = new Wire(LegacyTransform(false, key, nonce, header.ToArray(), cipherText.ToArray()));
            var plain = payload.Bytes(Wire.MaxPacket);
            var signature = payload.Bytes(64);
            payload.End();
            using var fields = new Wire(plain);
            var sender = new DHTPeer(fields.Bytes(DHTPeer.MaxEncodedLength));
            var requestId = fields.Bytes(16).ToArray();
            fields.Long();
            var body = fields.Bytes(Wire.MaxPacket).ToArray();
            fields.End();
            using var signed = new Wire();
            signed.Put(header.Span);
            signed.Put(plain.Span);
            Assert.True(Crypto.Verify(sender.SigningKey, signed.WrittenMemory, signature), "The legacy reference must verify the signature.");
            return (sender, requestId, kind, body);
        }

        /// <summary>Derives the envelope key with the provider's agreement and HKDF objects, as the previous implementation did.</summary>
        /// <param name="secret">The local private key object.</param>
        /// <param name="remote">The remote public key.</param>
        /// <param name="header">The authenticated header.</param>
        /// <returns>The symmetric key.</returns>
        private static byte[] LegacyDerive(X25519PrivateKeyParameters secret, byte[] remote, byte[] header)
        {
            var shared = new byte[32];
            secret.GenerateSecret(new X25519PublicKeyParameters(remote, 0), shared, 0);
            var generator = new HkdfBytesGenerator(new Sha256Digest());
            generator.Init(new HkdfParameters(shared, Crypto.Hash(header), Encoding.ASCII.GetBytes("MajDHT/1/envelope")));
            var key = new byte[32];
            generator.GenerateBytes(key, 0, key.Length);
            return key;
        }

        /// <summary>Transforms a message out of place with a fresh provider cipher, as the previous implementation did.</summary>
        /// <param name="encrypt">Whether to encrypt.</param>
        /// <param name="key">The symmetric key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="header">The additional authenticated data.</param>
        /// <param name="input">The plaintext or ciphertext.</param>
        /// <returns>The independently owned output.</returns>
        private static byte[] LegacyTransform(bool encrypt, byte[] key, byte[] nonce, byte[] header, byte[] input)
        {
            var cipher = new ChaCha20Poly1305();
            cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, nonce));
            cipher.ProcessAadBytes(header, 0, header.Length);
            var output = new byte[cipher.GetOutputSize(input.Length)];
            var count = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            cipher.DoFinal(output, count);
            return output;
        }
    }
}
