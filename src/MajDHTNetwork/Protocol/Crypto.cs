using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Provides portable cryptography with borrowed memory at legacy array-only provider boundaries.</summary>
    internal static class Crypto
    {
        /// <summary>The synchronized cryptographic random generator.</summary>
        private static readonly SecureRandom s_random = new SecureRandom();
        /// <summary>The immutable HKDF domain label.</summary>
        private static readonly byte[] s_envelopeInfo = Encoding.ASCII.GetBytes("MajDHT/1/envelope");
        /// <summary>The immutable identity proof-of-work domain label.</summary>
        private static readonly byte[] s_workDomain = Encoding.ASCII.GetBytes("MajDHT/1/identity-work");

        /// <summary>Shuffles a list in place with a cryptographic random source, so attackers cannot predict selections.</summary>
        /// <typeparam name="T">The element type.</typeparam>
        /// <param name="items">The list to shuffle.</param>
        internal static void Shuffle<T>(IList<T> items)
        {
            for (var index = items.Count - 1; index > 0; index--)
            {
                var other = RandomNumberGenerator.GetInt32(index + 1);
                var swap = items[index];
                items[index] = items[other];
                items[other] = swap;
            }
        }

        /// <summary>Counts the identity proof-of-work of a nonce: the leading zero bits of its domain-separated digest.</summary>
        /// <param name="nodeHash">The 32-byte node digest.</param>
        /// <param name="nonce">The proof-of-work nonce.</param>
        /// <returns>The number of leading zero bits, from 0 to 256.</returns>
        internal static int IdentityWork(ReadOnlySpan<byte> nodeHash, long nonce)
        {
            using var sha = SHA256.Create();
            return IdentityWork(sha, nodeHash, nonce);
        }

        /// <summary>Finds the smallest non-negative nonce whose identity proof-of-work reaches a difficulty.</summary>
        /// <param name="nodeHash">The 32-byte node digest.</param>
        /// <param name="bits">The required number of leading zero bits.</param>
        /// <returns>The nonce.</returns>
        internal static long FindIdentityWork(ReadOnlySpan<byte> nodeHash, int bits)
        {
            using var sha = SHA256.Create();
            for (long nonce = 0; ; nonce++)
            {
                if (IdentityWork(sha, nodeHash, nonce) >= bits)
                {
                    return nonce;
                }
            }
        }

        /// <summary>Counts the leading zero bits of SHA-256(domain, node digest, big-endian nonce) with a reusable hash.</summary>
        /// <param name="sha">The reusable hash algorithm.</param>
        /// <param name="nodeHash">The 32-byte node digest.</param>
        /// <param name="nonce">The proof-of-work nonce.</param>
        /// <returns>The number of leading zero bits.</returns>
        private static int IdentityWork(SHA256 sha, ReadOnlySpan<byte> nodeHash, long nonce)
        {
            Span<byte> input = stackalloc byte[s_workDomain.Length + 40];
            s_workDomain.CopyTo(input);
            nodeHash.Slice(0, 32).CopyTo(input.Slice(s_workDomain.Length));
            BinaryPrimitives.WriteInt64BigEndian(input.Slice(s_workDomain.Length + 32), nonce);
            Span<byte> digest = stackalloc byte[32];
            sha.TryComputeHash(input, digest, out _);
            var bits = 0;
            foreach (var value in digest)
            {
                if (value == 0)
                {
                    bits += 8;
                    continue;
                }
                var mask = 0x80;
                while ((value & mask) == 0)
                {
                    bits++;
                    mask >>= 1;
                }
                break;
            }
            return bits;
        }

        /// <summary>Generates independently owned random bytes.</summary>
        /// <param name="count">The byte count.</param>
        /// <returns>The random bytes.</returns>
        internal static byte[] Random(int count)
        {
            var bytes = new byte[count];
            s_random.NextBytes(bytes);
            return bytes;
        }

        /// <summary>Hashes borrowed bytes into an owned digest.</summary>
        /// <param name="bytes">The input.</param>
        /// <returns>The 32-byte SHA-256 digest.</returns>
        internal static byte[] Hash(ReadOnlySpan<byte> bytes)
        {
            var digest = new byte[32];
            Hash(bytes, digest);
            return digest;
        }

        /// <summary>Hashes borrowed input directly into caller-owned storage.</summary>
        /// <param name="bytes">The input.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        internal static void Hash(ReadOnlySpan<byte> bytes, Span<byte> destination)
        {
            using var sha = SHA256.Create();
            if (!sha.TryComputeHash(bytes, destination, out var written) || written != 32)
            {
                throw new ArgumentException("A SHA-256 destination requires 32 bytes.", nameof(destination));
            }
        }

        /// <summary>Formats lowercase hexadecimal without per-byte strings or a StringBuilder.</summary>
        /// <param name="bytes">The borrowed input.</param>
        /// <returns>The canonical hexadecimal string.</returns>
        internal static string Hex(ReadOnlySpan<byte> bytes)
        {
            char[]? rented = null;
            Span<char> characters = bytes.Length <= 256 ? stackalloc char[bytes.Length * 2] : (rented = ArrayPool<char>.Shared.Rent(checked(bytes.Length * 2)));
            try
            {
                const string Digits = "0123456789abcdef";
                for (var i = 0; i < bytes.Length; i++)
                {
                    characters[i * 2] = Digits[bytes[i] >> 4];
                    characters[(i * 2) + 1] = Digits[bytes[i] & 15];
                }
                return new string(characters.Slice(0, bytes.Length * 2));
            }
            finally
            {
                if (rented != null)
                {
                    ArrayPool<char>.Shared.Return(rented, clearArray: true);
                }
            }
        }

        /// <summary>Parses a canonical identifier into newly owned digest storage.</summary>
        /// <param name="value">The lowercase identifier.</param>
        /// <returns>The 32-byte digest.</returns>
        internal static byte[] ParseHash(string value)
        {
            var digest = new byte[32];
            ParseHash(value, digest);
            return digest;
        }

        /// <summary>Parses an identifier into caller-owned storage without allocating.</summary>
        /// <param name="value">The canonical lowercase identifier.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        /// <exception cref="ArgumentException">The input or destination is invalid.</exception>
        internal static void ParseHash(string value, Span<byte> destination)
        {
            if (value == null || value.Length != 64 || destination.Length < 32)
            {
                throw new ArgumentException("Expected a lowercase SHA-256 identifier and a 32-byte destination.");
            }
            for (var i = 0; i < 32; i++)
            {
                var high = "0123456789abcdef".IndexOf(value[i * 2]);
                var low = "0123456789abcdef".IndexOf(value[(i * 2) + 1]);
                if (high < 0 || low < 0)
                {
                    throw new ArgumentException("Expected a lowercase SHA-256 identifier.", nameof(value));
                }
                destination[i] = (byte)((high << 4) | low);
            }
        }

        /// <summary>Gets an array segment for the provider's .NET Standard 2.0 APIs without copying array-backed views.</summary>
        /// <param name="memory">The borrowed bytes.</param>
        /// <returns>The underlying segment, or one compatibility copy for a custom memory manager.</returns>
        internal static ArraySegment<byte> Array(ReadOnlyMemory<byte> memory)
        {
            return MemoryMarshal.TryGetArray(memory, out var segment) ? segment : new ArraySegment<byte>(memory.ToArray());
        }

        /// <summary>Signs directly from a borrowed canonical message without the signer's buffering stream.</summary>
        /// <param name="key">The cached private key.</param>
        /// <param name="bytes">The canonical message.</param>
        /// <returns>The detached signature.</returns>
        internal static byte[] Sign(Ed25519PrivateKeyParameters key, ReadOnlyMemory<byte> bytes)
        {
            var input = Array(bytes);
            var signature = new byte[64];
            key.Sign(Ed25519.Algorithm.Ed25519, null, input.Array!, input.Offset, input.Count, signature, 0);
            return signature;
        }

        /// <summary>Verifies a signature directly over borrowed memory without message copies.</summary>
        /// <param name="publicKey">The signing public key.</param>
        /// <param name="bytes">The canonical message.</param>
        /// <param name="signature">The detached signature.</param>
        /// <returns>Whether the signature is valid.</returns>
        internal static bool Verify(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> bytes, ReadOnlyMemory<byte> signature)
        {
            if (publicKey.Length != 32 || signature.Length != 64)
            {
                return false;
            }
            var key = Array(publicKey);
            var input = Array(bytes);
            var signed = Array(signature);
            var verifier = new Ed25519PublicKeyParameters(key.Array!, key.Offset);
            return verifier.Verify(Ed25519.Algorithm.Ed25519, null, input.Array!, input.Offset, input.Count, signed.Array!, signed.Offset);
        }

        /// <summary>Derives an independent agreement key from an identity seed.</summary>
        /// <param name="seed">The private identity seed.</param>
        /// <returns>The agreement key.</returns>
        internal static X25519PrivateKeyParameters AgreementKey(ReadOnlySpan<byte> seed)
        {
            using var wire = new Wire();
            wire.PutText("MajDHT/1/identity-agreement");
            wire.Put(seed);
            var digest = Hash(wire.WrittenSpan);
            try
            {
                return new X25519PrivateKeyParameters(digest, 0);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(digest);
            }
        }

        /// <summary>Derives a transcript-bound symmetric key using X25519 and HKDF-SHA256.</summary>
        /// <param name="secret">The private agreement key.</param>
        /// <param name="remote">The remote public key.</param>
        /// <param name="header">The authenticated header.</param>
        /// <returns>The symmetric key, cleared by the transform operation.</returns>
        /// <exception cref="CryptographicException">The agreement public key is invalid.</exception>
        internal static byte[] Derive(X25519PrivateKeyParameters secret, ReadOnlyMemory<byte> remote, ReadOnlyMemory<byte> header)
        {
            var shared = new byte[32];
            try
            {
                var publicKey = Array(remote);
                secret.GenerateSecret(new X25519PublicKeyParameters(publicKey.Array!, publicKey.Offset), shared, 0);
                var hkdf = new HkdfBytesGenerator(new Sha256Digest());
                hkdf.Init(new HkdfParameters(shared, Hash(header.Span), s_envelopeInfo));
                var key = new byte[32];
                hkdf.GenerateBytes(key, 0, key.Length);
                return key;
            }
            catch (InvalidOperationException exception)
            {
                throw new CryptographicException("Invalid agreement public key.", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(shared);
            }
        }

        /// <summary>Writes length-prefixed ciphertext directly into the pooled final envelope.</summary>
        /// <param name="writer">The envelope writer.</param>
        /// <param name="key">The symmetric key, cleared before returning.</param>
        /// <param name="nonce">The 96-bit nonce.</param>
        /// <param name="header">The authenticated header.</param>
        /// <param name="input">The borrowed plaintext.</param>
        internal static void EncryptTo(Wire writer, byte[] key, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> input)
        {
            try
            {
                var cipher = new ChaCha20Poly1305();
                cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, nonce.ToArray()));
                var aad = Array(header);
                cipher.ProcessAadBytes(aad.Array!, aad.Offset, aad.Count);
                var source = Array(input);
                var length = cipher.GetOutputSize(source.Count);
                writer.PutLong(length);
                var destination = Array(writer.Allocate(length));
                var count = cipher.ProcessBytes(source.Array!, source.Offset, source.Count, destination.Array!, destination.Offset);
                count += cipher.DoFinal(destination.Array!, destination.Offset + count);
                if (count != length)
                {
                    throw new InvalidDataException("Unexpected authenticated output length.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>Transforms a borrowed message with ChaCha20-Poly1305.</summary>
        /// <param name="encrypt">Whether to encrypt.</param>
        /// <param name="key">The symmetric key, cleared before returning.</param>
        /// <param name="nonce">The 96-bit nonce.</param>
        /// <param name="header">The additional authenticated data.</param>
        /// <param name="input">The plaintext or ciphertext.</param>
        /// <returns>The independently owned authenticated output.</returns>
        /// <exception cref="CryptographicException">Ciphertext authentication failed.</exception>
        internal static byte[] Transform(bool encrypt, byte[] key, ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> input)
        {
            byte[]? output = null;
            try
            {
                var cipher = new ChaCha20Poly1305();
                cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, nonce.ToArray()));
                var aad = Array(header);
                cipher.ProcessAadBytes(aad.Array!, aad.Offset, aad.Count);
                var source = Array(input);
                output = new byte[cipher.GetOutputSize(source.Count)];
                var count = cipher.ProcessBytes(source.Array!, source.Offset, source.Count, output, 0);
                count += cipher.DoFinal(output, count);
                if (count != output.Length)
                {
                    throw new InvalidDataException("Unexpected authenticated output length.");
                }
                return output;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException exception)
            {
                if (output != null)
                {
                    CryptographicOperations.ZeroMemory(output);
                }
                throw new CryptographicException("Envelope authentication failed.", exception);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }
}
