using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc7748;
using Org.BouncyCastle.Math.EC.Rfc8032;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Provides portable cryptography with borrowed memory, thread-cached hash and cipher instances, stack or pooled secrets,
    /// and array segments at the legacy array-only provider boundaries.
    /// </summary>
    public static class Crypto
    {
        /// <summary>The SHA-256 digest size.</summary>
        public const int DigestLength = 32;
        /// <summary>The X25519 scalar, public key and shared-secret size.</summary>
        public const int AgreementKeyLength = 32;
        /// <summary>The ChaCha20-Poly1305 nonce size.</summary>
        public const int NonceLength = 12;
        /// <summary>The ChaCha20-Poly1305 authentication tag size.</summary>
        public const int TagLength = 16;
        /// <summary>The HMAC-SHA256 block size.</summary>
        private const int HmacBlockLength = 64;
        /// <summary>The largest HMAC message handled on the stack; longer messages use pooled storage.</summary>
        private const int HmacStackLimit = 512;
        /// <summary>The hexadecimal digits used by canonical identifiers.</summary>
        private const string HexDigits = "0123456789abcdef";
        /// <summary>The per-thread SHA-256 instance; one-shot hashing resets it after every use.</summary>
        [ThreadStatic]
        private static SHA256? t_sha256;
        /// <summary>The per-thread incremental SHA-256 instance used to hash a domain prefix followed by a block.</summary>
        [ThreadStatic]
        private static IncrementalHash? t_prefixedSha256;
        /// <summary>The per-thread authenticated cipher; every envelope reinitializes it with a fresh key and nonce.</summary>
        [ThreadStatic]
        private static ChaCha20Poly1305? t_cipher;

        /// <summary>Gets the per-thread SHA-256 instance, creating it on first use.</summary>
        private static SHA256 Sha256 => t_sha256 ??= SHA256.Create();

        /// <summary>Shuffles a list in place with a cryptographic random source, so attackers cannot predict selections.</summary>
        /// <typeparam name="T">The element type.</typeparam>
        /// <param name="items">The list to shuffle.</param>
        public static void Shuffle<T>(IList<T> items)
        {
            for (var index = items.Count - 1; index > 0; index--)
            {
                var other = RandomNumberGenerator.GetInt32(index + 1);
                var swap = items[index];
                items[index] = items[other];
                items[other] = swap;
            }
        }

        /// <summary>Generates independently owned random bytes.</summary>
        /// <param name="count">The byte count.</param>
        /// <returns>The random bytes.</returns>
        public static byte[] Random(int count)
        {
            var bytes = new byte[count];
            Fill(bytes);
            return bytes;
        }

        /// <summary>Fills caller-owned storage with cryptographic random bytes without allocating.</summary>
        /// <param name="destination">The storage to fill.</param>
        public static void Fill(Span<byte> destination)
        {
            RandomNumberGenerator.Fill(destination);
        }

        /// <summary>Hashes borrowed bytes into an owned digest.</summary>
        /// <param name="bytes">The input.</param>
        /// <returns>The 32-byte SHA-256 digest.</returns>
        public static byte[] Hash(ReadOnlySpan<byte> bytes)
        {
            var digest = new byte[DigestLength];
            Hash(bytes, digest);
            return digest;
        }

        /// <summary>Hashes borrowed input directly into caller-owned storage using the per-thread hash instance.</summary>
        /// <param name="bytes">The input.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        /// <exception cref="CryptographicException">The hash provider failed.</exception>
        public static void Hash(ReadOnlySpan<byte> bytes, Span<byte> destination)
        {
            if (destination.Length < DigestLength)
            {
                throw new ArgumentException("A SHA-256 destination requires 32 bytes.", nameof(destination));
            }
            if (!Sha256.TryComputeHash(bytes, destination, out var written) || written != DigestLength)
            {
                throw new CryptographicException("SHA-256 hashing failed.");
            }
        }

        /// <summary>Hashes a one-byte domain prefix followed by a borrowed block without concatenating them.</summary>
        /// <param name="prefix">The domain-separation byte.</param>
        /// <param name="bytes">The block.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        /// <exception cref="CryptographicException">The hash provider failed.</exception>
        public static void HashPrefixed(byte prefix, ReadOnlySpan<byte> bytes, Span<byte> destination)
        {
            if (destination.Length < DigestLength)
            {
                throw new ArgumentException("A SHA-256 destination requires 32 bytes.", nameof(destination));
            }
            var hash = t_prefixedSha256 ??= IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            try
            {
                Span<byte> first = stackalloc byte[1];
                first[0] = prefix;
                hash.AppendData(first);
                hash.AppendData(bytes);
                if (!hash.TryGetHashAndReset(destination, out var written) || written != DigestLength)
                {
                    throw new CryptographicException("Prefixed SHA-256 hashing failed.");
                }
            }
            catch
            {
                // A failed append leaves data in the instance, so the thread gets a fresh one next time.
                t_prefixedSha256 = null;
                hash.Dispose();
                throw;
            }
        }

        /// <summary>Formats lowercase hexadecimal without per-byte strings or a StringBuilder.</summary>
        /// <param name="bytes">The borrowed input.</param>
        /// <returns>The canonical hexadecimal string.</returns>
        public static string Hex(ReadOnlySpan<byte> bytes)
        {
            char[]? rented = null;
            Span<char> characters = bytes.Length <= 256 ? stackalloc char[bytes.Length * 2] : (rented = ArrayPool<char>.Shared.Rent(checked(bytes.Length * 2)));
            try
            {
                for (var i = 0; i < bytes.Length; i++)
                {
                    characters[i * 2] = HexDigits[bytes[i] >> 4];
                    characters[(i * 2) + 1] = HexDigits[bytes[i] & 15];
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

        /// <summary>Writes lowercase hexadecimal ASCII directly into caller-owned storage.</summary>
        /// <param name="bytes">The borrowed input.</param>
        /// <param name="destination">Exactly twice as many writable bytes as the input.</param>
        /// <exception cref="ArgumentException">The destination length does not match.</exception>
        public static void HexTo(ReadOnlySpan<byte> bytes, Span<byte> destination)
        {
            if (destination.Length != bytes.Length * 2)
            {
                throw new ArgumentException("A hexadecimal destination requires two bytes per input byte.", nameof(destination));
            }
            for (var i = 0; i < bytes.Length; i++)
            {
                destination[i * 2] = (byte)HexDigits[bytes[i] >> 4];
                destination[(i * 2) + 1] = (byte)HexDigits[bytes[i] & 15];
            }
        }

        /// <summary>Parses a canonical identifier into newly owned digest storage.</summary>
        /// <param name="value">The lowercase identifier.</param>
        /// <returns>The 32-byte digest.</returns>
        public static byte[] ParseHash(string value)
        {
            var digest = new byte[DigestLength];
            ParseHash(value, digest);
            return digest;
        }

        /// <summary>Parses an identifier into caller-owned storage without allocating.</summary>
        /// <param name="value">The canonical lowercase identifier.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        /// <exception cref="ArgumentException">The input or destination is invalid.</exception>
        public static void ParseHash(string value, Span<byte> destination)
        {
            if (value == null || value.Length != DigestLength * 2 || destination.Length < DigestLength)
            {
                throw new ArgumentException("Expected a lowercase SHA-256 identifier and a 32-byte destination.");
            }
            for (var i = 0; i < DigestLength; i++)
            {
                var high = HexDigits.IndexOf(value[i * 2]);
                var low = HexDigits.IndexOf(value[(i * 2) + 1]);
                if (high < 0 || low < 0)
                {
                    throw new ArgumentException("Expected a lowercase SHA-256 identifier.", nameof(value));
                }
                destination[i] = (byte)((high << 4) | low);
            }
        }

        /// <summary>Parses a canonical ASCII identifier received on the wire into caller-owned storage without decoding text.</summary>
        /// <param name="ascii">The 64 lowercase hexadecimal ASCII bytes.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        /// <exception cref="InvalidDataException">The identifier is not 64 lowercase hexadecimal digits.</exception>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        public static void ParseHash(ReadOnlySpan<byte> ascii, Span<byte> destination)
        {
            if (destination.Length < DigestLength)
            {
                throw new ArgumentException("A SHA-256 destination requires 32 bytes.", nameof(destination));
            }
            if (ascii.Length != DigestLength * 2)
            {
                throw new InvalidDataException("Expected a 64-digit protocol identifier.");
            }
            for (var i = 0; i < DigestLength; i++)
            {
                var high = HexValue(ascii[i * 2]);
                var low = HexValue(ascii[(i * 2) + 1]);
                if (high < 0 || low < 0)
                {
                    throw new InvalidDataException("Expected a lowercase hexadecimal protocol identifier.");
                }
                destination[i] = (byte)((high << 4) | low);
            }
        }

        /// <summary>Checks whether ASCII bytes form a canonical identifier without allocating.</summary>
        /// <param name="ascii">The bytes to check.</param>
        /// <returns>Whether the bytes are exactly 64 lowercase hexadecimal digits.</returns>
        public static bool IsHash(ReadOnlySpan<byte> ascii)
        {
            if (ascii.Length != DigestLength * 2)
            {
                return false;
            }
            foreach (var value in ascii)
            {
                if (HexValue(value) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Checks whether a string is a canonical identifier.</summary>
        /// <param name="value">The string to check.</param>
        /// <returns>Whether the string is exactly 64 lowercase hexadecimal digits.</returns>
        public static bool IsHash(string? value)
        {
            if (value == null || value.Length != DigestLength * 2)
            {
                return false;
            }
            foreach (var character in value)
            {
                if (character > 0x7f || HexValue((byte)character) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Compares ASCII bytes with a string ordinally without decoding.</summary>
        /// <param name="ascii">The ASCII bytes.</param>
        /// <param name="text">The expected text.</param>
        /// <returns>Whether every character matches.</returns>
        public static bool AsciiEquals(ReadOnlySpan<byte> ascii, string text)
        {
            if (text == null || ascii.Length != text.Length)
            {
                return false;
            }
            for (var i = 0; i < ascii.Length; i++)
            {
                if (ascii[i] != text[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Maps one lowercase hexadecimal ASCII digit to its value.</summary>
        /// <param name="value">The ASCII byte.</param>
        /// <returns>The digit value, or minus one for any other byte.</returns>
        private static int HexValue(byte value)
        {
            if (value >= '0' && value <= '9')
            {
                return value - '0';
            }
            if (value >= 'a' && value <= 'f')
            {
                return value - 'a' + 10;
            }
            return -1;
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

        /// <summary>Signs a borrowed canonical message directly into array-backed destination memory.</summary>
        /// <param name="key">The cached private key.</param>
        /// <param name="bytes">The canonical message.</param>
        /// <param name="destination">Exactly 64 writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is not 64 bytes long.</exception>
        internal static void SignTo(Ed25519PrivateKeyParameters key, ReadOnlyMemory<byte> bytes, Memory<byte> destination)
        {
            if (destination.Length != 64)
            {
                throw new ArgumentException("An Ed25519 signature requires exactly 64 bytes.", nameof(destination));
            }
            var input = Array(bytes);
            if (MemoryMarshal.TryGetArray<byte>(destination, out var segment))
            {
                key.Sign(Ed25519.Algorithm.Ed25519, null, input.Array!, input.Offset, input.Count, segment.Array!, segment.Offset);
                return;
            }
            Sign(key, bytes).CopyTo(destination);
        }

        /// <summary>Verifies a signature directly over borrowed memory without message copies.</summary>
        /// <param name="publicKey">The signing public key.</param>
        /// <param name="bytes">The canonical message.</param>
        /// <param name="signature">The detached signature.</param>
        /// <returns>Whether the signature is valid.</returns>
        public static bool Verify(ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> bytes, ReadOnlyMemory<byte> signature)
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

        /// <summary>Derives the owned private X25519 scalar of an identity from its signing seed.</summary>
        /// <param name="seed">The private identity seed.</param>
        /// <returns>The 32-byte scalar; the agreement clamps it on use, so it is interchangeable with a provider private key object.</returns>
        internal static byte[] AgreementScalar(ReadOnlySpan<byte> seed)
        {
            using var wire = new Wire();
            wire.Put(ProtocolTags.IdentityAgreement);
            wire.Put(seed);
            return Hash(wire.WrittenSpan);
        }

        /// <summary>Computes the X25519 public key of a scalar directly into array-backed destination memory.</summary>
        /// <param name="scalar">The private scalar, read from offset zero.</param>
        /// <param name="destination">Exactly 32 writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is not 32 bytes long.</exception>
        internal static void AgreementPublicKey(byte[] scalar, Memory<byte> destination)
        {
            if (destination.Length != AgreementKeyLength)
            {
                throw new ArgumentException("An X25519 public key requires exactly 32 bytes.", nameof(destination));
            }
            if (MemoryMarshal.TryGetArray<byte>(destination, out var segment))
            {
                X25519.ScalarMultBase(scalar, 0, segment.Array!, segment.Offset);
                return;
            }
            var copy = ArrayPool<byte>.Shared.Rent(AgreementKeyLength);
            try
            {
                X25519.ScalarMultBase(scalar, 0, copy, 0);
                copy.AsSpan(0, AgreementKeyLength).CopyTo(destination.Span);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(copy, clearArray: true);
            }
        }

        /// <summary>Creates an ephemeral X25519 key pair for one envelope.</summary>
        /// <param name="publicKey">Exactly 32 array-backed bytes receiving the public key.</param>
        /// <returns>The private scalar in pooled storage, which the caller returns with <see cref="ReturnSecret"/> after sealing.</returns>
        internal static byte[] EphemeralAgreement(Memory<byte> publicKey)
        {
            var scalar = ArrayPool<byte>.Shared.Rent(AgreementKeyLength);
            try
            {
                Fill(scalar.AsSpan(0, AgreementKeyLength));
                AgreementPublicKey(scalar, publicKey);
                return scalar;
            }
            catch
            {
                ReturnSecret(scalar);
                throw;
            }
        }

        /// <summary>Clears and returns pooled secret storage.</summary>
        /// <param name="secret">The pooled storage.</param>
        internal static void ReturnSecret(byte[] secret)
        {
            ArrayPool<byte>.Shared.Return(secret, clearArray: true);
        }

        /// <summary>Computes HMAC-SHA256 over up to three concatenated message parts using stack storage.</summary>
        /// <param name="key">The key of any length.</param>
        /// <param name="first">The first message part.</param>
        /// <param name="second">The second message part.</param>
        /// <param name="third">The third message part.</param>
        /// <param name="destination">At least 32 writable bytes.</param>
        private static void HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third,
            Span<byte> destination)
        {
            Span<byte> paddedKey = stackalloc byte[HmacBlockLength];
            if (key.Length > HmacBlockLength)
            {
                Hash(key, paddedKey);
            }
            else
            {
                key.CopyTo(paddedKey);
            }
            var length = HmacBlockLength + first.Length + second.Length + third.Length;
            byte[]? rented = null;
            Span<byte> inner = length <= HmacStackLimit ? stackalloc byte[HmacStackLimit] : (rented = ArrayPool<byte>.Shared.Rent(length));
            inner = inner.Slice(0, length);
            try
            {
                for (var i = 0; i < HmacBlockLength; i++)
                {
                    inner[i] = (byte)(paddedKey[i] ^ 0x36);
                }
                first.CopyTo(inner.Slice(HmacBlockLength));
                second.CopyTo(inner.Slice(HmacBlockLength + first.Length));
                third.CopyTo(inner.Slice(HmacBlockLength + first.Length + second.Length));
                Span<byte> outer = stackalloc byte[HmacBlockLength + DigestLength];
                for (var i = 0; i < HmacBlockLength; i++)
                {
                    outer[i] = (byte)(paddedKey[i] ^ 0x5c);
                }
                Hash(inner, outer.Slice(HmacBlockLength));
                Hash(outer, destination);
                CryptographicOperations.ZeroMemory(outer);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(inner);
                CryptographicOperations.ZeroMemory(paddedKey);
                if (rented != null)
                {
                    ArrayPool<byte>.Shared.Return(rented, clearArray: true);
                }
            }
        }

        /// <summary>Derives key material with HKDF-SHA256 (RFC 5869) entirely in stack storage.</summary>
        /// <param name="inputKeyMaterial">The input keying material, such as an agreed shared secret.</param>
        /// <param name="salt">The salt; an empty salt is equivalent to 32 zero bytes.</param>
        /// <param name="info">The context label of at most 256 bytes.</param>
        /// <param name="output">The destination of at most 8160 bytes.</param>
        /// <exception cref="ArgumentException">The label or output length is outside the supported range.</exception>
        public static void Hkdf(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, Span<byte> output)
        {
            if (info.Length > 256 || output.Length > 255 * DigestLength)
            {
                throw new ArgumentException("Unsupported HKDF label or output length.");
            }
            Span<byte> pseudoRandomKey = stackalloc byte[DigestLength];
            Span<byte> previous = stackalloc byte[DigestLength];
            Span<byte> counter = stackalloc byte[1];
            try
            {
                HmacSha256(salt, inputKeyMaterial, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, pseudoRandomKey);
                var previousLength = 0;
                var offset = 0;
                for (var index = 1; offset < output.Length; index++)
                {
                    counter[0] = (byte)index;
                    HmacSha256(pseudoRandomKey, previous.Slice(0, previousLength), info, counter, previous);
                    previousLength = DigestLength;
                    var count = Math.Min(DigestLength, output.Length - offset);
                    previous.Slice(0, count).CopyTo(output.Slice(offset));
                    offset += count;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pseudoRandomKey);
                CryptographicOperations.ZeroMemory(previous);
            }
        }

        /// <summary>Agrees on the envelope secret, derives the transcript-bound key and initializes the per-thread cipher.</summary>
        /// <param name="encrypt">Whether the cipher will encrypt.</param>
        /// <param name="scalar">The local private scalar, read from offset zero.</param>
        /// <param name="remote">The remote 32-byte public key.</param>
        /// <param name="header">The authenticated header, also hashed into the key derivation salt.</param>
        /// <param name="nonce">The 96-bit nonce.</param>
        /// <returns>The initialized cipher with the header already authenticated.</returns>
        /// <exception cref="CryptographicException">The public key, nonce or agreement is invalid.</exception>
        private static ChaCha20Poly1305 Prepare(bool encrypt, byte[] scalar, ReadOnlyMemory<byte> remote, ReadOnlyMemory<byte> header,
            ReadOnlyMemory<byte> nonce)
        {
            if (remote.Length != AgreementKeyLength || nonce.Length != NonceLength)
            {
                throw new CryptographicException("Invalid agreement public key or nonce length.");
            }
            var secrets = ArrayPool<byte>.Shared.Rent(AgreementKeyLength * 2);
            try
            {
                var publicKey = Array(remote);
                if (!X25519.CalculateAgreement(scalar, 0, publicKey.Array!, publicKey.Offset, secrets, 0))
                {
                    throw new CryptographicException("Invalid agreement public key.");
                }
                Span<byte> salt = stackalloc byte[DigestLength];
                Hash(header.Span, salt);
                Hkdf(secrets.AsSpan(0, AgreementKeyLength), salt, ProtocolTags.Envelope, secrets.AsSpan(AgreementKeyLength, AgreementKeyLength));
                var cipher = t_cipher ??= new ChaCha20Poly1305();
                cipher.Init(encrypt, new AeadParameters(new KeyParameter(secrets, AgreementKeyLength, AgreementKeyLength), TagLength * 8, nonce.ToArray()));
                var aad = Array(header);
                cipher.ProcessAadBytes(aad.Array!, aad.Offset, aad.Count);
                return cipher;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(secrets, clearArray: true);
            }
        }

        /// <summary>Encrypts a borrowed message and writes the length-prefixed ciphertext directly into the pooled envelope.</summary>
        /// <param name="writer">The envelope writer, which must not own the input.</param>
        /// <param name="scalar">The ephemeral private scalar, read from offset zero.</param>
        /// <param name="remote">The recipient's 32-byte agreement public key.</param>
        /// <param name="header">The authenticated header.</param>
        /// <param name="nonce">The 96-bit nonce.</param>
        /// <param name="input">The borrowed plaintext.</param>
        /// <exception cref="CryptographicException">The recipient key or nonce is invalid.</exception>
        internal static void EncryptTo(Wire writer, byte[] scalar, ReadOnlyMemory<byte> remote, ReadOnlyMemory<byte> header, ReadOnlyMemory<byte> nonce,
            ReadOnlyMemory<byte> input)
        {
            var cipher = Prepare(true, scalar, remote, header, nonce);
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

        /// <summary>
        /// Authenticates and decrypts ciphertext in place, so the received envelope buffer becomes the plaintext owner and no
        /// plaintext array is allocated.
        /// </summary>
        /// <param name="scalar">The local private scalar, read from offset zero.</param>
        /// <param name="remote">The sender's ephemeral 32-byte public key.</param>
        /// <param name="header">The authenticated header.</param>
        /// <param name="nonce">The 96-bit nonce.</param>
        /// <param name="cipherText">The exclusively owned ciphertext, overwritten with plaintext, or zeroed when authentication fails.</param>
        /// <returns>The plaintext view at the start of the ciphertext memory.</returns>
        /// <exception cref="CryptographicException">The public key or nonce is invalid, or ciphertext authentication failed.</exception>
        internal static ReadOnlyMemory<byte> DecryptInPlace(byte[] scalar, ReadOnlyMemory<byte> remote, ReadOnlyMemory<byte> header,
            ReadOnlyMemory<byte> nonce, ReadOnlyMemory<byte> cipherText)
        {
            if (cipherText.Length < TagLength)
            {
                throw new CryptographicException("Envelope authentication failed.");
            }
            if (!MemoryMarshal.TryGetArray(cipherText, out var segment))
            {
                // A custom memory manager cannot be written through a read-only view, so the copy becomes the plaintext owner.
                return DecryptInPlace(scalar, remote, header, nonce, cipherText.ToArray());
            }
            var cipher = Prepare(false, scalar, remote, header, nonce);
            var length = cipher.GetOutputSize(segment.Count);
            try
            {
                var count = cipher.ProcessBytes(segment.Array!, segment.Offset, segment.Count, segment.Array!, segment.Offset);
                count += cipher.DoFinal(segment.Array!, segment.Offset + count);
                if (count != length)
                {
                    throw new InvalidDataException("Unexpected authenticated output length.");
                }
                return cipherText.Slice(0, length);
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException exception)
            {
                CryptographicOperations.ZeroMemory(segment.AsSpan());
                throw new CryptographicException("Envelope authentication failed.", exception);
            }
        }
    }
}
