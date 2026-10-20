using System;
using System.Net;
using System.Security.Cryptography;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork.Transport
{
    /// <summary>Validates UDP return reachability with fixed-size cookies and borrowed envelope views.</summary>
    internal sealed class UdpCookies : IDisposable
    {
        /// <summary>The fixed transport header length.</summary>
        internal const int PrefixLength = 5;
        /// <summary>The SHA-256 request digest and cookie size.</summary>
        internal const int DigestLength = 32;
        /// <summary>The request and correlated-response transport overhead.</summary>
        internal const int CorrelatedPrefixLength = PrefixLength + DigestLength;
        /// <summary>The non-amplifying hello and challenge length.</summary>
        internal const int HelloLength = 69;
        /// <summary>The maximum transport datagram size.</summary>
        internal const int MaxDatagram = Wire.MaxPacket + CorrelatedPrefixLength;
        /// <summary>The keyed hash over the running-node cookie secret, reused for every cookie under <see cref="_hmacGate"/>.</summary>
        private readonly HMACSHA256 _hmac = new HMACSHA256(Crypto.Random(32));
        /// <summary>Serializes use of the keyed hash, which is not thread-safe.</summary>
        private readonly object _hmacGate = new object();

        /// <summary>Writes a fixed transport header.</summary>
        /// <param name="destination">At least five writable bytes.</param>
        /// <param name="kind">The transport operation.</param>
        private static void Header(Span<byte> destination, byte kind)
        {
            destination[0] = 0x4d;
            destination[1] = 0x44;
            destination[2] = 0x55;
            destination[3] = 1;
            destination[4] = kind;
        }

        /// <summary>Checks the header and absolute frame size.</summary>
        /// <param name="bytes">The received frame.</param>
        /// <param name="kind">The expected operation.</param>
        /// <returns>Whether the frame header is valid.</returns>
        internal static bool IsFrame(ReadOnlySpan<byte> bytes, byte kind)
        {
            return bytes.Length >= PrefixLength && bytes.Length <= MaxDatagram
                && bytes[0] == 0x4d && bytes[1] == 0x44 && bytes[2] == 0x55 && bytes[3] == 1 && bytes[4] == kind;
        }

        /// <summary>Creates a padded address-validation hello.</summary>
        /// <param name="packetHash">The sealed-request SHA-256.</param>
        /// <returns>The fixed-size owned frame.</returns>
        internal static byte[] Hello(ReadOnlySpan<byte> packetHash)
        {
            var bytes = new byte[HelloLength];
            Header(bytes, 0);
            packetHash.CopyTo(bytes.AsSpan(PrefixLength, 32));
            return bytes;
        }

        /// <summary>Computes a source- and request-bound cookie into caller-owned storage.</summary>
        /// <param name="endpoint">The observed source endpoint.</param>
        /// <param name="packetHash">The request digest.</param>
        /// <param name="window">The server minute window.</param>
        /// <param name="destination">The cookie destination.</param>
        private void Cookie(IPEndPoint endpoint, ReadOnlySpan<byte> packetHash, long window, Span<byte> destination)
        {
            using var wire = new Wire();
            Span<byte> address = stackalloc byte[16];
            endpoint.Address.TryWriteBytes(address, out var count);
            wire.Put(address.Slice(0, count));
            wire.PutLong(endpoint.Port);
            wire.PutLong(window);
            wire.Put(packetHash);
            lock (_hmacGate)
            {
                if (!_hmac.TryComputeHash(wire.WrittenSpan, destination, out var written) || written != 32)
                {
                    throw new CryptographicException("UDP cookie hashing failed.");
                }
            }
        }

        /// <summary>Releases the keyed hash and its secret.</summary>
        public void Dispose()
        {
            lock (_hmacGate)
            {
                _hmac.Dispose();
            }
        }

        /// <summary>Creates a same-size stateless challenge without temporary digest arrays.</summary>
        /// <param name="hello">The hello frame.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <returns>The fixed-size challenge or null for invalid input.</returns>
        internal byte[]? Challenge(ReadOnlySpan<byte> hello, IPEndPoint source)
        {
            if (!IsFrame(hello, 0) || hello.Length != HelloLength)
            {
                return null;
            }
            var digest = hello.Slice(PrefixLength, 32);
            var bytes = new byte[HelloLength];
            Header(bytes, 1);
            Cookie(source, digest, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60, bytes.AsSpan(PrefixLength, 32));
            digest.CopyTo(bytes.AsSpan(PrefixLength + 32, 32));
            return bytes;
        }

        /// <summary>Writes a cookie-bearing request into reusable transport storage.</summary>
        /// <param name="challenge">The challenge frame.</param>
        /// <param name="packet">The sealed request.</param>
        /// <param name="packetHash">The expected request digest.</param>
        /// <param name="destination">Exactly packet length plus 37 writable bytes.</param>
        /// <returns>Whether the challenge and destination are valid.</returns>
        internal static bool WriteRequest(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> packet, ReadOnlySpan<byte> packetHash, Span<byte> destination)
        {
            if (!IsFrame(challenge, 1) || challenge.Length != HelloLength || destination.Length != packet.Length + 37
                || !CryptographicOperations.FixedTimeEquals(challenge.Slice(PrefixLength + 32, 32), packetHash))
            {
                return false;
            }
            Header(destination, 2);
            challenge.Slice(PrefixLength, 32).CopyTo(destination.Slice(PrefixLength, 32));
            packet.CopyTo(destination.Slice(PrefixLength + 32));
            return true;
        }

        /// <summary>Creates a retained request for callers needing independently owned bytes.</summary>
        /// <param name="challenge">The server challenge.</param>
        /// <param name="packet">The sealed request.</param>
        /// <param name="packetHash">The request digest.</param>
        /// <returns>The request or null for an unrelated challenge.</returns>
        internal static byte[]? Request(ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> packet, ReadOnlySpan<byte> packetHash)
        {
            var bytes = new byte[packet.Length + 37];
            return WriteRequest(challenge, packet, packetHash, bytes) ? bytes : null;
        }

        /// <summary>Authenticates the source and returns a zero-copy sealed-packet view.</summary>
        /// <param name="request">The received transport frame.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <returns>The packet view or null when the cookie is invalid.</returns>
        internal ReadOnlyMemory<byte>? OpenRequest(ReadOnlyMemory<byte> request, IPEndPoint source)
        {
            if (!IsFrame(request.Span, 2) || request.Length <= PrefixLength + 32)
            {
                return null;
            }
            var packet = request.Slice(PrefixLength + 32);
            Span<byte> digest = stackalloc byte[32];
            Span<byte> expected = stackalloc byte[32];
            Crypto.Hash(packet.Span, digest);
            var window = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 60;
            var cookie = request.Span.Slice(PrefixLength, 32);
            Cookie(source, digest, window, expected);
            if (!CryptographicOperations.FixedTimeEquals(cookie, expected))
            {
                Cookie(source, digest, window - 1, expected);
                if (!CryptographicOperations.FixedTimeEquals(cookie, expected))
                {
                    return null;
                }
            }
            return packet;
        }

        /// <summary>Writes a sealed response into pooled caller storage.</summary>
        /// <param name="packet">The sealed response.</param>
        /// <param name="destination">Exactly packet length plus five bytes.</param>
        internal static void WriteReply(ReadOnlySpan<byte> packet, Span<byte> destination)
        {
            Header(destination, 3);
            packet.CopyTo(destination.Slice(PrefixLength));
        }

        /// <summary>Writes a response correlated to the exact sealed request.</summary>
        /// <param name="packet">The sealed response.</param>
        /// <param name="packetHash">The 32-byte sealed-request SHA-256 digest.</param>
        /// <param name="destination">Exactly packet length plus 37 writable bytes.</param>
        /// <exception cref="ArgumentException">A digest or destination length is invalid.</exception>
        internal static void WriteReply(ReadOnlySpan<byte> packet, ReadOnlySpan<byte> packetHash, Span<byte> destination)
        {
            if (packetHash.Length != DigestLength || packet.Length == 0 || packet.Length > Wire.MaxPacket
                || destination.Length != packet.Length + CorrelatedPrefixLength)
            {
                throw new ArgumentException("Invalid correlated UDP response size.");
            }
            Header(destination, 4);
            packetHash.CopyTo(destination.Slice(PrefixLength, DigestLength));
            packet.CopyTo(destination.Slice(CorrelatedPrefixLength));
        }

        /// <summary>Reads the request digest echoed by a fixed-size challenge.</summary>
        /// <param name="challenge">The received challenge.</param>
        /// <returns>The borrowed digest or null for an invalid challenge.</returns>
        internal static ReadOnlyMemory<byte>? ChallengeDigest(ReadOnlyMemory<byte> challenge)
        {
            if (!IsFrame(challenge.Span, 1) || challenge.Length != HelloLength)
            {
                return null;
            }
            return challenge.Slice(CorrelatedPrefixLength, DigestLength);
        }

        /// <summary>Reads a correlated reply's request digest without accepting legacy frames.</summary>
        /// <param name="reply">The received transport frame.</param>
        /// <returns>The borrowed digest or null for an invalid correlated reply.</returns>
        internal static ReadOnlyMemory<byte>? ReplyDigest(ReadOnlyMemory<byte> reply)
        {
            if (!IsFrame(reply.Span, 4) || reply.Length <= CorrelatedPrefixLength)
            {
                return null;
            }
            return reply.Slice(PrefixLength, DigestLength);
        }

        /// <summary>Extracts a response only when its request digest matches.</summary>
        /// <param name="reply">The received correlated transport frame.</param>
        /// <param name="packetHash">The expected sealed-request digest.</param>
        /// <returns>The packet view or null for an invalid or unrelated frame.</returns>
        internal static ReadOnlyMemory<byte>? OpenReply(ReadOnlyMemory<byte> reply, ReadOnlySpan<byte> packetHash)
        {
            var digest = ReplyDigest(reply);
            if (!digest.HasValue || packetHash.Length != DigestLength
                || !CryptographicOperations.FixedTimeEquals(digest.Value.Span, packetHash))
            {
                return null;
            }
            return reply.Slice(CorrelatedPrefixLength);
        }

        /// <summary>Extracts a legacy or correlated response without copying its payload.</summary>
        /// <param name="reply">The received transport frame.</param>
        /// <returns>The packet view or null for an invalid frame.</returns>
        internal static ReadOnlyMemory<byte>? OpenReply(ReadOnlyMemory<byte> reply)
        {
            if (ReplyDigest(reply).HasValue)
            {
                return reply.Slice(CorrelatedPrefixLength);
            }
            if (!IsFrame(reply.Span, 3) || reply.Length <= PrefixLength || reply.Length > Wire.MaxPacket + PrefixLength)
            {
                return null;
            }
            return reply.Slice(PrefixLength);
        }
    }
}
