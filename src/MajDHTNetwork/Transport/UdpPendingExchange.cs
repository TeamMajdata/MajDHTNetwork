using System;
using System.Buffers.Binary;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace MajDHTNetwork.Transport
{
    /// <summary>Identifies a UDP exchange by its pinned source and complete request digest.</summary>
    internal readonly struct UdpExchangeKey : IEquatable<UdpExchangeKey>
    {
        /// <summary>The pinned remote address, or null for the default key.</summary>
        private readonly IPAddress? _address;
        /// <summary>The pinned remote port.</summary>
        private readonly int _port;
        /// <summary>The first digest word.</summary>
        private readonly ulong _first;
        /// <summary>The second digest word.</summary>
        private readonly ulong _second;
        /// <summary>The third digest word.</summary>
        private readonly ulong _third;
        /// <summary>The fourth digest word.</summary>
        private readonly ulong _fourth;

        /// <summary>Copies the correlation fields without retaining a received datagram.</summary>
        /// <param name="endpoint">The observed or explicitly pinned endpoint.</param>
        /// <param name="digest">The 32-byte sealed-request digest.</param>
        /// <exception cref="ArgumentOutOfRangeException">The digest is shorter than 32 bytes.</exception>
        internal UdpExchangeKey(IPEndPoint endpoint, ReadOnlySpan<byte> digest)
        {
            _address = endpoint.Address;
            _port = endpoint.Port;
            _first = BinaryPrimitives.ReadUInt64BigEndian(digest);
            _second = BinaryPrimitives.ReadUInt64BigEndian(digest.Slice(8));
            _third = BinaryPrimitives.ReadUInt64BigEndian(digest.Slice(16));
            _fourth = BinaryPrimitives.ReadUInt64BigEndian(digest.Slice(24));
        }

        /// <inheritdoc />
        public bool Equals(UdpExchangeKey other)
        {
            return _port == other._port && object.Equals(_address, other._address)
                && _first == other._first && _second == other._second
                && _third == other._third && _fourth == other._fourth;
        }

        /// <inheritdoc />
        public override bool Equals(object? obj)
        {
            return obj is UdpExchangeKey other && Equals(other);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            return HashCode.Combine(_address, _port, _first, _second, _third, _fourth);
        }
    }

    /// <summary>Owns bounded challenge and response signals for one UDP exchange.</summary>
    internal sealed class UdpPendingExchange
    {
        /// <summary>The first challenge from the pinned endpoint.</summary>
        internal TaskCompletionSource<ReadOnlyMemory<byte>> Challenge { get; } =
            new TaskCompletionSource<ReadOnlyMemory<byte>>(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>The first correlated response after sending a cookie-bearing request.</summary>
        internal TaskCompletionSource<ReadOnlyMemory<byte>> Response { get; } =
            new TaskCompletionSource<ReadOnlyMemory<byte>>(TaskCreationOptions.RunContinuationsAsynchronously);
        /// <summary>Gets the immutable destination snapshot.</summary>
        internal IPEndPoint Endpoint { get; }
        /// <summary>Gets the exact request digest.</summary>
        internal byte[] Digest { get; }
        /// <summary>Whether the challenge has been used to send a request.</summary>
        private int _requestSent;
        /// <summary>Gets whether a cookie-bearing request has been sent.</summary>
        internal bool RequestSent => Volatile.Read(ref _requestSent) != 0;

        /// <summary>Creates the two signals for a pinned request.</summary>
        /// <param name="endpoint">The destination endpoint, already copied by the caller.</param>
        /// <param name="digest">The owned sealed-request digest.</param>
        internal UdpPendingExchange(IPEndPoint endpoint, byte[] digest)
        {
            Endpoint = endpoint;
            Digest = digest;
        }

        /// <summary>Allows replies after committing to transmit the validated request.</summary>
        internal void MarkRequestSent()
        {
            Volatile.Write(ref _requestSent, 1);
        }
    }
}
