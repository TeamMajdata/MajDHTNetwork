using System;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>An authenticated packet together with the owned envelope that its sender, identifier and body borrow.</summary>
    /// <remarks>
    /// Disposing the packet releases the received frame behind the envelope, after which none of the packet's fields may be
    /// read. Narrowing transfers the frame to a view of some of the packet's bytes, such as its response body, so the packet
    /// must not be disposed afterwards.
    /// </remarks>
    internal readonly struct OwnedPacket : IDisposable
    {
        /// <summary>The owned envelope the packet was opened from.</summary>
        private readonly OwnedMemory _envelope;

        /// <summary>Gets the authenticated packet, valid until the owner is disposed.</summary>
        internal Packet Packet { get; }

        /// <summary>Pairs an opened packet with the envelope it borrows.</summary>
        /// <param name="packet">The packet opened from the envelope.</param>
        /// <param name="envelope">The owned envelope, released when this owner is disposed.</param>
        internal OwnedPacket(Packet packet, OwnedMemory envelope)
        {
            Packet = packet;
            _envelope = envelope;
        }

        /// <summary>Transfers the frame to a view of some of the packet's bytes, such as its body.</summary>
        /// <param name="bytes">The bytes to view, which must lie inside the packet's envelope.</param>
        /// <returns>The view, which now releases the frame; this packet must not be disposed afterwards.</returns>
        internal OwnedMemory Narrow(ReadOnlyMemory<byte> bytes)
        {
            return _envelope.Narrow(bytes);
        }

        /// <summary>Releases the received frame exactly once.</summary>
        public void Dispose()
        {
            _envelope.Dispose();
        }
    }
}
