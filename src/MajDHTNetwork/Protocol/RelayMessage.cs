using System;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>The decoded arguments of a Relay request.</summary>
    public readonly struct RelayRequest
    {
        /// <summary>Gets the final recipient's node identifier.</summary>
        public string DestinationId { get; }
        /// <summary>Gets the opaque inner envelope, sealed to the destination, borrowing the request body.</summary>
        public ReadOnlyMemory<byte> Envelope { get; }

        /// <summary>Creates the arguments of a Relay request.</summary>
        /// <param name="destinationId">The final recipient's node identifier.</param>
        /// <param name="envelope">The opaque inner envelope.</param>
        /// <exception cref="ArgumentNullException">The destination is null.</exception>
        public RelayRequest(string destinationId, ReadOnlyMemory<byte> envelope)
        {
            DestinationId = destinationId ?? throw new ArgumentNullException(nameof(destinationId));
            Envelope = envelope;
        }
    }

    /// <summary>
    /// Encodes the Relay operation: the request names a destination and carries an opaque envelope sealed to it; the result
    /// is the destination's opaque response envelope, which only the original requester can open.
    /// </summary>
    public static class RelayMessage
    {
        /// <summary>Writes a Relay request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="destinationId">The final recipient's node identifier.</param>
        /// <param name="envelope">The inner request already sealed to the destination.</param>
        public static void WriteRequest(Wire writer, string destinationId, ReadOnlySpan<byte> envelope)
        {
            writer.PutText(destinationId);
            writer.Put(envelope);
        }

        /// <summary>
        /// Reads a complete Relay request body and checks that the inner envelope is a Ping, Find, Store or Block request
        /// addressed to the declared destination, so a relay never forwards responses, control operations or nested relays.
        /// </summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The destination and the forwardable inner envelope.</returns>
        /// <exception cref="InvalidDataException">The body is malformed or the inner envelope must not be forwarded.</exception>
        public static RelayRequest ReadRequest(Wire reader)
        {
            var destination = reader.Text(Crypto.DigestLength * 2);
            var envelope = reader.Bytes(Wire.MaxPacket);
            reader.End();
            Packet.CheckForward(envelope, destination);
            return new RelayRequest(destination, envelope);
        }

        /// <summary>Writes a successful Relay result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="envelope">The destination's response envelope, forwarded unchanged.</param>
        public static void WriteResponse(Wire writer, ReadOnlySpan<byte> envelope)
        {
            writer.Put(envelope);
        }

        /// <summary>Reads a complete Relay result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The opaque response envelope, borrowing the result memory; the requester authenticates it against the destination.</returns>
        /// <exception cref="InvalidDataException">The result is malformed.</exception>
        public static ReadOnlyMemory<byte> ReadResponse(Wire reader)
        {
            var envelope = reader.Bytes(Wire.MaxPacket);
            reader.End();
            return envelope;
        }
    }
}
