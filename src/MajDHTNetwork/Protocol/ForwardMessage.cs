using System;
using System.IO;
using System.Net;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>The first byte of every Forward request.</summary>
    public enum ForwardAction : byte
    {
        /// <summary>Opens or refreshes the sender's forwarding session: the forwarder records the observed source endpoint.</summary>
        Session = 0,
        /// <summary>Asks the forwarder to relay an opaque envelope to a destination and return the destination's opaque response.</summary>
        Relay = 1,
        /// <summary>Delivers a relayed opaque envelope from the forwarder to its destination, which returns its opaque response.</summary>
        Deliver = 2
    }

    /// <summary>The decoded arguments of a Forward <see cref="ForwardAction.Relay"/> request.</summary>
    public readonly struct ForwardRelayRequest
    {
        /// <summary>Gets the final recipient's node identifier.</summary>
        public string DestinationId { get; }
        /// <summary>Gets the opaque inner envelope, sealed to the destination, borrowing the request body.</summary>
        public ReadOnlyMemory<byte> Envelope { get; }

        /// <summary>Creates the arguments of a Relay action.</summary>
        /// <param name="destinationId">The final recipient's node identifier.</param>
        /// <param name="envelope">The opaque inner envelope.</param>
        /// <exception cref="ArgumentNullException">The destination is null.</exception>
        public ForwardRelayRequest(string destinationId, ReadOnlyMemory<byte> envelope)
        {
            DestinationId = destinationId ?? throw new ArgumentNullException(nameof(destinationId));
            Envelope = envelope;
        }
    }

    /// <summary>
    /// Encodes the Forward operation, which a Forwarder serves: a requester opens a session so the forwarder learns where to
    /// deliver to it, a requester asks the forwarder to relay an opaque envelope to a destination, and the forwarder delivers
    /// that envelope to the destination inside its own authenticated request. The inner envelope and the inner response are
    /// opened only by the two peers that exchange them. Every request starts with a <see cref="ForwardAction"/> byte, read with
    /// <see cref="ReadAction"/> before the action's own reader.
    /// </summary>
    public static class ForwardMessage
    {
        /// <summary>Reads the action byte that starts every Forward request body.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The action; the caller continues with that action's reader.</returns>
        /// <exception cref="InvalidDataException">The action is unknown.</exception>
        public static ForwardAction ReadAction(Wire reader)
        {
            var action = reader.Byte();
            if (action > (byte)ForwardAction.Deliver)
            {
                throw new InvalidDataException("Invalid forward action.");
            }
            return (ForwardAction)action;
        }

        /// <summary>Writes a complete <see cref="ForwardAction.Session"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        public static void WriteSessionRequest(Wire writer)
        {
            writer.PutByte((byte)ForwardAction.Session);
        }

        /// <summary>Reads the remainder of a <see cref="ForwardAction.Session"/> request body, which is empty.</summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <exception cref="InvalidDataException">The body has trailing data.</exception>
        public static void ReadSessionRequest(Wire reader)
        {
            reader.End();
        }

        /// <summary>Writes a successful <see cref="ForwardAction.Session"/> result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="observed">The endpoint the forwarder observed for the requester on this transport.</param>
        public static void WriteSessionResponse(Wire writer, IPEndPoint observed)
        {
            ObservedEndpoint.Write(writer, observed);
        }

        /// <summary>Reads a complete <see cref="ForwardAction.Session"/> result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The endpoint the forwarder observed for the requester.</returns>
        /// <exception cref="InvalidDataException">The endpoint is malformed or the result has trailing data.</exception>
        public static IPEndPoint ReadSessionResponse(Wire reader)
        {
            var observed = ObservedEndpoint.Read(reader);
            reader.End();
            return observed;
        }

        /// <summary>Writes a complete <see cref="ForwardAction.Relay"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="destinationId">The final recipient's node identifier.</param>
        /// <param name="envelope">The inner request already sealed to the destination.</param>
        public static void WriteRelayRequest(Wire writer, string destinationId, ReadOnlySpan<byte> envelope)
        {
            writer.PutByte((byte)ForwardAction.Relay);
            writer.PutText(destinationId);
            writer.Put(envelope);
        }

        /// <summary>
        /// Reads the remainder of a <see cref="ForwardAction.Relay"/> request body and checks that the inner envelope is a Ping,
        /// Find, Store or Block request addressed to the declared destination, so a forwarder never relays responses, control
        /// operations or nested forwards.
        /// </summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <returns>The destination and the relayable inner envelope.</returns>
        /// <exception cref="InvalidDataException">The body is malformed or the inner envelope must not be relayed.</exception>
        public static ForwardRelayRequest ReadRelayRequest(Wire reader)
        {
            var destination = reader.Text(Crypto.DigestLength * 2);
            var envelope = reader.Bytes(Wire.MaxPacket);
            reader.End();
            Packet.CheckForward(envelope, destination);
            return new ForwardRelayRequest(destination, envelope);
        }

        /// <summary>Writes a complete <see cref="ForwardAction.Deliver"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="envelope">The relayed inner request, sealed by its origin to the destination.</param>
        public static void WriteDeliverRequest(Wire writer, ReadOnlySpan<byte> envelope)
        {
            writer.PutByte((byte)ForwardAction.Deliver);
            writer.Put(envelope);
        }

        /// <summary>
        /// Reads the remainder of a <see cref="ForwardAction.Deliver"/> request body and checks that the inner envelope is a
        /// Ping, Find, Store or Block request addressed to the receiving node.
        /// </summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <param name="recipientId">The receiving node's identifier, which the inner header must name.</param>
        /// <returns>The inner envelope, borrowing the request body.</returns>
        /// <exception cref="InvalidDataException">The body is malformed or the inner envelope must not be delivered.</exception>
        public static ReadOnlyMemory<byte> ReadDeliverRequest(Wire reader, string recipientId)
        {
            var envelope = reader.Bytes(Wire.MaxPacket);
            reader.End();
            Packet.CheckForward(envelope, recipientId);
            return envelope;
        }

        /// <summary>Writes the successful result of a <see cref="ForwardAction.Relay"/> or <see cref="ForwardAction.Deliver"/> request.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="envelope">The destination's response envelope, passed on unchanged.</param>
        public static void WriteEnvelopeResponse(Wire writer, ReadOnlySpan<byte> envelope)
        {
            writer.Put(envelope);
        }

        /// <summary>Reads the complete result of a <see cref="ForwardAction.Relay"/> or <see cref="ForwardAction.Deliver"/> request.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The opaque response envelope, borrowing the result memory; the origin authenticates it against the destination.</returns>
        /// <exception cref="InvalidDataException">The result is malformed.</exception>
        public static ReadOnlyMemory<byte> ReadEnvelopeResponse(Wire reader)
        {
            var envelope = reader.Bytes(Wire.MaxPacket);
            reader.End();
            return envelope;
        }
    }
}
