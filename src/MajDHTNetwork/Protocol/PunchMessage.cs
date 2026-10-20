using System;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Encodes the Punch operation, the direct probe both introduced peers send from their listening ports: the body is
    /// exactly the raw 16-byte introduction ticket without a length prefix, and a successful result is empty.
    /// </summary>
    public static class PunchMessage
    {
        /// <summary>The ticket length in bytes.</summary>
        public const int TicketLength = 16;

        /// <summary>Writes a Punch request body.</summary>
        /// <param name="writer">The request body encoder, which must be empty.</param>
        /// <param name="ticket">The 16-byte ticket from the relay's introduction.</param>
        /// <exception cref="ArgumentException">The ticket is not 16 bytes long.</exception>
        public static void WriteRequest(Wire writer, ReadOnlySpan<byte> ticket)
        {
            if (ticket.Length != TicketLength)
            {
                throw new ArgumentException("A punch ticket must contain 16 bytes.", nameof(ticket));
            }
            writer.PutRaw(ticket);
        }

        /// <summary>Validates a Punch request body.</summary>
        /// <param name="body">The decrypted request body.</param>
        /// <returns>The ticket, borrowing the body memory.</returns>
        /// <exception cref="InvalidDataException">The body is not exactly 16 bytes long.</exception>
        public static ReadOnlyMemory<byte> ReadRequest(ReadOnlyMemory<byte> body)
        {
            if (body.Length != TicketLength)
            {
                throw new InvalidDataException("A direct probe requires a 128-bit introduction ticket.");
            }
            return body;
        }
    }
}
