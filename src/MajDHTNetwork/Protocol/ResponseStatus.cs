using System;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Frames the body of every response: one status byte followed by the length-prefixed result of a successful operation.
    /// Requests never carry this wrapper.
    /// </summary>
    public static class ResponseStatus
    {
        /// <summary>The status of a successful operation whose result follows.</summary>
        public const byte Success = 0;
        /// <summary>The generic rejection status; it carries an empty result and no private error details.</summary>
        public const byte Rejected = 1;

        /// <summary>Writes a successful response body.</summary>
        /// <param name="body">The response body encoder, which must be empty.</param>
        /// <param name="result">The operation result, or empty for operations without a result.</param>
        public static void WriteSuccess(Wire body, ReadOnlySpan<byte> result)
        {
            body.PutByte(Success);
            body.Put(result);
        }

        /// <summary>Writes a rejection body without disclosing why the request failed.</summary>
        /// <param name="body">The response body encoder, which must be empty.</param>
        public static void WriteRejection(Wire body)
        {
            body.PutByte(Rejected);
            body.Put(ReadOnlySpan<byte>.Empty);
        }

        /// <summary>Validates the status of an authenticated response body and returns its result.</summary>
        /// <param name="body">The decrypted response body, as <see cref="Packet.Body"/> exposes it.</param>
        /// <returns>The operation result, borrowing the body memory.</returns>
        /// <exception cref="IOException">The authenticated peer rejected the request.</exception>
        /// <exception cref="InvalidDataException">The body is not a status byte followed by exactly one result value.</exception>
        public static ReadOnlyMemory<byte> ReadResult(ReadOnlyMemory<byte> body)
        {
            using var reader = new Wire(body);
            var status = reader.Byte();
            var result = reader.Bytes(Wire.MaxPacket);
            reader.End();
            if (status != Success)
            {
                throw new IOException("The authenticated peer rejected the request.");
            }
            return result;
        }
    }
}
