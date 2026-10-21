using System;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>The decoded arguments of a Probe request.</summary>
    public readonly struct ProbeRequest
    {
        /// <summary>Gets the 16-byte dial-back nonce issued by the Traversal node, borrowing the request body.</summary>
        public ReadOnlyMemory<byte> Nonce { get; }
        /// <summary>Gets the index of the probed port in the dial-back's candidate port list.</summary>
        public int PortIndex { get; }

        /// <summary>Creates the arguments of a Probe request.</summary>
        /// <param name="nonce">The dial-back nonce.</param>
        /// <param name="portIndex">The candidate port index.</param>
        /// <exception cref="ArgumentException">The nonce is not 16 bytes long.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The index is outside the candidate port range.</exception>
        public ProbeRequest(ReadOnlyMemory<byte> nonce, int portIndex)
        {
            if (nonce.Length != ProbeMessage.NonceLength)
            {
                throw new ArgumentException("A dial-back nonce must contain 16 bytes.", nameof(nonce));
            }
            if (portIndex < 0 || portIndex >= TraversalMessage.MaxProbePorts)
            {
                throw new ArgumentOutOfRangeException(nameof(portIndex));
            }
            Nonce = nonce;
            PortIndex = portIndex;
        }
    }

    /// <summary>
    /// Encodes the Probe operation, the independent dial-back a helper sends to prove that an observed endpoint is
    /// reachable: the request carries the nonce issued by the Traversal node and the candidate port index, and a successful
    /// result is empty.
    /// </summary>
    public static class ProbeMessage
    {
        /// <summary>The nonce length in bytes.</summary>
        public const int NonceLength = 16;

        /// <summary>Writes a Probe request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="nonce">The 16-byte dial-back nonce.</param>
        /// <param name="portIndex">The index of the probed port in the candidate list.</param>
        public static void WriteRequest(Wire writer, ReadOnlySpan<byte> nonce, int portIndex)
        {
            writer.Put(nonce);
            writer.PutLong(portIndex);
        }

        /// <summary>Reads a complete Probe request body.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The nonce and port index; the receiver matches them against its pending dial-back.</returns>
        /// <exception cref="InvalidDataException">The nonce length or port index is invalid, or the body has trailing data.</exception>
        public static ProbeRequest ReadRequest(Wire reader)
        {
            var nonce = reader.Bytes(NonceLength);
            var index = reader.Long();
            reader.End();
            if (nonce.Length != NonceLength || index < 0 || index >= TraversalMessage.MaxProbePorts)
            {
                throw new InvalidDataException("Invalid dial-back probe.");
            }
            return new ProbeRequest(nonce, (int)index);
        }
    }
}
