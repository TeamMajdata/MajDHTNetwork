using System.IO;
using System.Net;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Encodes an endpoint that a node observed as the socket source of an authenticated request: a canonical address string
    /// followed by an integer port. Hello, Traversal and Forward session responses report observed endpoints.
    /// </summary>
    public static class ObservedEndpoint
    {
        /// <summary>The maximum UTF-8 length of a canonical address string.</summary>
        public const int MaxAddressLength = 96;

        /// <summary>Writes an observed endpoint.</summary>
        /// <param name="writer">The destination encoder.</param>
        /// <param name="endpoint">The observed socket endpoint.</param>
        public static void Write(Wire writer, IPEndPoint endpoint)
        {
            writer.PutText(endpoint.Address.ToString());
            writer.PutLong(endpoint.Port);
        }

        /// <summary>Reads a canonical unicast endpoint with a nonzero port.</summary>
        /// <param name="reader">The source decoder.</param>
        /// <returns>The observed endpoint.</returns>
        /// <exception cref="InvalidDataException">The address is not canonical unicast text or the port is out of range.</exception>
        public static IPEndPoint Read(Wire reader)
        {
            var text = reader.Text(MaxAddressLength);
            var port = reader.Long();
            if (!IPAddress.TryParse(text, out var address) || address.ToString() != text || !NetworkScope.IsUnicast(address)
                || port < 1 || port > 65535)
            {
                throw new InvalidDataException("Invalid observed endpoint.");
            }
            return new IPEndPoint(address, (int)port);
        }
    }
}
