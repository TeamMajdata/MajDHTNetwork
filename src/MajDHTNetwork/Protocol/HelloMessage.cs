using System.IO;
using System.Net;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Encodes the Hello operation, which learns the signed contact listening at an endpoint: the request is empty and sent
    /// as a signed plaintext envelope with <see cref="Packet.SealHello"/>; the result reports the endpoint the responder
    /// observed for the requester, and the response envelope itself carries the responder's contact.
    /// </summary>
    public static class HelloMessage
    {
        /// <summary>Reads a complete Hello request body, which must be empty.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <exception cref="InvalidDataException">The body is not empty.</exception>
        public static void ReadRequest(Wire reader)
        {
            reader.End();
        }

        /// <summary>Writes a successful Hello result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="observedSource">The socket endpoint the request arrived from.</param>
        public static void WriteResponse(Wire writer, IPEndPoint observedSource)
        {
            ObservedEndpoint.Write(writer, observedSource);
        }

        /// <summary>Reads a complete Hello result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The endpoint the responder observed for the requester.</returns>
        /// <exception cref="InvalidDataException">The endpoint is invalid or the result has trailing data.</exception>
        public static IPEndPoint ReadResponse(Wire reader)
        {
            var observed = ObservedEndpoint.Read(reader);
            reader.End();
            return observed;
        }
    }
}
