using System;
using System.Collections.Generic;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Encodes the bounded peer lists of a Find response: an integer count followed by that many peers, each a signed contact
    /// and the endpoints at which the responder observed it. Each contact is verified independently when read.
    /// </summary>
    public static class PeerList
    {
        /// <summary>The maximum number of peers in one list.</summary>
        public const int MaxPeers = 16;
        /// <summary>
        /// The default byte budget of one list, including the length prefixes of its contacts, which keeps a Find response with
        /// two lists below the envelope limit even when contacts carry hints.
        /// </summary>
        public const int DefaultBudget = 26000;
        /// <summary>
        /// The bytes reserved for one peer's endpoint list in the budget: the count and four endpoints with maximal address
        /// text, so a list written within a budget stays within it whatever endpoints its peers carry.
        /// </summary>
        public const int MaxEndpointsLength = 8 + (DHTPeer.MaxEndpoints * (8 + DHTEndpoint.MaxAddressLength + 8 + 8));

        /// <summary>Writes the leading peers that fit the count and byte budget.</summary>
        /// <param name="writer">The destination encoder.</param>
        /// <param name="peers">The ordered candidate peers; at most <see cref="MaxPeers"/> are written.</param>
        /// <param name="budget">The maximum encoded bytes of the written peers, counting each contact with its length prefix and endpoints.</param>
        public static void Write(Wire writer, IReadOnlyList<DHTPeer> peers, int budget = DefaultBudget)
        {
            var count = 0;
            var used = 0;
            while (count < Math.Min(MaxPeers, peers.Count) && used + 8 + peers[count].Contact.Encoded.Length + MaxEndpointsLength <= budget)
            {
                used += 8 + peers[count].Contact.Encoded.Length + MaxEndpointsLength;
                count++;
            }
            writer.PutLong(count);
            for (var index = 0; index < count; index++)
            {
                peers[index].Write(writer);
            }
        }

        /// <summary>Reads and verifies a peer list, reusing cached verifications of repeated contacts.</summary>
        /// <param name="reader">The source decoder positioned at the list count.</param>
        /// <returns>The verified, unexpired peers in list order.</returns>
        /// <exception cref="InvalidDataException">The count is out of range or a peer is malformed, expired or forged.</exception>
        public static List<DHTPeer> Read(Wire reader)
        {
            var count = reader.Long();
            if (count < 0 || count > MaxPeers)
            {
                throw new InvalidDataException("Invalid peer list size.");
            }
            var peers = new List<DHTPeer>((int)count);
            for (var index = 0; index < count; index++)
            {
                peers.Add(DHTPeer.Read(reader));
            }
            return peers;
        }
    }
}
