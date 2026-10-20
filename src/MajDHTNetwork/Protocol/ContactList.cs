using System;
using System.Collections.Generic;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Encodes the bounded contact lists of a Find response: an integer count followed by that many signed contacts, each
    /// verified independently when read.
    /// </summary>
    public static class ContactList
    {
        /// <summary>The maximum number of contacts in one list.</summary>
        public const int MaxContacts = 16;
        /// <summary>
        /// The default byte budget of one list, including the length prefixes of its contacts, which keeps a Find response with
        /// two lists below the envelope limit even when contacts carry relay hints.
        /// </summary>
        public const int DefaultBudget = 26000;

        /// <summary>Writes the leading contacts that fit the count and byte budget.</summary>
        /// <param name="writer">The destination encoder.</param>
        /// <param name="peers">The ordered candidate contacts; at most <see cref="MaxContacts"/> are written.</param>
        /// <param name="budget">The maximum encoded bytes of the written contacts, including their length prefixes.</param>
        public static void Write(Wire writer, IReadOnlyList<DHTPeer> peers, int budget = DefaultBudget)
        {
            var count = 0;
            var used = 0;
            while (count < Math.Min(MaxContacts, peers.Count) && used + 8 + peers[count].Encoded.Length <= budget)
            {
                used += 8 + peers[count].Encoded.Length;
                count++;
            }
            writer.PutLong(count);
            for (var index = 0; index < count; index++)
            {
                writer.Put(peers[index].Encoded);
            }
        }

        /// <summary>Reads and verifies a contact list, reusing cached verifications of repeated contacts.</summary>
        /// <param name="reader">The source decoder positioned at the list count.</param>
        /// <returns>The verified, unexpired contacts in list order.</returns>
        /// <exception cref="InvalidDataException">The count is out of range or a contact is malformed, expired or forged.</exception>
        public static List<DHTPeer> Read(Wire reader)
        {
            var count = reader.Long();
            if (count < 0 || count > MaxContacts)
            {
                throw new InvalidDataException("Invalid contact list size.");
            }
            var peers = new List<DHTPeer>((int)count);
            for (var index = 0; index < count; index++)
            {
                peers.Add(DHTPeer.Parse(reader.Bytes(DHTPeer.MaxEncodedLength)));
            }
            return peers;
        }
    }
}
