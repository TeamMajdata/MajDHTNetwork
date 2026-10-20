using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Encodes the Store operation: the request is one signed record and a successful result is empty. The receiver records
    /// the authenticated sender as a provider of a content record and accepts a withdrawal from any sender.
    /// </summary>
    public static class StoreMessage
    {
        /// <summary>Writes a Store request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="record">The signed record or withdrawal to replicate.</param>
        public static void WriteRequest(Wire writer, DHTRecord record)
        {
            writer.Put(record.Encoded);
        }

        /// <summary>Reads and verifies a complete Store request body.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The authenticated, unexpired record.</returns>
        /// <exception cref="InvalidDataException">The record is malformed, expired or forged, or the body has trailing data.</exception>
        public static DHTRecord ReadRequest(Wire reader)
        {
            var record = DHTRecord.ParseCached(reader.Bytes(DHTRecord.MaxEncodedLength));
            reader.End();
            return record;
        }
    }
}
