using System;
using System.Collections.Generic;
using System.IO;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Selects what a Find request looks up.</summary>
    public enum FindMode : byte
    {
        /// <summary>Finds nodes near a 64-digit routing identifier.</summary>
        Nodes = 0,
        /// <summary>Resolves a canonical key to its signed record and the record's providers.</summary>
        Record = 1,
        /// <summary>Finds providers of a complete-file hash.</summary>
        Providers = 2
    }

    /// <summary>The decoded arguments of a Find request.</summary>
    public readonly struct FindRequest
    {
        /// <summary>Gets the lookup mode.</summary>
        public FindMode Mode { get; }
        /// <summary>Gets the lookup target: a routing identifier, a canonical key or a file hash, depending on the mode.</summary>
        public string Target { get; }

        /// <summary>Creates the arguments of a Find request.</summary>
        /// <param name="mode">The lookup mode.</param>
        /// <param name="target">The lookup target.</param>
        /// <exception cref="ArgumentNullException">The target is null.</exception>
        public FindRequest(FindMode mode, string target)
        {
            Mode = mode;
            Target = target ?? throw new ArgumentNullException(nameof(target));
        }
    }

    /// <summary>The decoded result of a Find request.</summary>
    public readonly struct FindResponse
    {
        /// <summary>Gets the signed record matching a <see cref="FindMode.Record"/> target, or null.</summary>
        public DHTRecord? Record { get; }
        /// <summary>Gets the verified contacts nearest to the target, owned by the caller.</summary>
        public List<DHTPeer> Peers { get; }
        /// <summary>Gets the verified provider contacts, owned by the caller.</summary>
        public List<DHTPeer> Providers { get; }

        /// <summary>Creates a Find result.</summary>
        /// <param name="record">The matching record, or null.</param>
        /// <param name="peers">The nearest contacts.</param>
        /// <param name="providers">The provider contacts.</param>
        /// <exception cref="ArgumentNullException">A list is null.</exception>
        public FindResponse(DHTRecord? record, List<DHTPeer> peers, List<DHTPeer> providers)
        {
            Record = record;
            Peers = peers ?? throw new ArgumentNullException(nameof(peers));
            Providers = providers ?? throw new ArgumentNullException(nameof(providers));
        }
    }

    /// <summary>
    /// Encodes the Find operation: the request is a mode byte and a target string; the result is a record or empty bytes,
    /// the contact list nearest to the target and the provider contact list.
    /// </summary>
    public static class FindMessage
    {
        /// <summary>The maximum UTF-8 length of a lookup target.</summary>
        public const int MaxTargetLength = 1024;

        /// <summary>Writes a Find request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="mode">The lookup mode.</param>
        /// <param name="target">The lookup target.</param>
        public static void WriteRequest(Wire writer, FindMode mode, string target)
        {
            writer.PutByte((byte)mode);
            writer.PutText(target);
        }

        /// <summary>Reads a complete Find request body.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The lookup mode and target; the receiver interprets the target according to the mode.</returns>
        /// <exception cref="InvalidDataException">The mode is unknown, the target is oversized or the body has trailing data.</exception>
        public static FindRequest ReadRequest(Wire reader)
        {
            var mode = reader.Byte();
            var target = reader.Text(MaxTargetLength);
            reader.End();
            if (mode > (byte)FindMode.Providers)
            {
                throw new InvalidDataException("Invalid lookup mode.");
            }
            return new FindRequest((FindMode)mode, target);
        }

        /// <summary>Writes a successful Find result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="record">The record matching a <see cref="FindMode.Record"/> target, or null to write empty bytes.</param>
        /// <param name="peers">The contacts nearest to the target, bounded by the list budget.</param>
        /// <param name="providers">The provider contacts, bounded by the list budget.</param>
        /// <param name="budget">The byte budget of each contact list.</param>
        public static void WriteResponse(Wire writer, DHTRecord? record, IReadOnlyList<DHTPeer> peers, IReadOnlyList<DHTPeer> providers,
            int budget = ContactList.DefaultBudget)
        {
            if (record == null)
            {
                writer.Put(ReadOnlySpan<byte>.Empty);
            }
            else
            {
                writer.Put(record.Encoded);
            }
            ContactList.Write(writer, peers, budget);
            ContactList.Write(writer, providers, budget);
        }

        /// <summary>Reads and verifies a complete Find result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The verified record, nearest contacts and providers; the caller still checks that the record belongs to its target.</returns>
        /// <exception cref="InvalidDataException">A record or contact is malformed, expired or forged, or the result has trailing data.</exception>
        public static FindResponse ReadResponse(Wire reader)
        {
            var encoded = reader.Bytes(DHTRecord.MaxEncodedLength);
            var record = encoded.Length == 0 ? null : DHTRecord.ParseCached(encoded);
            var peers = ContactList.Read(reader);
            var providers = ContactList.Read(reader);
            reader.End();
            return new FindResponse(record, peers, providers);
        }
    }
}
