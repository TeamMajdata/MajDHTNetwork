using System;
using System.Collections.Generic;
using System.IO;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// A self-signed node contact: identity keys, capabilities, reachability and the hinted Traversal and Forwarder nodes the
    /// owner holds live sessions with. A contact never carries the owner's own endpoints; the nodes that exchange packets with
    /// the owner observe them and pair them with the contact in a <see cref="DHTPeer"/>.
    /// </summary>
    public sealed class DHTContact
    {
        /// <summary>The maximum accepted signed payload length.</summary>
        public const int MaxPayloadLength = 2048;
        /// <summary>The maximum accepted encoded contact length, including framing and signature.</summary>
        public const int MaxEncodedLength = 2200;
        /// <summary>The maximum number of embedded hints.</summary>
        public const int MaxHints = 3;
        /// <summary>The maximum accepted encoded length of one hinted contact.</summary>
        public const int MaxHintLength = 1024;
        /// <summary>The reachability bits that encode <see cref="DHTReachability"/>.</summary>
        private const byte ReachabilityMask = 0x03;
        /// <summary>The reachability bit marking an endpoint-dependent NAT mapping.</summary>
        private const byte EndpointDependentBit = 0x04;
        /// <summary>The capabilities a contact may advertise.</summary>
        private const DHTCapabilities KnownCapabilities =
            DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Traversal | DHTCapabilities.Forwarder;
        /// <summary>The capabilities that qualify a node as a hint.</summary>
        private const DHTCapabilities AssistingCapabilities = DHTCapabilities.Traversal | DHTCapabilities.Forwarder;
        /// <summary>The maximum number of distinct contacts whose verification is cached process-wide.</summary>
        private const int CacheCapacity = 512;
        /// <summary>
        /// The verified contacts keyed by their exact bytes, so the sender of every request and the contacts repeated across
        /// lookups are parsed, signature-checked and allocated once instead of on every packet.
        /// </summary>
        private static readonly EncodedCache<DHTContact> s_cache = new EncodedCache<DHTContact>(CacheCapacity,
            static encoded => new DHTContact(encoded), static (contact, encoded) => !contact.IsExpired && contact.Encoded.SequenceEqual(encoded));
        /// <summary>The immutable canonical contact bytes.</summary>
        private readonly byte[] _encoded;
        /// <summary>The signing public key.</summary>
        private readonly ReadOnlyMemory<byte> _signingKey;
        /// <summary>The agreement public key.</summary>
        private readonly ReadOnlyMemory<byte> _agreementKey;
        /// <summary>The cached node digest used for allocation-free routing comparisons.</summary>
        private readonly byte[] _nodeHash;
        /// <summary>The validated hints.</summary>
        private readonly DHTPeer[] _hints;

        /// <summary>Gets the stable node fingerprint.</summary>
        public string NodeId { get; }
        /// <summary>
        /// Gets the Traversal and Forwarder nodes the owner holds live sessions with, each at the endpoints the owner observed
        /// for it. A requester punches through a hinted Traversal node and forwards through a hinted Forwarder.
        /// </summary>
        public IReadOnlyList<DHTPeer> Hints => _hints;
        /// <summary>Gets how other nodes can reach this contact.</summary>
        public DHTReachability Reachability { get; }
        /// <summary>Gets whether the owner observed an endpoint-dependent NAT mapping, which makes hole punching unlikely.</summary>
        public bool HasEndpointDependentMapping { get; }
        /// <summary>Gets the advertised and signed node capabilities.</summary>
        public DHTCapabilities Capabilities { get; }
        /// <summary>
        /// Gets the identity work of the contact owner: the leading zero bits of Argon2id over its node digest. It is evaluated
        /// once per process and cached; while the process-wide evaluation budget is spent, an unevaluated identity reports zero.
        /// Nodes reject contacts below their configured difficulty.
        /// </summary>
        public int IdentityWork => IdentityPuzzle.Work(NodeId, _nodeHash);
        /// <summary>Gets the owner's strictly increasing issue sequence; a higher value supersedes a lower one.</summary>
        public long Sequence { get; }
        /// <summary>Gets the expiry of this contact.</summary>
        public DateTimeOffset ExpiresAt { get; }
        /// <summary>Gets whether the contact lease is still valid.</summary>
        public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;
        /// <summary>Gets a borrowed view of the owned immutable signed contact.</summary>
        public ReadOnlySpan<byte> Encoded => _encoded;
        /// <summary>Gets the cached node digest without allocation.</summary>
        public ReadOnlySpan<byte> NodeHash => _nodeHash;
        /// <summary>Gets the signing public key for protocol verification.</summary>
        public ReadOnlyMemory<byte> SigningKey => _signingKey;
        /// <summary>Gets the agreement public key for envelope encryption.</summary>
        public ReadOnlyMemory<byte> AgreementKey => _agreementKey;

        /// <summary>Parses and verifies canonical contact bytes.</summary>
        /// <param name="encoded">The signed bytes.</param>
        /// <exception cref="InvalidDataException">The contact is malformed, expired or forged.</exception>
        internal DHTContact(ReadOnlyMemory<byte> encoded) : this(encoded, true)
        {
        }

        /// <summary>Gets the verified contact for canonical bytes, reusing the cached instance when the same bytes were verified before.</summary>
        /// <param name="encoded">The borrowed signed bytes; they are never retained.</param>
        /// <returns>The verified, unexpired contact.</returns>
        /// <exception cref="InvalidDataException">The contact is malformed, expired or forged.</exception>
        public static DHTContact Parse(ReadOnlyMemory<byte> encoded)
        {
            if (encoded.Length > MaxEncodedLength)
            {
                throw new InvalidDataException("Oversized node contact.");
            }
            return s_cache.Get(encoded);
        }

        /// <summary>Parses and verifies canonical contact bytes, optionally rejecting nested hints.</summary>
        /// <param name="encoded">The signed bytes.</param>
        /// <param name="allowHints">Whether the contact may embed hints.</param>
        /// <exception cref="InvalidDataException">The contact is malformed, expired, forged or illegally nested.</exception>
        private DHTContact(ReadOnlyMemory<byte> encoded, bool allowHints)
        {
            if (encoded.Length > MaxEncodedLength)
            {
                throw new InvalidDataException("Oversized node contact.");
            }
            _encoded = encoded.ToArray();
            using var wrapper = new Wire(_encoded);
            var payload = wrapper.Bytes(MaxPayloadLength);
            var signature = wrapper.Bytes(64);
            wrapper.End();
            using var wire = new Wire(payload);
            if (!wire.Tag(ProtocolTags.Contact))
            {
                throw new InvalidDataException("Unsupported contact version.");
            }
            _signingKey = wire.Bytes(32);
            _agreementKey = wire.Bytes(32);
            var capabilities = (DHTCapabilities)wire.Byte();
            var reachability = wire.Byte();
            var sequence = wire.Long();
            var expiry = wire.Long();
            var hintCount = wire.Long();
            if (hintCount < 0 || hintCount > (allowHints ? MaxHints : 0))
            {
                throw new InvalidDataException("Invalid contact hint count.");
            }
            _hints = new DHTPeer[hintCount];
            for (var index = 0; index < _hints.Length; index++)
            {
                var hinted = new DHTContact(wire.Bytes(MaxHintLength), false);
                _hints[index] = DHTPeer.ReadEndpoints(hinted, wire);
            }
            wire.End();
            _nodeHash = Crypto.Hash(_signingKey.Span);
            NodeId = Crypto.Hex(_nodeHash);
            Capabilities = capabilities;
            Reachability = (DHTReachability)(reachability & ReachabilityMask);
            HasEndpointDependentMapping = (reachability & EndpointDependentBit) != 0;
            Sequence = sequence;
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry);
            if (_signingKey.Length != 32 || _agreementKey.Length != 32 || sequence < 0
                || (capabilities & ~KnownCapabilities) != 0
                || (reachability & ~(ReachabilityMask | EndpointDependentBit)) != 0 || (reachability & ReachabilityMask) == ReachabilityMask
                || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                || expiry > DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds()
                || !HasValidAdvertisement()
                || !Crypto.Verify(_signingKey, payload, signature))
            {
                throw new InvalidDataException("Invalid, expired or forged node contact.");
            }
        }

        /// <summary>Creates a signed contact.</summary>
        /// <param name="identity">The contact owner.</param>
        /// <param name="capabilities">The permitted node services.</param>
        /// <param name="reachability">The owner's reachability state.</param>
        /// <param name="endpointDependentMapping">Whether the owner observed an endpoint-dependent NAT mapping.</param>
        /// <param name="hints">
        /// At most three public Traversal or Forwarder nodes without nested hints, each at the endpoints the owner observed for it.
        /// </param>
        /// <param name="lifetime">The requested lease, shortened to the earliest hint expiry.</param>
        /// <returns>A verified contact.</returns>
        /// <exception cref="InvalidDataException">The resulting contact violates the contact rules.</exception>
        public static DHTContact Create(DHTIdentity identity, DHTCapabilities capabilities, DHTReachability reachability,
            bool endpointDependentMapping, IReadOnlyList<DHTPeer> hints, TimeSpan lifetime)
        {
            var expiry = DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds();
            foreach (var hint in hints)
            {
                expiry = Math.Min(expiry, hint.ExpiresAt.ToUnixTimeSeconds());
            }
            using var payload = new Wire();
            payload.Put(ProtocolTags.Contact);
            payload.Put(identity.PublicKey);
            payload.Put(identity.AgreementPublicKey);
            payload.PutByte((byte)capabilities);
            payload.PutByte((byte)((byte)reachability | (endpointDependentMapping ? EndpointDependentBit : 0)));
            payload.PutLong(identity.NextSequence());
            payload.PutLong(expiry);
            payload.PutLong(hints.Count);
            foreach (var hint in hints)
            {
                hint.Write(payload);
            }
            using var wrapper = new Wire();
            wrapper.Put(payload.WrittenSpan);
            wrapper.Put(identity.Sign(payload.WrittenMemory));
            return new DHTContact(wrapper.WrittenMemory);
        }

        /// <summary>Creates a signed contact with unknown reachability, no hints and a one-day lease.</summary>
        /// <param name="identity">The contact owner.</param>
        /// <param name="capabilities">The permitted node services.</param>
        /// <returns>A verified contact.</returns>
        public static DHTContact Create(DHTIdentity identity, DHTCapabilities capabilities)
        {
            return Create(identity, capabilities, DHTReachability.Unknown, false, Array.Empty<DHTPeer>(), TimeSpan.FromDays(1));
        }

        /// <summary>Checks whether two contacts advertise the same capabilities, reachability and hints.</summary>
        /// <param name="other">The other contact.</param>
        /// <returns>Whether only the sequence, lease or signature differ.</returns>
        public bool SameAdvertisement(DHTContact other)
        {
            if (Capabilities != other.Capabilities || Reachability != other.Reachability
                || HasEndpointDependentMapping != other.HasEndpointDependentMapping || _hints.Length != other._hints.Length)
            {
                return false;
            }
            for (var index = 0; index < _hints.Length; index++)
            {
                if (_hints[index].NodeId != other._hints[index].NodeId || !_hints[index].SameEndpoints(other._hints[index]))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Validates the hints and the reachability rules.</summary>
        /// <returns>Whether the advertisement is consistent.</returns>
        private bool HasValidAdvertisement()
        {
            var forwarder = false;
            for (var index = 0; index < _hints.Length; index++)
            {
                var hint = _hints[index];
                if ((hint.Capabilities & AssistingCapabilities) == 0 || hint.Reachability != DHTReachability.Public
                    || hint.Endpoints.Count == 0 || hint.NodeId == NodeId || hint.ExpiresAt < ExpiresAt)
                {
                    return false;
                }
                for (var previous = 0; previous < index; previous++)
                {
                    if (_hints[previous].NodeId == hint.NodeId)
                    {
                        return false;
                    }
                }
                forwarder |= (hint.Capabilities & DHTCapabilities.Forwarder) != 0;
            }
            return Reachability != DHTReachability.Private || forwarder;
        }
    }
}
