using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>A self-signed node contact describing its endpoints, reachability and relay hints.</summary>
    public sealed class DHTPeer
    {
        /// <summary>The maximum accepted signed payload length.</summary>
        public const int MaxPayloadLength = 2048;
        /// <summary>The maximum accepted encoded contact length, including framing and signature.</summary>
        public const int MaxEncodedLength = 2200;
        /// <summary>The maximum number of advertised endpoints.</summary>
        public const int MaxEndpoints = 4;
        /// <summary>The maximum number of embedded relay hints.</summary>
        public const int MaxRelayHints = 3;
        /// <summary>The maximum accepted encoded length of one embedded relay hint.</summary>
        public const int MaxHintLength = 1024;
        /// <summary>The reachability bits that encode <see cref="DHTReachability"/>.</summary>
        private const byte ReachabilityMask = 0x03;
        /// <summary>The reachability bit marking an endpoint-dependent NAT mapping.</summary>
        private const byte EndpointDependentBit = 0x04;
        /// <summary>The maximum number of distinct contacts whose verification is cached process-wide.</summary>
        private const int CacheCapacity = 512;
        /// <summary>
        /// The verified contacts keyed by their exact bytes, so the sender of every request and the contacts repeated across
        /// lookups are parsed, signature-checked and allocated once instead of on every packet.
        /// </summary>
        private static readonly EncodedCache<DHTPeer> s_cache = new EncodedCache<DHTPeer>(CacheCapacity,
            static encoded => new DHTPeer(encoded), static (peer, encoded) => !peer.IsExpired && peer.Encoded.SequenceEqual(encoded));
        /// <summary>The immutable canonical contact bytes.</summary>
        private readonly byte[] _encoded;
        /// <summary>The signing public key.</summary>
        private readonly ReadOnlyMemory<byte> _signingKey;
        /// <summary>The agreement public key.</summary>
        private readonly ReadOnlyMemory<byte> _agreementKey;
        /// <summary>The cached node digest used for allocation-free routing comparisons.</summary>
        private readonly byte[] _nodeHash;
        /// <summary>The validated advertised endpoints.</summary>
        private readonly DHTEndpoint[] _endpoints;
        /// <summary>The validated relay hints.</summary>
        private readonly DHTPeer[] _relayHints;
        /// <summary>The confirmed external address, or null when unknown.</summary>
        private readonly IPAddress? _externalAddress;
        /// <summary>Gets the stable node fingerprint.</summary>
        public string NodeId { get; }
        /// <summary>Gets the advertised endpoints, ordered by the owner's preference.</summary>
        public IReadOnlyList<DHTEndpoint> Endpoints => _endpoints;
        /// <summary>Gets the public relays through which a private node can be reached.</summary>
        public IReadOnlyList<DHTPeer> RelayHints => _relayHints;
        /// <summary>Gets how other nodes can reach this contact.</summary>
        public DHTReachability Reachability { get; }
        /// <summary>Gets whether the owner observed an endpoint-dependent NAT mapping, which makes hole punching unlikely.</summary>
        public bool HasEndpointDependentMapping { get; }
        /// <summary>Gets a copy of the external address confirmed by independent relays, or null when unknown.</summary>
        public IPAddress? ExternalAddress => _externalAddress == null ? null : NetworkScope.CopyAddress(_externalAddress);
        /// <summary>Gets the internally cached external address.</summary>
        internal IPAddress? ExternalNetworkAddress => _externalAddress;
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
        internal DHTPeer(ReadOnlyMemory<byte> encoded) : this(encoded, true)
        {
        }

        /// <summary>Gets the verified contact for canonical bytes, reusing the cached instance when the same bytes were verified before.</summary>
        /// <param name="encoded">The borrowed signed bytes; they are never retained.</param>
        /// <returns>The verified, unexpired contact.</returns>
        /// <exception cref="InvalidDataException">The contact is malformed, expired or forged.</exception>
        public static DHTPeer Parse(ReadOnlyMemory<byte> encoded)
        {
            if (encoded.Length > MaxEncodedLength)
            {
                throw new InvalidDataException("Oversized node contact.");
            }
            return s_cache.Get(encoded);
        }

        /// <summary>Parses and verifies canonical contact bytes, optionally rejecting nested relay hints.</summary>
        /// <param name="encoded">The signed bytes.</param>
        /// <param name="allowRelayHints">Whether the contact may embed relay hints.</param>
        /// <exception cref="InvalidDataException">The contact is malformed, expired, forged or illegally nested.</exception>
        private DHTPeer(ReadOnlyMemory<byte> encoded, bool allowRelayHints)
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
            var external = wire.Text(96);
            var endpointCount = wire.Long();
            if (endpointCount < 0 || endpointCount > MaxEndpoints)
            {
                throw new InvalidDataException("Invalid contact endpoint count.");
            }
            _endpoints = new DHTEndpoint[endpointCount];
            for (var index = 0; index < _endpoints.Length; index++)
            {
                _endpoints[index] = ReadEndpoint(wire);
            }
            var hintCount = wire.Long();
            if (hintCount < 0 || hintCount > (allowRelayHints ? MaxRelayHints : 0))
            {
                throw new InvalidDataException("Invalid contact relay hint count.");
            }
            _relayHints = new DHTPeer[hintCount];
            for (var index = 0; index < _relayHints.Length; index++)
            {
                _relayHints[index] = new DHTPeer(wire.Bytes(MaxHintLength), false);
            }
            wire.End();
            _nodeHash = Crypto.Hash(_signingKey.Span);
            NodeId = Crypto.Hex(_nodeHash);
            _externalAddress = external.Length == 0 ? null : ParseAddress(external);
            Capabilities = capabilities;
            Reachability = (DHTReachability)(reachability & ReachabilityMask);
            HasEndpointDependentMapping = (reachability & EndpointDependentBit) != 0;
            Sequence = sequence;
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry);
            if (_signingKey.Length != 32 || _agreementKey.Length != 32 || sequence < 0
                || (capabilities & ~(DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Relay)) != 0
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
        /// <param name="endpoints">At most four distinct advertised endpoints.</param>
        /// <param name="capabilities">The permitted node services.</param>
        /// <param name="reachability">The owner's reachability state.</param>
        /// <param name="endpointDependentMapping">Whether the owner observed an endpoint-dependent NAT mapping.</param>
        /// <param name="externalAddress">The confirmed external address, or null.</param>
        /// <param name="relayHints">At most three public relay contacts without nested hints.</param>
        /// <param name="lifetime">The requested lease, shortened to the earliest relay hint expiry.</param>
        /// <returns>A verified contact.</returns>
        /// <exception cref="InvalidDataException">The resulting contact violates the contact rules.</exception>
        public static DHTPeer Create(DHTIdentity identity, IReadOnlyList<DHTEndpoint> endpoints, DHTCapabilities capabilities,
            DHTReachability reachability, bool endpointDependentMapping, IPAddress? externalAddress, IReadOnlyList<DHTPeer> relayHints,
            TimeSpan lifetime)
        {
            var expiry = DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeSeconds();
            foreach (var hint in relayHints)
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
            payload.PutText(externalAddress == null ? string.Empty : externalAddress.ToString());
            payload.PutLong(endpoints.Count);
            foreach (var endpoint in endpoints)
            {
                payload.PutText(endpoint.NetworkAddress.ToString());
                payload.PutLong(endpoint.TcpPort);
                payload.PutLong(endpoint.UdpPort);
                payload.PutByte((byte)endpoint.Flags);
            }
            payload.PutLong(relayHints.Count);
            foreach (var hint in relayHints)
            {
                payload.Put(hint.Encoded);
            }
            using var wrapper = new Wire();
            wrapper.Put(payload.WrittenSpan);
            wrapper.Put(identity.Sign(payload.WrittenMemory));
            return new DHTPeer(wrapper.WrittenMemory);
        }

        /// <summary>Creates a signed contact with one unverified endpoint and a one-day lease.</summary>
        /// <param name="identity">The contact owner.</param>
        /// <param name="address">The reachable IP address.</param>
        /// <param name="tcpPort">The TCP port or zero.</param>
        /// <param name="udpPort">The UDP port or zero.</param>
        /// <param name="capabilities">The permitted node services.</param>
        /// <returns>A verified contact with unknown reachability.</returns>
        public static DHTPeer Create(DHTIdentity identity, IPAddress address, int tcpPort, int udpPort, DHTCapabilities capabilities)
        {
            return Create(identity, new[] { new DHTEndpoint(address, tcpPort, udpPort, DHTEndpointFlags.None) }, capabilities,
                DHTReachability.Unknown, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromDays(1));
        }

        /// <summary>Checks whether two contacts advertise the same reachability, endpoints and relays.</summary>
        /// <param name="other">The other contact.</param>
        /// <returns>Whether only the sequence, lease or signature differ.</returns>
        public bool SameAdvertisement(DHTPeer other)
        {
            if (Capabilities != other.Capabilities || Reachability != other.Reachability
                || HasEndpointDependentMapping != other.HasEndpointDependentMapping
                || !Equals(_externalAddress, other._externalAddress)
                || _endpoints.Length != other._endpoints.Length || _relayHints.Length != other._relayHints.Length)
            {
                return false;
            }
            for (var index = 0; index < _endpoints.Length; index++)
            {
                var left = _endpoints[index];
                var right = other._endpoints[index];
                if (!left.NetworkAddress.Equals(right.NetworkAddress) || left.TcpPort != right.TcpPort
                    || left.UdpPort != right.UdpPort || left.Flags != right.Flags)
                {
                    return false;
                }
            }
            for (var index = 0; index < _relayHints.Length; index++)
            {
                if (_relayHints[index].NodeId != other._relayHints[index].NodeId)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Validates endpoint uniqueness, relay hints and the reachability rules.</summary>
        /// <returns>Whether the advertisement is consistent.</returns>
        private bool HasValidAdvertisement()
        {
            var reachable = false;
            var localOnly = true;
            for (var index = 0; index < _endpoints.Length; index++)
            {
                reachable |= _endpoints[index].IsReachable;
                localOnly &= (_endpoints[index].Flags & DHTEndpointFlags.Local) != 0;
                for (var previous = 0; previous < index; previous++)
                {
                    if (_endpoints[previous].NetworkAddress.Equals(_endpoints[index].NetworkAddress))
                    {
                        return false;
                    }
                }
            }
            for (var index = 0; index < _relayHints.Length; index++)
            {
                var hint = _relayHints[index];
                if ((hint.Capabilities & DHTCapabilities.Relay) == 0 || hint.Reachability != DHTReachability.Public
                    || hint.NodeId == NodeId || hint.ExpiresAt < ExpiresAt)
                {
                    return false;
                }
                for (var previous = 0; previous < index; previous++)
                {
                    if (_relayHints[previous].NodeId == hint.NodeId)
                    {
                        return false;
                    }
                }
            }
            switch (Reachability)
            {
                case DHTReachability.Public:
                    return reachable;
                case DHTReachability.Private:
                    return _relayHints.Length != 0 && localOnly;
                default:
                    return true;
            }
        }

        /// <summary>Reads one canonical advertised endpoint.</summary>
        /// <param name="reader">The payload decoder.</param>
        /// <returns>The validated endpoint.</returns>
        /// <exception cref="InvalidDataException">The endpoint is malformed.</exception>
        private static DHTEndpoint ReadEndpoint(Wire reader)
        {
            var address = ParseAddress(reader.Text(96));
            var tcp = reader.Long();
            var udp = reader.Long();
            var flags = (DHTEndpointFlags)reader.Byte();
            if (tcp < 0 || tcp > 65535 || udp < 0 || udp > 65535)
            {
                throw new InvalidDataException("Invalid contact endpoint port.");
            }
            try
            {
                return new DHTEndpoint(address, (int)tcp, (int)udp, flags);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Invalid contact endpoint.", exception);
            }
        }

        /// <summary>Parses a canonical unicast address.</summary>
        /// <param name="text">The canonical address text.</param>
        /// <returns>The parsed address.</returns>
        /// <exception cref="InvalidDataException">The address is not canonical unicast text.</exception>
        private static IPAddress ParseAddress(string text)
        {
            if (!IPAddress.TryParse(text, out var address) || address.ToString() != text || !NetworkScope.IsUnicast(address))
            {
                throw new InvalidDataException("Invalid contact address.");
            }
            return address;
        }
    }
}
