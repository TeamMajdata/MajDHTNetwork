using System;
using System.IO;
using System.Net;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>A self-signed node contact suitable for sharing as a bootstrap invitation.</summary>
    public sealed class DHTPeer
    {
        /// <summary>The immutable canonical contact bytes.</summary>
        private readonly byte[] _encoded;
        /// <summary>The signing public key.</summary>
        private readonly ReadOnlyMemory<byte> _signingKey;
        /// <summary>The agreement public key.</summary>
        private readonly ReadOnlyMemory<byte> _agreementKey;
        /// <summary>The cached node digest used for allocation-free routing comparisons.</summary>
        private readonly byte[] _nodeHash;
        /// <summary>The internally shared immutable-by-convention network address.</summary>
        private readonly IPAddress _networkAddress;
        /// <summary>The advertised IP address string.</summary>
        private readonly string _address;
        /// <summary>Gets the stable node fingerprint.</summary>
        public string NodeId { get; }
        /// <summary>Gets a copy of the advertised IP address.</summary>
        public IPAddress Address => IPAddress.Parse(_address);
        /// <summary>Gets the internally cached address for socket operations.</summary>
        internal IPAddress NetworkAddress => _networkAddress;
        /// <summary>Gets the TCP port or zero when TCP is disabled.</summary>
        public int TcpPort { get; }
        /// <summary>Gets the UDP port or zero when UDP is disabled.</summary>
        public int UdpPort { get; }
        /// <summary>Gets the advertised and signed node capabilities.</summary>
        public DHTCapabilities Capabilities { get; }
        /// <summary>Gets the expiry of this contact invitation.</summary>
        public DateTimeOffset ExpiresAt { get; }
        /// <summary>Gets whether the contact lease is still valid.</summary>
        public bool IsExpired => ExpiresAt <= DateTimeOffset.UtcNow;
        /// <summary>Gets a borrowed view of the owned immutable signed contact.</summary>
        internal ReadOnlySpan<byte> Encoded => _encoded;
        /// <summary>Gets the cached node digest without allocation.</summary>
        internal ReadOnlySpan<byte> NodeHash => _nodeHash;
        /// <summary>Gets the signing public key for protocol verification.</summary>
        internal ReadOnlyMemory<byte> SigningKey => _signingKey;
        /// <summary>Gets the agreement public key for envelope encryption.</summary>
        internal ReadOnlyMemory<byte> AgreementKey => _agreementKey;

        /// <summary>Parses and verifies canonical contact bytes.</summary>
        /// <param name="encoded">The signed bytes.</param>
        /// <exception cref="InvalidDataException">The contact is malformed, expired or forged.</exception>
        internal DHTPeer(ReadOnlyMemory<byte> encoded)
        {
            _encoded = encoded.ToArray();
            using var wrapper = new Wire(_encoded);
            var payload = wrapper.Bytes(1024);
            var signature = wrapper.Bytes(64);
            wrapper.End();
            using var wire = new Wire(payload);
            if (wire.Text(32) != "MajDHT/1/contact")
            {
                throw new InvalidDataException("Unsupported contact version.");
            }
            _signingKey = wire.Bytes(32);
            _agreementKey = wire.Bytes(32);
            _address = wire.Text(96);
            var tcp = wire.Long();
            var udp = wire.Long();
            var capabilities = (DHTCapabilities)wire.Byte();
            var expiry = wire.Long();
            wire.End();
            if (_signingKey.Length != 32 || _agreementKey.Length != 32
                || !IPAddress.TryParse(_address, out var address) || address.ToString() != _address
                || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
                || address.Equals(IPAddress.None) || address.IsIPv6Multicast
                || tcp < 0 || tcp > 65535 || udp < 0 || udp > 65535 || (tcp == 0 && udp == 0)
                || (capabilities & ~(DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Relay)) != 0
                || expiry <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                || expiry > DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds()
                || !Crypto.Verify(_signingKey, payload, signature))
            {
                throw new InvalidDataException("Invalid, expired or forged node contact.");
            }
            _networkAddress = address;
            TcpPort = (int)tcp;
            UdpPort = (int)udp;
            Capabilities = capabilities;
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(expiry);
            _nodeHash = Crypto.Hash(_signingKey.Span);
            NodeId = Crypto.Hex(_nodeHash);
        }

        /// <summary>Creates a signed contact for a bound listener.</summary>
        /// <param name="identity">The contact owner.</param>
        /// <param name="address">The reachable IP address.</param>
        /// <param name="tcpPort">The TCP port or zero.</param>
        /// <param name="udpPort">The UDP port or zero.</param>
        /// <param name="capabilities">The permitted node services.</param>
        /// <returns>A verified contact with a one-day lease.</returns>
        internal static DHTPeer Create(DHTIdentity identity, IPAddress address, int tcpPort, int udpPort, DHTCapabilities capabilities)
        {
            using var payload = new Wire();
            payload.PutText("MajDHT/1/contact");
            payload.Put(identity.PublicKey);
            payload.Put(identity.Agreement.GeneratePublicKey().GetEncoded());
            payload.PutText(address.ToString());
            payload.PutLong(tcpPort);
            payload.PutLong(udpPort);
            payload.PutByte((byte)capabilities);
            payload.PutLong(DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds());
            using var wrapper = new Wire();
            wrapper.Put(payload.WrittenSpan);
            wrapper.Put(identity.Sign(payload.WrittenMemory));
            return new DHTPeer(wrapper.WrittenMemory);
        }

        /// <summary>Formats the public contact as a portable bootstrap invitation.</summary>
        /// <returns>A versioned base64 public contact containing no private identity seed.</returns>
        public string ToInvitation()
        {
            return "majdht1:" + Convert.ToBase64String(_encoded);
        }

        /// <summary>Parses and verifies a bootstrap invitation received through a trusted channel.</summary>
        /// <param name="invitation">The versioned public contact.</param>
        /// <returns>The verified contact; authenticity of the initial source remains the caller's responsibility.</returns>
        /// <exception cref="ArgumentException">The invitation format is invalid.</exception>
        /// <exception cref="InvalidDataException">The signed contact is invalid or expired.</exception>
        public static DHTPeer ParseInvitation(string invitation)
        {
            if (invitation == null || invitation.Length > 2048 || !invitation.StartsWith("majdht1:", StringComparison.Ordinal))
            {
                throw new ArgumentException("Invalid MajDHT invitation.", nameof(invitation));
            }
            try
            {
                return new DHTPeer(Convert.FromBase64String(invitation.Substring(8)));
            }
            catch (FormatException exception)
            {
                throw new ArgumentException("Invalid MajDHT invitation encoding.", nameof(invitation), exception);
            }
        }
    }
}
