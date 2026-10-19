#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using MajDHTNetwork.Protocol;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks the signed contact rules for endpoints, reachability, relay hints and Hello envelopes.</summary>
    public sealed class ContactTests
    {
        /// <summary>Round-trips a private contact whose lease is bounded by its relay hint.</summary>
        [Fact]
        public void PrivateContactsCarryLocalEndpointsAndBoundedRelayHints()
        {
            var relay = PublicRelay(IPAddress.Parse("203.0.113.10"));
            var identity = new DHTIdentity();
            var local = new DHTEndpoint(IPAddress.Parse("192.168.1.20"), 42000, 42001, DHTEndpointFlags.Local);
            var contact = DHTPeer.Create(identity, new[] { local }, DHTCapabilities.Provide, DHTReachability.Private, true,
                IPAddress.Parse("198.51.100.7"), new[] { relay }, TimeSpan.FromDays(1));
            var parsed = new DHTPeer(contact.Encoded.ToArray());
            Assert.Equal(DHTReachability.Private, parsed.Reachability);
            Assert.True(parsed.HasEndpointDependentMapping);
            Assert.Equal(IPAddress.Parse("198.51.100.7"), parsed.ExternalAddress);
            Assert.Equal(relay.NodeId, Assert.Single(parsed.RelayHints).NodeId);
            Assert.Equal(DHTEndpointFlags.Local, Assert.Single(parsed.Endpoints).Flags);
            Assert.True(parsed.ExpiresAt <= relay.ExpiresAt, "A contact must not outlive its relay hints.");
            Assert.True(DHTPeer.Create(identity, IPAddress.Loopback, 1, 0, DHTCapabilities.Download).Sequence > parsed.Sequence,
                "Each newly signed contact must supersede earlier contacts.");
        }

        /// <summary>Rejects advertisements that contradict their reachability state.</summary>
        [Fact]
        public void ReachabilityStatesRequireMatchingEvidence()
        {
            var identity = new DHTIdentity();
            var relay = PublicRelay(IPAddress.Parse("203.0.113.10"));
            var unverified = new DHTEndpoint(IPAddress.Parse("198.51.100.7"), 42000, 0, DHTEndpointFlags.None);
            var noHints = Array.Empty<DHTPeer>();
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, Array.Empty<DHTEndpoint>(), DHTCapabilities.Download,
                DHTReachability.Private, false, null, noHints, TimeSpan.FromHours(1)));
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, new[] { unverified }, DHTCapabilities.Download,
                DHTReachability.Public, false, null, noHints, TimeSpan.FromHours(1)));
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, new[] { unverified }, DHTCapabilities.Download,
                DHTReachability.Private, false, null, new[] { relay }, TimeSpan.FromHours(1)));
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, new[] { unverified, unverified }, DHTCapabilities.Download,
                DHTReachability.Unknown, false, null, noHints, TimeSpan.FromHours(1)));
            Assert.ThrowsAny<ArgumentException>(() => new DHTEndpoint(IPAddress.Any, 1, 0, DHTEndpointFlags.None));
            Assert.ThrowsAny<ArgumentException>(() => new DHTEndpoint(IPAddress.Loopback, 1, 0, DHTEndpointFlags.Verified | DHTEndpointFlags.Local));
            var clientOnly = DHTPeer.Create(identity, Array.Empty<DHTEndpoint>(), DHTCapabilities.Download, DHTReachability.Unknown, false, null,
                noHints, TimeSpan.FromHours(1));
            Assert.Empty(new DHTPeer(clientOnly.Encoded.ToArray()).Endpoints);
        }

        /// <summary>Accepts only public relays without nested hints as relay hints.</summary>
        [Fact]
        public void RelayHintsMustBePublicRelaysWithoutNestedHints()
        {
            var identity = new DHTIdentity();
            var unknownRelay = DHTPeer.Create(new DHTIdentity(), IPAddress.Parse("203.0.113.11"), 1, 0, DHTCapabilities.Relay);
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, Array.Empty<DHTEndpoint>(), DHTCapabilities.Download,
                DHTReachability.Private, false, null, new[] { unknownRelay }, TimeSpan.FromHours(1)));
            var publicDownloader = DHTPeer.Create(new DHTIdentity(),
                new[] { new DHTEndpoint(IPAddress.Parse("203.0.113.12"), 1, 0, DHTEndpointFlags.Configured) }, DHTCapabilities.Download,
                DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, Array.Empty<DHTEndpoint>(), DHTCapabilities.Download,
                DHTReachability.Private, false, null, new[] { publicDownloader }, TimeSpan.FromHours(1)));
            var inner = PublicRelay(IPAddress.Parse("203.0.113.13"));
            var nested = DHTPeer.Create(new DHTIdentity(),
                new[] { new DHTEndpoint(IPAddress.Parse("203.0.113.14"), 1, 0, DHTEndpointFlags.Configured) }, DHTCapabilities.Relay,
                DHTReachability.Public, false, null, new[] { inner }, TimeSpan.FromHours(1));
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, Array.Empty<DHTEndpoint>(), DHTCapabilities.Download,
                DHTReachability.Private, false, null, new[] { nested }, TimeSpan.FromHours(1)));
        }

        /// <summary>Authenticates a signed plaintext Hello request and refuses to forward it.</summary>
        [Fact]
        public void HelloRequestsAreSignedButNeverForwarded()
        {
            var identity = new DHTIdentity();
            var receiver = new DHTIdentity();
            var sender = DHTPeer.Create(identity, IPAddress.Loopback, 22001, 0, DHTCapabilities.Download);
            var hello = new Packet(sender, Crypto.Random(16), (byte)Operation.Hello, ReadOnlyMemory<byte>.Empty).SealHello(identity);
            var opened = Packet.Open(receiver, hello);
            Assert.Equal(identity.NodeId, opened.Sender.NodeId);
            Assert.Equal((byte)Operation.Hello, opened.Kind);
            Assert.ThrowsAny<InvalidDataException>(() => Packet.CheckForward(hello, new string('0', 64)));
            var tampered = (byte[])hello.Clone();
            tampered[tampered.Length - 1] ^= 1;
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(receiver, tampered));
            Assert.ThrowsAny<InvalidDataException>(() => new Packet(sender, Crypto.Random(16), (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty)
                .SealHello(identity));
        }

        /// <summary>Validates dual-stack listener, advertised-address and bootstrap-endpoint options.</summary>
        [Fact]
        public void AddressOptionsAreValidatedPerAddressFamily()
        {
            var dual = new DHTNodeOptions { ListenAddresses = new List<IPAddress> { IPAddress.Any, IPAddress.IPv6Any } }.Snapshot();
            Assert.Equal(2, dual.ListenAddresses.Count);
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { IPAddress.Loopback, IPAddress.Any }
            }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { ListenAddresses = new List<IPAddress>() }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions
            {
                AdvertisedAddresses = new List<IPAddress> { IPAddress.IPv6Loopback }
            }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions
            {
                BootstrapEndpoints = new List<IPEndPoint> { new IPEndPoint(IPAddress.Loopback, 0) }
            }.Snapshot());
        }

        /// <summary>Creates a public relay contact with one configured endpoint.</summary>
        /// <param name="address">The relay address.</param>
        /// <returns>The relay contact.</returns>
        private static DHTPeer PublicRelay(IPAddress address)
        {
            return DHTPeer.Create(new DHTIdentity(), new[] { new DHTEndpoint(address, 42000, 42000, DHTEndpointFlags.Configured) },
                DHTCapabilities.Relay, DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(2));
        }
    }
}
