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
    /// <summary>Checks the signed contact rules for reachability and hints, the observed-endpoint encoding and Hello envelopes.</summary>
    public sealed class ContactTests
    {
        /// <summary>Round-trips a private contact whose lease is bounded by its hinted Forwarder, kept at the owner's observed endpoints.</summary>
        [Fact]
        public void PrivateContactsCarryHintsWithObservedEndpointsAndBoundedLeases()
        {
            var forwarder = PublicAssistant(IPAddress.Parse("203.0.113.10"), DHTCapabilities.Forwarder, TimeSpan.FromHours(2));
            var identity = new DHTIdentity();
            var contact = DHTContact.Create(identity, DHTCapabilities.Provide, DHTReachability.Private, true, new[] { forwarder }, TimeSpan.FromDays(1));
            var parsed = new DHTContact(contact.Encoded.ToArray());
            Assert.Equal(DHTReachability.Private, parsed.Reachability);
            Assert.True(parsed.HasEndpointDependentMapping);
            var hint = Assert.Single(parsed.Hints);
            Assert.Equal(forwarder.NodeId, hint.NodeId);
            Assert.True(hint.SameEndpoints(forwarder), "A hint must carry the endpoints the owner observed for the assistant.");
            Assert.True(parsed.ExpiresAt <= forwarder.ExpiresAt, "A contact must not outlive its hints.");
            Assert.True(contact.SameAdvertisement(parsed), "Parsing must preserve the advertisement.");
            Assert.True(DHTContact.Create(identity, DHTCapabilities.Download).Sequence > parsed.Sequence,
                "Each newly signed contact must supersede earlier contacts.");
        }

        /// <summary>Rejects reachability states and hint lists that contradict the contact rules.</summary>
        [Fact]
        public void ReachabilityStatesRequireMatchingHints()
        {
            var identity = new DHTIdentity();
            var forwarder = PublicAssistant(IPAddress.Parse("203.0.113.10"), DHTCapabilities.Forwarder, TimeSpan.FromHours(2));
            var traversal = PublicAssistant(IPAddress.Parse("203.0.113.11"), DHTCapabilities.Traversal, TimeSpan.FromHours(2));
            var none = Array.Empty<DHTPeer>();
            // A private node is reached through a Forwarder; a Traversal node alone cannot carry its traffic.
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false, none,
                TimeSpan.FromHours(1)));
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false,
                new[] { traversal }, TimeSpan.FromHours(1)));
            var mixed = DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false, new[] { traversal, forwarder },
                TimeSpan.FromHours(1));
            Assert.Equal(2, mixed.Hints.Count);
            Assert.Empty(DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Unknown, false, none, TimeSpan.FromHours(1)).Hints);
            Assert.Single(DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Unknown, false, new[] { traversal }, TimeSpan.FromHours(1)).Hints);
            Assert.Empty(DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Public, false, none, TimeSpan.FromHours(1)).Hints);
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, (DHTReachability)3, false, none,
                TimeSpan.FromHours(1)));
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Unknown, false,
                new[] { forwarder, forwarder }, TimeSpan.FromHours(1)));
            var four = new[]
            {
                forwarder, traversal, PublicAssistant(IPAddress.Parse("203.0.113.12"), DHTCapabilities.Forwarder, TimeSpan.FromHours(2)),
                PublicAssistant(IPAddress.Parse("203.0.113.13"), DHTCapabilities.Forwarder, TimeSpan.FromHours(2))
            };
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Unknown, false, four,
                TimeSpan.FromHours(1)));
        }

        /// <summary>Accepts only public Traversal or Forwarder nodes with an observed endpoint and without nested hints as hints.</summary>
        [Fact]
        public void HintsMustBePublicAssistantsWithEndpointsAndWithoutNestedHints()
        {
            var identity = new DHTIdentity();
            var none = Array.Empty<DHTPeer>();
            var unknownForwarder = DHTPeer.Create(new DHTIdentity(), IPAddress.Parse("203.0.113.11"), 1, 0, DHTCapabilities.Forwarder);
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false,
                new[] { unknownForwarder }, TimeSpan.FromHours(1)));
            var publicDownloader = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Download, DHTReachability.Public, false, none,
                TimeSpan.FromHours(1)), new[] { new DHTEndpoint(IPAddress.Parse("203.0.113.12"), 1, 0) });
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false,
                new[] { publicDownloader }, TimeSpan.FromHours(1)));
            var withoutEndpoints = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Forwarder, DHTReachability.Public, false, none,
                TimeSpan.FromHours(1)), Array.Empty<DHTEndpoint>());
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false,
                new[] { withoutEndpoints }, TimeSpan.FromHours(1)));
            var inner = PublicAssistant(IPAddress.Parse("203.0.113.13"), DHTCapabilities.Forwarder, TimeSpan.FromHours(1));
            var nested = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Forwarder, DHTReachability.Public, false, new[] { inner },
                TimeSpan.FromHours(1)), new[] { new DHTEndpoint(IPAddress.Parse("203.0.113.14"), 1, 0) });
            Assert.ThrowsAny<InvalidDataException>(() => DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false,
                new[] { nested }, TimeSpan.FromHours(1)));
            // A hint that expires before the owner shortens the owner's lease instead of failing.
            var shortLived = PublicAssistant(IPAddress.Parse("203.0.113.15"), DHTCapabilities.Forwarder, TimeSpan.FromMinutes(10));
            var owner = DHTContact.Create(identity, DHTCapabilities.Download, DHTReachability.Private, false, new[] { shortLived }, TimeSpan.FromHours(1));
            Assert.True(owner.ExpiresAt <= shortLived.ExpiresAt, "The owner's lease must end with its hint.");
        }

        /// <summary>Merges observations per address, keeps at most four addresses and encodes a peer canonically.</summary>
        [Fact]
        public void ObservedEndpointsMergeAndRoundTrip()
        {
            var address = IPAddress.Parse("198.51.100.7");
            var tcp = DHTEndpoint.Observed(DHTTransport.Tcp, new IPEndPoint(address, 4000));
            var udp = DHTEndpoint.Observed(DHTTransport.Udp, new IPEndPoint(address, 4001));
            var merged = tcp.Merge(udp);
            Assert.Equal(4000, merged.TcpPort);
            Assert.Equal(4001, merged.UdpPort);
            Assert.ThrowsAny<ArgumentException>(() => tcp.Merge(new DHTEndpoint(IPAddress.Parse("198.51.100.8"), 1, 0)));
            Assert.ThrowsAny<ArgumentException>(() => new DHTEndpoint(IPAddress.Any, 1, 0));
            Assert.ThrowsAny<ArgumentException>(() => new DHTEndpoint(IPAddress.Loopback, 0, 0));
            var contact = DHTContact.Create(new DHTIdentity(), DHTCapabilities.Download);
            Assert.ThrowsAny<ArgumentException>(() => new DHTPeer(contact, new[] { tcp, udp }));
            var peer = new DHTPeer(contact, new[] { tcp }).WithEndpoint(udp);
            Assert.Equal(merged, Assert.Single(peer.Endpoints));
            for (var index = 1; index <= 4; index++)
            {
                peer = peer.WithEndpoint(new DHTEndpoint(IPAddress.Parse("203.0.113." + index), 1000, 0));
            }
            // The oldest address gives way once more than four addresses were observed.
            Assert.Equal(4, peer.Endpoints.Count);
            Assert.DoesNotContain(peer.Endpoints, endpoint => endpoint.Address.Equals(address));
            Assert.Equal(IPAddress.Parse("203.0.113.4"), peer.Endpoints[3].Address);
            Assert.True(peer.WasObservedAt(DHTTransport.Tcp, new IPEndPoint(IPAddress.Parse("203.0.113.4"), 1000)));
            Assert.False(peer.WasObservedAt(DHTTransport.Udp, new IPEndPoint(IPAddress.Parse("203.0.113.4"), 1000)));
            using var writer = new Wire();
            peer.Write(writer);
            using var reader = new Wire(writer.WrittenMemory);
            var read = DHTPeer.Read(reader);
            reader.End();
            Assert.Equal(peer.NodeId, read.NodeId);
            Assert.True(read.SameEndpoints(peer), "A peer must round trip with its observed endpoints in order.");
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

        /// <summary>Validates dual-stack listener and bootstrap-endpoint options.</summary>
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
                BootstrapEndpoints = new List<IPEndPoint> { new IPEndPoint(IPAddress.Loopback, 0) }
            }.Snapshot());
        }

        /// <summary>Creates a public assistant observed at one address on both transports.</summary>
        /// <param name="address">The observed address.</param>
        /// <param name="capabilities">The assisting capabilities.</param>
        /// <param name="lifetime">The contact lease.</param>
        /// <returns>The assistant.</returns>
        private static DHTPeer PublicAssistant(IPAddress address, DHTCapabilities capabilities, TimeSpan lifetime)
        {
            return new DHTPeer(DHTContact.Create(new DHTIdentity(), capabilities, DHTReachability.Public, false, Array.Empty<DHTPeer>(), lifetime),
                new[] { new DHTEndpoint(address, 42000, 42000) });
        }
    }
}
