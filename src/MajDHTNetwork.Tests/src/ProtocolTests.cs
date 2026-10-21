#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises identity, signed invitations, authenticated envelopes and malformed protocol inputs.</summary>
    public sealed class ProtocolTests
    {
        /// <summary>Restores a stable identity and keeps exported secret arrays caller owned.</summary>
        [Fact]
        public void IdentitySeedAndDefensiveExportsRoundTrip()
        {
            var identity = new DHTIdentity();
            var restored = new DHTIdentity(identity.ExportSeed());
            Assert.True(identity.NodeId == restored.NodeId, "Identity seed must restore the same node.");
            var exported = identity.ExportSeed();
            exported[0] ^= 1;
            Assert.True(identity.NodeId == restored.NodeId, "Exported secrets must be defensive copies.");
        }

        /// <summary>Round-trips signed contacts and rejects modified contact signatures.</summary>
        [Fact]
        public void SignedContactsRejectModifiedSignatures()
        {
            var identity = new DHTIdentity();
            var sender = DHTPeer.Create(identity, IPAddress.Loopback, 22001, 22002, DHTCapabilities.Download);
            var parsed = new DHTContact(sender.Contact.Encoded.ToArray());
            Assert.True(parsed.NodeId == identity.NodeId && parsed.Sequence == sender.Sequence, "A signed contact must round trip.");
            // The endpoints belong to the observer's peer, never to the signed contact.
            Assert.Equal(22001, sender.Endpoints[0].TcpPort);
            Assert.Equal(22002, sender.Endpoints[0].UdpPort);
            var contactBytes = sender.Contact.Encoded.ToArray();
            contactBytes[contactBytes.Length - 1] ^= 1;
            Assert.ThrowsAny<InvalidDataException>(() => new DHTContact(contactBytes));
        }

        /// <summary>Rejects substituted recipients, forged senders, modified ciphertext and nested forwards.</summary>
        [Fact]
        public void EncryptedEnvelopesAuthenticateSenderRecipientAndPayload()
        {
            var identity = new DHTIdentity();
            var remote = new DHTIdentity();
            var sender = DHTPeer.Create(identity, IPAddress.Loopback, 22001, 22002, DHTCapabilities.Download);
            var recipient = DHTPeer.Create(remote, IPAddress.Loopback, 22003, 22004, DHTCapabilities.Provide);
            var secret = Encoding.UTF8.GetBytes("private lookup key and content bytes");
            var message = new Packet(sender, Crypto.Random(16), (byte)Operation.Ping, secret);
            var encrypted = message.Seal(identity, recipient);
            // Opening decrypts in place, so the envelope is inspected and copied before it is consumed.
            Assert.True(!Encoding.UTF8.GetString(encrypted).Contains("private lookup"), "Application payload must be encrypted.");
            var changed = (byte[])encrypted.Clone();
            changed[changed.Length - 1] ^= 1;
            var wrongRecipient = (byte[])encrypted.Clone();
            var opened = Packet.Open(remote, encrypted);
            Assert.True(BytesEqual(opened.Body, secret) && opened.Sender.NodeId == sender.NodeId, "Envelope must authenticate sender and payload.");
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(identity, wrongRecipient));
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(remote, changed));
            Assert.True(Array.TrueForAll(changed.AsSpan(changed.Length - 64).ToArray(), value => value == 0),
                "A failed authentication must zero the ciphertext region instead of leaving partial plaintext.");
            var forged = message.Seal(new DHTIdentity(), recipient);
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(remote, forged));
            Packet.CheckForward(encrypted, recipient.NodeId);
            Assert.ThrowsAny<InvalidDataException>(() => Packet.CheckForward(encrypted, sender.NodeId));
            var nested = new Packet(sender, Crypto.Random(16), (byte)Operation.Forward, Array.Empty<byte>()).Seal(identity, recipient);
            Assert.ThrowsAny<InvalidDataException>(() => Packet.CheckForward(nested, recipient.NodeId));
        }

        /// <summary>Rejects oversized wire fields, unspecified listen addresses and invalid key names.</summary>
        [Fact]
        public void MalformedWireLengthsAndPublicInputsAreRejected()
        {
            var identity = new DHTIdentity();
            using var badLength = new Wire();
            badLength.PutLong(long.MaxValue);
            using var reader = new Wire(badLength.ToArray());
            Assert.ThrowsAny<InvalidDataException>(() => reader.Bytes(64));
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { ListenAddresses = new List<IPAddress> { IPAddress.Any, IPAddress.IPv6Any, IPAddress.Loopback } }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTKey(identity.NodeId, "bad\nname"));
        }
    }
}
