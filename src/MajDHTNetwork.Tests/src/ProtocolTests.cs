#nullable enable

using System;
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

        /// <summary>Round-trips signed contacts and rejects modified invitation signatures.</summary>
        [Fact]
        public void SignedInvitationsRejectModifiedSignatures()
        {
            var identity = new DHTIdentity();
            var remote = new DHTIdentity();
            var sender = DHTPeer.Create(identity, IPAddress.Loopback, 22001, 22002, DHTCapabilities.Download);
            var recipient = DHTPeer.Create(remote, IPAddress.Loopback, 22003, 22004, DHTCapabilities.Provide);
            Assert.True(DHTPeer.ParseInvitation(sender.ToInvitation()).NodeId == identity.NodeId, "Public invitation must round trip.");
            var inviteBytes = sender.Encoded.ToArray();
            inviteBytes[inviteBytes.Length - 1] ^= 1;
            Assert.ThrowsAny<InvalidDataException>(() => new DHTPeer(inviteBytes));
        }

        /// <summary>Rejects substituted recipients, forged senders, modified ciphertext and nested relays.</summary>
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
            var opened = Packet.Open(remote, encrypted);
            Assert.True(BytesEqual(opened.Body, secret) && opened.Sender.NodeId == sender.NodeId, "Envelope must authenticate sender and payload.");
            Assert.True(!Encoding.UTF8.GetString(encrypted).Contains("private lookup"), "Application payload must be encrypted.");
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(identity, encrypted));
            var changed = (byte[])encrypted.Clone();
            changed[changed.Length - 1] ^= 1;
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(remote, changed));
            var forged = message.Seal(new DHTIdentity(), recipient);
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(remote, forged));
            Packet.CheckForward(encrypted, recipient.NodeId);
            Assert.ThrowsAny<InvalidDataException>(() => Packet.CheckForward(encrypted, sender.NodeId));
            var nested = new Packet(sender, Crypto.Random(16), (byte)Operation.Relay, Array.Empty<byte>()).Seal(identity, recipient);
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
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { ListenAddress = IPAddress.Any }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTKey(identity.NodeId, "bad\nname"));
        }
    }
}
