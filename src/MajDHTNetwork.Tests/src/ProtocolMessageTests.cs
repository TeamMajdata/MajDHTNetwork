#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises the public operation codecs that a custom node implementation builds on.</summary>
    public sealed class ProtocolMessageTests
    {
        /// <summary>Creates a signed record and its Merkle tree for content.</summary>
        /// <param name="identity">The publisher.</param>
        /// <param name="content">The file bytes.</param>
        /// <param name="blockSize">The block size.</param>
        /// <returns>The record and tree.</returns>
        private static (DHTRecord Record, MerkleTree Tree) Publish(DHTIdentity identity, byte[] content, int blockSize)
        {
            using var leaves = new Wire();
            var blockCount = Math.Max(1, (content.Length + blockSize - 1) / blockSize);
            for (var index = 0; index < blockCount; index++)
            {
                var offset = index * blockSize;
                MerkleTree.AppendLeaf(leaves, content.AsSpan(offset, Math.Min(blockSize, content.Length - offset)));
            }
            var tree = new MerkleTree(leaves.WrittenSpan);
            var record = DHTRecord.Create(identity, "codec/content", Crypto.Hex(Crypto.Hash(content)), tree.Root, content.Length, blockSize, 1,
                DateTimeOffset.UtcNow.AddHours(1));
            return (record, tree);
        }

        /// <summary>Wraps a status byte and result and reads them back, rejecting rejections and malformed framing.</summary>
        [Fact]
        public void ResponseStatusFramesResultsAndRejections()
        {
            using var success = new Wire();
            ResponseStatus.WriteSuccess(success, new byte[] { 1, 2, 3 });
            Assert.True(BytesEqual(ResponseStatus.ReadResult(success.WrittenMemory), new byte[] { 1, 2, 3 }), "A successful result must round trip.");
            using var rejection = new Wire();
            ResponseStatus.WriteRejection(rejection);
            Assert.ThrowsAny<IOException>(() => ResponseStatus.ReadResult(rejection.WrittenMemory));
            using var trailing = new Wire();
            ResponseStatus.WriteSuccess(trailing, ReadOnlySpan<byte>.Empty);
            trailing.PutByte(0);
            Assert.ThrowsAny<InvalidDataException>(() => ResponseStatus.ReadResult(trailing.WrittenMemory));
        }

        /// <summary>Bounds contact lists by count and byte budget and verifies every contact when reading.</summary>
        [Fact]
        public void ContactListsRespectCountAndBudget()
        {
            var peers = new List<DHTPeer>();
            for (var index = 0; index < 3; index++)
            {
                peers.Add(DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 1000 + index, 0, DHTCapabilities.Download));
            }
            using var full = new Wire();
            ContactList.Write(full, peers);
            using var fullReader = new Wire(full.WrittenMemory);
            var read = ContactList.Read(fullReader);
            fullReader.End();
            Assert.Equal(3, read.Count);
            Assert.Equal(peers[2].NodeId, read[2].NodeId);
            using var budgeted = new Wire();
            ContactList.Write(budgeted, peers, 8 + peers[0].Encoded.Length);
            using var budgetedReader = new Wire(budgeted.WrittenMemory);
            Assert.Single(ContactList.Read(budgetedReader));
            using var oversized = new Wire();
            oversized.PutLong(ContactList.MaxContacts + 1);
            using var oversizedReader = new Wire(oversized.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => ContactList.Read(oversizedReader));
            using var forged = new Wire();
            forged.PutLong(1);
            var bytes = peers[0].Encoded.ToArray();
            bytes[bytes.Length - 1] ^= 1;
            forged.Put(bytes);
            using var forgedReader = new Wire(forged.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => ContactList.Read(forgedReader));
        }

        /// <summary>Round-trips every Find mode and result shape and rejects unknown modes.</summary>
        [Fact]
        public void FindMessagesRoundTrip()
        {
            var identity = new DHTIdentity();
            var (record, _) = Publish(identity, Crypto.Random(100), 1024);
            var peer = DHTPeer.Create(identity, IPAddress.Loopback, 2000, 0, DHTCapabilities.Provide);
            foreach (var mode in new[] { FindMode.Nodes, FindMode.Record, FindMode.Providers })
            {
                var target = mode == FindMode.Record ? record.Key.ToString() : NodeHash();
                using var request = new Wire();
                FindMessage.WriteRequest(request, mode, target);
                using var reader = new Wire(request.WrittenMemory);
                var decoded = FindMessage.ReadRequest(reader);
                Assert.Equal(mode, decoded.Mode);
                Assert.Equal(target, decoded.Target);
            }
            using var unknown = new Wire();
            unknown.PutByte(3);
            unknown.PutText(NodeHash());
            using var unknownReader = new Wire(unknown.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => FindMessage.ReadRequest(unknownReader));
            using var response = new Wire();
            FindMessage.WriteResponse(response, record, new[] { peer }, new[] { peer });
            using var responseReader = new Wire(response.WrittenMemory);
            var result = FindMessage.ReadResponse(responseReader);
            Assert.True(result.Record != null && result.Record.Key.Equals(record.Key), "The record must round trip.");
            Assert.True(result.Peers.Count == 1 && result.Providers.Count == 1 && result.Peers[0].NodeId == peer.NodeId, "Contacts must round trip.");
            using var empty = new Wire();
            FindMessage.WriteResponse(empty, null, Array.Empty<DHTPeer>(), Array.Empty<DHTPeer>());
            using var emptyReader = new Wire(empty.WrittenMemory);
            var none = FindMessage.ReadResponse(emptyReader);
            Assert.True(none.Record == null && none.Peers.Count == 0 && none.Providers.Count == 0, "An empty result must round trip.");
        }

        /// <summary>Round-trips Store and Block requests and authenticates Block results against the requester's record.</summary>
        [Fact]
        public void StoreAndBlockMessagesAuthenticateContent()
        {
            var identity = new DHTIdentity();
            var content = Crypto.Random(2500);
            var (record, tree) = Publish(identity, content, 1024);
            using var store = new Wire();
            StoreMessage.WriteRequest(store, record);
            using var storeReader = new Wire(store.WrittenMemory);
            Assert.True(StoreMessage.ReadRequest(storeReader).Key.Equals(record.Key), "A stored record must round trip.");
            using var request = new Wire();
            BlockMessage.WriteRequest(request, record, 2);
            using var requestReader = new Wire(request.WrittenMemory);
            var decoded = BlockMessage.ReadRequest(requestReader);
            Assert.True(decoded.Index == 2 && decoded.Record.FileHash == record.FileHash, "A block request must round trip.");
            using var outOfRange = new Wire();
            BlockMessage.WriteRequest(outOfRange, record, record.BlockCount);
            using var outOfRangeReader = new Wire(outOfRange.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => BlockMessage.ReadRequest(outOfRangeReader));
            Assert.ThrowsAny<ArgumentOutOfRangeException>(() => new BlockRequest(record, -1));
            var last = content.AsSpan(2048).ToArray();
            using var response = new Wire();
            BlockMessage.WriteResponse(response, last, tree, 2);
            using var responseReader = new Wire(response.WrittenMemory);
            Assert.True(BytesEqual(BlockMessage.ReadResponse(responseReader, record, 2), last), "A verified block must round trip.");
            using var wrongIndex = new Wire(response.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => BlockMessage.ReadResponse(wrongIndex, record, 1));
            var changed = (byte[])last.Clone();
            changed[0] ^= 1;
            using var tampered = new Wire();
            BlockMessage.WriteResponse(tampered, changed, tree, 2);
            using var tamperedReader = new Wire(tampered.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => BlockMessage.ReadResponse(tamperedReader, record, 2));
        }

        /// <summary>Forwards only data requests addressed to the declared destination and round-trips opaque responses.</summary>
        [Fact]
        public void RelayMessagesOnlyForwardDataRequests()
        {
            var sender = new DHTIdentity();
            var destination = new DHTIdentity();
            var senderPeer = DHTPeer.Create(sender, IPAddress.Loopback, 3000, 0, DHTCapabilities.Download);
            var destinationPeer = DHTPeer.Create(destination, IPAddress.Loopback, 3001, 0, DHTCapabilities.Provide);
            var inner = new Packet(senderPeer, Crypto.Random(Packet.RequestIdLength), (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty)
                .Seal(sender, destinationPeer);
            using var request = new Wire();
            RelayMessage.WriteRequest(request, destinationPeer.NodeId, inner);
            using var requestReader = new Wire(request.WrittenMemory);
            var decoded = RelayMessage.ReadRequest(requestReader);
            Assert.True(decoded.DestinationId == destinationPeer.NodeId && BytesEqual(decoded.Envelope, inner), "A relay request must round trip.");
            using var misaddressed = new Wire();
            RelayMessage.WriteRequest(misaddressed, senderPeer.NodeId, inner);
            using var misaddressedReader = new Wire(misaddressed.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => RelayMessage.ReadRequest(misaddressedReader));
            var nested = new Packet(senderPeer, Crypto.Random(Packet.RequestIdLength), (byte)Operation.Relay, ReadOnlyMemory<byte>.Empty)
                .Seal(sender, destinationPeer);
            using var nestedRequest = new Wire();
            RelayMessage.WriteRequest(nestedRequest, destinationPeer.NodeId, nested);
            using var nestedReader = new Wire(nestedRequest.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => RelayMessage.ReadRequest(nestedReader));
            using var response = new Wire();
            RelayMessage.WriteResponse(response, inner);
            using var responseReader = new Wire(response.WrittenMemory);
            Assert.True(BytesEqual(RelayMessage.ReadResponse(responseReader), inner), "An opaque response must round trip.");
        }

        /// <summary>Round-trips the Hello result, Punch tickets and Probe arguments, rejecting wrong lengths.</summary>
        [Fact]
        public void HelloPunchAndProbeMessagesRoundTrip()
        {
            var observed = new IPEndPoint(IPAddress.Parse("203.0.113.9"), 4242);
            using var hello = new Wire();
            HelloMessage.WriteResponse(hello, observed);
            using var helloReader = new Wire(hello.WrittenMemory);
            Assert.Equal(observed, HelloMessage.ReadResponse(helloReader));
            using var wildcard = new Wire();
            ObservedEndpoint.Write(wildcard, new IPEndPoint(IPAddress.Any, 1));
            using var wildcardReader = new Wire(wildcard.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => ObservedEndpoint.Read(wildcardReader));
            var ticket = Crypto.Random(PunchMessage.TicketLength);
            using var punch = new Wire();
            PunchMessage.WriteRequest(punch, ticket);
            Assert.True(BytesEqual(PunchMessage.ReadRequest(punch.WrittenMemory), ticket), "A punch ticket is sent raw.");
            Assert.ThrowsAny<InvalidDataException>(() => PunchMessage.ReadRequest(new byte[15]));
            Assert.ThrowsAny<ArgumentException>(() => PunchMessage.WriteRequest(punch, new byte[17]));
            var nonce = Crypto.Random(ProbeMessage.NonceLength);
            using var probe = new Wire();
            ProbeMessage.WriteRequest(probe, nonce, 2);
            using var probeReader = new Wire(probe.WrittenMemory);
            var decoded = ProbeMessage.ReadRequest(probeReader);
            Assert.True(decoded.PortIndex == 2 && BytesEqual(decoded.Nonce, nonce), "A probe must round trip.");
            using var badIndex = new Wire();
            ProbeMessage.WriteRequest(badIndex, nonce, RendezvousMessage.MaxProbePorts);
            using var badIndexReader = new Wire(badIndex.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => ProbeMessage.ReadRequest(badIndexReader));
        }

        /// <summary>Round-trips every Rendezvous action and result and enforces the action, port and nonce rules.</summary>
        [Fact]
        public void RendezvousMessagesRoundTrip()
        {
            var identity = new DHTIdentity();
            var peer = DHTPeer.Create(identity, IPAddress.Loopback, 5000, 5000, DHTCapabilities.Provide);
            var observed = new IPEndPoint(IPAddress.Parse("198.51.100.7"), 6000);
            var expiry = DateTimeOffset.FromUnixTimeMilliseconds(DateTimeOffset.UtcNow.AddSeconds(5).ToUnixTimeMilliseconds());
            using var register = new Wire();
            RendezvousMessage.WriteRegisterRequest(register);
            using var registerReader = new Wire(register.WrittenMemory);
            Assert.Equal(RendezvousAction.Register, RendezvousMessage.ReadAction(registerReader));
            RendezvousMessage.ReadRegisterRequest(registerReader);
            using var introduce = new Wire();
            RendezvousMessage.WriteIntroduceRequest(introduce, peer.NodeId);
            using var introduceReader = new Wire(introduce.WrittenMemory);
            Assert.Equal(RendezvousAction.Introduce, RendezvousMessage.ReadAction(introduceReader));
            Assert.Equal(peer.NodeId, RendezvousMessage.ReadIntroduceRequest(introduceReader));
            using var badTarget = new Wire();
            RendezvousMessage.WriteIntroduceRequest(badTarget, "not-a-node-id");
            using var badTargetReader = new Wire(badTarget.WrittenMemory);
            RendezvousMessage.ReadAction(badTargetReader);
            Assert.ThrowsAny<InvalidDataException>(() => RendezvousMessage.ReadIntroduceRequest(badTargetReader));
            using var unknown = new Wire();
            unknown.PutByte(4);
            using var unknownReader = new Wire(unknown.WrittenMemory);
            Assert.ThrowsAny<InvalidDataException>(() => RendezvousMessage.ReadAction(unknownReader));
            var ticket = Crypto.Random(RendezvousMessage.TicketLength);
            var introduction = new RendezvousIntroduction(peer, observed, ticket, expiry);
            using var poll = new Wire();
            RendezvousMessage.WritePollResponse(poll, observed, introduction);
            using var pollReader = new Wire(poll.WrittenMemory);
            var polled = RendezvousMessage.ReadPollResponse(pollReader);
            Assert.True(polled.Observed.Equals(observed) && polled.Introduction.HasValue, "A poll with an introduction must round trip.");
            Assert.True(polled.Introduction!.Value.Peer.NodeId == peer.NodeId && BytesEqual(polled.Introduction.Value.Ticket, ticket)
                && polled.Introduction.Value.ExpiresAt == expiry && polled.Introduction.Value.Endpoint.Equals(observed), "The introduction must round trip.");
            using var idle = new Wire();
            RendezvousMessage.WritePollResponse(idle, observed, null);
            using var idleReader = new Wire(idle.WrittenMemory);
            Assert.False(RendezvousMessage.ReadPollResponse(idleReader).Introduction.HasValue, "An idle poll carries no introduction.");
            using var introduced = new Wire();
            RendezvousMessage.WriteIntroduction(introduced, introduction);
            using var introducedReader = new Wire(introduced.WrittenMemory);
            Assert.Equal(peer.NodeId, RendezvousMessage.ReadIntroduceResponse(introducedReader).Peer.NodeId);
            using var dialBack = new Wire();
            RendezvousMessage.WriteDialBackRequest(dialBack, new[] { 7000, 7001 });
            using var dialBackReader = new Wire(dialBack.WrittenMemory);
            Assert.Equal(RendezvousAction.DialBack, RendezvousMessage.ReadAction(dialBackReader));
            Assert.Equal(new[] { 7000, 7001 }, RendezvousMessage.ReadDialBackRequest(dialBackReader));
            Assert.ThrowsAny<ArgumentException>(() => RendezvousMessage.WriteDialBackRequest(dialBack, new[] { 1, 2, 3 }));
            var nonce = Crypto.Random(RendezvousMessage.NonceLength);
            var ports = new List<int> { 6000, 7000 };
            using var assist = new Wire();
            RendezvousMessage.WriteDialBackAssistRequest(assist, new DialBackDelegation(peer, DHTTransport.Udp, observed.Address, ports, nonce, expiry));
            using var assistReader = new Wire(assist.WrittenMemory);
            Assert.Equal(RendezvousAction.DialBackAssist, RendezvousMessage.ReadAction(assistReader));
            var delegation = RendezvousMessage.ReadDialBackAssistRequest(assistReader);
            Assert.True(delegation.Owner.NodeId == peer.NodeId && delegation.Transport == DHTTransport.Udp && delegation.TargetAddress.Equals(observed.Address)
                && delegation.ExpiresAt == expiry && BytesEqual(delegation.Nonce, nonce), "A delegation must round trip.");
            Assert.Equal(ports, new List<int>(delegation.Ports));
            using var arranged = new Wire();
            RendezvousMessage.WriteDialBackResponse(arranged, new DialBackArrangement(observed, peer.NodeId, nonce, expiry, ports));
            using var arrangedReader = new Wire(arranged.WrittenMemory);
            var arrangement = RendezvousMessage.ReadDialBackResponse(arrangedReader);
            Assert.True(arrangement.HelperId == peer.NodeId && arrangement.Observed.Equals(observed) && BytesEqual(arrangement.Nonce, nonce)
                && arrangement.ExpiresAt == expiry, "An arrangement must round trip.");
            Assert.Equal(ports, new List<int>(arrangement.Ports));
            Assert.ThrowsAny<ArgumentException>(() => new DialBackArrangement(observed, peer.NodeId, nonce, expiry, Array.Empty<int>()));
            Assert.ThrowsAny<ArgumentException>(() => new RendezvousIntroduction(peer, observed, new byte[8], expiry));
        }
    }
}
