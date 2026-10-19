#nullable enable

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises signed manifests, Merkle proofs and exact content hashes at block boundaries.</summary>
    public sealed class MerkleTests
    {
        /// <summary>Verifies empty, partial, exact and odd-leaf files while rejecting tampered manifests and proofs.</summary>
        /// <param name="size">The number of source bytes at a Merkle geometry boundary.</param>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(1024)]
        [InlineData(1025)]
        [InlineData(3072)]
        [InlineData(4097)]
        public async Task SignedManifestsAndProofsPreserveFileGeometry(int size)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            await using var node = new MajDHTNode(new DHTNodeOptions { BlockSize = 1024 }, identity);
            await node.StartAsync(token);
            var input = Crypto.Random(size);
            using var source = new MemoryStream(input);
            var record = await node.PublishAsync("geometry/" + size, source, cancellationToken: token);
            Assert.True(record.FileHash == Crypto.Hex(Crypto.Hash(input)), "Whole-file hash must cover exactly the supplied bytes.");
            Assert.True(DHTRecord.Parse(record.ToBytes()).Key.Equals(record.Key), "Signed record must round trip.");
            using var leaves = new Wire();
            for (var index = 0; index < record.BlockCount; index++)
            {
                var block = await node.ReadBlockAsync(record, node.LocalPeer, index, cancellationToken: token);
                MerkleTree.AppendLeaf(leaves, block.Span);
            }
            var tree = new MerkleTree(leaves.WrittenSpan);
            Assert.True(tree.Root == record.MerkleRoot, "Merkle root must match for all geometry boundaries.");
            var first = await node.ReadBlockAsync(record, node.LocalPeer, 0, cancellationToken: token);
            MerkleTree.Verify(record, 0, first.Span, tree.Proof(0).Span);
            if (first.Length != 0)
            {
                var changed = first.ToArray();
                changed[0] ^= 1;
                Assert.ThrowsAny<InvalidDataException>(() => MerkleTree.Verify(record, 0, changed, tree.Proof(0).Span));
            }
            if (record.BlockCount > 1)
            {
                var proof = tree.Proof(0).ToArray();
                proof[0] ^= 1;
                Assert.ThrowsAny<InvalidDataException>(() => MerkleTree.Verify(record, 0, first.Span, proof));
                Assert.ThrowsAny<InvalidDataException>(() => MerkleTree.Verify(record, 1, first.Span, tree.Proof(0).Span));
            }
            var damaged = record.ToBytes();
            damaged[damaged.Length - 1] ^= 1;
            Assert.ThrowsAny<InvalidDataException>(() => DHTRecord.Parse(damaged));
            using var downloaded = new MemoryStream();
            await node.DownloadAsync(record, downloaded, record.FileHash, token);
            Assert.True(BytesEqual(input, downloaded.ToArray()), "Local download must preserve empty and boundary files.");
            var wrongOwner = new DHTKey(new DHTIdentity().NodeId, record.Key.Name);
            Assert.True(await node.ResolveAsync(wrongOwner, token) == null, "Same name under another publisher must not resolve.");
        }
    }
}
