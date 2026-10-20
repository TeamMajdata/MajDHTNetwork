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
    /// <summary>
    /// Checks registering content from persisted Merkle leaves instead of reading it: resuming a publisher's own files and
    /// another publisher's copies after a restart, and the checks that keep the leaves consistent with the signed record.
    /// </summary>
    public sealed class LeafImportTests
    {
        /// <summary>The block size of the loopback test options.</summary>
        private const int BlockSize = 16384;

        /// <summary>Resumes serving a file after a restart from its persisted leaves and the blocks kept by the content store.</summary>
        /// <returns>Completion after the resumed file was downloaded.</returns>
        [Fact]
        public async Task ImportFromLeavesResumesServingAfterARestart()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            var store = new MemoryDHTContentStore();
            var content = Crypto.Random((BlockSize * 2) + 17);
            DHTRecord record;
            await using (var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide), identity, store))
            {
                await publisher.StartAsync(token);
                record = await publisher.PublishAsync("songs/resumed", new MemoryStream(content), cancellationToken: token);
            }
            // The restarted node keeps its identity and block store but no registration, so it re-registers from the persisted leaves.
            await using var restarted = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide), identity, store);
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(restarted.StartAsync(token), reader.StartAsync(token));
            await reader.JoinAsync(restarted.LocalPeer, token);
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, restarted.LocalPeer, 0, cancellationToken: token));
            Assert.True(await restarted.ImportContentAsync(record, LeavesOf(content), token) > 0, "The import must announce the restarted node as a provider.");
            Assert.True(BytesEqual(content.AsMemory(BlockSize * 2), await reader.ReadBlockAsync(record, restarted.LocalPeer, 2, cancellationToken: token)));
            using var destination = new MemoryStream();
            await reader.DownloadAsync(record.Key, destination, record.FileHash, token);
            Assert.True(BytesEqual(content, destination.ToArray()));
        }

        /// <summary>Accepts leaves without checking the stored blocks, so a missing block fails only the requests for it.</summary>
        /// <returns>Completion after the served and the refused block reads.</returns>
        [Fact]
        public async Task ImportFromLeavesLeavesMissingBlocksToLaterRequests()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var mirrorStore = new MemoryDHTContentStore();
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var mirror = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide), contentStore: mirrorStore);
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), mirror.StartAsync(token), reader.StartAsync(token));
            await mirror.JoinAsync(publisher.LocalPeer, token);
            await reader.JoinAsync(publisher.LocalPeer, token);
            var content = Crypto.Random(BlockSize + 1);
            var record = await publisher.PublishAsync("songs/half-stored", new MemoryStream(content), cancellationToken: token);
            // Only the first block is in the mirror's store; the import still registers the complete tree of another publisher's record.
            await mirrorStore.PutAsync(Crypto.Hex(MerkleTree.Leaf(content.AsSpan(0, BlockSize))), content.AsMemory(0, BlockSize), token);
            Assert.True(await mirror.ImportContentAsync(record, LeavesOf(content), token) > 0, "The import must announce the mirror as a provider.");
            Assert.True(publisher.StopProviding(record.FileHash));
            Assert.True(BytesEqual(content.AsMemory(0, BlockSize), await reader.ReadBlockAsync(record, mirror.LocalPeer, 0, cancellationToken: token)));
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, mirror.LocalPeer, 1, cancellationToken: token));
        }

        /// <summary>Rejects leaves that do not reproduce the signed block count or Merkle root, and malformed arguments.</summary>
        /// <returns>Completion after every rejected import.</returns>
        [Fact]
        public async Task ImportFromLeavesRejectsLeavesThatDifferFromTheRecord()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var mirror = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), mirror.StartAsync(token), reader.StartAsync(token));
            await mirror.JoinAsync(publisher.LocalPeer, token);
            await reader.JoinAsync(publisher.LocalPeer, token);
            var content = Crypto.Random((BlockSize * 2) + 17);
            var record = await publisher.PublishAsync("songs/checked", new MemoryStream(content), cancellationToken: token);
            var leaves = LeavesOf(content);
            var altered = (byte[])leaves.Clone();
            altered[40] ^= 1;
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => mirror.ImportContentAsync(record, altered, token));
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => mirror.ImportContentAsync(record, leaves.AsMemory(0, 64), token));
            var longer = new byte[leaves.Length + 32];
            leaves.CopyTo(longer, 0);
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => mirror.ImportContentAsync(record, longer, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => mirror.ImportContentAsync(record, Array.Empty<byte>(), token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => mirror.ImportContentAsync(record, leaves.AsMemory(0, 33), token));
            var withdrawal = DHTRecord.CreateWithdrawal(new DHTIdentity(), "songs/withdrawn", 2, DateTimeOffset.UtcNow.AddHours(1));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => mirror.ImportContentAsync(withdrawal, leaves, token));
            await Assert.ThrowsAnyAsync<ArgumentNullException>(() => mirror.ImportContentAsync(null!, leaves, token));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => reader.ImportContentAsync(record, leaves, token));
            // No rejected import registered anything, and the correct leaves still import afterwards.
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, mirror.LocalPeer, 0, cancellationToken: token));
            Assert.True(await mirror.ImportContentAsync(record, leaves, token) > 0, "Correct leaves must import after rejected ones.");
        }

        /// <summary>Refuses expired records, records beyond the leaf quota and imports that would overfill the local Merkle metadata.</summary>
        /// <returns>Completion after the refused imports.</returns>
        [Fact]
        public async Task ImportFromLeavesRespectsExpiryAndTheLeafQuota()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var limitedOptions = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            limitedOptions.MaxLocalLeaves = 3;
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var limited = new MajDHTNode(limitedOptions);
            await Task.WhenAll(publisher.StartAsync(token), limited.StartAsync(token));
            await limited.JoinAsync(publisher.LocalPeer, token);
            var small = Crypto.Random(100);
            var expiring = DHTRecord.Create(new DHTIdentity(), "songs/expiring", Crypto.Hex(Crypto.Hash(small)), new MerkleTree(LeavesOf(small)).Root,
                small.Length, BlockSize, 1, DateTimeOffset.UtcNow.AddSeconds(2));
            while (!expiring.IsExpired)
            {
                await Task.Delay(100, token);
            }
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => limited.ImportContentAsync(expiring, LeavesOf(small), token));
            var large = Crypto.Random((BlockSize * 3) + 1);
            var fourBlocks = await publisher.PublishAsync("songs/four-blocks", new MemoryStream(large), cancellationToken: token);
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => limited.ImportContentAsync(fourBlocks, LeavesOf(large), token));
            var first = Crypto.Random(BlockSize * 2);
            var second = Crypto.Random(BlockSize * 2);
            var firstRecord = await publisher.PublishAsync("songs/first-pair", new MemoryStream(first), cancellationToken: token);
            var secondRecord = await publisher.PublishAsync("songs/second-pair", new MemoryStream(second), cancellationToken: token);
            Assert.True(await limited.ImportContentAsync(firstRecord, LeavesOf(first), token) > 0, "Two leaves must fit a quota of three.");
            await Assert.ThrowsAnyAsync<IOException>(() => limited.ImportContentAsync(secondRecord, LeavesOf(second), token));
        }

        /// <summary>Signs a new revision for already stored blocks from their persisted leaves, hash and length, without reading them.</summary>
        /// <returns>Completion after the renewed publication was downloaded.</returns>
        [Fact]
        public async Task PublishFromLeavesSignsANewRevisionWithoutReadingTheContent()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            var store = new MemoryDHTContentStore();
            var content = Crypto.Random((BlockSize * 2) + 17);
            DHTRecord original;
            await using (var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide), identity, store))
            {
                await publisher.StartAsync(token);
                original = await publisher.PublishAsync("songs/renewed", new MemoryStream(content), cancellationToken: token);
            }
            await using var restarted = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide), identity, store);
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(restarted.StartAsync(token), reader.StartAsync(token));
            await reader.JoinAsync(restarted.LocalPeer, token);
            var renewed = await restarted.PublishAsync("songs/renewed", LeavesOf(content), original.FileHash, content.Length, 2, token);
            Assert.Equal(2, renewed.Revision);
            Assert.True(renewed.Key.Equals(original.Key) && renewed.SameContent(original), "The renewed record must bind the same key to the same content.");
            var resolved = await reader.ResolveAsync(original.Key, token);
            Assert.True(resolved != null && resolved.Revision == 2, "Peers must see the renewed revision.");
            using var destination = new MemoryStream();
            await reader.DownloadAsync(renewed, destination, original.FileHash, token);
            Assert.True(BytesEqual(content, destination.ToArray()));
        }

        /// <summary>Rejects publications from leaves whose arguments disagree with each other or exceed configured limits.</summary>
        /// <returns>Completion after every rejected publication.</returns>
        [Fact]
        public async Task PublishFromLeavesRejectsInconsistentArgumentsAndLimits()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var limitedOptions = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            limitedOptions.MaxLocalLeaves = 2;
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var limited = new MajDHTNode(limitedOptions);
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), limited.StartAsync(token), reader.StartAsync(token));
            var content = Crypto.Random((BlockSize * 2) + 17);
            var hash = Crypto.Hex(Crypto.Hash(content));
            var leaves = LeavesOf(content);
            var record = await publisher.PublishAsync("songs/from-leaves", leaves, hash, content.Length, cancellationToken: token);
            Assert.Equal(1, record.Revision);
            Assert.Equal(3, record.BlockCount);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/from-leaves", leaves, hash, content.Length, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/short", leaves, hash, BlockSize * 2, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/long", leaves, hash, (BlockSize * 3) + 1, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/negative", leaves, hash, -1, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/huge", leaves, hash, 2L * 1024 * 1024 * 1024, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/bad-hash", leaves, "not a hash", content.Length, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/torn", leaves.AsMemory(0, 33), hash, content.Length, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/empty", Array.Empty<byte>(), hash, content.Length, 1, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => limited.PublishAsync("songs/too-many", leaves, hash, content.Length, 1, token));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => reader.PublishAsync("songs/download-only", leaves, hash, content.Length, 1, token));
        }

        /// <summary>Computes the leaves of content at the test block size, as an application persisting them next to its files would.</summary>
        /// <param name="content">The complete content.</param>
        /// <returns>The concatenated 32-byte leaf digests in block order.</returns>
        private static byte[] LeavesOf(byte[] content)
        {
            using var leaves = new Wire();
            var offset = 0;
            do
            {
                var count = Math.Min(BlockSize, content.Length - offset);
                MerkleTree.AppendLeaf(leaves, content.AsSpan(offset, count));
                offset += count;
            }
            while (offset < content.Length);
            return leaves.WrittenSpan.ToArray();
        }
    }
}
