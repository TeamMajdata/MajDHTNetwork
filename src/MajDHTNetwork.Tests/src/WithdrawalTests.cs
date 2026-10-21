#nullable enable

using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks publisher withdrawals and local provider shutdown.</summary>
    public sealed class WithdrawalTests
    {
        /// <summary>Round-trips a signed withdrawal that describes no content.</summary>
        [Fact]
        public void WithdrawalsAreSignedRecordsWithoutContent()
        {
            var identity = new DHTIdentity();
            var withdrawal = DHTRecord.CreateWithdrawal(identity, "songs/withdrawn", 3, DateTimeOffset.UtcNow.AddHours(1));
            var parsed = DHTRecord.Parse(withdrawal.ToBytes());
            Assert.True(parsed.IsWithdrawn);
            Assert.Equal(3, parsed.Revision);
            Assert.Equal(string.Empty, parsed.FileHash);
            Assert.Equal(0, parsed.BlockCount);
            Assert.Equal(new DHTKey(identity.NodeId, "songs/withdrawn"), parsed.Key);
            var tampered = withdrawal.ToBytes();
            tampered[tampered.Length - 1] ^= 1;
            Assert.ThrowsAny<InvalidDataException>(() => DHTRecord.Parse(tampered));
            var content = DHTRecord.Create(identity, "songs/withdrawn", Crypto.Hex(Crypto.Hash(new byte[] { 1 })),
                Crypto.Hex(MerkleTree.Leaf(new byte[] { 1 })), 1, 1024, 3, DateTimeOffset.UtcNow.AddHours(1));
            Assert.False(content.IsWithdrawn);
            Assert.False(content.SameContent(parsed), "A withdrawal must conflict with content at the same revision.");
        }

        /// <summary>
        /// Withdraws a downloaded publication: the key resolves as withdrawn, honest nodes stop serving and advertising the
        /// file, old revisions cannot be replayed, and only a higher revision can publish the name again.
        /// </summary>
        /// <returns>Completion after the withdrawal assertions.</returns>
        [Fact]
        public async Task UnpublishedKeysResolveAsWithdrawnAndStopBeingServed()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            await using var bootstrap = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var mirror = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(bootstrap.StartAsync(token), publisher.StartAsync(token), mirror.StartAsync(token), reader.StartAsync(token));
            foreach (var node in new[] { publisher, mirror, reader })
            {
                await node.JoinAsync(bootstrap.LocalPeer, token);
            }
            var content = Crypto.Random(5000);
            using var source = new MemoryStream(content);
            var record = await publisher.PublishAsync("songs/withdraw-me", source, cancellationToken: token);
            using (var copy = new MemoryStream())
            {
                await mirror.DownloadAsync(record.Key, copy, record.FileHash, token);
            }
            Assert.Equal(2, (await reader.FindProvidersAsync(record.FileHash, token)).Count);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.UnpublishAsync("songs/withdraw-me", record.Revision, token));
            var withdrawal = await publisher.UnpublishAsync("songs/withdraw-me", cancellationToken: token);
            Assert.True(withdrawal.IsWithdrawn);
            Assert.Equal(record.Revision + 1, withdrawal.Revision);
            Assert.True(withdrawal.ExpiresAt >= record.ExpiresAt, "A withdrawal must outlive the publication it withdraws.");
            var resolved = await reader.ResolveAsync(record.Key, token);
            Assert.NotNull(resolved);
            Assert.True(resolved!.IsWithdrawn);
            await Assert.ThrowsAnyAsync<FileNotFoundException>(() => reader.DownloadAsync(record.Key, new MemoryStream(), null, token));
            Assert.Empty(await reader.FindProvidersAsync(record.FileHash, token));
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, publisher.LocalPeer, 0, cancellationToken: token));
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, mirror.LocalPeer, 0, cancellationToken: token));
            await using var replayer = new ScriptedPeer(IPAddress.Parse("127.0.0.6"), DHTCapabilities.Provide, DHTReachability.Unknown);
            using var replay = new Wire();
            replay.Put(record.Encoded);
            Assert.Equal(1, (await replayer.SendAsync(bootstrap.LocalPeer, Operation.Store, replay.ToArray(), token)).Status);
            Assert.True((await bootstrap.ResolveAsync(record.Key, token))!.IsWithdrawn, "An old revision must not replace a withdrawal.");
            Assert.True(await reader.AnnounceAsync(withdrawal, token) > 0, "Any node may replicate a signed withdrawal.");
            using var replacement = new MemoryStream(Crypto.Random(300));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => publisher.PublishAsync("songs/withdraw-me", replacement, withdrawal.Revision, token));
            replacement.Position = 0;
            var republished = await publisher.PublishAsync("songs/withdraw-me", replacement, withdrawal.Revision + 1, token);
            Assert.False((await reader.ResolveAsync(record.Key, token))!.IsWithdrawn);
            Assert.Equal(republished.Revision, (await reader.ResolveAsync(record.Key, token))!.Revision);
        }

        /// <summary>Stops serving a file locally without withdrawing its key.</summary>
        /// <returns>Completion after the provider stopped serving.</returns>
        [Fact]
        public async Task StopProvidingRefusesBlocksAndProviderLookups()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var provider = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var client = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(provider.StartAsync(token), client.StartAsync(token));
            await client.JoinAsync(provider.LocalPeer, token);
            var content = Crypto.Random(3000);
            using var source = new MemoryStream(content);
            var record = await provider.PublishAsync("songs/local-only", source, cancellationToken: token);
            Assert.True(BytesEqual(content, await client.ReadBlockAsync(record, provider.LocalPeer, 0, cancellationToken: token)));
            Assert.True(provider.StopProviding(record.FileHash));
            Assert.False(provider.StopProviding(record.FileHash));
            await Assert.ThrowsAnyAsync<IOException>(() => client.ReadBlockAsync(record, provider.LocalPeer, 0, cancellationToken: token));
            // Remote indexes keep the earlier claim until it expires; the provider itself must stop advertising the file.
            await using var asker = new ScriptedPeer(IPAddress.Parse("127.0.0.6"), DHTCapabilities.Download, DHTReachability.Unknown);
            using var find = new Wire();
            find.PutByte(2);
            find.PutText(record.FileHash);
            var answer = await asker.SendAsync(provider.LocalPeer, Operation.Find, find.ToArray(), token);
            Assert.Equal(0, answer.Status);
            Assert.Equal(0, ProviderCount(answer.Result));
            Assert.False((await client.ResolveAsync(record.Key, token))!.IsWithdrawn, "Stopping locally must not withdraw the key.");
            Assert.ThrowsAny<ArgumentException>(() => provider.StopProviding("not-a-hash"));
        }

        /// <summary>Counts the providers of a Find result.</summary>
        /// <param name="result">The Find result body.</param>
        /// <returns>The number of providers.</returns>
        private static long ProviderCount(ReadOnlyMemory<byte> result)
        {
            using var reader = new Wire(result);
            reader.Bytes(2200);
            var nearest = reader.Long();
            for (var index = 0; index < nearest; index++)
            {
                DHTPeer.Read(reader);
            }
            return reader.Long();
        }
    }
}
