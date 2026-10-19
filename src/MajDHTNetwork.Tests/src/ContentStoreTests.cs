#nullable enable

using System;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises bounded cache eviction, caller-owned snapshots and defensive content copies.</summary>
    public sealed class ContentStoreTests
    {
        /// <summary>Enforces the entry quota and prevents caller mutations from changing cached bytes.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task EntryQuotaEvictsTheOldestBlockAndReadCopiesRemainIndependent()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var cache = new MemoryDHTContentStore(32768, 1);
            var a = Crypto.Random(16);
            var b = Crypto.Random(16);
            var aId = Crypto.Hex(MerkleTree.Leaf(a));
            var bId = Crypto.Hex(MerkleTree.Leaf(b));
            await cache.PutAsync(aId, a, token);
            await cache.PutAsync(bId, b, token);
            Assert.True(!((await cache.GetAsync(aId, token)).HasValue), "Memory store must enforce its entry quota.");
            var cached = (await cache.GetAsync(bId, token))!.Value.ToArray();
            cached[0] ^= 1;
            Assert.True(BytesEqual((await cache.GetAsync(bId, token))!.Value.ToArray(), b), "Cache reads must be defensive copies.");
        }

        /// <summary>Retains immutable cache views after source mutation and eviction.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task ReadOnlySnapshotsSurviveInputMutationAndEviction()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var content = new byte[] { 2, 4, 6 };
            var cache = new MemoryDHTContentStore(32768, 1);
            var hash = Crypto.Hex(MerkleTree.Leaf(content));
            await cache.PutAsync(hash, content, token);
            var snapshot = (await cache.GetAsync(hash, token))!.Value;
            content[0] ^= 1;
            var other = new byte[] { 9 };
            await cache.PutAsync(Crypto.Hex(MerkleTree.Leaf(other)), other, token);
            Assert.True(snapshot.Span.SequenceEqual(new byte[] { 2, 4, 6 }), "Read-only cache snapshots must survive input mutation and eviction.");
        }
    }
}
