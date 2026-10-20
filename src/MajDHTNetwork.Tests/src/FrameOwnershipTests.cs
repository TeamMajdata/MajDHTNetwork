#nullable enable

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// Verifies that pooled receive frames never outlive their consumers: blocks copied into the store, the destination and
    /// public block reads stay intact after the shared array pool is churned, so nothing retained aliases a released frame.
    /// </summary>
    public sealed class FrameOwnershipTests
    {
        /// <summary>The block size of the published file, so block replies arrive in the largest frames the protocol uses.</summary>
        private const int BlockSize = 32768;
        /// <summary>The number of blocks, enough for several download workers to hold frames at once; the last block is partial.</summary>
        private const int BlockCount = 12;

        /// <summary>Downloads a file and reads every block again, then recycles the pool and checks everything that was kept.</summary>
        /// <param name="transport">The single transport used by both nodes.</param>
        /// <returns>Completion after the stored, written and individually read blocks were compared with the source.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task DownloadedAndReadBlocksSurvivePoolChurn(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            var providerOptions = Options(transport, DHTCapabilities.Download | DHTCapabilities.Provide);
            providerOptions.BlockSize = BlockSize;
            var downloaderOptions = Options(transport, DHTCapabilities.Download);
            downloaderOptions.BlockSize = BlockSize;
            var store = new MemoryDHTContentStore();
            await using var provider = new MajDHTNode(providerOptions);
            await using var downloader = new MajDHTNode(downloaderOptions, contentStore: store);
            await provider.StartAsync(token);
            await downloader.StartAsync(token);
            await downloader.JoinAsync(provider.LocalPeer, token);
            var input = Crypto.Random((BlockSize * BlockCount) - 1000);
            using var source = new MemoryStream(input);
            var record = await provider.PublishAsync("ownership/blocks", source, cancellationToken: token);
            Assert.Equal(BlockCount, record.BlockCount);
            using var destination = new MemoryStream();
            await downloader.DownloadAsync(record, destination, record.FileHash, token);
            var read = new List<ReadOnlyMemory<byte>>();
            for (var index = 0; index < record.BlockCount; index++)
            {
                read.Add(await downloader.ReadBlockAsync(record, provider.LocalPeer, index, cancellationToken: token));
            }
            ChurnPool();
            Assert.True(BytesEqual(input, destination.ToArray()), "The destination must hold the bytes written while the frames were alive.");
            for (var index = 0; index < record.BlockCount; index++)
            {
                var expected = input.AsMemory(index * BlockSize, Math.Min(BlockSize, input.Length - (index * BlockSize)));
                var stored = await store.GetAsync(Crypto.Hex(MerkleTree.Leaf(expected.Span)), token);
                Assert.True(stored.HasValue && BytesEqual(expected, stored.Value), "The store must keep its own copy of block " + index + ".");
                Assert.True(BytesEqual(expected, read[index]), "A public block read must not alias the released response frame of block " + index + ".");
            }
        }

        /// <summary>
        /// Rents, overwrites and returns enough arrays of every bucket that frames use to recycle any frame the transports released,
        /// so a retained alias of a released frame would now read the overwritten bytes.
        /// </summary>
        private static void ChurnPool()
        {
            var rented = new List<byte[]>();
            var perBucket = (Environment.ProcessorCount * 8) + 64;
            foreach (var length in new[] { 200, 500, 1000, 2000, 4000, 40000 })
            {
                for (var count = 0; count < perBucket; count++)
                {
                    var array = ArrayPool<byte>.Shared.Rent(length);
                    array.AsSpan().Fill(0xA5);
                    rented.Add(array);
                }
            }
            foreach (var array in rented)
            {
                ArrayPool<byte>.Shared.Return(array);
            }
        }
    }
}
