#nullable enable

using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Measures isolated warmed managed allocations for protocol hot paths.</summary>
    [Collection(AllocationCollection.Name)]
    public sealed class AllocationTests
    {
        /// <summary>Receives allocation diagnostics after each measured interval completes.</summary>
        private readonly ITestOutputHelper _output;

        /// <summary>Creates a test instance with per-test diagnostic output.</summary>
        /// <param name="output">The runner-owned diagnostic sink, used outside measured intervals.</param>
        public AllocationTests(ITestOutputHelper output)
        {
            _output = output;
        }

        /// <summary>Bounds warmed codec allocation while retaining the integer and byte-field round trip.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void WireRoundTripStaysWithinAllocationBudget()
        {
            var block = Crypto.Random(32768);
            Measure("Wire 32 KiB round trip", () =>
            {
                using var writer = new Wire();
                writer.PutLong(123);
                writer.Put(block);
                using var reader = new Wire(writer.WrittenMemory);
                if (reader.Long() != 123 || reader.Bytes(32768).Length != block.Length)
                {
                    throw new InvalidOperationException("Codec round trip failed.");
                }
            }, 1000, 2048, 98864);
        }

        /// <summary>Bounds warmed allocation for a 32 KiB Merkle leaf.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void MerkleLeafStaysWithinAllocationBudget()
        {
            var block = Crypto.Random(32768);
            Measure("Merkle 32 KiB leaf", () => MerkleTree.Leaf(block), 1000, 1024, 33048);
        }

        /// <summary>Bounds warmed allocation for a contiguous 128-leaf Merkle tree.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void MerkleTreeStaysWithinAllocationBudget()
        {
            var block = Crypto.Random(32768);
            using var leaves = new Wire();
            for (var i = 0; i < 128; i++)
            {
                leaves.PutRaw(Crypto.Hash(block));
            }
            Measure("Merkle 128-leaf tree", () => new MerkleTree(leaves.WrittenSpan), 100, 16000, 46120);
        }

        /// <summary>Bounds warmed SHA-256 hexadecimal formatting allocation.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void HexadecimalFormattingStaysWithinAllocationBudget()
        {
            var hash = Crypto.Random(32);
            Measure("SHA-256 hexadecimal", () => Crypto.Hex(hash), 1000, 256, 1376);
        }

        /// <summary>Bounds warmed envelope allocation while performing authenticated encryption and decryption.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void EncryptedPacketRoundTripStaysWithinAllocationBudget()
        {
            var block = Crypto.Random(32768);
            var sender = new DHTIdentity();
            var recipient = new DHTIdentity();
            var source = DHTPeer.Create(sender, IPAddress.Loopback, 20000, 0, DHTCapabilities.Download);
            var target = DHTPeer.Create(recipient, IPAddress.Loopback, 20001, 0, DHTCapabilities.Download);
            var packet = new Packet(source, Crypto.Random(16), (byte)Operation.Ping, block);
            Measure("Encrypted 32 KiB packet round trip", () => Packet.Open(recipient, packet.Seal(sender, target)), 100, 60000, 700807);
        }

        /// <summary>
        /// Bounds the fixed cost of sealing and opening a small request, which every block request, lookup and keep-alive pays:
        /// the envelope copy, the provider's signature and agreement arithmetic, and nothing for the cached sender contact.
        /// </summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void SmallPacketRoundTripStaysWithinAllocationBudget()
        {
            var body = Crypto.Random(64);
            var sender = new DHTIdentity();
            var recipient = new DHTIdentity();
            var source = DHTPeer.Create(sender, IPAddress.Loopback, 20002, 0, DHTCapabilities.Download);
            var target = DHTPeer.Create(recipient, IPAddress.Loopback, 20003, 0, DHTCapabilities.Download);
            var packet = new Packet(source, Crypto.Random(16), (byte)Operation.Find, body);
            Measure("Encrypted 64-byte packet round trip", () => Packet.Open(recipient, packet.Seal(sender, target)), 1000, 16000);
        }

        /// <summary>Bounds repeated read-only cached block retrieval without copying the stored content.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void CachedBlockReadStaysWithinAllocationBudget()
        {
            var block = Crypto.Random(32768);
            var store = new MemoryDHTContentStore();
            var hash = Crypto.Hex(MerkleTree.Leaf(block));
            var pendingWrite = store.PutAsync(hash, block, CancellationToken.None);
            Assert.True(pendingWrite.IsCompletedSuccessfully);
            Measure("Cached 32 KiB block read", () => store.GetAsync(hash, CancellationToken.None).GetAwaiter().GetResult(), 1000, 64);
        }

        /// <summary>Requires disabled structured logger events to allocate no managed bytes.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void DisabledLoggerEventsDoNotAllocate()
        {
            Measure("Disabled ILogger event", () => DHTLog.Write(NullLogger.Instance, LogLevel.Debug, "Allocation validation"), 1000, 0);
        }

        /// <summary>
        /// Bounds the process-wide managed allocation of a complete multi-block download between two loopback nodes, which
        /// covers request sealing, transport framing, envelope authentication, block verification and storage on both sides.
        /// </summary>
        /// <param name="transport">The single transport used by both nodes.</param>
        /// <returns>Completion after the measured download.</returns>
        [Theory]
        [Trait("Category", "Allocation")]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task BlockDownloadStaysWithinAllocationBudget(DHTTransport transport)
        {
            const int BlockCount = 64;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            var providerOptions = TestSupport.Options(transport, DHTCapabilities.Download | DHTCapabilities.Provide);
            providerOptions.BlockSize = 32768;
            var downloaderOptions = TestSupport.Options(transport, DHTCapabilities.Download);
            downloaderOptions.BlockSize = 32768;
            await using var provider = new MajDHTNode(providerOptions);
            await using var downloader = new MajDHTNode(downloaderOptions);
            await provider.StartAsync(token);
            await downloader.StartAsync(token);
            await downloader.JoinAsync(provider.LocalPeer, token);
            // A downloaded file is served locally afterwards, so the warm-up and the measurement use distinct files.
            using var warmUpSource = new MemoryStream(Crypto.Random(32768 * BlockCount));
            using var source = new MemoryStream(Crypto.Random(32768 * BlockCount));
            var warmUp = await provider.PublishAsync("allocation/warm-up", warmUpSource, cancellationToken: token);
            var record = await provider.PublishAsync("allocation/blocks", source, cancellationToken: token);
            await downloader.DownloadAsync(warmUp, Stream.Null, warmUp.FileHash, token);
            // The budget lies below the roughly 142,000 bytes measured while each received frame was still a fresh array, so
            // reintroducing that copy fails this test.
            await MeasureAsync(transport + " 32 KiB block download", async () =>
            {
                await downloader.DownloadAsync(record, Stream.Null, record.FileHash, token);
            }, BlockCount, 130000);
        }

        /// <summary>Measures process-wide managed allocation of one asynchronous operation; the caller warms the code paths.</summary>
        /// <param name="name">The workload described in the diagnostic output.</param>
        /// <param name="operation">The asynchronous operation to measure, which may run on any thread.</param>
        /// <param name="units">The number of units, such as blocks, that the operation processes.</param>
        /// <param name="budget">The maximum permitted managed bytes per unit.</param>
        private async Task MeasureAsync(string name, Func<Task> operation, int units, long budget)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            var before = GC.GetTotalAllocatedBytes(true);
            await operation();
            var allocated = (GC.GetTotalAllocatedBytes(true) - before) / units;
            _output.WriteLine(name + ": " + allocated + " bytes/unit");
            Assert.True(allocated <= budget, name + " exceeded its allocation budget of " + budget + " bytes/unit; measured " + allocated + ".");
        }

        /// <summary>Measures synchronous managed allocation after warming providers and pools.</summary>
        /// <param name="name">The workload described in the diagnostic output.</param>
        /// <param name="operation">The synchronous operation to measure on the current thread.</param>
        /// <param name="iterations">The number of measured operations.</param>
        /// <param name="budget">The maximum permitted managed bytes per operation.</param>
        /// <param name="baseline">The original implementation's measured allocation, when available.</param>
        private void Measure(string name, Action operation, int iterations, long budget, long? baseline = null)
        {
            for (var i = 0; i < 16; i++)
            {
                operation();
            }
            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var i = 0; i < iterations; i++)
            {
                operation();
            }
            var allocated = (GC.GetAllocatedBytesForCurrentThread() - before) / iterations;
            _output.WriteLine(name + ": " + allocated + " bytes/op" + (baseline.HasValue ? " (baseline " + baseline.Value + ")" : string.Empty));
            Assert.True(allocated <= budget, name + " exceeded its allocation budget of " + budget + " bytes/op; measured " + allocated + ".");
        }
    }
}
