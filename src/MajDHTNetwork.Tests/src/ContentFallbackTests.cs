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
    /// <summary>Checks serving another publisher's content from a local copy and on demand through a content fallback.</summary>
    public sealed class ContentFallbackTests
    {
        /// <summary>Imports a local copy of a foreign publication and serves it after the publisher stopped serving.</summary>
        /// <returns>Completion after the imported copy was downloaded.</returns>
        [Fact]
        public async Task ImportedContentIsServedForAnotherPublishersRecord()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var mirror = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), mirror.StartAsync(token), reader.StartAsync(token));
            await mirror.JoinAsync(publisher.LocalPeer, token);
            await reader.JoinAsync(publisher.LocalPeer, token);
            var content = Crypto.Random((16384 * 2) + 17);
            using var source = new MemoryStream(content);
            var record = await publisher.PublishAsync("songs/imported", source, cancellationToken: token);
            using (var copy = new MemoryStream(content))
            {
                Assert.True(await mirror.ImportContentAsync(record, copy, token) > 0, "The import must announce the mirror as a provider.");
            }
            Assert.True(publisher.StopProviding(record.FileHash));
            Assert.True(BytesEqual(content.AsMemory(0, 16384), await reader.ReadBlockAsync(record, mirror.LocalPeer, 0, cancellationToken: token)));
            using var destination = new MemoryStream();
            await reader.DownloadAsync(record.Key, destination, record.FileHash, token);
            Assert.True(BytesEqual(content, destination.ToArray()));
        }

        /// <summary>Rejects imports whose content or record cannot be served.</summary>
        /// <returns>Completion after every rejected import.</returns>
        [Fact]
        public async Task ImportRejectsDifferentContentWithdrawalsAndDownloadOnlyNodes()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var mirror = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(publisher.StartAsync(token), mirror.StartAsync(token), reader.StartAsync(token));
            await mirror.JoinAsync(publisher.LocalPeer, token);
            await reader.JoinAsync(publisher.LocalPeer, token);
            var content = Crypto.Random(20000);
            using var source = new MemoryStream(content);
            var record = await publisher.PublishAsync("songs/checked", source, cancellationToken: token);
            var changed = (byte[])content.Clone();
            changed[changed.Length - 1] ^= 1;
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => mirror.ImportContentAsync(record, new MemoryStream(changed), token));
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => mirror.ImportContentAsync(record, new MemoryStream(content, 0, 19999), token));
            var longer = new byte[content.Length + 1];
            content.CopyTo(longer, 0);
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => mirror.ImportContentAsync(record, new MemoryStream(longer), token));
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, mirror.LocalPeer, 0, cancellationToken: token));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => reader.ImportContentAsync(record, new MemoryStream(content), token));
            var withdrawal = DHTRecord.CreateWithdrawal(new DHTIdentity(), "songs/withdrawn", 2, DateTimeOffset.UtcNow.AddHours(1));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => mirror.ImportContentAsync(withdrawal, new MemoryStream(content), token));
            await Assert.ThrowsAnyAsync<ArgumentNullException>(() => mirror.ImportContentAsync(null!, new MemoryStream(content), token));
        }

        /// <summary>Applies the configurable local Merkle leaf quota to publications and imports.</summary>
        /// <returns>Completion after the quota checks.</returns>
        [Fact]
        public async Task PublishAndImportRespectTheConfiguredLeafQuota()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { MaxLocalLeaves = 0 }.Snapshot());
            Assert.ThrowsAny<ArgumentException>(() => new DHTNodeOptions { MaxLocalLeaves = 16777217 }.Snapshot());
            var limitedOptions = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            limitedOptions.MaxLocalLeaves = 2;
            await using var publisher = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var limited = new MajDHTNode(limitedOptions);
            await Task.WhenAll(publisher.StartAsync(token), limited.StartAsync(token));
            await limited.JoinAsync(publisher.LocalPeer, token);
            var content = Crypto.Random((16384 * 2) + 1);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => limited.PublishAsync("songs/too-large", new MemoryStream(content), cancellationToken: token));
            var record = await publisher.PublishAsync("songs/three-blocks", new MemoryStream(content), cancellationToken: token);
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => limited.ImportContentAsync(record, new MemoryStream(content), token));
            var small = await limited.PublishAsync("songs/two-blocks", new MemoryStream(content, 0, 16384 * 2), cancellationToken: token);
            Assert.Equal(2, small.BlockCount);
        }

        /// <summary>
        /// Counts the leaves of a geometry registered again under another key once, and returns the leaves of content the
        /// node stopped providing to the quota.
        /// </summary>
        /// <returns>Completion after the quota checks.</returns>
        [Fact]
        public async Task LeafQuotaCountsReplacedContentOnceAndReleasesStoppedContent()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var options = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            options.MaxLocalLeaves = 4;
            await using var node = new MajDHTNode(options);
            await node.StartAsync(token);
            var first = await node.PublishAsync("songs/first", new MemoryStream(Crypto.Random(16384 * 2)), cancellationToken: token);
            await node.PublishAliasAsync("songs/first-alias", first, cancellationToken: token);
            // The alias replaced the tree of the same geometry, so two leaves remain for a second two-block file.
            await node.PublishAsync("songs/second", new MemoryStream(Crypto.Random(16384 * 2)), cancellationToken: token);
            var third = Crypto.Random(16384 * 2);
            await Assert.ThrowsAnyAsync<IOException>(() => node.PublishAsync("songs/third", new MemoryStream(third), cancellationToken: token));
            Assert.True(node.StopProviding(first.FileHash), "The first file must have been provided.");
            var released = await node.PublishAsync("songs/third", new MemoryStream(third), cancellationToken: token);
            Assert.Equal(2, released.BlockCount);
        }

        /// <summary>Asks the fallback once for unknown content, then serves the acquired content directly.</summary>
        /// <returns>Completion after the pulled-through block reads.</returns>
        [Fact]
        public async Task ContentFallbackMakesRequestedContentAvailable()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var fallback = new PullThroughFallback();
            await using var publisher = new MajDHTNode(SlowOptions(DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var replica = new MajDHTNode(SlowOptions(DHTCapabilities.Download | DHTCapabilities.Provide), contentFallback: fallback);
            await using var reader = new MajDHTNode(SlowOptions(DHTCapabilities.Download));
            fallback.Node = replica;
            await Task.WhenAll(publisher.StartAsync(token), replica.StartAsync(token), reader.StartAsync(token));
            await replica.JoinAsync(publisher.LocalPeer, token);
            await reader.JoinAsync(publisher.LocalPeer, token);
            var content = Crypto.Random(16384 + 100);
            using var source = new MemoryStream(content);
            var record = await publisher.PublishAsync("songs/pulled", source, cancellationToken: token);
            var first = await reader.ReadBlockAsync(record, replica.LocalPeer, 1, cancellationToken: token);
            Assert.True(BytesEqual(content.AsMemory(16384), first));
            Assert.Equal(1, fallback.Calls);
            Assert.True(publisher.StopProviding(record.FileHash));
            var second = await reader.ReadBlockAsync(record, replica.LocalPeer, 0, cancellationToken: token);
            Assert.True(BytesEqual(content.AsMemory(0, 16384), second));
            Assert.Equal(1, fallback.Calls);
        }

        /// <summary>Refuses a block when the fallback declines or fails, without affecting other requests.</summary>
        /// <returns>Completion after the refused block reads.</returns>
        [Fact]
        public async Task DecliningOrFailingFallbackRefusesTheBlock()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var fallback = new PullThroughFallback { Mode = FallbackMode.Decline };
            await using var publisher = new MajDHTNode(SlowOptions(DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var replica = new MajDHTNode(SlowOptions(DHTCapabilities.Download | DHTCapabilities.Provide), contentFallback: fallback);
            await using var reader = new MajDHTNode(SlowOptions(DHTCapabilities.Download));
            fallback.Node = replica;
            await Task.WhenAll(publisher.StartAsync(token), replica.StartAsync(token), reader.StartAsync(token));
            await replica.JoinAsync(publisher.LocalPeer, token);
            await reader.JoinAsync(publisher.LocalPeer, token);
            using var source = new MemoryStream(Crypto.Random(500));
            var record = await publisher.PublishAsync("songs/refused", source, cancellationToken: token);
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, replica.LocalPeer, 0, cancellationToken: token));
            fallback.Mode = FallbackMode.Throw;
            await Assert.ThrowsAnyAsync<IOException>(() => reader.ReadBlockAsync(record, replica.LocalPeer, 0, cancellationToken: token));
            Assert.Equal(2, fallback.Calls);
        }

        /// <summary>Creates TCP loopback options whose request timeout leaves room for a nested pull-through download.</summary>
        /// <param name="capabilities">The advertised services.</param>
        /// <returns>Independent node options.</returns>
        private static DHTNodeOptions SlowOptions(DHTCapabilities capabilities)
        {
            var options = Options(DHTTransport.Tcp, capabilities);
            options.RequestTimeout = TimeSpan.FromSeconds(5);
            return options;
        }

        /// <summary>Selects how the test fallback answers.</summary>
        private enum FallbackMode
        {
            /// <summary>Downloads the requested record from the DHT.</summary>
            Download,
            /// <summary>Declines every request.</summary>
            Decline,
            /// <summary>Throws an I/O failure.</summary>
            Throw
        }

        /// <summary>Downloads requested content from other providers, as a pull-through replica would.</summary>
        private sealed class PullThroughFallback : IDHTContentFallback
        {
            /// <summary>The number of fallback invocations.</summary>
            private int _calls;

            /// <summary>Gets or sets the node that downloads the requested content.</summary>
            internal MajDHTNode? Node { get; set; }

            /// <summary>Gets or sets how the fallback answers.</summary>
            internal FallbackMode Mode { get; set; }

            /// <summary>Gets the number of fallback invocations.</summary>
            internal int Calls => Volatile.Read(ref _calls);

            /// <summary>Downloads, declines or fails according to <see cref="Mode"/>.</summary>
            /// <param name="record">The requested signed manifest.</param>
            /// <param name="cancellationToken">The request lifetime.</param>
            /// <returns>Whether the content was downloaded.</returns>
            /// <exception cref="IOException">The fallback is configured to fail.</exception>
            public async ValueTask<bool> TryAcquireAsync(DHTRecord record, CancellationToken cancellationToken)
            {
                Interlocked.Increment(ref _calls);
                switch (Mode)
                {
                    case FallbackMode.Decline:
                        return false;
                    case FallbackMode.Throw:
                        throw new IOException("Simulated origin failure.");
                    default:
                        await Node!.DownloadAsync(record, Stream.Null, record.FileHash, cancellationToken);
                        return true;
                }
            }
        }
    }
}
