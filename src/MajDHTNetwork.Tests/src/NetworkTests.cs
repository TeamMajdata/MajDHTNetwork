#nullable enable

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises real TCP-only and UDP-only discovery, aliases, verified transfers and opaque relays.</summary>
    public sealed class NetworkTests
    {
        /// <summary>Discovers the genuine provider and preserves exact multi-block content through an alias.</summary>
        /// <param name="transport">The only transport enabled on all three nodes.</param>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task IndirectDiscoveryDownloadsAliasesAndPinsContentHashes(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var network = await ThreeNodeNetwork.CreateAsync(transport, token);
            var bootstrap = network.Bootstrap;
            var provider = network.Provider;
            var downloader = network.Downloader;
            var providerIdentity = network.ProviderIdentity;
            var input = network.Input;
            var record = network.Record;
            var alias = network.Alias;
            Assert.True(record.FileHash == alias.FileHash && !record.Key.Equals(alias.Key), "Several keys must share one content hash.");
            Assert.True(downloader.KnownPeers.Count >= 2, "A bootstrap must introduce other nodes.");
            var found = await downloader.ResolveAsync(alias.Key, token);
            Assert.True(found != null && found.FileHash == record.FileHash, "An indirect join must resolve a replicated alias.");
            var providers = await downloader.FindProvidersAsync(record.FileHash, token);
            Assert.True(providers.Count == 1 && providers[0].NodeId == provider.NodeId, "The relay must not claim content it does not hold.");
            using var destination = new MemoryStream();
            await downloader.DownloadAsync(alias.Key, destination, record.FileHash, token);
            Assert.True(BytesEqual(input, destination.ToArray()), "Multi-block network download must match exact file bytes.");
            using var wrongHashDestination = new MemoryStream();
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => downloader.DownloadAsync(record, wrongHashDestination, new string('0', 64), token));
            Assert.True(wrongHashDestination.Length == 0, "Trusted hash mismatch must fail before writing content.");
            Assert.True((await downloader.FindNodesAsync(Crypto.Hex(Crypto.Random(32)), token)).Count >= 1, "XOR lookup must return reachable contacts.");
        }

        /// <summary>Reads through an explicit relay and recovers an unreachable direct contact through the relay.</summary>
        /// <param name="transport">The only transport enabled on all three nodes.</param>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ExplicitAndAutomaticRelaysAuthenticateBlocks(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var network = await ThreeNodeNetwork.CreateAsync(transport, token);
            var bootstrap = network.Bootstrap;
            var provider = network.Provider;
            var downloader = network.Downloader;
            var providerIdentity = network.ProviderIdentity;
            var input = network.Input;
            var record = network.Record;
            var alias = network.Alias;
            var providers = await downloader.FindProvidersAsync(record.FileHash, token);
            Assert.True(providers.Count == 1 && providers[0].NodeId == provider.NodeId, "The relay must not claim content it does not hold.");
            var relayed = await downloader.ReadBlockAsync(record, provider.LocalPeer, 1, bootstrap.LocalPeer, token);
            Assert.True(BytesEqual(relayed, input.AsSpan(16384, 16384).ToArray()), "Explicit relay must preserve end-to-end authenticated blocks.");
            var unreachable = DHTPeer.Create(providerIdentity, IPAddress.Loopback, 1, 0, DHTCapabilities.Provide);
            var recovered = await downloader.ReadBlockAsync(record, unreachable, 0, cancellationToken: token);
            Assert.True(BytesEqual(recovered, input.AsSpan(0, 16384).ToArray()), "Automatic relay must recover a failed direct path.");
        }

        /// <summary>Rejects rollback announcements and conflicting revisions after a newer signed binding is observed.</summary>
        /// <param name="transport">The only transport enabled on all three nodes.</param>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task NewerSignedRevisionsRejectOldAnnouncements(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var network = await ThreeNodeNetwork.CreateAsync(transport, token);
            var bootstrap = network.Bootstrap;
            var provider = network.Provider;
            var downloader = network.Downloader;
            var providerIdentity = network.ProviderIdentity;
            var input = network.Input;
            var record = network.Record;
            var alias = network.Alias;
            using var updateSource = new MemoryStream(Encoding.UTF8.GetBytes("new content revision"));
            var updated = await provider.PublishAsync("songs/test", updateSource, 2, token);
            Assert.True((await downloader.ResolveAsync(record.Key, token))!.Revision == 2, "A higher signed revision must win.");
            using var announcement = new Wire();
            announcement.Put(record.ToBytes());
            var replay = new Packet(provider.LocalPeer, Crypto.Random(16), (byte)Operation.Store, announcement.ToArray()).Seal(providerIdentity, bootstrap.LocalPeer);
            await using (var raw = new SocketTransport(Options(transport, DHTCapabilities.Download).Snapshot(), (bytes, ct) => Task.FromResult(bytes), NullLogger.Instance))
            {
                await raw.ExchangeAsync(bootstrap.LocalPeer, replay, token);
            }
            Assert.True((await bootstrap.ResolveAsync(updated.Key, token))!.Revision == 2, "An old signed binding must not roll back an observed higher revision.");
            await Assert.ThrowsAnyAsync<ArgumentException>(() => provider.PublishAliasAsync("songs/test", updated, 2, token));
        }

        /// <summary>Rejects authenticated corrupt content and recovers by retrying a healthy provider.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task CorruptProvidersAreRejectedAndHealthyProvidersAreRetried()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var honest = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Provide));
            await using var client = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(honest.StartAsync(token), client.StartAsync(token));
            await client.BootstrapAsync(honest.LocalPeer, token);
            var input = Crypto.Random(40000);
            using var source = new MemoryStream(input);
            var record = await honest.PublishAsync("corruption", source, cancellationToken: token);
            var identity = new DHTIdentity();
            DHTPeer? maliciousPeer = null;
            var corruptBlocks = 0;
            var handler = new Func<ReadOnlyMemory<byte>, CancellationToken, Task<ReadOnlyMemory<byte>>>((encoded, cancellation) =>
            {
                var packet = Packet.Open(identity, encoded);
                using var operation = new Wire();
                if (packet.Kind == (byte)Operation.Find)
                {
                    operation.Put(Array.Empty<byte>());
                    operation.PutLong(0);
                    operation.PutLong(0);
                }
                else if (packet.Kind == (byte)Operation.Block)
                {
                    Interlocked.Increment(ref corruptBlocks);
                    using var request = new Wire(packet.Body);
                    var manifest = DHTRecord.Parse(request.Bytes(2200).Span);
                    var index = (int)request.Long();
                    var length = (int)Math.Min(manifest.BlockSize, manifest.Length - ((long)index * manifest.BlockSize));
                    operation.Put(new byte[length]);
                    operation.PutLong(0);
                }
                using var body = new Wire();
                body.PutByte(0);
                body.Put(operation.ToArray());
                return Task.FromResult<ReadOnlyMemory<byte>>(new Packet(maliciousPeer!, packet.RequestId, (byte)(packet.Kind | 128), body.ToArray()).Seal(identity, packet.Sender));
            });
            await using var malicious = new SocketTransport(Options(DHTTransport.Tcp, DHTCapabilities.Provide).Snapshot(), handler, NullLogger.Instance);
            malicious.Bind();
            maliciousPeer = DHTPeer.Create(identity, IPAddress.Loopback, malicious.TcpPort, 0, DHTCapabilities.Provide);
            malicious.Run();
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => client.ReadBlockAsync(record, maliciousPeer, 0, cancellationToken: token));
            using var announcement = new Wire();
            announcement.Put(record.ToBytes());
            var announce = new Packet(maliciousPeer, Crypto.Random(16), (byte)Operation.Store, announcement.ToArray()).Seal(identity, honest.LocalPeer);
            await malicious.ExchangeAsync(honest.LocalPeer, announce, token);
            Assert.True((await client.FindProvidersAsync(record.FileHash, token)).Count == 2, "Provider lookup must support independent seeders for one hash.");
            using var destination = new MemoryStream();
            await client.DownloadAsync(record, destination, record.FileHash, token);
            Assert.True(BytesEqual(input, destination.ToArray()) && corruptBlocks >= 2, "Download must reject corrupt blocks and retry the healthy provider.");
        }
    }
}
