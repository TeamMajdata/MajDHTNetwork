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
    /// <summary>Proves that a node written only against the public protocol API interoperates with the reference node.</summary>
    public sealed class CustomNodeTests
    {
        /// <summary>A reference node bootstraps from a custom node, discovers it as provider and downloads its verified content.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task ReferenceNodeDownloadsContentServedByCustomNode()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var content = Crypto.Random(2500);
            await using var custom = new MinimalProtocolNode(IPAddress.Loopback, "custom/served", content);
            await using var downloader = new MajDHTNode(new DHTNodeOptions
            {
                UdpPort = null,
                Capabilities = DHTCapabilities.Download,
                RequestTimeout = TimeSpan.FromSeconds(2),
                BootstrapEndpoints = { custom.Endpoint }
            });
            await downloader.StartAsync(token);
            Assert.Equal(1, await downloader.BootstrapAsync(token));
            Assert.Contains(downloader.KnownPeers, peer => peer.NodeId == custom.Identity.NodeId);
            var providers = await downloader.FindProvidersAsync(custom.Record.FileHash, token);
            Assert.True(providers.Count == 1 && providers[0].NodeId == custom.Identity.NodeId, "The custom node must announce itself as provider.");
            var resolved = await downloader.ResolveAsync(custom.Record.Key, token);
            Assert.True(resolved != null && resolved.FileHash == custom.Record.FileHash, "The custom node must serve its record by key.");
            using var destination = new MemoryStream();
            await downloader.DownloadAsync(custom.Record.Key, destination, custom.Record.FileHash, token);
            Assert.True(BytesEqual(content, destination.ToArray()), "Blocks served by the custom node must verify and reassemble.");
            Assert.True(custom.Received(Operation.Hello) >= 1, "The reference node must learn the custom contact through Hello.");
            Assert.True(custom.Received(Operation.Block) >= custom.Record.BlockCount, "Every block must be fetched from the custom node.");
        }

        /// <summary>A custom node resolves and downloads from a reference node, then announces its own content to the reference index.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task CustomNodeQueriesDownloadsAndAnnouncesThroughReferenceNodes()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var published = Crypto.Random(3000);
            await using var provider = new MajDHTNode(new DHTNodeOptions
            {
                UdpPort = null,
                BlockSize = 1024,
                RequestTimeout = TimeSpan.FromSeconds(2)
            });
            await provider.StartAsync(token);
            using var source = new MemoryStream(published);
            var record = await provider.PublishAsync("reference/published", source, cancellationToken: token);
            var served = Crypto.Random(1500);
            await using var custom = new MinimalProtocolNode(IPAddress.Loopback, "custom/announced", served);
            var contact = await custom.HelloAsync(new IPEndPoint(IPAddress.Loopback, provider.LocalPeer.Endpoints[0].TcpPort), token);
            Assert.Equal(provider.NodeId, contact.NodeId);
            var found = await custom.FindAsync(contact, FindMode.Record, record.Key.ToString(), token);
            Assert.True(found.Record != null && found.Record.FileHash == record.FileHash, "The reference node must return its record.");
            Assert.Contains(found.Providers, peer => peer.NodeId == provider.NodeId);
            var downloaded = await custom.DownloadAsync(contact, record, token);
            Assert.True(BytesEqual(published, downloaded), "Blocks read through the public codecs must verify and reassemble.");
            await custom.StoreAsync(contact, custom.Record, token);
            await using var downloader = new MajDHTNode(new DHTNodeOptions
            {
                UdpPort = null,
                Capabilities = DHTCapabilities.Download,
                RequestTimeout = TimeSpan.FromSeconds(2),
                BootstrapEndpoints = { new IPEndPoint(IPAddress.Loopback, provider.LocalPeer.Endpoints[0].TcpPort) }
            });
            await downloader.StartAsync(token);
            await downloader.BootstrapAsync(token);
            using var destination = new MemoryStream();
            await downloader.DownloadAsync(custom.Record.Key, destination, custom.Record.FileHash, token);
            Assert.True(BytesEqual(served, destination.ToArray()), "A record announced by the custom node must resolve through the reference index.");
            Assert.True(custom.Received(Operation.Block) >= custom.Record.BlockCount, "Every block must be fetched from the custom node.");
        }
    }
}
