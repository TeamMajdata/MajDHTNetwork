#nullable enable

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises real transport fallback, option snapshots, IPv6 and UDP replay-cache retransmission.</summary>
    public sealed class TransportTests
    {
        /// <summary>Keeps both listeners available and prevents download-only maintenance from advertising cached files.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task DualListenersSnapshotOptionsAndFallBackFromTcpToUdp()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            var options = new DHTNodeOptions { RequestTimeout = TimeSpan.FromMilliseconds(350), UdpAttempts = 2 };
            await using var server = new MajDHTNode(options, identity);
            options.TcpPort = null;
            options.UdpPort = null;
            options.Capabilities = DHTCapabilities.Download;
            await server.StartAsync(token);
            Assert.True(server.LocalPeer.TcpPort != 0 && server.LocalPeer.UdpPort != 0, "The node must snapshot options and bind both listeners.");
            await using var client = new MajDHTNode(new DHTNodeOptions
            {
                RequestTimeout = TimeSpan.FromMilliseconds(350),
                Capabilities = DHTCapabilities.Download,
                MaintenanceInterval = TimeSpan.FromSeconds(1)
            });
            await client.StartAsync(token);
            var fallback = DHTPeer.Create(identity, IPAddress.Loopback, 1, server.LocalPeer.UdpPort, DHTCapabilities.Provide);
            await client.BootstrapAsync(fallback, token);
            Assert.True(client.KnownPeers.Count == 1, "UDP must recover a failed TCP connection.");
            using var source = new MemoryStream(Encoding.UTF8.GetBytes("dual transport"));
            var record = await server.PublishAsync("dual", source, cancellationToken: token);
            using var destination = new MemoryStream();
            await client.DownloadAsync(record.Key, destination, record.FileHash, token);
            Assert.True(destination.Length == record.Length, "Direct TCP must remain available after UDP fallback.");
            await Task.Delay(TimeSpan.FromSeconds(1.1), token);
            var providers = await client.FindProvidersAsync(record.FileHash, token);
            Assert.True(providers.Count == 1 && providers[0].NodeId == server.NodeId,
                "A download-only node must not advertise cached content during maintenance.");
        }

        /// <summary>Transfers a published file over IPv6 loopback when the host supports IPv6 sockets.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task Ipv6DiscoveryAndVerifiedTransferPreserveTheFile()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            Assert.SkipUnless(Socket.OSSupportsIPv6, "The host does not support IPv6 sockets.");
            var options = new DHTNodeOptions { ListenAddress = IPAddress.IPv6Loopback, UdpPort = null };
            await using var provider = new MajDHTNode(options);
            await using var client = new MajDHTNode(options);
            await Task.WhenAll(provider.StartAsync(token), client.StartAsync(token));
            await client.BootstrapAsync(provider.LocalPeer, token);
            using var source = new MemoryStream(Crypto.Random(2049));
            var record = await provider.PublishAsync("ipv6", source, cancellationToken: token);
            using var destination = new MemoryStream();
            await client.DownloadAsync(record, destination, record.FileHash, token);
            Assert.True(destination.Length == source.Length, "IPv6 file download must preserve its length and whole-file hash.");
        }

        /// <summary>Retransmits through a real lossy UDP proxy and receives byte-identical cached encrypted replies.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task LostUdpResponsesReuseIdenticalReplayCachedCiphertext()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            await using var server = new MajDHTNode(Options(DHTTransport.Udp, DHTCapabilities.Download), identity);
            await server.StartAsync(token);
            await using var proxy = new LossyUdpProxy(new IPEndPoint(server.LocalPeer.Address, server.LocalPeer.UdpPort));
            var options = Options(DHTTransport.Udp, DHTCapabilities.Download);
            await using var client = new MajDHTNode(options);
            await client.StartAsync(token);
            var invitation = DHTPeer.Create(identity, IPAddress.Loopback, 0, proxy.Port, DHTCapabilities.Download);
            await client.BootstrapAsync(invitation, token);
            Assert.True(proxy.Responses >= 2 && proxy.DuplicateReplyMatched, "UDP retry must receive the same cached ciphertext after response loss.");
        }
    }
}
