#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises endpoint-based bootstrap through Hello exchanges and dual-stack listeners.</summary>
    public sealed class BootstrapTests
    {
        /// <summary>Joins automatically after startup through a configured endpoint.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after the background bootstrap discovered the endpoint's node.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ConfiguredEndpointsJoinInTheBackground(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var bootstrap = new MajDHTNode(Options(transport, DHTCapabilities.Download));
            await bootstrap.StartAsync(token);
            var port = transport == DHTTransport.Tcp ? bootstrap.LocalPeer.TcpPort() : bootstrap.LocalPeer.UdpPort();
            var options = Options(transport, DHTCapabilities.Download);
            options.BootstrapEndpoints = new List<IPEndPoint> { new IPEndPoint(IPAddress.Loopback, port) };
            await using var node = new MajDHTNode(options);
            await node.StartAsync(token);
            while (!ContainsNode(node.KnownPeers, bootstrap.NodeId) || !ContainsNode(bootstrap.KnownPeers, node.NodeId))
            {
                await Task.Delay(50, token);
            }
        }

        /// <summary>Reports missing and unreachable bootstrap endpoints.</summary>
        /// <returns>Completion after both failures are observed.</returns>
        [Fact]
        public async Task BootstrapFailuresAreReported()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var isolated = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await isolated.StartAsync(token);
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => isolated.BootstrapAsync(token));
            using var closed = new TcpListener(IPAddress.Loopback, 0);
            closed.Start();
            var closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
            closed.Stop();
            var options = Options(DHTTransport.Tcp, DHTCapabilities.Download);
            options.BootstrapEndpoints = new List<IPEndPoint> { new IPEndPoint(IPAddress.Loopback, closedPort) };
            await using var unreachable = new MajDHTNode(options);
            await unreachable.StartAsync(token);
            await Assert.ThrowsAnyAsync<IOException>(() => unreachable.BootstrapAsync(token));
        }

        /// <summary>Adds nodes by address and port, trying the requested transport first and falling back to the other one.</summary>
        /// <param name="transport">The transport requested first, which is not the adding node's preferred transport.</param>
        /// <returns>Completion after both added nodes entered the routing table.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ManuallyAddedPeersUseTheRequestedTransportFirst(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var other = transport == DHTTransport.Tcp ? DHTTransport.Udp : DHTTransport.Tcp;
            // Both nodes listen on both transports at independently assigned ports; the adding node prefers the other transport.
            var targetOptions = Options(transport, DHTCapabilities.Download);
            targetOptions.TcpPort = 0;
            targetOptions.UdpPort = 0;
            var nodeOptions = Options(other, DHTCapabilities.Download);
            nodeOptions.TcpPort = 0;
            nodeOptions.UdpPort = 0;
            await using var target = new MajDHTNode(targetOptions);
            await using var tcpOnly = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var node = new MajDHTNode(nodeOptions);
            await Task.WhenAll(target.StartAsync(token), tcpOnly.StartAsync(token), node.StartAsync(token));
            var endpoint = new IPEndPoint(IPAddress.Loopback, transport == DHTTransport.Tcp ? target.LocalPeer.TcpPort() : target.LocalPeer.UdpPort());
            var added = await node.AddPeerAsync(endpoint, transport, token);
            Assert.Equal(target.NodeId, added.NodeId);
            Assert.True(ContainsNode(node.KnownPeers, target.NodeId), "An added node must enter the routing table.");
            var statistics = node.GetPeerStatistics(target.NodeId);
            Assert.NotNull(statistics);
            Assert.NotNull(statistics!.GetRoute(endpoint, transport));
            Assert.Null(statistics.GetRoute(endpoint, other));
            // A node without the requested transport is still added through the other transport at the same port.
            var fallback = new IPEndPoint(IPAddress.Loopback, tcpOnly.LocalPeer.TcpPort());
            Assert.Equal(tcpOnly.NodeId, (await node.AddPeerAsync(fallback, DHTTransport.Udp, token)).NodeId);
            Assert.True(ContainsNode(node.KnownPeers, tcpOnly.NodeId), "The fallback transport must admit the node.");
            Assert.NotNull(node.GetPeerStatistics(tcpOnly.NodeId)!.GetRoute(fallback, DHTTransport.Tcp));
        }

        /// <summary>Rejects invalid endpoints and transports, unstarted nodes and endpoints that do not answer.</summary>
        /// <returns>Completion after every rejection.</returns>
        [Fact]
        public async Task ManualPeerAdditionReportsInvalidAndUnreachableEndpoints()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            using var closed = new TcpListener(IPAddress.Loopback, 0);
            closed.Start();
            var closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
            closed.Stop();
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => node.AddPeerAsync(new IPEndPoint(IPAddress.Loopback, closedPort), null, token));
            await node.StartAsync(token);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => node.AddPeerAsync(null!, null, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => node.AddPeerAsync(new IPEndPoint(IPAddress.Loopback, 0), null, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => node.AddPeerAsync(new IPEndPoint(IPAddress.Parse("224.0.0.1"), closedPort), null, token));
            await Assert.ThrowsAnyAsync<ArgumentException>(() => node.AddPeerAsync(new IPEndPoint(IPAddress.Loopback, closedPort), (DHTTransport)7, token));
            await Assert.ThrowsAnyAsync<IOException>(() => node.AddPeerAsync(new IPEndPoint(IPAddress.Loopback, closedPort), DHTTransport.Tcp, token));
            Assert.Empty(node.KnownPeers);
        }

        /// <summary>Serves IPv4-only and IPv6-only clients from one dual-stack node.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after both clients downloaded the verified file.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task DualStackListenersServeBothAddressFamilies(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            Assert.SkipUnless(Socket.OSSupportsIPv6, "The host does not support IPv6 sockets.");
            var serverOptions = Options(transport, DHTCapabilities.Download | DHTCapabilities.Provide);
            serverOptions.ListenAddresses = new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback };
            await using var server = new MajDHTNode(serverOptions);
            await server.StartAsync(token);
            var endpoints = server.LocalPeer.Endpoints;
            Assert.Equal(2, endpoints.Count);
            Assert.Equal(AddressFamily.InterNetwork, endpoints[0].Address.AddressFamily);
            Assert.Equal(AddressFamily.InterNetworkV6, endpoints[1].Address.AddressFamily);
            var content = Crypto.Random(20000);
            using var source = new MemoryStream(content);
            var record = await server.PublishAsync("dual-stack", source, cancellationToken: token);
            foreach (var endpoint in endpoints)
            {
                var clientOptions = Options(transport, DHTCapabilities.Download);
                clientOptions.ListenAddresses = new List<IPAddress> { endpoint.Address };
                var port = transport == DHTTransport.Tcp ? endpoint.TcpPort : endpoint.UdpPort;
                clientOptions.BootstrapEndpoints = new List<IPEndPoint> { new IPEndPoint(endpoint.Address, port) };
                await using var client = new MajDHTNode(clientOptions);
                await client.StartAsync(token);
                Assert.Equal(1, await client.BootstrapAsync(token));
                using var destination = new MemoryStream();
                await client.DownloadAsync(record.Key, destination, record.FileHash, token);
                Assert.True(BytesEqual(content, destination.ToArray()), "Each address family must deliver the verified file.");
            }
        }

        /// <summary>Checks whether a contact list contains a node.</summary>
        /// <param name="peers">The contacts.</param>
        /// <param name="nodeId">The node identifier.</param>
        /// <returns>Whether the node is present.</returns>
        private static bool ContainsNode(IReadOnlyList<DHTPeer> peers, string nodeId)
        {
            foreach (var peer in peers)
            {
                if (peer.NodeId == nodeId)
                {
                    return true;
                }
            }
            return false;
        }
    }
}
