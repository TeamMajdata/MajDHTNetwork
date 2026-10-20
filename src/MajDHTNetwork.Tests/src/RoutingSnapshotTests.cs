#nullable enable

using System;
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
    /// <summary>Checks exporting the routing table and restoring it on another node.</summary>
    public sealed class RoutingSnapshotTests
    {
        /// <summary>Restores every exported contact on a new node, which then participates without any bootstrap endpoint.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after the restored node resolved a publication through the restored contacts.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task ExportedRoutingTablesRestoreKnownPeers(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            await using var first = new MajDHTNode(Options(transport, DHTCapabilities.Download));
            await using var second = new MajDHTNode(Options(transport, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var exporter = new MajDHTNode(Options(transport, DHTCapabilities.Download));
            await Task.WhenAll(first.StartAsync(token), second.StartAsync(token), exporter.StartAsync(token));
            await exporter.JoinAsync(first.LocalPeer, token);
            await exporter.JoinAsync(second.LocalPeer, token);
            Assert.Contains(exporter.KnownPeers, peer => peer.NodeId == first.NodeId);
            Assert.Contains(exporter.KnownPeers, peer => peer.NodeId == second.NodeId);
            var snapshot = exporter.ExportRoutingTable();
            await using var restored = new MajDHTNode(Options(transport, DHTCapabilities.Download));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => restored.RestoreRoutingTableAsync(snapshot, token));
            await restored.StartAsync(token);
            Assert.Equal(2, await restored.RestoreRoutingTableAsync(snapshot, token));
            var known = restored.KnownPeers;
            Assert.Contains(known, peer => peer.NodeId == first.NodeId);
            Assert.Contains(known, peer => peer.NodeId == second.NodeId);
            // The restored contacts make the node a usable participant without any bootstrap endpoint.
            using var source = new MemoryStream(Crypto.Random(3000));
            var record = await second.PublishAsync("snapshot/content", source, cancellationToken: token);
            Assert.NotNull(await restored.ResolveAsync(record.Key, token));
            // An unstarted node exports an empty table, which restores nothing and changes nothing.
            await using var unstarted = new MajDHTNode(Options(transport, DHTCapabilities.Download));
            Assert.Equal(0, await restored.RestoreRoutingTableAsync(unstarted.ExportRoutingTable(), token));
            Assert.Contains(restored.KnownPeers, peer => peer.NodeId == first.NodeId);
            Assert.Contains(restored.KnownPeers, peer => peer.NodeId == second.NodeId);
        }

        /// <summary>Skips saved contacts that no longer answer or whose endpoint now answers under another identity.</summary>
        /// <returns>Completion after only the reachable contact was restored.</returns>
        [Fact]
        public async Task UnreachableAndReidentifiedContactsAreSkipped()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            await using var reachable = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var reidentified = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await using var restorer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(reachable.StartAsync(token), reidentified.StartAsync(token), restorer.StartAsync(token));
            using var closed = new TcpListener(IPAddress.Loopback, 0);
            closed.Start();
            var closedPort = ((IPEndPoint)closed.LocalEndpoint).Port;
            closed.Stop();
            var snapshot = Snapshot(
                (reachable.NodeId, reachable.LocalPeer.Endpoints[0]),
                (NodeHash(), reidentified.LocalPeer.Endpoints[0]),
                (NodeHash(), new DHTEndpoint(IPAddress.Loopback, closedPort, 0, DHTEndpointFlags.None)));
            Assert.Equal(1, await restorer.RestoreRoutingTableAsync(snapshot, token));
            var known = restorer.KnownPeers;
            Assert.Contains(known, peer => peer.NodeId == reachable.NodeId);
            Assert.DoesNotContain(known, peer => peer.NodeId == reidentified.NodeId);
        }

        /// <summary>Rejects snapshots with a wrong label, truncation, trailing bytes, repeated or invalid identifiers.</summary>
        /// <returns>Completion after every malformed snapshot was rejected.</returns>
        [Fact]
        public async Task MalformedSnapshotsAreRejected()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await node.StartAsync(token);
            var endpoint = new DHTEndpoint(IPAddress.Loopback, 1, 0, DHTEndpointFlags.None);
            var nodeId = NodeHash();
            var valid = Snapshot((nodeId, endpoint));
            var trailing = new byte[valid.Length + 1];
            valid.CopyTo(trailing, 0);
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => node.RestoreRoutingTableAsync(Crypto.Random(40), token));
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => node.RestoreRoutingTableAsync(valid.AsMemory(0, valid.Length - 1), token));
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => node.RestoreRoutingTableAsync(trailing, token));
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => node.RestoreRoutingTableAsync(Snapshot((nodeId, endpoint), (nodeId, endpoint)), token));
            await Assert.ThrowsAnyAsync<InvalidDataException>(() => node.RestoreRoutingTableAsync(Snapshot(("not-a-node-identifier", endpoint)), token));
            Assert.Empty(node.KnownPeers);
        }

        /// <summary>Encodes a routing snapshot with one endpoint per contact.</summary>
        /// <param name="contacts">The saved identities and their single endpoint.</param>
        /// <returns>The encoded snapshot.</returns>
        private static byte[] Snapshot(params (string NodeId, DHTEndpoint Endpoint)[] contacts)
        {
            using var writer = new Wire();
            writer.Put(ProtocolTags.RoutingSnapshot);
            writer.PutLong(contacts.Length);
            foreach (var (nodeId, endpoint) in contacts)
            {
                writer.PutText(nodeId);
                writer.PutLong(1);
                DHTPeer.WriteEndpoint(writer, endpoint);
            }
            return writer.ToArray();
        }
    }
}
