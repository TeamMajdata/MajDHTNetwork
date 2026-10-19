#nullable enable

using System;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises revision floors, expiring record quotas, signed contact renewal and alias retention.</summary>
    public sealed class LeaseTests
    {
        /// <summary>Rejects an older valid signature after the newer signed record lease has expired.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task ExpiredNewerRevisionsKeepTheirRollbackFloor()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var identity = new DHTIdentity();
            var publisher = DHTPeer.Create(identity, IPAddress.Loopback, 1, 0, DHTCapabilities.Provide);
            await using var replica = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await replica.StartAsync(token);
            var content = new byte[] { 1 };
            var hash = Crypto.Hex(Crypto.Hash(content));
            var root = Crypto.Hex(MerkleTree.Leaf(content));
            var old = DHTRecord.Create(identity, "rollback-lease", hash, root, 1, 1024, 1, DateTimeOffset.UtcNow.AddHours(1));
            var current = DHTRecord.Create(identity, "rollback-lease", hash, root, 1, 1024, 2, DateTimeOffset.UtcNow.AddSeconds(2));
            await using var raw = new SocketTransport(Options(DHTTransport.Tcp, DHTCapabilities.Download).Snapshot(), (bytes, ct) => Task.FromResult(bytes), NullLogger.Instance);
            foreach (var record in new[] { old, current })
            {
                using var body = new Wire();
                body.Put(record.ToBytes());
                var packet = new Packet(publisher, Crypto.Random(16), (byte)Operation.Store, body.ToArray()).Seal(identity, replica.LocalPeer);
                var response = Packet.Open(identity, await raw.ExchangeAsync(replica.LocalPeer, packet, token));
                using var decoded = new Wire(response.Body);
                Assert.True(decoded.Byte() == 0, "Replica must accept an advancing signed revision.");
            }
            await Task.Delay(TimeSpan.FromSeconds(2.2), token);
            using var replayBody = new Wire();
            replayBody.Put(old.ToBytes());
            var replay = new Packet(publisher, Crypto.Random(16), (byte)Operation.Store, replayBody.ToArray()).Seal(identity, replica.LocalPeer);
            var rejected = Packet.Open(identity, await raw.ExchangeAsync(replica.LocalPeer, replay, token));
            using var result = new Wire(rejected.Body);
            Assert.True(result.Byte() == 1, "An expired newer lease must retain its revision floor against old-record replay.");
            Assert.True(await replica.ResolveAsync(old.Key, token) == null, "An expired newest record must not expose a superseded signed binding.");
        }

        /// <summary>Reclaims expired metadata, enforces file and record limits and renews signed contacts.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task ExpiryReclaimsQuotasAndMaintenanceRenewsContacts()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var options = new DHTNodeOptions
            {
                UdpPort = null,
                MaxFileSize = 1024,
                MaxRecords = 1,
                RecordLifetime = TimeSpan.FromSeconds(2),
                MaintenanceInterval = TimeSpan.FromSeconds(1)
            };
            await using var node = new MajDHTNode(options);
            await node.StartAsync(token);
            var oldContact = node.LocalPeer;
            using var source = new MemoryStream(new byte[32]);
            var record = await node.PublishAsync("quota", source, cancellationToken: token);
            await Assert.ThrowsAnyAsync<IOException>(() => node.PublishAliasAsync("overflow", record, cancellationToken: token));
            using var oversized = new MemoryStream(new byte[1025]);
            await Assert.ThrowsAnyAsync<ArgumentException>(() => node.PublishAsync("too-large", oversized, cancellationToken: token));
            await Task.Delay(TimeSpan.FromSeconds(2.2), token);
            Assert.True(node.LocalPeer.ExpiresAt > oldContact.ExpiresAt, "Maintenance must refresh the signed contact lease.");
            Assert.True(await node.ResolveAsync(record.Key, token) == null, "Expired records must not resolve.");
            using var fresh = new MemoryStream(new byte[1]);
            var replacement = await node.PublishAsync("after-expiry", fresh, cancellationToken: token);
            Assert.True(replacement.Key.Name == "after-expiry", "Expired records must release the record quota.");
        }

        /// <summary>Preserves the raw blocks and Merkle metadata when a signed alias is renewed after expiry.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task AliasRenewalDuringExpiryCleanupRetainsMerkleData()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var renewable = new MajDHTNode(new DHTNodeOptions
            {
                RecordLifetime = TimeSpan.FromSeconds(1),
                MaintenanceInterval = TimeSpan.FromHours(1)
            });
            await renewable.StartAsync(token);
            using var initial = new MemoryStream(new byte[] { 8, 6, 4 });
            var previous = await renewable.PublishAsync("renewable", initial, cancellationToken: token);
            await Task.Delay(TimeSpan.FromSeconds(1.2), token);
            var renewed = await renewable.PublishAliasAsync("renewable", previous, 2, token);
            Assert.True(BytesEqual(await renewable.ReadBlockAsync(renewed, renewable.LocalPeer, 0, cancellationToken: token), new byte[] { 8, 6, 4 }),
                "Renewal during expiry cleanup must retain the Merkle tree and raw blocks.");
        }
    }
}
