#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises malformed framing, capabilities, cancellation, provider failures and shutdown drainage.</summary>
    public sealed class LifecycleTests
    {
        /// <summary>Enforces start and publish state while preserving idempotent shutdown when logging fails.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task LifecycleAndCapabilityGatesSurviveLoggerProviderFailures()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var logs = new List<LogLevel>();
            var options = Options(DHTTransport.Tcp, DHTCapabilities.Download);
            options.Logger = new TestLogger(logs, throwOnWrite: true);
            await using var node = new MajDHTNode(options);
            Assert.ThrowsAny<InvalidOperationException>(() => node.LocalPeer);
            await node.StartAsync(token);
            var contact = node.LocalPeer;
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => node.StartAsync(token));
            using var source = new MemoryStream(new byte[1]);
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => node.PublishAsync("disabled", source, cancellationToken: token));
            await node.StopAsync();
            await node.StopAsync();
            Assert.ThrowsAny<InvalidOperationException>(() => node.LocalPeer);
            Assert.True(logs.Contains(LogLevel.Information), "Lifecycle logging must survive diagnostic callback exceptions.");
        }

        /// <summary>Closes an oversized TCP frame without leaving the node unavailable.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task OversizedTcpFramesAreRejectedBeforeAllocatingPayloads()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await node.StartAsync(token);
            var contact = node.LocalPeer;
            using (var badClient = new TcpClient())
            {
                await badClient.ConnectAsync(IPAddress.Loopback, contact.TcpPort(), token);
                await badClient.GetStream().WriteAsync(new byte[] { 255, 255, 255, 255 }, token);
                var buffer = new byte[1];
                Assert.True(await badClient.GetStream().ReadAsync(buffer, token) == 0, "Oversized TCP frame must be rejected without allocation.");
            }
            await using var observer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await observer.StartAsync(token);
            await observer.JoinAsync(contact, token);
        }

        /// <summary>Propagates cancellation from a request token before issuing a routing lookup.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task PreCancelledRoutingRequestsAreRejected()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await node.StartAsync(token);
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => node.FindNodesAsync(NodeHash(), cancelled.Token));
        }

        /// <summary>Stops an externally cancelled UDP node and drains its background socket work.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task LifetimeCancellationDrainsUdpListeners()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            using var lifetime = new CancellationTokenSource();
            await using var externallyCancelled = new MajDHTNode(Options(DHTTransport.Udp, DHTCapabilities.Download));
            await externallyCancelled.StartAsync(lifetime.Token);
            lifetime.Cancel();
            await externallyCancelled.StopAsync();
        }

        /// <summary>Enforces download capabilities and cancels active remote reads during node shutdown.</summary>
        /// <returns>Completion after the regression assertions and node cleanup.</returns>
        [Fact]
        public async Task StopCancelsOutstandingStorageBackedReads()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var observer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await observer.StartAsync(token);
            var store = new BlockingStore();
            await using var provider = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Provide), contentStore: store);
            await provider.StartAsync(token);
            using var content = new MemoryStream(new byte[32]);
            var record = await provider.PublishAsync("blocked", content, cancellationToken: token);
            using var forbiddenDownload = new MemoryStream();
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => provider.DownloadAsync(record, forbiddenDownload, cancellationToken: token));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => provider.DownloadAsync(record.Key, forbiddenDownload, cancellationToken: token));
            await Assert.ThrowsAnyAsync<InvalidOperationException>(() => provider.ReadBlockAsync(record, observer.LocalPeer, 0, cancellationToken: token));
            var read = observer.ReadBlockAsync(record, provider.LocalPeer, 0, cancellationToken: token);
            await store.Entered.Task.WaitAsync(token);
            await observer.StopAsync();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => read);
            await provider.StopAsync();
        }
    }
}
