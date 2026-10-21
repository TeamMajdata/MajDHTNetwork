#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// Exercises the keepalive of punched TCP and UDP routes: idle routes are pinged once per interval and busy ones are not,
    /// routes that stop answering are dropped, and keepalives hold a route open through NATs whose flows expire without
    /// outbound traffic, which an idle route does not survive without them.
    /// </summary>
    [Trait("Category", "NAT")]
    public sealed class DirectRouteKeepAliveTests
    {
        /// <summary>The keepalive interval of the fast scenarios.</summary>
        private static readonly TimeSpan s_keepAlive = TimeSpan.FromMilliseconds(300);
        /// <summary>The idle time after which a simulated NAT flow stops admitting inbound datagrams.</summary>
        private static readonly TimeSpan s_flowTimeout = TimeSpan.FromSeconds(1);

        /// <summary>Pings an idle punched route from both ends about once per interval, after which the route still carries data.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after the counted keepalives and a verified block read.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task IdlePunchedRoutesArePingedOncePerInterval(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var pair = await PunchedPair.StartAsync(transport, token);
            var leftBefore = SentOver(pair.Left, pair.Right.NodeId, transport);
            var rightBefore = SentOver(pair.Right, pair.Left.NodeId, transport);
            await Task.Delay(TimeSpan.FromMilliseconds(1500), token);
            var leftPings = SentOver(pair.Left, pair.Right.NodeId, transport) - leftBefore;
            var rightPings = SentOver(pair.Right, pair.Left.NodeId, transport) - rightBefore;
            // Five intervals of idleness: each end pings once per interval, never far more often.
            Assert.InRange(leftPings, 3, 8);
            Assert.InRange(rightPings, 3, 8);
            var block = await pair.Left.ReadBlockAsync(pair.RightRecord, pair.HiddenRight, 0, cancellationToken: token);
            Assert.True(block.Span.SequenceEqual(pair.RightBytes.AsSpan(0, block.Length)), "The kept route must still carry verified blocks.");
        }

        /// <summary>Sends no keepalive over a route that carries requests more often than the interval.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after the busy period's transmissions were compared with its requests.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task BusyPunchedRoutesAreNotPinged(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var pair = await PunchedPair.StartAsync(transport, token);
            await pair.Left.ReadBlockAsync(pair.RightRecord, pair.HiddenRight, 0, cancellationToken: token);
            var before = SentOver(pair.Left, pair.Right.NodeId, transport);
            var reads = 0;
            var watch = Stopwatch.StartNew();
            while (watch.Elapsed < TimeSpan.FromMilliseconds(1500))
            {
                await pair.Left.ReadBlockAsync(pair.RightRecord, pair.HiddenRight, 0, cancellationToken: token);
                reads++;
                await Task.Delay(TimeSpan.FromMilliseconds(50), token);
            }
            var transmissions = SentOver(pair.Left, pair.Right.NodeId, transport) - before;
            Assert.True(transmissions <= reads + 1, "A busy route needs no keepalive: " + transmissions + " transmissions for " + reads + " reads.");
        }

        /// <summary>Drops a punched route after its peer stopped answering two keepalives in a row.</summary>
        /// <param name="transport">The only transport enabled on every node.</param>
        /// <returns>Completion after the route disappeared.</returns>
        [Theory]
        [InlineData(DHTTransport.Tcp)]
        [InlineData(DHTTransport.Udp)]
        public async Task PunchedRoutesThatStopAnsweringKeepalivesAreDropped(DHTTransport transport)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var pair = await PunchedPair.StartAsync(transport, token);
            Assert.True(pair.Left.HasDirectRoute(pair.Right.NodeId, transport));
            await pair.Right.StopAsync();
            var watch = Stopwatch.StartNew();
            await WaitUntilAsync(() => !pair.Left.HasDirectRoute(pair.Right.NodeId, transport), token);
            // Two failed UDP keepalives take two attempts of 700 milliseconds each, plus the ticks between them.
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(10), "A dead route must be dropped within a few keepalives: " + watch.Elapsed);
        }

        /// <summary>Keeps an idle punched UDP route open through two NATs whose flows expire after one second without outbound traffic.</summary>
        /// <returns>Completion after verified block reads in both directions over the kept route.</returns>
        [Fact]
        public async Task KeepalivesHoldIdleUdpRoutesOpenThroughExpiringNatFlows()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var scenario = await NatScenario.StartAsync(s_keepAlive, token);
            await Task.Delay(s_flowTimeout * 3, token);
            var fromRight = await scenario.Left.ReadBlockAsync(scenario.RightRecord, scenario.HiddenRight, 0, cancellationToken: token);
            var fromLeft = await scenario.Right.ReadBlockAsync(scenario.LeftRecord, scenario.HiddenLeft, 0, cancellationToken: token);
            Assert.True(fromRight.Span.SequenceEqual(scenario.RightBytes.AsSpan(0, fromRight.Length)), "The requester must read over the kept route.");
            Assert.True(fromLeft.Span.SequenceEqual(scenario.LeftBytes.AsSpan(0, fromLeft.Length)), "The target must read over the kept route.");
        }

        /// <summary>
        /// Loses an idle punched UDP route when the keepalive interval exceeds the NAT flow timeout, which shows that the
        /// simulated NATs expire flows and that the keepalive is what keeps the route open.
        /// </summary>
        /// <returns>Completion after the failed read and the NAT's filtered datagrams were checked.</returns>
        [Fact]
        public async Task IdleUdpRoutesCloseWhenNatFlowsExpireBeforeTheNextKeepalive()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            await using var scenario = await NatScenario.StartAsync(TimeSpan.FromSeconds(25), token);
            await Task.Delay(s_flowTimeout * 3, token);
            var filtered = scenario.RightNat.FilteredDatagrams;
            // A live route answers within milliseconds; the window only bounds the assisted fallback that follows its failure.
            using var window = CancellationTokenSource.CreateLinkedTokenSource(token);
            window.CancelAfter(TimeSpan.FromSeconds(3));
            var failure = await Record.ExceptionAsync(() => scenario.Left.ReadBlockAsync(scenario.RightRecord, scenario.HiddenRight, 0,
                cancellationToken: window.Token));
            Assert.True(failure is IOException || failure is SocketException || failure is TimeoutException || failure is OperationCanceledException,
                "An idle route whose NAT flows expired must not carry the request.");
            Assert.True(scenario.RightNat.FilteredDatagrams > filtered, "The target's NAT must have dropped the request at the expired flow.");
        }

        /// <summary>Adds up the transmissions a node counted towards a peer over one transport.</summary>
        /// <param name="node">The counting node.</param>
        /// <param name="nodeId">The peer.</param>
        /// <param name="transport">The transport.</param>
        /// <returns>The transmissions on every route of that transport.</returns>
        private static long SentOver(MajDHTNode node, string nodeId, DHTTransport transport)
        {
            var sent = 0L;
            var statistics = node.GetPeerStatistics(nodeId);
            if (statistics == null)
            {
                return 0;
            }
            foreach (var route in statistics.Routes)
            {
                if (route.Transport == transport)
                {
                    sent += route.SentPackets;
                }
            }
            return sent;
        }

        /// <summary>Polls a condition until it holds or the deadline passes.</summary>
        /// <param name="condition">The condition.</param>
        /// <param name="token">The test deadline.</param>
        /// <returns>Completion once the condition holds.</returns>
        private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken token)
        {
            while (!condition())
            {
                await Task.Delay(25, token);
            }
        }

        /// <summary>Creates single-transport options bound to one loopback host with fast NAT timings.</summary>
        /// <param name="address">The loopback address of the node.</param>
        /// <param name="transport">The only transport to bind.</param>
        /// <param name="capabilities">The advertised services.</param>
        /// <param name="keepAlive">The keepalive interval of punched routes.</param>
        /// <returns>Independent options.</returns>
        private static DHTNodeOptions Options(string address, DHTTransport transport, DHTCapabilities capabilities, TimeSpan keepAlive)
        {
            return new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { IPAddress.Parse(address) },
                TcpPort = transport == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = transport == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = transport,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(700),
                UdpAttempts = 2,
                NatTraversalTimeout = TimeSpan.FromSeconds(3),
                NatPollInterval = TimeSpan.FromMilliseconds(75),
                NatRegistrationLifetime = TimeSpan.FromSeconds(3),
                NatKeepAliveInterval = keepAlive
            };
        }

        /// <summary>Pairs a node's contact with an endpoint where nothing listens, so only punched routes can reach it.</summary>
        /// <param name="node">The running node.</param>
        /// <returns>The contact at a dead address with the node's real ports.</returns>
        private static DHTPeer Hidden(MajDHTNode node)
        {
            var listener = node.LocalPeer.Endpoints[0];
            return new DHTPeer(node.LocalContact, new[] { new DHTEndpoint(IPAddress.Parse("127.0.0.254"), listener.TcpPort, listener.UdpPort) });
        }

        /// <summary>Two loopback nodes with a punched route between them whose Traversal node has stopped, so nothing can punch again.</summary>
        private sealed class PunchedPair : IAsyncDisposable
        {
            /// <summary>The stopped Traversal node.</summary>
            private readonly MajDHTNode _traversal;

            /// <summary>Gets the node that requested the punch.</summary>
            internal MajDHTNode Left { get; }
            /// <summary>Gets the punched node.</summary>
            internal MajDHTNode Right { get; }
            /// <summary>Gets the punched node's contact at a dead address.</summary>
            internal DHTPeer HiddenRight { get; }
            /// <summary>Gets the punched node's record.</summary>
            internal DHTRecord RightRecord { get; }
            /// <summary>Gets the punched node's file.</summary>
            internal byte[] RightBytes { get; }

            /// <summary>Stores the started nodes.</summary>
            /// <param name="traversal">The stopped Traversal node.</param>
            /// <param name="left">The requesting node.</param>
            /// <param name="right">The punched node.</param>
            /// <param name="rightRecord">The punched node's record.</param>
            /// <param name="rightBytes">The punched node's file.</param>
            private PunchedPair(MajDHTNode traversal, MajDHTNode left, MajDHTNode right, DHTRecord rightRecord, byte[] rightBytes)
            {
                _traversal = traversal;
                Left = left;
                Right = right;
                RightRecord = rightRecord;
                RightBytes = rightBytes;
                HiddenRight = Hidden(right);
            }

            /// <summary>Starts three nodes, punches from the left node to the right one and stops the Traversal node.</summary>
            /// <param name="transport">The only transport enabled on every node.</param>
            /// <param name="token">The test deadline.</param>
            /// <returns>The pair with its punched route.</returns>
            internal static async Task<PunchedPair> StartAsync(DHTTransport transport, CancellationToken token)
            {
                var traversal = new MajDHTNode(Options("127.0.0.1", transport, DHTCapabilities.Traversal, s_keepAlive));
                var left = new MajDHTNode(Options("127.0.0.1", transport, DHTCapabilities.Download | DHTCapabilities.Provide, s_keepAlive));
                var right = new MajDHTNode(Options("127.0.0.1", transport, DHTCapabilities.Download | DHTCapabilities.Provide, s_keepAlive));
                await Task.WhenAll(traversal.StartAsync(token), left.StartAsync(token), right.StartAsync(token));
                var rightBytes = Crypto.Random(3001);
                using var source = new MemoryStream(rightBytes);
                var rightRecord = await right.PublishAsync("keepalive/right", source, cancellationToken: token);
                await left.JoinAsync(traversal.LocalPeer, token);
                await right.JoinAsync(traversal.LocalPeer, token);
                Assert.True(await left.TryPunchAsync(Hidden(right), traversal.LocalPeer, transport, token), "The loopback punch must succeed.");
                await traversal.StopAsync();
                return new PunchedPair(traversal, left, right, rightRecord, rightBytes);
            }

            /// <summary>Stops every node.</summary>
            /// <returns>Completion after the nodes stopped.</returns>
            public async ValueTask DisposeAsync()
            {
                await Left.DisposeAsync();
                await Right.DisposeAsync();
                await _traversal.DisposeAsync();
            }
        }

        /// <summary>
        /// Two UDP nodes, each behind a NAT with port-restricted filtering and expiring flows, with a punched route between them;
        /// the Traversal node that coordinated the punch has stopped, so nothing can punch again.
        /// </summary>
        private sealed class NatScenario : IAsyncDisposable
        {
            /// <summary>The requester's NAT.</summary>
            private readonly FlowTimeoutUdpNat _leftNat;

            /// <summary>Gets the target's NAT.</summary>
            internal FlowTimeoutUdpNat RightNat { get; }
            /// <summary>Gets the requesting node.</summary>
            internal MajDHTNode Left { get; }
            /// <summary>Gets the target node.</summary>
            internal MajDHTNode Right { get; }
            /// <summary>Gets the requester's contact at a dead address.</summary>
            internal DHTPeer HiddenLeft { get; }
            /// <summary>Gets the target's contact at a dead address.</summary>
            internal DHTPeer HiddenRight { get; }
            /// <summary>Gets the requester's record.</summary>
            internal DHTRecord LeftRecord { get; }
            /// <summary>Gets the target's record.</summary>
            internal DHTRecord RightRecord { get; }
            /// <summary>Gets the requester's file.</summary>
            internal byte[] LeftBytes { get; }
            /// <summary>Gets the target's file.</summary>
            internal byte[] RightBytes { get; }

            /// <summary>Stores the started components.</summary>
            /// <param name="leftNat">The requester's NAT.</param>
            /// <param name="rightNat">The target's NAT.</param>
            /// <param name="left">The requesting node.</param>
            /// <param name="right">The target node.</param>
            /// <param name="leftRecord">The requester's record.</param>
            /// <param name="rightRecord">The target's record.</param>
            /// <param name="leftBytes">The requester's file.</param>
            /// <param name="rightBytes">The target's file.</param>
            private NatScenario(FlowTimeoutUdpNat leftNat, FlowTimeoutUdpNat rightNat, MajDHTNode left, MajDHTNode right,
                DHTRecord leftRecord, DHTRecord rightRecord, byte[] leftBytes, byte[] rightBytes)
            {
                _leftNat = leftNat;
                RightNat = rightNat;
                Left = left;
                Right = right;
                LeftRecord = leftRecord;
                RightRecord = rightRecord;
                LeftBytes = leftBytes;
                RightBytes = rightBytes;
                HiddenLeft = Hidden(left);
                HiddenRight = Hidden(right);
            }

            /// <summary>
            /// Starts both nodes behind their NATs, registers them through their NATs with a translating Traversal node, punches
            /// from the left node to the right one and stops the Traversal node.
            /// </summary>
            /// <param name="keepAlive">The keepalive interval of both nodes.</param>
            /// <param name="token">The test deadline.</param>
            /// <returns>The scenario with its punched route.</returns>
            internal static async Task<NatScenario> StartAsync(TimeSpan keepAlive, CancellationToken token)
            {
                var leftNat = new FlowTimeoutUdpNat(IPAddress.Parse("127.0.0.50"), 50, s_flowTimeout);
                var rightNat = new FlowTimeoutUdpNat(IPAddress.Parse("127.0.0.60"), 60, s_flowTimeout);
                var nats = new Dictionary<IPAddress, FlowTimeoutUdpNat> { [leftNat.ExternalAddress] = leftNat, [rightNat.ExternalAddress] = rightNat };
                IPEndPoint Translate(IPEndPoint requester, IPEndPoint endpoint)
                {
                    return nats[requester.Address].InternalEndpointFor(endpoint);
                }
                var left = new MajDHTNode(Options("127.0.0.41", DHTTransport.Udp, DHTCapabilities.Download | DHTCapabilities.Provide, keepAlive));
                var right = new MajDHTNode(Options("127.0.0.42", DHTTransport.Udp, DHTCapabilities.Download | DHTCapabilities.Provide, keepAlive));
                await Task.WhenAll(left.StartAsync(token), right.StartAsync(token));
                var leftBytes = Crypto.Random(3001);
                var rightBytes = Crypto.Random(2003);
                using var leftSource = new MemoryStream(leftBytes);
                using var rightSource = new MemoryStream(rightBytes);
                var leftRecord = await left.PublishAsync("keepalive/left", leftSource, cancellationToken: token);
                var rightRecord = await right.PublishAsync("keepalive/right", rightSource, cancellationToken: token);
                await using (var traversal = new TranslatingTraversalNode(IPAddress.Parse("127.0.0.40"), Translate))
                {
                    var leftTraversal = traversal.PeerAt(leftNat.InternalEndpointFor(traversal.Endpoint));
                    await left.RegisterTraversalAsync(leftTraversal, token);
                    await right.RegisterTraversalAsync(traversal.PeerAt(rightNat.InternalEndpointFor(traversal.Endpoint)), token);
                    Assert.True(await left.TryPunchAsync(Hidden(right), leftTraversal, DHTTransport.Udp, token),
                        "Two port-restricted cone NATs must be punched.");
                }
                return new NatScenario(leftNat, rightNat, left, right, leftRecord, rightRecord, leftBytes, rightBytes);
            }

            /// <summary>Stops the nodes and the NATs.</summary>
            /// <returns>Completion after everything stopped.</returns>
            public async ValueTask DisposeAsync()
            {
                await Left.DisposeAsync();
                await Right.DisposeAsync();
                await _leftNat.DisposeAsync();
                await RightNat.DisposeAsync();
            }
        }
    }
}
