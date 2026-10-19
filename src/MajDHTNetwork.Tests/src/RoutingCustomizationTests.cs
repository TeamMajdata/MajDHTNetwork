#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks the default route selection and the injection of custom routing tables and route selectors.</summary>
    public sealed class RoutingCustomizationTests
    {
        /// <summary>Orders direct routes by endpoint evidence and transport preference.</summary>
        [Fact]
        public void DefaultSelectorOrdersVerifiedThenUnverifiedThenLocalEndpoints()
        {
            var contact = DHTPeer.Create(new DHTIdentity(), new[]
            {
                new DHTEndpoint(IPAddress.Parse("192.168.1.2"), 1001, 0, DHTEndpointFlags.Local),
                new DHTEndpoint(IPAddress.Parse("198.51.100.2"), 1002, 2002, DHTEndpointFlags.None),
                new DHTEndpoint(IPAddress.Parse("203.0.113.2"), 0, 2003, DHTEndpointFlags.Verified)
            }, DHTCapabilities.Provide, DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
            var routes = new DefaultDHTRouteSelector().SelectDirectRoutes(contact, Context(DHTTransport.Tcp, true));
            Assert.Collection(routes,
                route => AssertRoute(route, "203.0.113.2", 2003, DHTTransport.Udp),
                route => AssertRoute(route, "198.51.100.2", 1002, DHTTransport.Tcp),
                route => AssertRoute(route, "198.51.100.2", 2002, DHTTransport.Udp),
                route => AssertRoute(route, "192.168.1.2", 1001, DHTTransport.Tcp));
        }

        /// <summary>Lists relay hints before bounded routed relays and only punches through registered hints.</summary>
        [Fact]
        public void DefaultSelectorPrefersRelayHintsAndBoundsRoutedRelays()
        {
            var hinted = PublicRelay("203.0.113.10");
            var registered = PublicRelay("203.0.113.11");
            var destination = DHTPeer.Create(new DHTIdentity(), Array.Empty<DHTEndpoint>(), DHTCapabilities.Provide, DHTReachability.Private,
                false, null, new[] { hinted, registered }, TimeSpan.FromHours(1));
            var routed = new List<DHTPeer> { PublicRelay("203.0.113.20"), registered, PublicRelay("203.0.113.21"), PublicRelay("203.0.113.22") };
            var context = new DHTRouteContext(DHTTransport.Tcp, true, Array.Empty<IPAddress>(), new[] { registered.NodeId }, 2);
            var routes = new DefaultDHTRouteSelector().SelectRelayRoutes(destination, routed, context);
            Assert.Equal(4, routes.Count);
            Assert.Equal(hinted.NodeId, routes[0].Relay.NodeId);
            Assert.False(routes[0].AttemptPunch, "Punching through an unregistered hint would consume a relay slot.");
            Assert.Equal(registered.NodeId, routes[1].Relay.NodeId);
            Assert.True(routes[1].AttemptPunch);
            Assert.Equal(routed[0].NodeId, routes[2].Relay.NodeId);
            Assert.Equal(routed[2].NodeId, routes[3].Relay.NodeId);
            Assert.Empty(new DefaultDHTRouteSelector().SelectDirectRoutes(destination, context));
            var withoutTraversal = new DHTRouteContext(DHTTransport.Tcp, false, Array.Empty<IPAddress>(), new[] { registered.NodeId }, 2);
            Assert.All(new DefaultDHTRouteSelector().SelectRelayRoutes(destination, routed, withoutTraversal), route => Assert.False(route.AttemptPunch));
        }

        /// <summary>Initializes a custom routing table once and filters private contacts it returns.</summary>
        /// <returns>Completion after the assertions and node cleanup.</returns>
        [Fact]
        public async Task CustomRoutingTablesAreInitializedOnceAndTheirResultsValidated()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var injected = DHTPeer.Create(new DHTIdentity(), Array.Empty<DHTEndpoint>(), DHTCapabilities.Provide, DHTReachability.Private,
                false, null, new[] { PublicRelay("203.0.113.30") }, TimeSpan.FromMinutes(30));
            var table = new RecordingRoutingTable(injected);
            await using var node = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download), routingTable: table);
            Assert.Equal(node.NodeId, table.LocalNodeId);
            Assert.Equal(8, table.BucketSize);
            Assert.ThrowsAny<InvalidOperationException>(() => new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download), routingTable: table));
            await using var bootstrap = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(node.StartAsync(token), bootstrap.StartAsync(token));
            await node.JoinAsync(bootstrap.LocalPeer, token);
            Assert.Contains(bootstrap.NodeId, table.Observed);
            var known = Assert.Single(node.KnownPeers);
            Assert.Equal(bootstrap.NodeId, known.NodeId);
        }

        /// <summary>Uses a custom selector that forbids direct access to the provider, so the block arrives through a relay.</summary>
        /// <returns>Completion after the relayed verified block read.</returns>
        [Fact]
        public async Task CustomRouteSelectorsChooseTheRelayPath()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Relay));
            await using var provider = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await Task.WhenAll(relay.StartAsync(token), provider.StartAsync(token));
            var selector = new RelayOnlySelector(provider.NodeId, relay.LocalPeer);
            await using var client = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download), routeSelector: selector);
            await client.StartAsync(token);
            await provider.JoinAsync(relay.LocalPeer, token);
            await client.JoinAsync(relay.LocalPeer, token);
            var content = Crypto.Random(4000);
            using var source = new MemoryStream(content);
            var record = await provider.PublishAsync("custom/route", source, cancellationToken: token);
            var block = await client.ReadBlockAsync(record, provider.LocalPeer, 0, cancellationToken: token);
            Assert.True(BytesEqual(content, block), "The relay chosen by the selector must deliver the verified block.");
            Assert.True(selector.RelaySelections > 0, "The selector must have chosen the relay path.");
        }

        /// <summary>Checks one direct route.</summary>
        /// <param name="route">The route.</param>
        /// <param name="address">The expected address.</param>
        /// <param name="port">The expected port.</param>
        /// <param name="transport">The expected transport.</param>
        private static void AssertRoute(DHTDirectRoute route, string address, int port, DHTTransport transport)
        {
            Assert.Equal(IPAddress.Parse(address), route.Endpoint.Address);
            Assert.Equal(port, route.Endpoint.Port);
            Assert.Equal(transport, route.Transport);
        }

        /// <summary>Creates a routing context without external addresses or registrations.</summary>
        /// <param name="preferred">The preferred transport.</param>
        /// <param name="traversal">Whether NAT traversal is enabled.</param>
        /// <returns>The context.</returns>
        private static DHTRouteContext Context(DHTTransport preferred, bool traversal)
        {
            return new DHTRouteContext(preferred, traversal, Array.Empty<IPAddress>(), Array.Empty<string>(), 8);
        }

        /// <summary>Creates a public relay contact with one configured endpoint.</summary>
        /// <param name="address">The relay address.</param>
        /// <returns>The relay contact.</returns>
        private static DHTPeer PublicRelay(string address)
        {
            return DHTPeer.Create(new DHTIdentity(), new[] { new DHTEndpoint(IPAddress.Parse(address), 42000, 0, DHTEndpointFlags.Configured) },
                DHTCapabilities.Relay, DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(2));
        }

        /// <summary>Wraps the default table, records its use and injects a private contact into every query result.</summary>
        private sealed class RecordingRoutingTable : IDHTRoutingTable
        {
            /// <summary>The wrapped default table.</summary>
            private readonly KademliaDHTRoutingTable _inner = new KademliaDHTRoutingTable();
            /// <summary>The contact the node must filter out.</summary>
            private readonly DHTPeer _injected;
            /// <summary>Protects the recorded identifiers.</summary>
            private readonly object _gate = new object();
            /// <summary>The observed node identifiers.</summary>
            private readonly List<string> _observed = new List<string>();

            /// <summary>Gets the identifier passed to <see cref="Initialize"/>.</summary>
            internal string? LocalNodeId { get; private set; }
            /// <summary>Gets the bucket size passed to <see cref="Initialize"/>.</summary>
            internal int BucketSize { get; private set; }
            /// <summary>Gets a snapshot of the observed node identifiers.</summary>
            internal List<string> Observed
            {
                get
                {
                    lock (_gate)
                    {
                        return new List<string>(_observed);
                    }
                }
            }

            /// <summary>Creates a recording table.</summary>
            /// <param name="injected">The private contact injected into results.</param>
            internal RecordingRoutingTable(DHTPeer injected)
            {
                _injected = injected;
            }

            /// <inheritdoc />
            public void Initialize(string localNodeId, int bucketSize)
            {
                _inner.Initialize(localNodeId, bucketSize);
                LocalNodeId = localNodeId;
                BucketSize = bucketSize;
            }

            /// <inheritdoc />
            public void Observe(DHTPeer peer)
            {
                lock (_gate)
                {
                    _observed.Add(peer.NodeId);
                }
                _inner.Observe(peer);
            }

            /// <inheritdoc />
            public void Remove(string nodeId)
            {
                _inner.Remove(nodeId);
            }

            /// <inheritdoc />
            public IReadOnlyList<DHTPeer> Closest(string routingId, int count)
            {
                var result = new List<DHTPeer> { _injected };
                result.AddRange(_inner.Closest(routingId, count));
                return result;
            }
        }

        /// <summary>Forbids direct access to one node and routes it through one relay, recording its use.</summary>
        private sealed class RelayOnlySelector : IDHTRouteSelector
        {
            /// <summary>The default behavior for every other destination.</summary>
            private readonly DefaultDHTRouteSelector _default = new DefaultDHTRouteSelector();
            /// <summary>The destination that must be relayed.</summary>
            private readonly string _relayedNodeId;
            /// <summary>The relay to use.</summary>
            private readonly DHTPeer _relay;
            /// <summary>The number of relay selections for the relayed destination.</summary>
            private int _relaySelections;

            /// <summary>Gets the number of relay selections for the relayed destination.</summary>
            internal int RelaySelections => Volatile.Read(ref _relaySelections);

            /// <summary>Creates the selector.</summary>
            /// <param name="relayedNodeId">The destination that must be relayed.</param>
            /// <param name="relay">The relay to use.</param>
            internal RelayOnlySelector(string relayedNodeId, DHTPeer relay)
            {
                _relayedNodeId = relayedNodeId;
                _relay = relay;
            }

            /// <inheritdoc />
            public IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context)
            {
                return destination.NodeId == _relayedNodeId ? Array.Empty<DHTDirectRoute>() : _default.SelectDirectRoutes(destination, context);
            }

            /// <inheritdoc />
            public IReadOnlyList<DHTRelayRoute> SelectRelayRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownRelays, DHTRouteContext context)
            {
                if (destination.NodeId != _relayedNodeId)
                {
                    return _default.SelectRelayRoutes(destination, knownRelays, context);
                }
                Interlocked.Increment(ref _relaySelections);
                // The unusable first route checks that the node skips relays that cannot serve the destination.
                return new[] { new DHTRelayRoute(destination, false), new DHTRelayRoute(_relay, false) };
            }
        }
    }
}
