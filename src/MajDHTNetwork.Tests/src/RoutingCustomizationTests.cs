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
        /// <summary>Orders direct routes by most recent observation and transport preference, and dials no private destination.</summary>
        [Fact]
        public void DefaultSelectorOrdersObservedEndpointsMostRecentFirst()
        {
            var endpoints = new[]
            {
                new DHTEndpoint(IPAddress.Parse("192.168.1.2"), 1001, 0),
                new DHTEndpoint(IPAddress.Parse("198.51.100.2"), 1002, 2002),
                new DHTEndpoint(IPAddress.Parse("203.0.113.2"), 0, 2003)
            };
            var peer = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Provide, DHTReachability.Public, false, Array.Empty<DHTPeer>(),
                TimeSpan.FromHours(1)), endpoints);
            var routes = new DefaultDHTRouteSelector().SelectDirectRoutes(peer, Context(DHTTransport.Tcp, true));
            Assert.Collection(routes,
                route => AssertRoute(route, "203.0.113.2", 2003, DHTTransport.Udp),
                route => AssertRoute(route, "198.51.100.2", 1002, DHTTransport.Tcp),
                route => AssertRoute(route, "198.51.100.2", 2002, DHTTransport.Udp),
                route => AssertRoute(route, "192.168.1.2", 1001, DHTTransport.Tcp));
            // A private node's observed endpoints are NAT mappings that failed a dial-back, so they are never dialed.
            var hidden = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Provide, DHTReachability.Private, false,
                new[] { PublicAssistant("203.0.113.10", DHTCapabilities.Forwarder) }, TimeSpan.FromHours(1)), endpoints);
            Assert.Empty(new DefaultDHTRouteSelector().SelectDirectRoutes(hidden, Context(DHTTransport.Tcp, true)));
        }

        /// <summary>Lists hints before bounded routed assistants and punches only through Traversal nodes this node is registered with.</summary>
        [Fact]
        public void DefaultSelectorPrefersHintsAndBoundsRoutedAssistants()
        {
            var hintedForwarder = PublicAssistant("203.0.113.10", DHTCapabilities.Forwarder);
            var registered = PublicAssistant("203.0.113.11", DHTCapabilities.Traversal | DHTCapabilities.Forwarder);
            var unregistered = PublicAssistant("203.0.113.12", DHTCapabilities.Traversal | DHTCapabilities.Forwarder);
            var destination = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Provide, DHTReachability.Private, false,
                new[] { hintedForwarder, registered, unregistered }, TimeSpan.FromHours(1)), Array.Empty<DHTEndpoint>());
            var routed = new List<DHTPeer>
            {
                PublicAssistant("203.0.113.20", DHTCapabilities.Traversal), registered, PublicAssistant("203.0.113.21", DHTCapabilities.Forwarder),
                PublicAssistant("203.0.113.22", DHTCapabilities.Traversal | DHTCapabilities.Forwarder)
            };
            var context = new DHTRouteContext(DHTTransport.Tcp, true, new[] { registered.NodeId }, 2);
            var selector = new DefaultDHTRouteSelector();
            var routes = selector.SelectAssistedRoutes(destination, routed, context);
            Assert.Equal(5, routes.Count);
            Assert.Equal(hintedForwarder.NodeId, routes[0].Assistant.NodeId);
            Assert.False(routes[0].AttemptPunch, "A Forwarder that does not coordinate traversal cannot punch.");
            Assert.Equal(registered.NodeId, routes[1].Assistant.NodeId);
            Assert.True(routes[1].AttemptPunch);
            Assert.Equal(unregistered.NodeId, routes[2].Assistant.NodeId);
            Assert.False(routes[2].AttemptPunch, "Punching through an unregistered hint would consume a registration slot.");
            // Routed assistants are drawn in random order from the nearest candidates, so only membership is fixed.
            var routedIds = new HashSet<string> { routed[0].NodeId, routed[2].NodeId, routed[3].NodeId };
            Assert.Contains(routes[3].Assistant.NodeId, routedIds);
            Assert.Contains(routes[4].Assistant.NodeId, routedIds);
            Assert.NotEqual(routes[3].Assistant.NodeId, routes[4].Assistant.NodeId);
            for (var index = 3; index < routes.Count; index++)
            {
                Assert.Equal((routes[index].Assistant.Capabilities & DHTCapabilities.Traversal) != 0, routes[index].AttemptPunch);
            }
            Assert.Empty(selector.SelectDirectRoutes(destination, context));
            var withoutTraversal = new DHTRouteContext(DHTTransport.Tcp, false, new[] { registered.NodeId }, 2);
            Assert.All(selector.SelectAssistedRoutes(destination, routed, withoutTraversal), route => Assert.False(route.AttemptPunch));
        }

        /// <summary>Initializes a custom routing table once and filters private peers it returns.</summary>
        /// <returns>Completion after the assertions and node cleanup.</returns>
        [Fact]
        public async Task CustomRoutingTablesAreInitializedOnceAndTheirResultsValidated()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var injected = new DHTPeer(DHTContact.Create(new DHTIdentity(), DHTCapabilities.Provide, DHTReachability.Private, false,
                new[] { PublicAssistant("203.0.113.30", DHTCapabilities.Forwarder) }, TimeSpan.FromMinutes(30)), Array.Empty<DHTEndpoint>());
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

        /// <summary>Uses a custom selector that forbids direct access to the provider, so the block arrives through a Forwarder.</summary>
        /// <returns>Completion after the forwarded verified block read.</returns>
        [Fact]
        public async Task CustomRouteSelectorsChooseTheForwardedPath()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var forwarder = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Forwarder));
            await using var provider = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await Task.WhenAll(forwarder.StartAsync(token), provider.StartAsync(token));
            var selector = new ForwardOnlySelector(provider.NodeId, forwarder.LocalPeer);
            await using var client = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download), routeSelector: selector);
            await client.StartAsync(token);
            await provider.JoinAsync(forwarder.LocalPeer, token);
            await client.JoinAsync(forwarder.LocalPeer, token);
            var content = Crypto.Random(4000);
            using var source = new MemoryStream(content);
            var record = await provider.PublishAsync("custom/route", source, cancellationToken: token);
            var block = await client.ReadBlockAsync(record, provider.LocalPeer, 0, cancellationToken: token);
            Assert.True(BytesEqual(content, block), "The Forwarder chosen by the selector must deliver the verified block.");
            Assert.True(selector.AssistedSelections > 0, "The selector must have chosen the forwarded path.");
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

        /// <summary>Creates a routing context without registrations.</summary>
        /// <param name="preferred">The preferred transport.</param>
        /// <param name="traversal">Whether NAT traversal is enabled.</param>
        /// <returns>The context.</returns>
        private static DHTRouteContext Context(DHTTransport preferred, bool traversal)
        {
            return new DHTRouteContext(preferred, traversal, Array.Empty<string>(), 8);
        }

        /// <summary>Creates a public assistant observed at one TCP endpoint.</summary>
        /// <param name="address">The observed address.</param>
        /// <param name="capabilities">The assisting capabilities.</param>
        /// <returns>The assistant.</returns>
        private static DHTPeer PublicAssistant(string address, DHTCapabilities capabilities)
        {
            return new DHTPeer(DHTContact.Create(new DHTIdentity(), capabilities, DHTReachability.Public, false, Array.Empty<DHTPeer>(),
                TimeSpan.FromHours(2)), new[] { new DHTEndpoint(IPAddress.Parse(address), 42000, 0) });
        }

        /// <summary>Wraps the default table, records its use and injects a private peer into every query result.</summary>
        private sealed class RecordingRoutingTable : IDHTRoutingTable
        {
            /// <summary>The wrapped default table.</summary>
            private readonly KademliaDHTRoutingTable _inner = new KademliaDHTRoutingTable();
            /// <summary>The peer the node must filter out.</summary>
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
            /// <param name="injected">The private peer injected into results.</param>
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
            public void Observe(DHTContact contact, DHTEndpoint? observed)
            {
                lock (_gate)
                {
                    _observed.Add(contact.NodeId);
                }
                _inner.Observe(contact, observed);
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

        /// <summary>Forbids direct access to one node and routes it through one Forwarder, recording its use.</summary>
        private sealed class ForwardOnlySelector : IDHTRouteSelector
        {
            /// <summary>The default behavior for every other destination.</summary>
            private readonly DefaultDHTRouteSelector _default = new DefaultDHTRouteSelector();
            /// <summary>The destination that must be forwarded.</summary>
            private readonly string _forwardedNodeId;
            /// <summary>The Forwarder to use.</summary>
            private readonly DHTPeer _forwarder;
            /// <summary>The number of assisted selections for the forwarded destination.</summary>
            private int _assistedSelections;

            /// <summary>Gets the number of assisted selections for the forwarded destination.</summary>
            internal int AssistedSelections => Volatile.Read(ref _assistedSelections);

            /// <summary>Creates the selector.</summary>
            /// <param name="forwardedNodeId">The destination that must be forwarded.</param>
            /// <param name="forwarder">The Forwarder to use.</param>
            internal ForwardOnlySelector(string forwardedNodeId, DHTPeer forwarder)
            {
                _forwardedNodeId = forwardedNodeId;
                _forwarder = forwarder;
            }

            /// <inheritdoc />
            public IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context)
            {
                return destination.NodeId == _forwardedNodeId ? Array.Empty<DHTDirectRoute>() : _default.SelectDirectRoutes(destination, context);
            }

            /// <inheritdoc />
            public IReadOnlyList<DHTAssistedRoute> SelectAssistedRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownAssistants, DHTRouteContext context)
            {
                if (destination.NodeId != _forwardedNodeId)
                {
                    return _default.SelectAssistedRoutes(destination, knownAssistants, context);
                }
                Interlocked.Increment(ref _assistedSelections);
                // The unusable first route checks that the node skips assistants that cannot serve the destination.
                return new[] { new DHTAssistedRoute(destination, false), new DHTAssistedRoute(_forwarder, false) };
            }
        }
    }
}
