#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// A user-space UDP NAT on loopback with endpoint-independent mappings, address-and-port-dependent filtering and
    /// connection-tracking flow timeouts: an inbound datagram passes only while the mapping has sent to its exact source within
    /// the flow timeout, and inbound traffic never refreshes a flow. A host behind the NAT reaches every outside endpoint
    /// through an internal-facing proxy socket at an alias of the outside address with the outside port, so a Traversal node
    /// must translate the endpoints it reports to that host into these aliases.
    /// </summary>
    internal sealed class FlowTimeoutUdpNat : IAsyncDisposable
    {
        /// <summary>The Windows control code that keeps a UDP socket receiving after a datagram reached a closed port.</summary>
        private const int SioUdpConnReset = -1744830452;
        /// <summary>Serializes the proxy and mapping tables.</summary>
        private readonly object _gate = new object();
        /// <summary>The receive loops of every proxy and mapping socket.</summary>
        private readonly List<Task> _loops = new List<Task>();
        /// <summary>The internal-facing proxies indexed by the outside endpoint they represent.</summary>
        private readonly Dictionary<IPEndPoint, Proxy> _proxies = new Dictionary<IPEndPoint, Proxy>();
        /// <summary>The mappings indexed by the internal socket they translate.</summary>
        private readonly Dictionary<IPEndPoint, Mapping> _mappings = new Dictionary<IPEndPoint, Mapping>();
        /// <summary>The third octet of every alias address.</summary>
        private readonly byte _alias;
        /// <summary>The idle time after which a flow stops admitting inbound datagrams, in stopwatch ticks.</summary>
        private readonly long _flowTimeout;
        /// <summary>The number of inbound datagrams dropped by the filtering.</summary>
        private int _filtered;
        /// <summary>Whether the NAT was disposed.</summary>
        private volatile bool _stopped;

        /// <summary>Gets the public address every mapping is allocated on.</summary>
        internal IPAddress ExternalAddress { get; }
        /// <summary>Gets the number of inbound datagrams dropped because no live flow admitted them.</summary>
        internal int FilteredDatagrams => Volatile.Read(ref _filtered);

        /// <summary>Creates a NAT without mappings.</summary>
        /// <param name="externalAddress">The loopback address that models the NAT's public address.</param>
        /// <param name="alias">The third octet of the alias addresses at which hosts behind the NAT see outside addresses.</param>
        /// <param name="flowTimeout">The idle time after which a flow without outbound traffic stops admitting inbound datagrams.</param>
        internal FlowTimeoutUdpNat(IPAddress externalAddress, byte alias, TimeSpan flowTimeout)
        {
            ExternalAddress = externalAddress;
            _alias = alias;
            _flowTimeout = (long)(flowTimeout.TotalSeconds * Stopwatch.Frequency);
        }

        /// <summary>Gets the endpoint a host behind this NAT sends to in order to reach an outside endpoint, opening its proxy if needed.</summary>
        /// <param name="outside">The outside IPv4 endpoint.</param>
        /// <returns>The proxy endpoint at the alias address, which keeps the last octet of the outside address, and the outside port.</returns>
        internal IPEndPoint InternalEndpointFor(IPEndPoint outside)
        {
            lock (_gate)
            {
                return ProxyLocked(outside).Internal;
            }
        }

        /// <summary>Closes every socket and waits for the receive loops.</summary>
        /// <returns>Completion after the loops end.</returns>
        public async ValueTask DisposeAsync()
        {
            _stopped = true;
            List<Task> loops;
            lock (_gate)
            {
                foreach (var proxy in _proxies.Values)
                {
                    proxy.Socket.Dispose();
                }
                foreach (var mapping in _mappings.Values)
                {
                    mapping.Socket.Dispose();
                }
                loops = new List<Task>(_loops);
            }
            await Task.WhenAll(loops);
        }

        /// <summary>Finds or opens the internal-facing proxy of an outside endpoint.</summary>
        /// <param name="outside">The outside endpoint.</param>
        /// <returns>The proxy.</returns>
        /// <remarks>The caller must hold the table lock.</remarks>
        private Proxy ProxyLocked(IPEndPoint outside)
        {
            if (_proxies.TryGetValue(outside, out var proxy))
            {
                return proxy;
            }
            var octets = outside.Address.GetAddressBytes();
            var socket = Bind(new IPEndPoint(new IPAddress(new byte[] { 127, 0, _alias, octets[3] }), outside.Port));
            proxy = new Proxy(socket, Copy(outside), (IPEndPoint)socket.Client.LocalEndPoint!);
            _proxies.Add(proxy.Outside, proxy);
            _loops.Add(ForwardOutboundAsync(proxy));
            return proxy;
        }

        /// <summary>Forwards what a host behind the NAT sends to a proxy through the host's mapping, refreshing that flow.</summary>
        /// <param name="proxy">The proxy whose socket receives.</param>
        /// <returns>Completion after disposal.</returns>
        private async Task ForwardOutboundAsync(Proxy proxy)
        {
            while (!_stopped)
            {
                try
                {
                    var received = await proxy.Socket.ReceiveAsync();
                    Mapping mapping;
                    lock (_gate)
                    {
                        if (!_mappings.TryGetValue(received.RemoteEndPoint, out mapping!))
                        {
                            mapping = new Mapping(Copy(received.RemoteEndPoint), Bind(new IPEndPoint(ExternalAddress, 0)));
                            _mappings.Add(mapping.InternalSource, mapping);
                            _loops.Add(ForwardInboundAsync(mapping));
                        }
                        mapping.Flows[proxy.Outside] = Stopwatch.GetTimestamp();
                    }
                    await mapping.Socket.SendAsync(received.Buffer, received.Buffer.Length, proxy.Outside);
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (SocketException)
                {
                    // An unreachable endpoint is reported on a later receive; the NAT keeps forwarding.
                }
            }
        }

        /// <summary>Delivers datagrams that reach a mapping from the source of a live flow to the internal socket.</summary>
        /// <param name="mapping">The mapping whose external socket receives.</param>
        /// <returns>Completion after disposal.</returns>
        private async Task ForwardInboundAsync(Mapping mapping)
        {
            while (!_stopped)
            {
                try
                {
                    var received = await mapping.Socket.ReceiveAsync();
                    Proxy proxy;
                    lock (_gate)
                    {
                        if (!mapping.Flows.TryGetValue(received.RemoteEndPoint, out var lastOutbound)
                            || Stopwatch.GetTimestamp() - lastOutbound > _flowTimeout)
                        {
                            Interlocked.Increment(ref _filtered);
                            continue;
                        }
                        proxy = ProxyLocked(received.RemoteEndPoint);
                    }
                    await proxy.Socket.SendAsync(received.Buffer, received.Buffer.Length, mapping.InternalSource);
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (SocketException)
                {
                    // A closed internal socket is reported on a later receive; the NAT keeps forwarding.
                }
            }
        }

        /// <summary>Binds a UDP socket that keeps receiving after a datagram reached a closed port.</summary>
        /// <param name="endpoint">The local endpoint.</param>
        /// <returns>The bound socket.</returns>
        private static UdpClient Bind(IPEndPoint endpoint)
        {
            var socket = new UdpClient(endpoint);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                socket.Client.IOControl(SioUdpConnReset, new byte[] { 0 }, null);
            }
            return socket;
        }

        /// <summary>Copies a socket-owned endpoint before storing it.</summary>
        /// <param name="endpoint">The endpoint.</param>
        /// <returns>An independent copy.</returns>
        private static IPEndPoint Copy(IPEndPoint endpoint)
        {
            return new IPEndPoint(new IPAddress(endpoint.Address.GetAddressBytes()), endpoint.Port);
        }

        /// <summary>An internal-facing socket that represents one outside endpoint to the hosts behind the NAT.</summary>
        private sealed class Proxy
        {
            /// <summary>Gets the proxy socket.</summary>
            internal UdpClient Socket { get; }
            /// <summary>Gets the outside endpoint the proxy represents.</summary>
            internal IPEndPoint Outside { get; }
            /// <summary>Gets the endpoint the hosts behind the NAT send to.</summary>
            internal IPEndPoint Internal { get; }

            /// <summary>Creates a proxy.</summary>
            /// <param name="socket">The bound proxy socket.</param>
            /// <param name="outside">The outside endpoint.</param>
            /// <param name="internalEndpoint">The bound proxy endpoint.</param>
            internal Proxy(UdpClient socket, IPEndPoint outside, IPEndPoint internalEndpoint)
            {
                Socket = socket;
                Outside = outside;
                Internal = internalEndpoint;
            }
        }

        /// <summary>The external socket of one internal socket and the time it last sent to each outside endpoint.</summary>
        private sealed class Mapping
        {
            /// <summary>Gets the internal socket.</summary>
            internal IPEndPoint InternalSource { get; }
            /// <summary>Gets the external socket.</summary>
            internal UdpClient Socket { get; }
            /// <summary>Gets the stopwatch timestamp of the latest outbound datagram to each outside endpoint.</summary>
            internal Dictionary<IPEndPoint, long> Flows { get; } = new Dictionary<IPEndPoint, long>();

            /// <summary>Creates a mapping without flows.</summary>
            /// <param name="internalSource">The internal socket.</param>
            /// <param name="socket">The bound external socket.</param>
            internal Mapping(IPEndPoint internalSource, UdpClient socket)
            {
                InternalSource = internalSource;
                Socket = socket;
            }
        }
    }
}
