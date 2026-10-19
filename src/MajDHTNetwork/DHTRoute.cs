using System;
using System.Net;
using System.Net.Sockets;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>One direct attempt: a remote endpoint and the transport used to reach it.</summary>
    public sealed class DHTDirectRoute
    {
        /// <summary>The owned remote endpoint.</summary>
        private readonly IPEndPoint _endpoint;

        /// <summary>Gets a copy of the remote endpoint.</summary>
        public IPEndPoint Endpoint => new IPEndPoint(IPAddress.Parse(_endpoint.Address.ToString()), _endpoint.Port);
        /// <summary>Gets the owned endpoint for socket operations.</summary>
        internal IPEndPoint NetworkEndpoint => _endpoint;
        /// <summary>Gets the transport.</summary>
        public DHTTransport Transport { get; }

        /// <summary>Creates a direct attempt.</summary>
        /// <param name="endpoint">The unicast remote endpoint with a non-zero port; it is copied.</param>
        /// <param name="transport">The transport.</param>
        /// <exception cref="ArgumentException">The endpoint or transport is invalid.</exception>
        public DHTDirectRoute(IPEndPoint endpoint, DHTTransport transport)
        {
            if (endpoint == null || endpoint.Port < 1 || endpoint.Port > 65535 || !NetworkScope.IsUnicast(endpoint.Address)
                || (endpoint.AddressFamily != AddressFamily.InterNetwork && endpoint.AddressFamily != AddressFamily.InterNetworkV6)
                || (transport != DHTTransport.Tcp && transport != DHTTransport.Udp))
            {
                throw new ArgumentException("A direct route needs a unicast endpoint, a non-zero port and a TCP or UDP transport.");
            }
            _endpoint = new IPEndPoint(IPAddress.Parse(endpoint.Address.ToString()), endpoint.Port);
            Transport = transport;
        }
    }

    /// <summary>One relay attempt: the relay and whether to try hole punching through it before opaque forwarding.</summary>
    public sealed class DHTRelayRoute
    {
        /// <summary>Gets the relay contact.</summary>
        public DHTPeer Relay { get; }
        /// <summary>
        /// Gets whether to ask the relay for a direct introduction first; punching registers with the relay when this node
        /// is not registered yet and is skipped when NAT traversal is disabled.
        /// </summary>
        public bool AttemptPunch { get; }

        /// <summary>Creates a relay attempt.</summary>
        /// <param name="relay">The relay contact.</param>
        /// <param name="attemptPunch">Whether to try hole punching first.</param>
        /// <exception cref="ArgumentNullException">The relay is null.</exception>
        public DHTRelayRoute(DHTPeer relay, bool attemptPunch)
        {
            Relay = relay ?? throw new ArgumentNullException(nameof(relay));
            AttemptPunch = attemptPunch;
        }
    }
}
