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
        public IPEndPoint Endpoint => NetworkScope.CopyEndpoint(_endpoint);
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
            _endpoint = NetworkScope.CopyEndpoint(endpoint);
            Transport = transport;
        }
    }

    /// <summary>
    /// One assisted attempt through a Traversal or Forwarder node: hole punching coordinated by a Traversal node, forwarding
    /// through a Forwarder, or both in that order when the assistant has both capabilities.
    /// </summary>
    public sealed class DHTAssistedRoute
    {
        /// <summary>Gets the assisting node at the endpoints it was observed.</summary>
        public DHTPeer Assistant { get; }
        /// <summary>
        /// Gets whether to ask the assistant, when it is a Traversal node, for a direct introduction before forwarding;
        /// punching registers with the assistant when this node is not registered yet and is skipped when NAT traversal is
        /// disabled.
        /// </summary>
        public bool AttemptPunch { get; }

        /// <summary>Creates an assisted attempt.</summary>
        /// <param name="assistant">The assisting node.</param>
        /// <param name="attemptPunch">Whether to try hole punching first.</param>
        /// <exception cref="ArgumentNullException">The assistant is null.</exception>
        public DHTAssistedRoute(DHTPeer assistant, bool attemptPunch)
        {
            Assistant = assistant ?? throw new ArgumentNullException(nameof(assistant));
            AttemptPunch = attemptPunch;
        }
    }
}
