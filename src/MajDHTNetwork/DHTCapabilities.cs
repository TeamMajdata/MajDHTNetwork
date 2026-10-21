using System;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Advertises the operations a node permits.</summary>
    [Flags]
    public enum DHTCapabilities
    {
        /// <summary>Participates in discovery and downloads content.</summary>
        Download = 1,
        /// <summary>Serves locally available content blocks.</summary>
        Provide = 2,
        /// <summary>
        /// Coordinates direct connections: observes the endpoints of registered peers, introduces two peers to each other for
        /// TCP or UDP hole punching and arranges or performs the dial-backs that probe direct reachability.
        /// </summary>
        Traversal = 4,
        /// <summary>
        /// Relays encrypted envelopes between two peers: hosts forwarding sessions, addresses their destinations by observed
        /// endpoint and forwards traffic, so two peers that cannot connect directly still communicate.
        /// </summary>
        Forwarder = 8
    }

    /// <summary>Identifies the preferred transport for outgoing requests.</summary>
    public enum DHTTransport
    {
        /// <summary>Uses length-prefixed TCP requests.</summary>
        Tcp,
        /// <summary>Uses bounded UDP datagrams with request retries.</summary>
        Udp
    }

    /// <summary>Describes how other nodes can reach a signed contact.</summary>
    public enum DHTReachability
    {
        /// <summary>Reachability has not been established; the observed endpoints are tried before the hinted forwarders.</summary>
        Unknown = 0,
        /// <summary>The node accepts unsolicited packets at its observed endpoint, verified by an independent dial-back or configured.</summary>
        Public = 1,
        /// <summary>The node is behind a NAT or firewall and is reached through the forwarders in its hints.</summary>
        Private = 2
    }
}
