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
        /// <summary>Forwards encrypted requests to known peers.</summary>
        Relay = 4
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
        /// <summary>Reachability has not been established; advertised endpoints are tried before relay hints.</summary>
        Unknown = 0,
        /// <summary>At least one advertised endpoint was configured or verified by an independent dial-back.</summary>
        Public = 1,
        /// <summary>The node is behind a NAT or firewall and is reached through its relay hints.</summary>
        Private = 2
    }

    /// <summary>Describes the provenance and scope of one advertised contact endpoint.</summary>
    [Flags]
    public enum DHTEndpointFlags
    {
        /// <summary>The endpoint is an unverified listener address.</summary>
        None = 0,
        /// <summary>An independent node reached this endpoint during the current external-address epoch.</summary>
        Verified = 1,
        /// <summary>The endpoint is only reachable inside the owner's local network.</summary>
        Local = 2,
        /// <summary>The endpoint was configured by the application, for example after a router port mapping.</summary>
        Configured = 4
    }

}
