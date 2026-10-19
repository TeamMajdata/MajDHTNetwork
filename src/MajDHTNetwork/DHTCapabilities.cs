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

}
