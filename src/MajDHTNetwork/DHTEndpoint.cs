using System;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>An immutable endpoint advertised inside a signed node contact.</summary>
    public sealed class DHTEndpoint
    {
        /// <summary>The internally shared immutable-by-convention address used for socket operations.</summary>
        private readonly IPAddress _address;

        /// <summary>Gets a copy of the advertised IP address.</summary>
        public IPAddress Address => Protocol.NetworkScope.CopyAddress(_address);
        /// <summary>Gets the internally cached address for socket operations.</summary>
        internal IPAddress NetworkAddress => _address;
        /// <summary>Gets the TCP port, or zero when this endpoint does not accept TCP.</summary>
        public int TcpPort { get; }
        /// <summary>Gets the UDP port, or zero when this endpoint does not accept UDP.</summary>
        public int UdpPort { get; }
        /// <summary>Gets the provenance and scope of the endpoint.</summary>
        public DHTEndpointFlags Flags { get; }

        /// <summary>Creates a validated advertised endpoint.</summary>
        /// <param name="address">The unicast IP address; it is copied.</param>
        /// <param name="tcpPort">The TCP port, or zero when TCP is not accepted.</param>
        /// <param name="udpPort">The UDP port, or zero when UDP is not accepted.</param>
        /// <param name="flags">The provenance and scope flags.</param>
        /// <exception cref="ArgumentException">The address, ports or flags are invalid.</exception>
        public DHTEndpoint(IPAddress address, int tcpPort, int udpPort, DHTEndpointFlags flags)
        {
            if (address == null || !Protocol.NetworkScope.IsUnicast(address)
                || tcpPort < 0 || tcpPort > 65535 || udpPort < 0 || udpPort > 65535 || (tcpPort == 0 && udpPort == 0)
                || (flags & ~(DHTEndpointFlags.Verified | DHTEndpointFlags.Local | DHTEndpointFlags.Configured)) != 0
                || ((flags & DHTEndpointFlags.Verified) != 0 && (flags & DHTEndpointFlags.Local) != 0))
            {
                throw new ArgumentException("Invalid advertised endpoint address, port or flags.");
            }
            _address = Protocol.NetworkScope.CopyAddress(address);
            TcpPort = tcpPort;
            UdpPort = udpPort;
            Flags = flags;
        }

        /// <summary>Gets whether the endpoint was configured or verified as directly reachable.</summary>
        public bool IsReachable => (Flags & (DHTEndpointFlags.Verified | DHTEndpointFlags.Configured)) != 0;

        /// <summary>Gets the port for one transport.</summary>
        /// <param name="transport">The transport.</param>
        /// <returns>The port, or zero when the transport is not accepted.</returns>
        public int Port(DHTTransport transport)
        {
            return transport == DHTTransport.Tcp ? TcpPort : UdpPort;
        }
    }
}
