using System;
using System.IO;
using System.Net;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// An immutable endpoint at which a node observed another node: the source of an authenticated request it received, or
    /// the destination that answered one of its requests. Peers never announce their own endpoints; every endpoint a node
    /// knows for a peer was observed by some node from actual packets.
    /// </summary>
    public sealed class DHTEndpoint : IEquatable<DHTEndpoint>
    {
        /// <summary>The maximum UTF-8 length of a canonical address string.</summary>
        public const int MaxAddressLength = 96;
        /// <summary>The internally shared immutable-by-convention address used for socket operations.</summary>
        private readonly IPAddress _address;

        /// <summary>Gets a copy of the observed IP address.</summary>
        public IPAddress Address => NetworkScope.CopyAddress(_address);
        /// <summary>Gets the internally cached address for socket operations.</summary>
        internal IPAddress NetworkAddress => _address;
        /// <summary>Gets the observed TCP source port, or zero when the node was not observed over TCP at this address.</summary>
        public int TcpPort { get; }
        /// <summary>Gets the observed UDP source port, or zero when the node was not observed over UDP at this address.</summary>
        public int UdpPort { get; }

        /// <summary>Creates a validated observed endpoint.</summary>
        /// <param name="address">The unicast IP address; it is copied.</param>
        /// <param name="tcpPort">The observed TCP port, or zero when unknown.</param>
        /// <param name="udpPort">The observed UDP port, or zero when unknown.</param>
        /// <exception cref="ArgumentException">The address is not unicast, a port is out of range or both ports are zero.</exception>
        public DHTEndpoint(IPAddress address, int tcpPort, int udpPort)
        {
            if (address == null || !NetworkScope.IsUnicast(address)
                || tcpPort < 0 || tcpPort > 65535 || udpPort < 0 || udpPort > 65535 || (tcpPort == 0 && udpPort == 0))
            {
                throw new ArgumentException("Invalid observed endpoint address or port.");
            }
            _address = NetworkScope.CopyAddress(address);
            TcpPort = tcpPort;
            UdpPort = udpPort;
        }

        /// <summary>Creates the endpoint at which a node was observed over one transport.</summary>
        /// <param name="transport">The transport the packet travelled over.</param>
        /// <param name="endpoint">The observed socket endpoint.</param>
        /// <returns>An endpoint with only that transport's port.</returns>
        /// <exception cref="ArgumentException">The transport or endpoint is invalid.</exception>
        public static DHTEndpoint Observed(DHTTransport transport, IPEndPoint endpoint)
        {
            if (endpoint == null)
            {
                throw new ArgumentException("An observed socket endpoint is required.", nameof(endpoint));
            }
            switch (transport)
            {
                case DHTTransport.Tcp:
                    return new DHTEndpoint(endpoint.Address, endpoint.Port, 0);
                case DHTTransport.Udp:
                    return new DHTEndpoint(endpoint.Address, 0, endpoint.Port);
                default:
                    throw new ArgumentException("A TCP or UDP transport is required.", nameof(transport));
            }
        }

        /// <summary>Gets the observed port for one transport.</summary>
        /// <param name="transport">The transport.</param>
        /// <returns>The port, or zero when the node was not observed over that transport at this address.</returns>
        public int Port(DHTTransport transport)
        {
            return transport == DHTTransport.Tcp ? TcpPort : UdpPort;
        }

        /// <summary>Gets the socket endpoint for one transport.</summary>
        /// <param name="transport">The transport.</param>
        /// <returns>The socket endpoint, or null when the node was not observed over that transport at this address.</returns>
        public IPEndPoint? ToIPEndPoint(DHTTransport transport)
        {
            var port = Port(transport);
            return port == 0 ? null : new IPEndPoint(NetworkScope.CopyAddress(_address), port);
        }

        /// <summary>Combines a later observation at the same address: a newly observed transport port replaces the earlier one.</summary>
        /// <param name="later">The later observation, which must share this endpoint's address.</param>
        /// <returns>The combined endpoint.</returns>
        /// <exception cref="ArgumentException">The later observation has another address.</exception>
        public DHTEndpoint Merge(DHTEndpoint later)
        {
            if (later == null || !later._address.Equals(_address))
            {
                throw new ArgumentException("Only observations at the same address can be merged.", nameof(later));
            }
            return new DHTEndpoint(_address, later.TcpPort != 0 ? later.TcpPort : TcpPort, later.UdpPort != 0 ? later.UdpPort : UdpPort);
        }

        /// <summary>Writes the canonical encoding: address text, TCP port and UDP port.</summary>
        /// <param name="writer">The destination encoder.</param>
        public void Write(Wire writer)
        {
            writer.PutText(_address.ToString());
            writer.PutLong(TcpPort);
            writer.PutLong(UdpPort);
        }

        /// <summary>Reads one canonical endpoint written by <see cref="Write"/>.</summary>
        /// <param name="reader">The source decoder.</param>
        /// <returns>The validated endpoint.</returns>
        /// <exception cref="InvalidDataException">The address is not canonical unicast text or a port is invalid.</exception>
        public static DHTEndpoint Read(Wire reader)
        {
            var text = reader.Text(MaxAddressLength);
            var tcp = reader.Long();
            var udp = reader.Long();
            if (!IPAddress.TryParse(text, out var address) || address.ToString() != text || !NetworkScope.IsUnicast(address)
                || tcp < 0 || tcp > 65535 || udp < 0 || udp > 65535 || (tcp == 0 && udp == 0))
            {
                throw new InvalidDataException("Invalid observed endpoint.");
            }
            return new DHTEndpoint(address, (int)tcp, (int)udp);
        }

        /// <inheritdoc />
        public bool Equals(DHTEndpoint? other)
        {
            return other != null && _address.Equals(other._address) && TcpPort == other.TcpPort && UdpPort == other.UdpPort;
        }

        /// <inheritdoc />
        public override bool Equals(object? obj)
        {
            return obj is DHTEndpoint other && Equals(other);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            return HashCode.Combine(_address, TcpPort, UdpPort);
        }

        /// <inheritdoc />
        public override string ToString()
        {
            return _address + " tcp:" + TcpPort + " udp:" + UdpPort;
        }
    }
}
