#nullable enable

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Supplies shared loopback options and byte comparisons for the socket regressions.</summary>
    internal static class TestSupport
    {
        /// <summary>Creates a random routing identifier.</summary>
        /// <returns>A canonical SHA-256 identifier.</returns>
        internal static string NodeHash()
        {
            return Crypto.Hex(Crypto.Random(32));
        }

        /// <summary>Creates short-timeout loopback options using exactly one transport.</summary>
        /// <param name="transport">The enabled transport.</param>
        /// <param name="capabilities">The advertised services.</param>
        /// <returns>Independent node options.</returns>
        internal static DHTNodeOptions Options(DHTTransport transport, DHTCapabilities capabilities)
        {
            return new DHTNodeOptions
            {
                TcpPort = transport == DHTTransport.Tcp ? 0 : (int?)null,
                UdpPort = transport == DHTTransport.Udp ? 0 : (int?)null,
                PreferredTransport = transport,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(350),
                UdpAttempts = 2,
                EnableNatTraversal = false
            };
        }

        /// <summary>Compares byte sequences without text encoding.</summary>
        /// <param name="a">The first sequence.</param>
        /// <param name="b">The second sequence.</param>
        /// <returns>Whether every byte matches.</returns>
        internal static bool BytesEqual(ReadOnlyMemory<byte> a, ReadOnlyMemory<byte> b)
        {
            return a.Span.SequenceEqual(b.Span);
        }

        /// <summary>Gets the address of a contact's first advertised endpoint.</summary>
        /// <param name="peer">The contact.</param>
        /// <returns>The first endpoint address.</returns>
        internal static IPAddress Address(this DHTPeer peer)
        {
            return peer.Endpoints[0].Address;
        }

        /// <summary>Gets the TCP port of a contact's first advertised endpoint.</summary>
        /// <param name="peer">The contact.</param>
        /// <returns>The TCP port, or zero.</returns>
        internal static int TcpPort(this DHTPeer peer)
        {
            return peer.Endpoints[0].TcpPort;
        }

        /// <summary>Gets the UDP port of a contact's first advertised endpoint.</summary>
        /// <param name="peer">The contact.</param>
        /// <returns>The UDP port, or zero.</returns>
        internal static int UdpPort(this DHTPeer peer)
        {
            return peer.Endpoints[0].UdpPort;
        }

        /// <summary>Sends a sealed request to a contact's first endpoint, preferring TCP when it is advertised.</summary>
        /// <param name="transport">The raw transport.</param>
        /// <param name="peer">The destination contact.</param>
        /// <param name="packet">The sealed request.</param>
        /// <param name="token">The test deadline.</param>
        /// <returns>The opaque response, copied out of its pooled frame so a test can keep it.</returns>
        internal static async Task<ReadOnlyMemory<byte>> ExchangeAsync(this SocketTransport transport, DHTPeer peer, ReadOnlyMemory<byte> packet,
            CancellationToken token)
        {
            var protocol = peer.TcpPort() != 0 ? DHTTransport.Tcp : DHTTransport.Udp;
            var port = protocol == DHTTransport.Tcp ? peer.TcpPort() : peer.UdpPort();
            using var response = await transport.ExchangeAtAsync(protocol, new IPEndPoint(peer.Address(), port), packet, token);
            return response.Preserve();
        }
    }
}
