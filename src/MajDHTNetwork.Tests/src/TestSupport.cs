#nullable enable

using System;
using MajDHTNetwork.Protocol;

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

    }
}
