using System;
using System.Net;
using System.Net.Sockets;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Classifies IP addresses by routing scope and compares their network prefixes.</summary>
    internal static class NetworkScope
    {
        /// <summary>The routing scope of an address.</summary>
        internal enum Scope
        {
            /// <summary>A host-local loopback address.</summary>
            Loopback,
            /// <summary>A link-local address.</summary>
            LinkLocal,
            /// <summary>A private, carrier-grade NAT or unique-local address.</summary>
            Private,
            /// <summary>A globally routed address.</summary>
            Global
        }

        /// <summary>Checks whether an address can identify one remote interface.</summary>
        /// <param name="address">The address to inspect.</param>
        /// <returns>Whether the address is a canonical unicast address.</returns>
        internal static bool IsUnicast(IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork && address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                return false;
            }
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.None)
                || address.Equals(IPAddress.Broadcast) || address.IsIPv6Multicast)
            {
                return false;
            }
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                var first = address.GetAddressBytes()[0];
                return first < 224;
            }
            return true;
        }

        /// <summary>Checks whether an address is a wildcard listener address.</summary>
        /// <param name="address">The address to inspect.</param>
        /// <returns>Whether the address is the IPv4 or IPv6 wildcard.</returns>
        internal static bool IsWildcard(IPAddress address)
        {
            return address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any);
        }

        /// <summary>Classifies an address by routing scope.</summary>
        /// <param name="address">The unicast address.</param>
        /// <returns>The routing scope.</returns>
        internal static Scope Classify(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            if (IPAddress.IsLoopback(address))
            {
                return Scope.Loopback;
            }
            var bytes = address.GetAddressBytes();
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                if (bytes[0] == 169 && bytes[1] == 254)
                {
                    return Scope.LinkLocal;
                }
                if (bytes[0] == 10 || (bytes[0] == 172 && (bytes[1] & 0xf0) == 16) || (bytes[0] == 192 && bytes[1] == 168)
                    || (bytes[0] == 100 && (bytes[1] & 0xc0) == 64))
                {
                    return Scope.Private;
                }
                return Scope.Global;
            }
            if (address.IsIPv6LinkLocal)
            {
                return Scope.LinkLocal;
            }
            if ((bytes[0] & 0xfe) == 0xfc || address.IsIPv6SiteLocal)
            {
                return Scope.Private;
            }
            return Scope.Global;
        }

        /// <summary>Gets a stable key for the operator network of an address, matching <see cref="SameNetwork"/>.</summary>
        /// <param name="address">The address.</param>
        /// <returns>The IPv4 /24 or IPv6 /32 prefix for non-loopback addresses, or the exact loopback address.</returns>
        internal static string NetworkKey(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }
            if (IPAddress.IsLoopback(address))
            {
                return address.ToString();
            }
            var bytes = address.GetAddressBytes();
            var prefix = PrefixBytes(address.AddressFamily);
            Array.Clear(bytes, prefix, bytes.Length - prefix);
            return new IPAddress(bytes) + (address.AddressFamily == AddressFamily.InterNetwork ? "/24" : "/32");
        }

        /// <summary>Checks whether Sybil diversity limits apply to an address.</summary>
        /// <param name="address">The address.</param>
        /// <returns>
        /// Whether the address is globally routed; loopback, private and link-local peers share a network by design, for example
        /// on a LAN, and cannot be minted by a remote attacker.
        /// </returns>
        internal static bool IsDiversityLimited(IPAddress address)
        {
            return Classify(address) == Scope.Global;
        }

        /// <summary>Checks whether two addresses belong to the same operator network.</summary>
        /// <param name="left">The first address.</param>
        /// <param name="right">The second address.</param>
        /// <returns>
        /// Whether the addresses share an IPv4 /24 or IPv6 /32 prefix; loopback addresses compare exactly so that
        /// distinct loopback hosts can model distinct networks.
        /// </returns>
        internal static bool SameNetwork(IPAddress left, IPAddress right)
        {
            if (left.IsIPv4MappedToIPv6)
            {
                left = left.MapToIPv4();
            }
            if (right.IsIPv4MappedToIPv6)
            {
                right = right.MapToIPv4();
            }
            if (left.AddressFamily != right.AddressFamily)
            {
                return false;
            }
            if (IPAddress.IsLoopback(left) || IPAddress.IsLoopback(right))
            {
                return left.Equals(right);
            }
            var a = left.GetAddressBytes();
            var b = right.GetAddressBytes();
            var prefix = PrefixBytes(left.AddressFamily);
            return a.AsSpan(0, prefix).SequenceEqual(b.AsSpan(0, prefix));
        }

        /// <summary>Gets the length of the operator-network prefix of an address family.</summary>
        /// <param name="family">The address family.</param>
        /// <returns>
        /// Three bytes (/24) for IPv4, and four bytes (/32) for IPv6, because a single IPv6 allocation commonly spans a /32 and
        /// would otherwise provide tens of thousands of distinct /48 networks.
        /// </returns>
        private static int PrefixBytes(AddressFamily family)
        {
            return family == AddressFamily.InterNetwork ? 3 : 4;
        }
    }
}
