using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Configures a node before it starts; the node takes a validated snapshot.</summary>
    public sealed class DHTNodeOptions
    {
        /// <summary>The maximum number of configured bootstrap endpoints.</summary>
        private const int MaxBootstrapEndpoints = 16;

        /// <summary>
        /// Gets or sets the initial <see cref="IdentityWorkBits"/> of new option instances. Only test hosts change it, to avoid
        /// computing proofs of work for every short-lived test identity.
        /// </summary>
        internal static int DefaultIdentityWorkBits { get; set; } = 22;

        /// <summary>
        /// Gets or sets one or two local interfaces, at most one per address family; wildcard interfaces are allowed.
        /// Listing an IPv4 and an IPv6 address enables dual-stack listeners on the same configured ports.
        /// </summary>
        public IList<IPAddress> ListenAddresses { get; set; } = new List<IPAddress> { IPAddress.Loopback };
        /// <summary>
        /// Gets or sets up to four directly reachable addresses, such as a fixed public address or a router port mapping.
        /// Each address must match a listener's address family and is advertised as configured and public.
        /// When empty, specific (non-wildcard) listen addresses are advertised and reachability is discovered automatically.
        /// </summary>
        public IList<IPAddress> AdvertisedAddresses { get; set; } = new List<IPAddress>();
        /// <summary>Gets or sets up to sixteen endpoints of existing nodes contacted to join the network.</summary>
        public IList<IPEndPoint> BootstrapEndpoints { get; set; } = new List<IPEndPoint>();
        /// <summary>Gets or sets the TCP port, zero for an assigned port, or null to disable the TCP listener.</summary>
        public int? TcpPort { get; set; } = 0;
        /// <summary>Gets or sets the UDP port, zero for an assigned port, or null to disable the UDP listener.</summary>
        public int? UdpPort { get; set; } = 0;
        /// <summary>Gets or sets the transport to try first before trying the other advertised transport.</summary>
        public DHTTransport PreferredTransport { get; set; } = DHTTransport.Tcp;
        /// <summary>Gets or sets the capabilities advertised and enforced by this node.</summary>
        public DHTCapabilities Capabilities { get; set; } = DHTCapabilities.Download | DHTCapabilities.Provide;
        /// <summary>Gets or sets the maximum entries in each of the 256 XOR distance buckets.</summary>
        public int BucketSize { get; set; } = 8;
        /// <summary>Gets or sets the number of concurrent queries during an iterative lookup.</summary>
        public int LookupParallelism { get; set; } = 3;
        /// <summary>Gets or sets the maximum distinct peers queried during one lookup.</summary>
        public int MaxLookupQueries { get; set; } = 64;
        /// <summary>Gets or sets the maximum simultaneous incoming requests and relay forwards.</summary>
        public int MaxConcurrentRequests { get; set; } = 32;
        /// <summary>Gets or sets the maximum locally indexed publication records.</summary>
        public int MaxRecords { get; set; } = 1024;
        /// <summary>Gets or sets the maximum file length accepted by this node, up to 1 GiB.</summary>
        public long MaxFileSize { get; set; } = 1024L * 1024 * 1024;
        /// <summary>Gets or sets the block size for new publications, between 1 KiB and 32 KiB.</summary>
        public int BlockSize { get; set; } = 16384;
        /// <summary>
        /// Gets or sets the identity proof-of-work difficulty in leading zero bits, from 0 to 28. This node proves it in its own
        /// contact and rejects contacts that prove less; every node of one network must use the same value.
        /// </summary>
        public int IdentityWorkBits { get; set; } = DefaultIdentityWorkBits;
        /// <summary>Gets or sets the number of disjoint paths each iterative lookup follows, from 1 to 8.</summary>
        public int DisjointLookupPaths { get; set; } = 3;
        /// <summary>Gets or sets the maximum block requests one download keeps in flight across all providers, from 1 to 64.</summary>
        public int MaxConcurrentBlockRequests { get; set; } = 8;
        /// <summary>Gets or sets the maximum block requests one download keeps in flight to a single provider, from 1 to 16.</summary>
        public int MaxBlockRequestsPerPeer { get; set; } = 2;
        /// <summary>Gets or sets the timeout for each transport attempt, including a relay response.</summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(5);
        /// <summary>Gets or sets the total UDP transmissions per request, including the first transmission.</summary>
        public int UdpAttempts { get; set; } = 3;
        /// <summary>Gets or sets the lease for new publications, from one second to seven days.</summary>
        public TimeSpan RecordLifetime { get; set; } = TimeSpan.FromHours(24);
        /// <summary>Gets or sets the interval for peer refresh, expiry cleanup and local record reannouncement.</summary>
        public TimeSpan MaintenanceInterval { get; set; } = TimeSpan.FromMinutes(5);
        /// <summary>Gets or sets whether this client registers with relays, checks its reachability and attempts assisted direct connections.</summary>
        public bool EnableNatTraversal { get; set; } = true;
        /// <summary>Gets or sets the total budget for an assisted direct connection or dial-back, from 50 milliseconds to two minutes.</summary>
        public TimeSpan NatTraversalTimeout { get; set; } = TimeSpan.FromSeconds(5);
        /// <summary>Gets or sets the interval for refreshing mappings and receiving introductions, from 50 milliseconds to one minute.</summary>
        public TimeSpan NatPollInterval { get; set; } = TimeSpan.FromSeconds(1);
        /// <summary>Gets or sets the relay's observed mapping lease, at least three poll intervals and at most five minutes.</summary>
        public TimeSpan NatRegistrationLifetime { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Gets or sets the interval between reachability dial-back checks, from one minute to one day.</summary>
        public TimeSpan ReachabilityCheckInterval { get; set; } = TimeSpan.FromMinutes(30);
        /// <summary>Gets or sets the maximum observed peer registrations hosted by a relay and retained direct routes.</summary>
        public int MaxNatRegistrations { get; set; } = 256;
        /// <summary>Gets or sets the maximum assisting relays maintained by this client, from one to sixteen.</summary>
        public int MaxNatRelays { get; set; } = 4;
        /// <summary>Gets or sets the standard logger used by node services; defaults to a disabled logger.</summary>
        public ILogger Logger { get; set; } = NullLogger.Instance;

        /// <summary>Gets the validated listen address for an address family, or null when none is configured.</summary>
        /// <param name="family">The address family.</param>
        /// <returns>The configured listen address.</returns>
        internal IPAddress? ListenAddress(AddressFamily family)
        {
            foreach (var address in ListenAddresses)
            {
                if (address.AddressFamily == family)
                {
                    return address;
                }
            }
            return null;
        }

        /// <summary>Validates options and returns a separate instance for node ownership.</summary>
        /// <returns>A validated snapshot.</returns>
        /// <exception cref="ArgumentException">An address, endpoint, port, limit or timeout is invalid.</exception>
        internal DHTNodeOptions Snapshot()
        {
            if ((TcpPort == null && UdpPort == null)
                || TcpPort < 0 || TcpPort > 65535 || UdpPort < 0 || UdpPort > 65535
                || BucketSize < 1 || BucketSize > 16 || LookupParallelism < 1 || LookupParallelism > 16
                || MaxLookupQueries < BucketSize || MaxLookupQueries > 1024
                || MaxConcurrentRequests < 1 || MaxConcurrentRequests > 1024
                || MaxRecords < 1 || MaxRecords > 65536 || MaxFileSize < 0 || MaxFileSize > 1024L * 1024 * 1024
                || BlockSize < 1024 || BlockSize > 32768 || UdpAttempts < 1 || UdpAttempts > 5
                || IdentityWorkBits < 0 || IdentityWorkBits > 28 || DisjointLookupPaths < 1 || DisjointLookupPaths > 8
                || MaxConcurrentBlockRequests < 1 || MaxConcurrentBlockRequests > 64
                || MaxBlockRequestsPerPeer < 1 || MaxBlockRequestsPerPeer > 16
                || RequestTimeout < TimeSpan.FromMilliseconds(50) || RequestTimeout > TimeSpan.FromMinutes(2)
                || RecordLifetime < TimeSpan.FromSeconds(1) || RecordLifetime > TimeSpan.FromDays(7)
                || MaintenanceInterval < TimeSpan.FromSeconds(1) || MaintenanceInterval > TimeSpan.FromHours(1)
                || NatTraversalTimeout < TimeSpan.FromMilliseconds(50) || NatTraversalTimeout > TimeSpan.FromMinutes(2)
                || NatPollInterval < TimeSpan.FromMilliseconds(50) || NatPollInterval > TimeSpan.FromMinutes(1)
                || NatRegistrationLifetime < TimeSpan.FromSeconds(1) || NatRegistrationLifetime > TimeSpan.FromMinutes(5)
                || NatRegistrationLifetime.Ticks / 3 < NatPollInterval.Ticks
                || ReachabilityCheckInterval < TimeSpan.FromMinutes(1) || ReachabilityCheckInterval > TimeSpan.FromDays(1)
                || MaxNatRegistrations < 1 || MaxNatRegistrations > 65536 || MaxNatRelays < 1 || MaxNatRelays > 16
                || (PreferredTransport != DHTTransport.Tcp && PreferredTransport != DHTTransport.Udp)
                || (Capabilities & ~(DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Relay)) != 0)
            {
                throw new ArgumentException("Invalid DHT node port, capability, limit or timeout.");
            }
            var copy = (DHTNodeOptions)MemberwiseClone();
            copy.Logger = Logger ?? NullLogger.Instance;
            copy.ListenAddresses = CopyListenAddresses(ListenAddresses);
            copy.AdvertisedAddresses = CopyAdvertisedAddresses(AdvertisedAddresses, copy);
            copy.BootstrapEndpoints = CopyBootstrapEndpoints(BootstrapEndpoints);
            return copy;
        }

        /// <summary>Validates and copies the listener addresses.</summary>
        /// <param name="addresses">The configured listener addresses.</param>
        /// <returns>An owned copy.</returns>
        /// <exception cref="ArgumentException">The list is empty, too long, repeats a family or contains a non-unicast address.</exception>
        private static List<IPAddress> CopyListenAddresses(IList<IPAddress>? addresses)
        {
            if (addresses == null || addresses.Count < 1 || addresses.Count > 2)
            {
                throw new ArgumentException("Provide one listen address, or one IPv4 and one IPv6 address for dual-stack listening.");
            }
            var result = new List<IPAddress>(addresses.Count);
            foreach (var address in addresses)
            {
                if (address == null || (!NetworkScope.IsWildcard(address) && !NetworkScope.IsUnicast(address))
                    || (address.AddressFamily != AddressFamily.InterNetwork && address.AddressFamily != AddressFamily.InterNetworkV6))
                {
                    throw new ArgumentException("Listen addresses must be IPv4 or IPv6 unicast or wildcard addresses.");
                }
                foreach (var existing in result)
                {
                    if (existing.AddressFamily == address.AddressFamily)
                    {
                        throw new ArgumentException("Configure at most one listen address per address family.");
                    }
                }
                result.Add(IPAddress.Parse(address.ToString()));
            }
            return result;
        }

        /// <summary>Validates and copies the configured advertised addresses.</summary>
        /// <param name="addresses">The configured addresses.</param>
        /// <param name="snapshot">The snapshot whose listener families must match.</param>
        /// <returns>An owned copy.</returns>
        /// <exception cref="ArgumentException">An address is invalid, repeated or has no listener of its family.</exception>
        private static List<IPAddress> CopyAdvertisedAddresses(IList<IPAddress>? addresses, DHTNodeOptions snapshot)
        {
            var result = new List<IPAddress>();
            if (addresses == null)
            {
                return result;
            }
            if (addresses.Count > DHTPeer.MaxEndpoints)
            {
                throw new ArgumentException("Configure at most four advertised addresses.");
            }
            foreach (var address in addresses)
            {
                if (address == null || !NetworkScope.IsUnicast(address) || snapshot.ListenAddress(address.AddressFamily) == null
                    || result.Contains(address))
                {
                    throw new ArgumentException("Advertised addresses must be distinct unicast addresses of a listener's address family.");
                }
                result.Add(IPAddress.Parse(address.ToString()));
            }
            return result;
        }

        /// <summary>Validates and copies the bootstrap endpoints.</summary>
        /// <param name="endpoints">The configured endpoints.</param>
        /// <returns>An owned copy.</returns>
        /// <exception cref="ArgumentException">An endpoint is invalid or there are too many endpoints.</exception>
        private static List<IPEndPoint> CopyBootstrapEndpoints(IList<IPEndPoint>? endpoints)
        {
            var result = new List<IPEndPoint>();
            if (endpoints == null)
            {
                return result;
            }
            if (endpoints.Count > MaxBootstrapEndpoints)
            {
                throw new ArgumentException("Configure at most sixteen bootstrap endpoints.");
            }
            foreach (var endpoint in endpoints)
            {
                if (endpoint == null || endpoint.Port < 1 || endpoint.Port > 65535 || !NetworkScope.IsUnicast(endpoint.Address))
                {
                    throw new ArgumentException("Bootstrap endpoints require a unicast address and a non-zero port.");
                }
                result.Add(new IPEndPoint(IPAddress.Parse(endpoint.Address.ToString()), endpoint.Port));
            }
            return result;
        }
    }
}
