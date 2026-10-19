using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System;
using System.Net;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Configures a node before it starts; the node takes a validated snapshot.</summary>
    public sealed class DHTNodeOptions
    {
        /// <summary>Gets or sets the local interface, including a wildcard interface if required.</summary>
        public IPAddress ListenAddress { get; set; } = IPAddress.Loopback;
        /// <summary>Gets or sets the reachable address in signed invitations; required for wildcard listeners.</summary>
        public IPAddress? AdvertisedAddress { get; set; }
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
        /// <summary>Gets or sets the timeout for each transport attempt, including a relay response.</summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(5);
        /// <summary>Gets or sets the total UDP transmissions per request, including the first transmission.</summary>
        public int UdpAttempts { get; set; } = 3;
        /// <summary>Gets or sets the lease for new publications, from one second to seven days.</summary>
        public TimeSpan RecordLifetime { get; set; } = TimeSpan.FromHours(24);
        /// <summary>Gets or sets the interval for peer refresh, expiry cleanup and local record reannouncement.</summary>
        public TimeSpan MaintenanceInterval { get; set; } = TimeSpan.FromMinutes(5);
        /// <summary>Gets or sets whether this client registers with relays and attempts assisted direct connections.</summary>
        public bool EnableNatTraversal { get; set; } = true;
        /// <summary>Gets or sets the total budget for an assisted direct connection, from 50 milliseconds to two minutes.</summary>
        public TimeSpan NatTraversalTimeout { get; set; } = TimeSpan.FromSeconds(5);
        /// <summary>Gets or sets the interval for refreshing mappings and receiving introductions, from 50 milliseconds to one minute.</summary>
        public TimeSpan NatPollInterval { get; set; } = TimeSpan.FromSeconds(1);
        /// <summary>Gets or sets the relay's observed mapping lease, at least three poll intervals and at most five minutes.</summary>
        public TimeSpan NatRegistrationLifetime { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Gets or sets the maximum observed peer registrations hosted by a relay and retained direct routes.</summary>
        public int MaxNatRegistrations { get; set; } = 256;
        /// <summary>Gets or sets the maximum assisting relays maintained by this client, from one to sixteen.</summary>
        public int MaxNatRelays { get; set; } = 4;
        /// <summary>Gets or sets the standard logger used by node services; defaults to a disabled logger.</summary>
        public ILogger Logger { get; set; } = NullLogger.Instance;

        /// <summary>Validates options and returns a separate instance for node ownership.</summary>
        /// <returns>A validated snapshot.</returns>
        /// <exception cref="ArgumentException">An address, port, limit or timeout is invalid.</exception>
        internal DHTNodeOptions Snapshot()
        {
            if (ListenAddress == null || (TcpPort == null && UdpPort == null)
                || TcpPort < 0 || TcpPort > 65535 || UdpPort < 0 || UdpPort > 65535
                || BucketSize < 1 || BucketSize > 16 || LookupParallelism < 1 || LookupParallelism > 16
                || MaxLookupQueries < BucketSize || MaxLookupQueries > 1024
                || MaxConcurrentRequests < 1 || MaxConcurrentRequests > 1024
                || MaxRecords < 1 || MaxRecords > 65536 || MaxFileSize < 0 || MaxFileSize > 1024L * 1024 * 1024
                || BlockSize < 1024 || BlockSize > 32768 || UdpAttempts < 1 || UdpAttempts > 5
                || RequestTimeout < TimeSpan.FromMilliseconds(50) || RequestTimeout > TimeSpan.FromMinutes(2)
                || RecordLifetime < TimeSpan.FromSeconds(1) || RecordLifetime > TimeSpan.FromDays(7)
                || MaintenanceInterval < TimeSpan.FromSeconds(1) || MaintenanceInterval > TimeSpan.FromHours(1)
                || NatTraversalTimeout < TimeSpan.FromMilliseconds(50) || NatTraversalTimeout > TimeSpan.FromMinutes(2)
                || NatPollInterval < TimeSpan.FromMilliseconds(50) || NatPollInterval > TimeSpan.FromMinutes(1)
                || NatRegistrationLifetime < TimeSpan.FromSeconds(1) || NatRegistrationLifetime > TimeSpan.FromMinutes(5)
                || NatRegistrationLifetime.Ticks / 3 < NatPollInterval.Ticks
                || MaxNatRegistrations < 1 || MaxNatRegistrations > 65536 || MaxNatRelays < 1 || MaxNatRelays > 16
                || (PreferredTransport != DHTTransport.Tcp && PreferredTransport != DHTTransport.Udp)
                || (Capabilities & ~(DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Relay)) != 0)
            {
                throw new ArgumentException("Invalid DHT node address, port, capability, limit or timeout.");
            }
            var address = AdvertisedAddress ?? ListenAddress;
            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.IsIPv6Multicast
                || address.Equals(IPAddress.None) || address.AddressFamily != ListenAddress.AddressFamily)
            {
                throw new ArgumentException("Provide a reachable unicast advertised address in the listener address family.");
            }
            var copy = (DHTNodeOptions)MemberwiseClone();
            copy.Logger = Logger ?? NullLogger.Instance;
            copy.ListenAddress = IPAddress.Parse(ListenAddress.ToString());
            copy.AdvertisedAddress = IPAddress.Parse(address.ToString());
            return copy;
        }
    }
}
