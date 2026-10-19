using System;
using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// Stores the authenticated contacts a node uses as lookup hops and answers nearest-contact queries.
    /// Implementations must be thread-safe: a node calls every member concurrently from request handlers and background work.
    /// </summary>
    /// <remarks>
    /// The node only passes contacts whose signature it verified and never passes private contacts. It still validates every
    /// returned contact, discarding expired, private, duplicate and local entries, so an implementation cannot make the node
    /// advertise unusable referrals. Members should return quickly and must not perform network I/O.
    /// </remarks>
    public interface IDHTRoutingTable
    {
        /// <summary>Binds the table to one node before any other member is called; a node calls this exactly once.</summary>
        /// <param name="localNodeId">The owning node's lowercase SHA-256 identifier.</param>
        /// <param name="bucketSize">The configured <see cref="DHTNodeOptions.BucketSize"/>.</param>
        /// <exception cref="InvalidOperationException">The table is already bound to a node.</exception>
        void Initialize(string localNodeId, int bucketSize);

        /// <summary>Records an authenticated contact after a successful exchange; a higher sequence supersedes a known contact.</summary>
        /// <param name="peer">The verified, non-private contact.</param>
        void Observe(DHTPeer peer);

        /// <summary>Removes a node after it failed or became private.</summary>
        /// <param name="nodeId">The node identifier.</param>
        void Remove(string nodeId);

        /// <summary>Returns live contacts nearest a routing identifier, nearest first.</summary>
        /// <param name="routingId">The lowercase SHA-256 target identifier.</param>
        /// <param name="count">The maximum number of contacts to return.</param>
        /// <returns>A snapshot owned by the caller.</returns>
        IReadOnlyList<DHTPeer> Closest(string routingId, int count);
    }
}
