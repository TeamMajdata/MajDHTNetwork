using System;
using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// Stores the authenticated contacts a node uses as lookup hops, together with the endpoints at which the node observed
    /// them, and answers nearest-peer queries. Implementations must be thread-safe: a node calls every member concurrently from
    /// request handlers and background work.
    /// </summary>
    /// <remarks>
    /// The node only passes contacts whose signature it verified and never passes private contacts. It still validates every
    /// returned peer, discarding expired, private, duplicate and local entries, so an implementation cannot make the node
    /// advertise unusable referrals. Members should return quickly and must not perform network I/O.
    /// </remarks>
    public interface IDHTRoutingTable
    {
        /// <summary>Binds the table to one node before any other member is called; a node calls this exactly once.</summary>
        /// <param name="localNodeId">The owning node's lowercase SHA-256 identifier.</param>
        /// <param name="bucketSize">The configured <see cref="DHTNodeOptions.BucketSize"/>.</param>
        /// <exception cref="InvalidOperationException">The table is already bound to a node.</exception>
        void Initialize(string localNodeId, int bucketSize);

        /// <summary>
        /// Records an authenticated contact; a higher sequence supersedes a known contact. A new contact may only be admitted
        /// when <paramref name="observed"/> is supplied; otherwise the call only refreshes a contact already present.
        /// </summary>
        /// <param name="contact">The authenticated, non-private contact.</param>
        /// <param name="observed">
        /// The endpoint at which the node itself exchanged an authenticated packet with the contact: the source of an inbound
        /// request answered by a direct Ping, or the destination that answered a request. It is merged into the contact's known
        /// endpoints and its address counts towards the per-network admission limits. Null when the exchange proved no endpoint,
        /// such as a response relayed by a Forwarder.
        /// </param>
        void Observe(DHTContact contact, DHTEndpoint? observed);

        /// <summary>Removes a node after it failed or became private.</summary>
        /// <param name="nodeId">The node identifier.</param>
        void Remove(string nodeId);

        /// <summary>Returns live peers nearest a routing identifier, nearest first, each at the endpoints observed for it.</summary>
        /// <param name="routingId">The lowercase SHA-256 target identifier.</param>
        /// <param name="count">The maximum number of peers to return.</param>
        /// <returns>A snapshot owned by the caller.</returns>
        IReadOnlyList<DHTPeer> Closest(string routingId, int count);
    }
}
