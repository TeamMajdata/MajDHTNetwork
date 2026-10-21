using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// Chooses how a node reaches another node: which observed endpoints and transports to dial, and which Traversal and
    /// Forwarder nodes to try afterwards. Implementations must be thread-safe and must not perform network I/O.
    /// </summary>
    /// <remarks>
    /// Routes are only attempted, never trusted: every response is still authenticated against the destination's identity.
    /// Authenticated routes that the node already learned through hole punching, traversal registrations or forwarding
    /// sessions are tried before the selected direct routes. The node attempts at most sixteen direct routes and thirty-two
    /// assisted routes, and skips assisted routes whose assistant is local, the destination itself, expired, repeated or
    /// lacks both the Traversal and the Forwarder capability.
    /// </remarks>
    public interface IDHTRouteSelector
    {
        /// <summary>Orders the direct endpoint and transport attempts for a destination.</summary>
        /// <param name="destination">The destination at the endpoints this node or a referrer observed for it.</param>
        /// <param name="context">The local node's routing state.</param>
        /// <returns>The direct attempts in order; empty to skip direct access.</returns>
        IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context);

        /// <summary>Orders the Traversal and Forwarder nodes to try after every direct attempt failed.</summary>
        /// <param name="destination">The destination, whose contact carries its hints.</param>
        /// <param name="knownAssistants">Routed Traversal or Forwarder nodes, nearest to the destination first.</param>
        /// <param name="context">The local node's routing state.</param>
        /// <returns>The assisted attempts in order; empty to fail without assistance.</returns>
        IReadOnlyList<DHTAssistedRoute> SelectAssistedRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownAssistants, DHTRouteContext context);
    }
}
