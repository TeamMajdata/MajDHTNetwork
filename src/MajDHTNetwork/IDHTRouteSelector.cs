using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// Chooses how a node reaches another node: which endpoints and transports to dial, and which relays to try afterwards.
    /// Implementations must be thread-safe and must not perform network I/O.
    /// </summary>
    /// <remarks>
    /// Routes are only attempted, never trusted: every response is still authenticated against the destination's identity.
    /// Authenticated routes that the node already learned through hole punching or rendezvous registrations are tried
    /// before the selected direct routes. The node attempts at most sixteen direct routes and thirty-two relay routes, and
    /// skips relay routes whose relay is local, the destination itself, expired, repeated or lacks relay capability.
    /// </remarks>
    public interface IDHTRouteSelector
    {
        /// <summary>Orders the direct endpoint and transport attempts for a destination.</summary>
        /// <param name="destination">The signed destination contact.</param>
        /// <param name="context">The local node's routing state.</param>
        /// <returns>The direct attempts in order; empty to skip direct access.</returns>
        IReadOnlyList<DHTDirectRoute> SelectDirectRoutes(DHTPeer destination, DHTRouteContext context);

        /// <summary>Orders the relays to try after every direct attempt failed.</summary>
        /// <param name="destination">The signed destination contact, including its relay hints.</param>
        /// <param name="knownRelays">Routed relay-capable contacts, nearest to the destination first.</param>
        /// <param name="context">The local node's routing state.</param>
        /// <returns>The relay attempts in order; empty to fail without relaying.</returns>
        IReadOnlyList<DHTRelayRoute> SelectRelayRoutes(DHTPeer destination, IReadOnlyList<DHTPeer> knownRelays, DHTRouteContext context);
    }
}
