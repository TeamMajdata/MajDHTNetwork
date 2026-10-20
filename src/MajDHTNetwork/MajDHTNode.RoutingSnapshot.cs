using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The maximum contacts in a routing snapshot: the largest possible routing table.</summary>
        private const int MaxSnapshotContacts = 4096;
        /// <summary>The maximum saved contacts contacted at once while a snapshot is restored.</summary>
        private const int MaxRestoreParallelism = 16;

        /// <summary>
        /// Gets how many saved contacts a restoration contacts at once: at most <see cref="MaxRestoreParallelism"/> and at most
        /// half of the outgoing exchange budget, which leaves room for a background bootstrap and lookups.
        /// </summary>
        private int RestoreParallelism => Math.Max(1, Math.Min(MaxRestoreParallelism, _options.MaxConcurrentRequests / 2));

        /// <summary>
        /// Exports the routing table: the identity and advertised endpoints of every contact currently used as a lookup hop,
        /// nearest to this node first. Persist the result with the application's storage and pass it to
        /// <see cref="RestoreRoutingTableAsync"/> after a restart, so the node rejoins through the nodes it already knew
        /// instead of depending on bootstrap endpoints alone.
        /// </summary>
        /// <returns>An owned snapshot without signatures, keys or content; it may describe no contacts.</returns>
        /// <remarks>
        /// The snapshot keeps endpoints rather than signed contacts: contact leases last at most a day, so a snapshot restored
        /// later has to ask every endpoint for its current signed contact anyway. It can be taken at any time, including
        /// before the node starts and after it stopped.
        /// </remarks>
        public byte[] ExportRoutingTable()
        {
            var contacts = new List<DHTPeer>();
            foreach (var peer in RoutedPeers(NodeId, MaxSnapshotContacts))
            {
                if (peer.Endpoints.Count != 0)
                {
                    contacts.Add(peer);
                }
            }
            using var writer = new Wire();
            writer.Put(ProtocolTags.RoutingSnapshot);
            writer.PutLong(contacts.Count);
            foreach (var peer in contacts)
            {
                writer.PutText(peer.NodeId);
                writer.PutLong(peer.Endpoints.Count);
                foreach (var endpoint in peer.Endpoints)
                {
                    DHTPeer.WriteEndpoint(writer, endpoint);
                }
            }
            return writer.ToArray();
        }

        /// <summary>
        /// Restores a routing table exported by <see cref="ExportRoutingTable"/>: asks the saved endpoints for their current
        /// signed contacts, admits every node that still answers under its saved identity, registers with the answering
        /// relays when NAT traversal is enabled, and then discovers this node's current neighbors. Endpoints that no longer
        /// answer, or answer under another identity, are skipped.
        /// </summary>
        /// <param name="snapshot">The exported snapshot.</param>
        /// <param name="cancellationToken">Cancels the restoration.</param>
        /// <returns>The number of saved contacts that answered and were admitted; zero when none did.</returns>
        /// <remarks>
        /// At most sixteen saved contacts, and at most half of <see cref="DHTNodeOptions.MaxConcurrentRequests"/>, are
        /// contacted at once, each at its saved endpoints in order with the preferred transport first, so a snapshot full of
        /// unreachable nodes costs a few request timeouts per sixteen contacts.
        /// Whoever answers at a saved endpoint under the saved identity becomes a contact, so, like bootstrap endpoints, a
        /// snapshot must come from the application's own trusted storage. Restoring and bootstrapping combine freely.
        /// </remarks>
        /// <exception cref="InvalidDataException">The snapshot is malformed.</exception>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        /// <exception cref="OperationCanceledException">The restoration was cancelled.</exception>
        public async Task<int> RestoreRoutingTableAsync(ReadOnlyMemory<byte> snapshot, CancellationToken cancellationToken = default)
        {
            var contacts = ReadRoutingSnapshot(snapshot);
            using var cancellation = OperationCancellation(cancellationToken);
            if (contacts.Count == 0)
            {
                Log(LogLevel.Information, "The routing snapshot describes no contacts.");
                return 0;
            }
            var restored = 0;
            await ForEachAsync(contacts, RestoreParallelism, async contact =>
            {
                if (await RestoreContactAsync(contact, cancellation.Token).ConfigureAwait(false))
                {
                    Interlocked.Increment(ref restored);
                }
            }).ConfigureAwait(false);
            if (restored == 0)
            {
                Log(LogLevel.Warning, "No saved routing contact answered under its saved identity.");
                return 0;
            }
            await LookupAsync(0, NodeId, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Routing table restored and neighbor discovery completed.");
            return restored;
        }

        /// <summary>Asks a saved contact's endpoints for its current signed contact until one answers under the saved identity.</summary>
        /// <param name="contact">The saved contact.</param>
        /// <param name="cancellationToken">Cancels the attempts.</param>
        /// <returns>Whether the node answered and was admitted.</returns>
        /// <exception cref="OperationCanceledException">The restoration was cancelled.</exception>
        private async Task<bool> RestoreContactAsync(SavedContact contact, CancellationToken cancellationToken)
        {
            if (contact.NodeId == NodeId)
            {
                return false;
            }
            foreach (var endpoint in contact.Endpoints)
            {
                foreach (var transport in new[] { _options.PreferredTransport, OtherTransport(_options.PreferredTransport) })
                {
                    var port = endpoint.Port(transport);
                    if (port == 0)
                    {
                        continue;
                    }
                    try
                    {
                        var peer = await HelloAtAsync(transport, new IPEndPoint(endpoint.NetworkAddress, port), contact.NodeId, cancellationToken)
                            .ConfigureAwait(false);
                        if ((peer.Capabilities & DHTCapabilities.Relay) != 0 && HasRelayRoom())
                        {
                            await RegisterBootstrapRelayAsync(peer, cancellationToken).ConfigureAwait(false);
                        }
                        return true;
                    }
                    catch (Exception exception) when (IsPeerFailure(exception) || exception is OperationCanceledException)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        Log(LogLevel.Debug, "A saved routing contact did not answer at one of its endpoints: ", exception);
                    }
                }
            }
            return false;
        }

        /// <summary>Checks whether this node may still register with another rendezvous relay.</summary>
        /// <returns>Whether NAT traversal is enabled and the relay limit is not reached.</returns>
        private bool HasRelayRoom()
        {
            if (!_options.EnableNatTraversal)
            {
                return false;
            }
            lock (_gate)
            {
                return _natRelays.Count < _options.MaxNatRelays;
            }
        }

        /// <summary>Decodes a routing snapshot.</summary>
        /// <param name="snapshot">The exported bytes.</param>
        /// <returns>The saved contacts in their saved order.</returns>
        /// <exception cref="InvalidDataException">The snapshot is malformed.</exception>
        private static List<SavedContact> ReadRoutingSnapshot(ReadOnlyMemory<byte> snapshot)
        {
            using var reader = new Wire(snapshot);
            if (!reader.Tag(ProtocolTags.RoutingSnapshot))
            {
                throw new InvalidDataException("Unsupported routing snapshot version.");
            }
            var count = reader.Long();
            if (count < 0 || count > MaxSnapshotContacts)
            {
                throw new InvalidDataException("Invalid routing snapshot contact count.");
            }
            var contacts = new List<SavedContact>((int)count);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var index = 0; index < count; index++)
            {
                var nodeId = reader.Text(64);
                if (!Crypto.IsHash(nodeId) || !seen.Add(nodeId))
                {
                    throw new InvalidDataException("Invalid or repeated routing snapshot node identifier.");
                }
                var endpointCount = reader.Long();
                if (endpointCount < 1 || endpointCount > DHTPeer.MaxEndpoints)
                {
                    throw new InvalidDataException("Invalid routing snapshot endpoint count.");
                }
                var endpoints = new DHTEndpoint[endpointCount];
                for (var position = 0; position < endpoints.Length; position++)
                {
                    endpoints[position] = DHTPeer.ReadEndpoint(reader);
                }
                contacts.Add(new SavedContact(nodeId, endpoints));
            }
            reader.End();
            return contacts;
        }

        /// <summary>A contact as kept in a routing snapshot: its identity and the endpoints it advertised when exported.</summary>
        private sealed class SavedContact
        {
            /// <summary>Gets the node identifier that must answer at one of the endpoints.</summary>
            internal string NodeId { get; }
            /// <summary>Gets the advertised endpoints in their saved order.</summary>
            internal IReadOnlyList<DHTEndpoint> Endpoints { get; }

            /// <summary>Creates a saved contact.</summary>
            /// <param name="nodeId">The node identifier.</param>
            /// <param name="endpoints">The advertised endpoints.</param>
            internal SavedContact(string nodeId, IReadOnlyList<DHTEndpoint> endpoints)
            {
                NodeId = nodeId;
                Endpoints = endpoints;
            }
        }
    }
}
