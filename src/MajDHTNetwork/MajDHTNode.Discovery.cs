using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The maximum provider claims per file from one globally routed network.</summary>
        internal const int MaxProvidersPerNetwork = 3;

        /// <summary>Joins the network through every configured bootstrap endpoint, then discovers neighbors.</summary>
        /// <param name="cancellationToken">Cancels joining and initial discovery.</param>
        /// <returns>The number of bootstrap endpoints that answered.</returns>
        /// <remarks>
        /// Each endpoint first returns its signed contact through an unencrypted, signed Hello exchange. The library cannot
        /// authenticate which identity should answer at an endpoint, so configure endpoints only from trusted sources.
        /// </remarks>
        /// <exception cref="InvalidOperationException">The node is not running or no bootstrap endpoint is configured.</exception>
        /// <exception cref="IOException">No configured bootstrap endpoint answered.</exception>
        /// <exception cref="OperationCanceledException">Joining was cancelled.</exception>
        public async Task<int> BootstrapAsync(CancellationToken cancellationToken = default)
        {
            using var cancellation = OperationCancellation(cancellationToken);
            if (_options.BootstrapEndpoints.Count == 0)
            {
                throw new InvalidOperationException("No bootstrap endpoints are configured.");
            }
            var joined = 0;
            Exception? last = null;
            foreach (var endpoint in _options.BootstrapEndpoints)
            {
                try
                {
                    var peer = await HelloAsync(endpoint, _options.PreferredTransport, cancellation.Token).ConfigureAwait(false);
                    await RegisterBootstrapAssistantsAsync(peer, cancellation.Token).ConfigureAwait(false);
                    joined++;
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    last = exception;
                    Log(LogLevel.Warning, "Bootstrap endpoint did not answer: ", exception);
                }
            }
            if (joined == 0)
            {
                throw new IOException("No bootstrap endpoint answered.", last);
            }
            await LookupAsync(0, NodeId, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Bootstrap and neighbor discovery completed.");
            return joined;
        }

        /// <summary>
        /// Adds the node listening at an address and port, for example one a user typed or the application learned through
        /// its own channel: sends a signed Hello request through the transport to try first and, when that fails, through
        /// the other transport at the same port, admits the authenticated responder to the routing table, registers with it
        /// when it is a Traversal node or Forwarder and NAT traversal is enabled, and then discovers this node's neighbors through it.
        /// </summary>
        /// <param name="endpoint">The unicast address and port the node listens on.</param>
        /// <param name="preferredTransport">
        /// The transport to try first, or null for <see cref="DHTNodeOptions.PreferredTransport"/>; the other transport is
        /// tried at the same port when the first one does not answer.
        /// </param>
        /// <param name="cancellationToken">Cancels the exchange and the neighbor discovery.</param>
        /// <returns>The authenticated contact of the node that answered, at the endpoint that answered.</returns>
        /// <remarks>
        /// An endpoint does not identify a node: whoever answers at it becomes a contact, exactly as with a bootstrap
        /// endpoint, so add endpoints from trusted sources only. The node that answered is also returned, so the application
        /// can check or remember its identity.
        /// </remarks>
        /// <exception cref="ArgumentException">The endpoint is null, not unicast or has a zero port, or the transport is invalid.</exception>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        /// <exception cref="IOException">The endpoint did not answer through either transport.</exception>
        /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
        public async Task<DHTPeer> AddPeerAsync(IPEndPoint endpoint, DHTTransport? preferredTransport = null, CancellationToken cancellationToken = default)
        {
            if (endpoint == null || endpoint.Port < 1 || endpoint.Port > 65535 || !NetworkScope.IsUnicast(endpoint.Address))
            {
                throw new ArgumentException("A unicast address and a non-zero port are required.", nameof(endpoint));
            }
            var first = preferredTransport ?? _options.PreferredTransport;
            if (first != DHTTransport.Tcp && first != DHTTransport.Udp)
            {
                throw new ArgumentException("A TCP or UDP transport is required.", nameof(preferredTransport));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            var peer = await HelloAsync(NetworkScope.CopyEndpoint(endpoint), first, cancellation.Token).ConfigureAwait(false);
            await RegisterBootstrapAssistantsAsync(peer, cancellation.Token).ConfigureAwait(false);
            await LookupAsync(0, NodeId, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Peer added and neighbor discovery completed.");
            return peer;
        }

        /// <summary>Joins the network through an already known contact at the endpoints known for it.</summary>
        /// <param name="bootstrap">An unexpired remote peer.</param>
        /// <param name="cancellationToken">Cancels joining and initial discovery.</param>
        /// <returns>Completion after authentication and iterative neighbor discovery.</returns>
        /// <exception cref="ArgumentException">The contact is absent or local.</exception>
        /// <exception cref="IOException">The bootstrap node could not be contacted.</exception>
        /// <exception cref="OperationCanceledException">Joining was cancelled.</exception>
        internal async Task JoinAsync(DHTPeer bootstrap, CancellationToken cancellationToken = default)
        {
            if (bootstrap == null || bootstrap.NodeId == NodeId)
            {
                throw new ArgumentException("A remote bootstrap contact is required.", nameof(bootstrap));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            using var pong = await RequestAsync(bootstrap, Operation.Ping, Array.Empty<byte>(), cancellation.Token).ConfigureAwait(false);
            await RegisterBootstrapAssistantsAsync(bootstrap, cancellation.Token).ConfigureAwait(false);
            await LookupAsync(0, NodeId, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Bootstrap authentication and neighbor discovery completed.");
        }

        /// <summary>
        /// Registers with a bootstrap node that coordinates traversal and opens a forwarding session when it forwards traffic,
        /// while the respective limits leave room, logging rather than failing on errors.
        /// </summary>
        /// <param name="bootstrap">The authenticated bootstrap peer.</param>
        /// <param name="cancellationToken">Cancels registration.</param>
        /// <returns>Completion after the registration attempts.</returns>
        /// <exception cref="OperationCanceledException">Registration was cancelled.</exception>
        private async Task RegisterBootstrapAssistantsAsync(DHTPeer bootstrap, CancellationToken cancellationToken)
        {
            if ((bootstrap.Capabilities & DHTCapabilities.Traversal) != 0 && HasTraversalRoom())
            {
                try
                {
                    await RegisterTraversalAsync(bootstrap, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Warning, "Bootstrap traversal registration failed: ", exception);
                }
            }
            if ((bootstrap.Capabilities & DHTCapabilities.Forwarder) != 0 && HasForwarderRoom())
            {
                try
                {
                    await RegisterForwarderAsync(bootstrap, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Warning, "Bootstrap forwarding session failed: ", exception);
                }
            }
        }

        /// <summary>Learns the signed contact listening at an endpoint and the endpoint it observed for this node.</summary>
        /// <param name="endpoint">The remote endpoint, tried with one transport and then with the other one at the same port.</param>
        /// <param name="first">The transport to try first.</param>
        /// <param name="cancellationToken">Cancels the exchange.</param>
        /// <returns>The authenticated remote contact at the endpoint that answered.</returns>
        /// <exception cref="IOException">Neither transport answered.</exception>
        /// <exception cref="OperationCanceledException">The exchange was cancelled.</exception>
        private async Task<DHTPeer> HelloAsync(IPEndPoint endpoint, DHTTransport first, CancellationToken cancellationToken)
        {
            Exception? last = null;
            for (var attempt = 0; attempt < 2; attempt++)
            {
                var transport = attempt == 0 ? first : OtherTransport(first);
                try
                {
                    return await HelloAtAsync(transport, endpoint, null, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception) || exception is OperationCanceledException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    last = exception;
                }
            }
            throw new IOException("The endpoint did not answer a Hello request.", last);
        }

        /// <summary>
        /// Sends one signed Hello request through one transport and admits the authenticated responder as reachable at that
        /// endpoint.
        /// </summary>
        /// <param name="transport">The transport.</param>
        /// <param name="endpoint">The remote endpoint.</param>
        /// <param name="expectedNodeId">The identity that must answer, or null to accept any identity other than this node's.</param>
        /// <param name="cancellationToken">Cancels the exchange.</param>
        /// <returns>The authenticated remote contact at the endpoint that answered.</returns>
        /// <exception cref="IOException">The endpoint did not answer.</exception>
        /// <exception cref="CryptographicException">The response was forged, miscorrelated or signed by another identity.</exception>
        /// <exception cref="OperationCanceledException">The exchange was cancelled.</exception>
        private async Task<DHTPeer> HelloAtAsync(DHTTransport transport, IPEndPoint endpoint, string? expectedNodeId,
            CancellationToken cancellationToken)
        {
            var request = new Packet(LocalContact, Crypto.Random(16), (byte)Operation.Hello, ReadOnlyMemory<byte>.Empty);
            var counter = new TransmissionCounter();
            using var encoded = await _transport.ExchangeAtAsync(transport, endpoint, request.SealHello(_identity), cancellationToken, counter)
                .ConfigureAwait(false);
            // The contact and endpoint read below are copies, so the frame is released when this method ends.
            var response = Packet.Open(_identity, encoded.Bytes);
            if (response.Sender.NodeId == NodeId || !HasRequiredWork(response.Sender) || response.Kind != (request.Kind | 128)
                || !CryptographicOperations.FixedTimeEquals(response.RequestId.Span, request.RequestId.Span)
                || (expectedNodeId != null && response.Sender.NodeId != expectedNodeId))
            {
                throw new CryptographicException("Hello response sender, operation or correlation mismatch.");
            }
            using var reader = new Wire(ResponseStatus.ReadResult(response.Body));
            var observed = HelloMessage.ReadResponse(reader);
            // The endpoint answered authentically, which proves the responder is reachable there.
            var peer = DHTPeer.Observed(response.Sender, transport, endpoint);
            ObservePeer(response.Sender, peer.Endpoints[0]);
            RecordObservation(response.Sender, endpoint.Address, transport, observed);
            // The responder is unknown until it answers, so only answered Hello exchanges enter its statistics.
            RecordTransmissions(response.Sender.NodeId, transport, endpoint, counter);
            return peer;
        }

        /// <summary>Runs the initial bootstrap without failing node startup.</summary>
        /// <returns>Completion after the attempt.</returns>
        private async Task BootstrapInBackgroundAsync()
        {
            await Task.Yield();
            try
            {
                await BootstrapAsync(_lifetime.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception) when (IsPeerFailure(exception) || exception is InvalidOperationException)
            {
                Log(LogLevel.Warning, "Background bootstrap failed: ", exception);
            }
        }

        /// <summary>Finds reachable nodes nearest a SHA-256 routing identifier.</summary>
        /// <param name="routingId">The lowercase SHA-256 target identifier.</param>
        /// <param name="cancellationToken">Cancels the iterative lookup.</param>
        /// <returns>The nearest discovered peers, each at the endpoints observed for it.</returns>
        /// <exception cref="ArgumentException">The routing identifier is invalid.</exception>
        /// <exception cref="OperationCanceledException">The lookup was cancelled.</exception>
        public async Task<IReadOnlyList<DHTPeer>> FindNodesAsync(string routingId, CancellationToken cancellationToken = default)
        {
            Crypto.ParseHash(routingId);
            using var cancellation = OperationCancellation(cancellationToken);
            var result = await LookupAsync(0, routingId, cancellation.Token).ConfigureAwait(false);
            return result.Peers.AsReadOnly();
        }

        /// <summary>Resolves the highest observed unexpired publisher-signed record for a trusted key.</summary>
        /// <param name="key">The owner-scoped lookup key obtained through a trusted application channel.</param>
        /// <param name="cancellationToken">Cancels lookup.</param>
        /// <returns>The authenticated record, or null when no reachable node has it.</returns>
        /// <exception cref="ArgumentException">The key is uninitialized.</exception>
        /// <exception cref="OperationCanceledException">Lookup was cancelled.</exception>
        public async Task<DHTRecord?> ResolveAsync(DHTKey key, CancellationToken cancellationToken = default)
        {
            if (!key.IsValid)
            {
                throw new ArgumentException("An initialized publisher-scoped key is required.", nameof(key));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            var result = await LookupAsync(1, key.ToString(), cancellation.Token).ConfigureAwait(false);
            if (result.Record != null)
            {
                CacheRecord(result.Record, null);
            }
            return result.Record;
        }

        /// <summary>Discovers content providers independently of the alias used to publish the file.</summary>
        /// <param name="fileHash">The SHA-256 digest of the complete file.</param>
        /// <param name="cancellationToken">Cancels provider lookup.</param>
        /// <returns>Peers advertising content-providing capability, each at the endpoints observed for it.</returns>
        /// <exception cref="ArgumentException">The hash is invalid.</exception>
        /// <exception cref="OperationCanceledException">Lookup was cancelled.</exception>
        public async Task<IReadOnlyList<DHTPeer>> FindProvidersAsync(string fileHash, CancellationToken cancellationToken = default)
        {
            Crypto.ParseHash(fileHash);
            using var cancellation = OperationCancellation(cancellationToken);
            var result = await LookupAsync(2, fileHash, cancellation.Token).ConfigureAwait(false);
            return result.Providers.AsReadOnly();
        }

        /// <summary>
        /// Runs <see cref="DHTNodeOptions.DisjointLookupPaths"/> independent iterative lookups whose queried node sets never
        /// overlap, then merges their results, so that Sybil nodes capturing one path cannot hide a record or provider that an
        /// honest path reaches.
        /// </summary>
        /// <param name="mode">Zero for neighbors, one for a key, or two for content providers.</param>
        /// <param name="target">The routing identifier or canonical key.</param>
        /// <param name="cancellationToken">The lookup lifetime.</param>
        /// <returns>The discovered peers, record and provider set.</returns>
        /// <exception cref="InvalidDataException">A publisher signed conflicting content at the same revision.</exception>
        private async Task<LookupResult> LookupAsync(byte mode, string target, CancellationToken cancellationToken)
        {
            var routingId = mode == 1 ? DHTKey.Parse(target).RoutingId : target;
            var seeds = RoutedPeers(routingId, _options.BucketSize);
            var pathCount = Math.Max(1, Math.Min(_options.DisjointLookupPaths, seeds.Count));
            var pathSeeds = new List<DHTPeer>[pathCount];
            for (var path = 0; path < pathCount; path++)
            {
                pathSeeds[path] = new List<DHTPeer>();
            }
            // Distribute the nearest seeds round robin, so every path starts near the target with disjoint nodes.
            for (var index = 0; index < seeds.Count; index++)
            {
                pathSeeds[index % pathCount].Add(seeds[index]);
            }
            var budget = new LookupBudget(_options.MaxLookupQueries, pathCount);
            var paths = new Task<LookupResult>[pathCount];
            for (var path = 0; path < pathCount; path++)
            {
                paths[path] = LookupPathAsync(mode, target, routingId, pathSeeds[path], budget, path, cancellationToken);
            }
            var results = await Task.WhenAll(paths).ConfigureAwait(false);
            DHTRecord? best = null;
            var closest = new Dictionary<string, DHTPeer>();
            var providers = new Dictionary<string, DHTPeer>();
            if (mode == 1)
            {
                lock (_gate)
                {
                    if (_records.TryGetValue(target, out var record) && !record.IsExpired)
                    {
                        best = record;
                    }
                }
            }
            if (mode == 2)
            {
                foreach (var peer in LocalProviders(target))
                {
                    providers[peer.NodeId] = peer;
                }
            }
            foreach (var result in results)
            {
                if (result.Record != null)
                {
                    best = Newer(best, result.Record);
                }
                foreach (var peer in result.Peers)
                {
                    closest[peer.NodeId] = peer;
                }
                foreach (var provider in result.Providers)
                {
                    providers[provider.NodeId] = provider;
                }
            }
            var closestList = new List<DHTPeer>(closest.Values);
            XorDistanceComparer.Sort(closestList, routingId);
            if (closestList.Count > _options.BucketSize)
            {
                closestList.RemoveRange(_options.BucketSize, closestList.Count - _options.BucketSize);
            }
            var providerList = new List<DHTPeer>(providers.Values);
            XorDistanceComparer.Sort(providerList, routingId);
            if (providerList.Count > 16)
            {
                providerList.RemoveRange(16, providerList.Count - 16);
            }
            return new LookupResult(closestList, best, providerList);
        }

        /// <summary>Queries closer peers of one lookup path in bounded parallel rounds until its nearest set is exhausted.</summary>
        /// <param name="mode">Zero for neighbors, one for a key, or two for content providers.</param>
        /// <param name="target">The routing identifier or canonical key.</param>
        /// <param name="routingId">The routing identifier of the target.</param>
        /// <param name="seeds">The path's initial contacts.</param>
        /// <param name="budget">The node claims shared by every path and the per-path query budgets.</param>
        /// <param name="path">The index of this path in the budget.</param>
        /// <param name="cancellationToken">The lookup lifetime.</param>
        /// <returns>The path's responsive nearest contacts, best record and providers.</returns>
        /// <exception cref="InvalidDataException">A publisher signed conflicting content at the same revision.</exception>
        private async Task<LookupResult> LookupPathAsync(byte mode, string target, string routingId, List<DHTPeer> seeds, LookupBudget budget, int path,
            CancellationToken cancellationToken)
        {
            var candidates = new Dictionary<string, DHTPeer>();
            var providers = new Dictionary<string, DHTPeer>();
            var responsive = new HashSet<string>();
            DHTRecord? best = null;
            foreach (var peer in seeds)
            {
                candidates[peer.NodeId] = peer;
            }
            while (!budget.Exhausted(path))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var ordered = new List<DHTPeer>(candidates.Values);
                XorDistanceComparer.Sort(ordered, routingId);
                if (ordered.Count > _options.BucketSize)
                {
                    ordered.RemoveRange(_options.BucketSize, ordered.Count - _options.BucketSize);
                }
                var batch = new List<Task<LookupResult?>>();
                var queried = new List<DHTPeer>();
                foreach (var peer in ordered)
                {
                    // A node claimed by another path is never queried again, which keeps the paths disjoint.
                    if (!budget.TryClaim(path, peer.NodeId))
                    {
                        continue;
                    }
                    queried.Add(peer);
                    batch.Add(QueryLookupAsync(peer, mode, target, cancellationToken));
                    if (batch.Count >= _options.LookupParallelism || budget.Exhausted(path))
                    {
                        break;
                    }
                }
                if (batch.Count == 0)
                {
                    break;
                }
                var replies = await Task.WhenAll(batch).ConfigureAwait(false);
                for (var replyIndex = 0; replyIndex < replies.Length; replyIndex++)
                {
                    var reply = replies[replyIndex];
                    if (reply == null)
                    {
                        candidates.Remove(queried[replyIndex].NodeId);
                        continue;
                    }
                    responsive.Add(queried[replyIndex].NodeId);
                    foreach (var peer in reply.Peers)
                    {
                        if (peer.NodeId != NodeId && peer.Reachability != DHTReachability.Private
                            && (!budget.IsClaimed(peer.NodeId) || responsive.Contains(peer.NodeId))
                            && (candidates.Count < _options.MaxLookupQueries * 16 || candidates.ContainsKey(peer.NodeId)))
                        {
                            if (!candidates.TryGetValue(peer.NodeId, out var existing) || peer.Sequence > existing.Sequence)
                            {
                                candidates[peer.NodeId] = peer;
                            }
                        }
                    }
                    if (reply.Record != null && mode == 1 && reply.Record.Key.ToString() == target)
                    {
                        if (IsCurrentRevision(reply.Record))
                        {
                            best = Newer(best, reply.Record);
                        }
                    }
                    foreach (var provider in reply.Providers)
                    {
                        if ((provider.Capabilities & DHTCapabilities.Provide) != 0 && providers.Count < _options.MaxLookupQueries * 16)
                        {
                            providers[provider.NodeId] = provider;
                        }
                    }
                }
            }
            var closest = new List<DHTPeer>();
            foreach (var candidate in candidates.Values)
            {
                if (responsive.Contains(candidate.NodeId))
                {
                    closest.Add(candidate);
                }
            }
            return new LookupResult(closest, best, new List<DHTPeer>(providers.Values));
        }

        /// <summary>
        /// Shares the claimed nodes between the disjoint paths of one lookup and gives every path its own query budget, so a
        /// path captured by Sybil referrals cannot exhaust the queries of the honest paths.
        /// </summary>
        private sealed class LookupBudget
        {
            /// <summary>Protects the claimed nodes and counters.</summary>
            private readonly object _gate = new object();
            /// <summary>The nodes claimed by any path.</summary>
            private readonly HashSet<string> _claimed = new HashSet<string>(StringComparer.Ordinal);
            /// <summary>The queries used by each path.</summary>
            private readonly int[] _used;
            /// <summary>The maximum queries of one path.</summary>
            private readonly int _limitPerPath;

            /// <summary>Creates a budget.</summary>
            /// <param name="limit">The maximum queried nodes of the whole lookup, divided between the paths.</param>
            /// <param name="paths">The number of paths.</param>
            internal LookupBudget(int limit, int paths)
            {
                _used = new int[paths];
                _limitPerPath = Math.Max(1, (limit + paths - 1) / paths);
            }

            /// <summary>Gets whether a path has used all of its queries.</summary>
            /// <param name="path">The path index.</param>
            /// <returns>Whether the path's budget is exhausted.</returns>
            internal bool Exhausted(int path)
            {
                lock (_gate)
                {
                    return _used[path] >= _limitPerPath;
                }
            }

            /// <summary>Claims a node for a path.</summary>
            /// <param name="path">The path index.</param>
            /// <param name="nodeId">The node identifier.</param>
            /// <returns>Whether the node was unclaimed and the path's budget allowed another query.</returns>
            internal bool TryClaim(int path, string nodeId)
            {
                lock (_gate)
                {
                    if (_used[path] >= _limitPerPath || !_claimed.Add(nodeId))
                    {
                        return false;
                    }
                    _used[path]++;
                    return true;
                }
            }

            /// <summary>Checks whether any path has claimed a node.</summary>
            /// <param name="nodeId">The node identifier.</param>
            /// <returns>Whether the node is claimed.</returns>
            internal bool IsClaimed(string nodeId)
            {
                lock (_gate)
                {
                    return _claimed.Contains(nodeId);
                }
            }
        }

        /// <summary>Performs one authenticated lookup and validates all signed returned values.</summary>
        /// <param name="peer">The queried node.</param>
        /// <param name="mode">The lookup mode.</param>
        /// <param name="target">The canonical lookup target.</param>
        /// <param name="cancellationToken">The lookup lifetime.</param>
        /// <returns>The validated response, or null for an unusable peer.</returns>
        private async Task<LookupResult?> QueryLookupAsync(DHTPeer peer, byte mode, string target, CancellationToken cancellationToken)
        {
            using var body = new Wire();
            FindMessage.WriteRequest(body, (FindMode)mode, target);
            try
            {
                using var response = await RequestAsync(peer, Operation.Find, body.WrittenMemory, cancellationToken).ConfigureAwait(false);
                using var reader = new Wire(response.Bytes);
                var found = FindMessage.ReadResponse(reader);
                var record = found.Record;
                var peers = found.Peers;
                peers.RemoveAll(referred => !HasRequiredWork(referred.Contact));
                AttachResponderEndpoints(peers, peer);
                var providers = found.Providers;
                providers.RemoveAll(referred => !HasRequiredWork(referred.Contact));
                AttachResponderEndpoints(providers, peer);
                if (record != null && (mode != 1 || record.Key.ToString() != target || record.Length > _options.MaxFileSize))
                {
                    throw new InvalidDataException("Lookup returned a record for an unrelated key or excessive size.");
                }
                return new LookupResult(peers, record, providers);
            }
            catch (Exception exception) when (IsPeerFailure(exception))
            {
                cancellationToken.ThrowIfCancellationRequested();
                _routing.Remove(peer.NodeId);
                Log(LogLevel.Debug, "Lookup peer was unusable: ", exception);
                return null;
            }
        }

        /// <summary>
        /// Replaces the responder's own entries in a returned list with the endpoints this node reached the responder at: a node
        /// lists itself without endpoints because it does not know how others observe it.
        /// </summary>
        /// <param name="peers">The returned peers.</param>
        /// <param name="responder">The queried node at the endpoints known for it.</param>
        private static void AttachResponderEndpoints(List<DHTPeer> peers, DHTPeer responder)
        {
            for (var index = 0; index < peers.Count; index++)
            {
                if (peers[index].NodeId == responder.NodeId)
                {
                    var contact = peers[index].Sequence >= responder.Sequence ? peers[index].Contact : responder.Contact;
                    peers[index] = new DHTPeer(contact, responder.Endpoints);
                }
            }
        }

        /// <summary>Selects the highest authenticated revision and refuses equal-revision equivocation.</summary>
        /// <param name="current">The current record, if any.</param>
        /// <param name="candidate">The candidate record.</param>
        /// <returns>The selected record.</returns>
        /// <exception cref="InvalidDataException">One publisher signed conflicting content at the same revision.</exception>
        private static DHTRecord Newer(DHTRecord? current, DHTRecord candidate)
        {
            if (current == null || candidate.Revision > current.Revision)
            {
                return candidate;
            }
            if (candidate.Revision == current.Revision)
            {
                if (!current.SameContent(candidate))
                {
                    throw new InvalidDataException("Publisher equivocation at the same key revision.");
                }
                if (candidate.ExpiresAt > current.ExpiresAt)
                {
                    return candidate;
                }
            }
            return current;
        }

        /// <summary>Rejects rollback below the retained publisher revision, including after a newer lease expires.</summary>
        /// <param name="record">The signed candidate.</param>
        /// <returns>Whether the candidate has not been superseded.</returns>
        /// <exception cref="InvalidDataException">The publisher signed conflicting equal-revision content.</exception>
        private bool IsCurrentRevision(DHTRecord record)
        {
            lock (_gate)
            {
                if (_revisions.TryGetValue(record.Key.ToString(), out var observed))
                {
                    if (record.Revision < observed.Record.Revision)
                    {
                        return false;
                    }
                    Newer(observed.Record, record);
                }
            }
            return true;
        }

        /// <summary>
        /// Caches a signed binding and an optional authenticated provider claim within fixed quotas, keeping at most
        /// <see cref="MaxProvidersPerNetwork"/> claims per globally routed network for each file.
        /// </summary>
        /// <param name="record">The signed record.</param>
        /// <param name="provider">The authenticated announcing peer at the endpoints observed for it, or null for a lookup cache.</param>
        /// <param name="providerAddress">The observed source address of the announcement, or null for local claims.</param>
        /// <exception cref="IOException">The record quota is full.</exception>
        /// <exception cref="InvalidDataException">The record is expired, too large or conflicts with its revision.</exception>
        private void CacheRecord(DHTRecord record, DHTPeer? provider, IPAddress? providerAddress = null)
        {
            if (record.IsExpired || record.Length > _options.MaxFileSize)
            {
                throw new InvalidDataException("Publication is expired or exceeds the node's file limit.");
            }
            lock (_gate)
            {
                PruneIfDueLocked();
                var key = record.Key.ToString();
                if (!IsCurrentRevision(record))
                {
                    throw new InvalidDataException("The publication is below the retained publisher revision.");
                }
                EnsureRecordRoomLocked(key);
                _records.TryGetValue(key, out var existing);
                _records[key] = Newer(existing, record);
                _revisions[key] = (record, DateTimeOffset.UtcNow.AddDays(7).AddMinutes(2));
                if (record.IsWithdrawn)
                {
                    // Drop provider claims and local content that no remaining publication references.
                    PruneLocked();
                    return;
                }
                if (provider == null || provider.IsExpired || (provider.Capabilities & DHTCapabilities.Provide) == 0)
                {
                    return;
                }
                if (!_providers.TryGetValue(record.FileHash, out var providers))
                {
                    if (_providers.Count >= _options.MaxRecords)
                    {
                        return;
                    }
                    providers = new Dictionary<string, ProviderClaim>();
                    _providers[record.FileHash] = providers;
                }
                if (providers.TryGetValue(provider.NodeId, out var known))
                {
                    providers[provider.NodeId] = new ProviderClaim(MergeProvider(known.Peer, provider), providerAddress ?? known.Address);
                }
                else if (providers.Count < 16 && HasProviderRoom(providers, providerAddress))
                {
                    providers[provider.NodeId] = new ProviderClaim(provider, providerAddress);
                }
            }
        }

        /// <summary>Combines a repeated announcement with the known claim: the newest contact and the union of observed endpoints.</summary>
        /// <param name="known">The provider as claimed so far.</param>
        /// <param name="announced">The provider as it announced now.</param>
        /// <returns>The combined provider.</returns>
        private static DHTPeer MergeProvider(DHTPeer known, DHTPeer announced)
        {
            var contact = announced.Sequence >= known.Sequence ? announced.Contact : known.Contact;
            IReadOnlyList<DHTEndpoint> endpoints = known.Endpoints;
            foreach (var endpoint in announced.Endpoints)
            {
                endpoints = DHTPeer.Merge(endpoints, endpoint);
            }
            return new DHTPeer(contact, endpoints);
        }

        /// <summary>Checks whether a new provider claim from an address stays within the per-network limit.</summary>
        /// <param name="providers">The claims for one file.</param>
        /// <param name="address">The announcement's source address, or null for local claims.</param>
        /// <returns>Whether the claim may be added.</returns>
        internal static bool HasProviderRoom(Dictionary<string, ProviderClaim> providers, IPAddress? address)
        {
            if (address == null || !NetworkScope.IsDiversityLimited(address))
            {
                return true;
            }
            var count = 0;
            foreach (var claim in providers.Values)
            {
                if (claim.Address != null && NetworkScope.SameNetwork(claim.Address, address))
                {
                    count++;
                }
            }
            return count < MaxProvidersPerNetwork;
        }

        /// <summary>Returns a bounded snapshot of live locally indexed providers.</summary>
        /// <param name="fileHash">The whole-file identifier.</param>
        /// <returns>Live providers; this node lists itself with its current contact and no endpoints, which requesters fill in.</returns>
        private List<DHTPeer> LocalProviders(string fileHash)
        {
            var result = new List<DHTPeer>();
            lock (_gate)
            {
                if (_providers.TryGetValue(fileHash, out var providers))
                {
                    foreach (var claim in providers.Values)
                    {
                        var peer = claim.Peer;
                        if (!peer.IsExpired && (peer.Capabilities & DHTCapabilities.Provide) != 0)
                        {
                            result.Add(peer.NodeId == NodeId ? new DHTPeer(_self!, Array.Empty<DHTEndpoint>()) : peer);
                        }
                    }
                }
            }
            return result;
        }

        /// <summary>
        /// Checks the revision and record quotas for caching a key. A quota that appears full is pruned first, so only live
        /// entries can fill it, while the common case stays free of the full walk.
        /// </summary>
        /// <param name="key">The canonical lookup key about to be cached.</param>
        /// <exception cref="IOException">The revision or record quota is full of unexpired entries.</exception>
        private void EnsureRecordRoomLocked(string key)
        {
            var revisionQuota = _options.MaxRecords * 4;
            if ((!_revisions.ContainsKey(key) && _revisions.Count >= revisionQuota)
                || (!_records.ContainsKey(key) && _records.Count >= _options.MaxRecords))
            {
                PruneLocked();
                if (!_revisions.ContainsKey(key) && _revisions.Count >= revisionQuota)
                {
                    throw new IOException("The retained revision quota is full.");
                }
                if (!_records.ContainsKey(key) && _records.Count >= _options.MaxRecords)
                {
                    throw new IOException("The local DHT record quota is full.");
                }
            }
        }

        /// <summary>
        /// Prunes the index unless it was pruned less than <see cref="s_pruneInterval"/> ago, so the paths that cache or
        /// register one record pay for one full walk per interval instead of one per record.
        /// </summary>
        private void PruneIfDueLocked()
        {
            if (Stopwatch.GetTimestamp() - _lastPrune >= s_pruneInterval)
            {
                PruneLocked();
            }
        }

        /// <summary>Removes expired records, provider claims and unreferenced local tree metadata under the index lock.</summary>
        private void PruneLocked()
        {
            _lastPrune = Stopwatch.GetTimestamp();
            var expired = new List<string>();
            foreach (var observed in _revisions)
            {
                if (observed.Value.RetainUntil <= DateTimeOffset.UtcNow)
                {
                    expired.Add(observed.Key);
                }
            }
            foreach (var key in expired)
            {
                _revisions.Remove(key);
            }
            expired.Clear();
            var referenced = new HashSet<string>();
            var geometries = new HashSet<string>();
            foreach (var entry in _records)
            {
                if (entry.Value.IsExpired)
                {
                    expired.Add(entry.Key);
                }
                else if (!entry.Value.IsWithdrawn)
                {
                    referenced.Add(entry.Value.FileHash);
                    geometries.Add(ContentId(entry.Value));
                }
            }
            foreach (var key in expired)
            {
                _records.Remove(key);
                _announced.Remove(key);
            }
            expired.Clear();
            foreach (var entry in _providers)
            {
                var peers = new List<string>();
                foreach (var peer in entry.Value)
                {
                    if (peer.Value.Peer.IsExpired)
                    {
                        peers.Add(peer.Key);
                    }
                }
                foreach (var peer in peers)
                {
                    entry.Value.Remove(peer);
                }
                if (entry.Value.Count == 0 || !referenced.Contains(entry.Key))
                {
                    expired.Add(entry.Key);
                }
            }
            foreach (var hash in expired)
            {
                _providers.Remove(hash);
            }
            expired.Clear();
            foreach (var entry in _contents)
            {
                if (!geometries.Contains(entry.Key))
                {
                    expired.Add(entry.Key);
                }
            }
            foreach (var key in expired)
            {
                RemoveLocalContentLocked(key);
            }
        }

        /// <summary>
        /// Refreshes contact leases, retries bootstrap while isolated, schedules reachability checks and reannounces locally
        /// available content on a cancellable interval.
        /// </summary>
        /// <returns>Completion when the node stops.</returns>
        private async Task MaintainAsync()
        {
            try
            {
                while (!_lifetime.IsCancellationRequested)
                {
                    await Task.Delay(_options.MaintenanceInterval, _lifetime.Token).ConfigureAwait(false);
                    bool checkReachability;
                    lock (_gate)
                    {
                        RefreshLocalContactLocked();
                        PruneLocked();
                        checkReachability = _lastReachabilityCheck + _options.ReachabilityCheckInterval <= DateTimeOffset.UtcNow;
                    }
                    if (_options.BootstrapEndpoints.Count != 0 && RoutedPeers(NodeId, 1).Count == 0)
                    {
                        await BootstrapInBackgroundAsync().ConfigureAwait(false);
                    }
                    if (checkReachability)
                    {
                        TriggerReachabilityCheck();
                    }
                    await LookupAsync(0, NodeId, _lifetime.Token).ConfigureAwait(false);
                    await ReannounceLocalRecordsAsync(true, _lifetime.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                if (!_lifetime.IsCancellationRequested)
                {
                    Log(LogLevel.Error, "Maintenance stopped: ", exception);
                }
            }
        }

        /// <summary>
        /// Reannounces every unexpired locally available publication and this publisher's own withdrawals, as many at once as
        /// <see cref="MaxConcurrentReplications"/> allows.
        /// </summary>
        /// <param name="skipRecentlyAnnounced">
        /// Whether records announced less than one maintenance interval ago are left for the next pass, as maintenance does;
        /// false after a contact change, because every provider claim must then carry the new contact.
        /// </param>
        /// <param name="cancellationToken">The node lifetime.</param>
        /// <returns>Completion after every announcement attempt.</returns>
        /// <exception cref="OperationCanceledException">The node stopped.</exception>
        private async Task ReannounceLocalRecordsAsync(bool skipRecentlyAnnounced, CancellationToken cancellationToken)
        {
            var publications = LocalRecordsToReannounce(skipRecentlyAnnounced);
            await ForEachAsync(publications, MaxConcurrentReplications, async record =>
            {
                try
                {
                    if (record.IsExpired)
                    {
                        return;
                    }
                    if (record.IsWithdrawn)
                    {
                        await AnnounceWithdrawalAsync(record, null, cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        await AnnounceRecordAsync(record, cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Warning, "Maintenance announcement failed: ", exception);
                }
            }).ConfigureAwait(false);
        }

        /// <summary>
        /// Lists the records a reannouncement covers: every locally available publication and this publisher's own
        /// withdrawals. Leaving out records that reached a replica under the same revision less than one maintenance interval
        /// ago keeps maintenance from repeating, while many publications are still being announced, the announcements they
        /// just made; a record left out is included again by the following pass.
        /// </summary>
        /// <param name="skipRecentlyAnnounced">Whether records announced less than one maintenance interval ago are left out.</param>
        /// <returns>The records to reannounce.</returns>
        internal List<DHTRecord> LocalRecordsToReannounce(bool skipRecentlyAnnounced)
        {
            var recent = Stopwatch.GetTimestamp() - (long)(_options.MaintenanceInterval.TotalSeconds * Stopwatch.Frequency);
            var publications = new List<DHTRecord>();
            lock (_gate)
            {
                foreach (var entry in _records)
                {
                    var record = entry.Value;
                    if (!(record.IsWithdrawn ? record.Key.PublisherId == NodeId
                        : (_options.Capabilities & DHTCapabilities.Provide) != 0 && _contents.ContainsKey(ContentId(record))))
                    {
                        continue;
                    }
                    if (skipRecentlyAnnounced && _announced.TryGetValue(entry.Key, out var announced)
                        && announced.Revision == record.Revision && announced.Timestamp > recent)
                    {
                        continue;
                    }
                    publications.Add(record);
                }
            }
            return publications;
        }

        /// <summary>Associates an authenticated provider claim with the source address of its announcement.</summary>
        internal sealed class ProviderClaim
        {
            /// <summary>Gets the provider at the endpoints observed for it.</summary>
            internal DHTPeer Peer { get; }
            /// <summary>Gets the announcement's observed source address, or null for local claims.</summary>
            internal IPAddress? Address { get; }

            /// <summary>Creates a claim.</summary>
            /// <param name="peer">The provider contact.</param>
            /// <param name="address">The announcement's source address.</param>
            internal ProviderClaim(DHTPeer peer, IPAddress? address)
            {
                Peer = peer;
                Address = address;
            }
        }

        /// <summary>Keeps the validated result of one lookup or lookup round.</summary>
        private sealed class LookupResult
        {
            /// <summary>The closest returned contacts.</summary>
            internal List<DHTPeer> Peers { get; }
            /// <summary>The matching signed publication, if any.</summary>
            internal DHTRecord? Record { get; }
            /// <summary>The live content-provider contacts.</summary>
            internal List<DHTPeer> Providers { get; }

            /// <summary>Creates a lookup result snapshot.</summary>
            /// <param name="peers">The closest peers.</param>
            /// <param name="record">The matching record.</param>
            /// <param name="providers">The known providers.</param>
            internal LookupResult(List<DHTPeer> peers, DHTRecord? record, List<DHTPeer> providers)
            {
                Peers = peers;
                Record = record;
                Providers = providers;
            }
        }
    }
}
