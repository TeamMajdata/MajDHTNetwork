using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>Joins the network through any existing node's signed invitation.</summary>
        /// <param name="bootstrap">A trusted, unexpired public node contact.</param>
        /// <param name="cancellationToken">Cancels joining and initial discovery.</param>
        /// <returns>Completion after authentication and iterative neighbor discovery.</returns>
        /// <exception cref="IOException">The bootstrap node could not be contacted.</exception>
        /// <exception cref="OperationCanceledException">Joining was cancelled.</exception>
        public async Task BootstrapAsync(DHTPeer bootstrap, CancellationToken cancellationToken = default)
        {
            if (bootstrap == null || bootstrap.NodeId == NodeId)
            {
                throw new ArgumentException("A remote bootstrap contact is required.", nameof(bootstrap));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            await RequestAsync(bootstrap, Operation.Ping, Array.Empty<byte>(), cancellation.Token).ConfigureAwait(false);
            if (_options.EnableNatTraversal && (bootstrap.Capabilities & DHTCapabilities.Relay) != 0)
            {
                try
                {
                    await RegisterRelayAsync(bootstrap, cancellation.Token).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellation.Token.ThrowIfCancellationRequested();
                    Log(LogLevel.Warning, "Bootstrap relay registration failed: ", exception);
                }
            }
            await LookupAsync(0, NodeId, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Bootstrap authentication and neighbor discovery completed.");
        }

        /// <summary>Finds reachable nodes nearest a SHA-256 routing identifier.</summary>
        /// <param name="routingId">The lowercase SHA-256 target identifier.</param>
        /// <param name="cancellationToken">Cancels the iterative lookup.</param>
        /// <returns>The nearest discovered peer contacts.</returns>
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
        /// <returns>Signed contacts advertising content-providing capability.</returns>
        /// <exception cref="ArgumentException">The hash is invalid.</exception>
        /// <exception cref="OperationCanceledException">Lookup was cancelled.</exception>
        public async Task<IReadOnlyList<DHTPeer>> FindProvidersAsync(string fileHash, CancellationToken cancellationToken = default)
        {
            Crypto.ParseHash(fileHash);
            using var cancellation = OperationCancellation(cancellationToken);
            var result = await LookupAsync(2, fileHash, cancellation.Token).ConfigureAwait(false);
            return result.Providers.AsReadOnly();
        }

        /// <summary>Queries closer peers in bounded parallel rounds until the nearest known set is exhausted.</summary>
        /// <param name="mode">Zero for neighbors, one for a key, or two for content providers.</param>
        /// <param name="target">The routing identifier or canonical key.</param>
        /// <param name="cancellationToken">The lookup lifetime.</param>
        /// <returns>The discovered peers, record and provider set.</returns>
        private async Task<LookupResult> LookupAsync(byte mode, string target, CancellationToken cancellationToken)
        {
            var routingId = mode == 1 ? DHTKey.Parse(target).RoutingId : target;
            var candidates = new Dictionary<string, DHTPeer>();
            var providers = new Dictionary<string, DHTPeer>();
            var visited = new HashSet<string>();
            var responsive = new HashSet<string>();
            DHTRecord? best = null;
            foreach (var peer in _routing.Closest(routingId, _options.BucketSize))
            {
                candidates[peer.NodeId] = peer;
            }
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
            while (visited.Count < _options.MaxLookupQueries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var ordered = new List<DHTPeer>(candidates.Values);
                RoutingTable.Sort(ordered, routingId);
                if (ordered.Count > _options.BucketSize)
                {
                    ordered.RemoveRange(_options.BucketSize, ordered.Count - _options.BucketSize);
                }
                var batch = new List<Task<LookupResult?>>();
                var queried = new List<DHTPeer>();
                foreach (var peer in ordered)
                {
                    if (!visited.Add(peer.NodeId))
                    {
                        continue;
                    }
                    queried.Add(peer);
                    batch.Add(QueryLookupAsync(peer, mode, target, cancellationToken));
                    if (batch.Count >= _options.LookupParallelism || visited.Count >= _options.MaxLookupQueries)
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
                        if (peer.NodeId != NodeId && (!visited.Contains(peer.NodeId) || responsive.Contains(peer.NodeId))
                            && (candidates.Count < _options.MaxLookupQueries * 16 || candidates.ContainsKey(peer.NodeId)))
                        {
                            if (!candidates.TryGetValue(peer.NodeId, out var existing) || peer.ExpiresAt > existing.ExpiresAt)
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
            RoutingTable.Sort(closest, routingId);
            if (closest.Count > _options.BucketSize)
            {
                closest.RemoveRange(_options.BucketSize, closest.Count - _options.BucketSize);
            }
            var providerList = new List<DHTPeer>(providers.Values);
            RoutingTable.Sort(providerList, routingId);
            if (providerList.Count > 16)
            {
                providerList.RemoveRange(16, providerList.Count - 16);
            }
            return new LookupResult(closest, best, providerList);
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
            body.PutByte(mode);
            body.PutText(target);
            try
            {
                var response = await RequestAsync(peer, Operation.Find, body.WrittenMemory, cancellationToken).ConfigureAwait(false);
                using var reader = new Wire(response);
                var signedRecord = reader.Bytes(2200);
                var record = signedRecord.Length == 0 ? null : DHTRecord.Parse(signedRecord.Span);
                var peers = ReadPeers(reader);
                var providers = ReadPeers(reader);
                reader.End();
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

        /// <summary>Caches a signed binding and an optional authenticated provider claim within fixed quotas.</summary>
        /// <param name="record">The signed record.</param>
        /// <param name="provider">The authenticated announcing peer, or null for a lookup cache.</param>
        /// <exception cref="IOException">The record quota is full.</exception>
        /// <exception cref="InvalidDataException">The record is expired, too large or conflicts with its revision.</exception>
        private void CacheRecord(DHTRecord record, DHTPeer? provider)
        {
            if (record.IsExpired || record.Length > _options.MaxFileSize)
            {
                throw new InvalidDataException("Publication is expired or exceeds the node's file limit.");
            }
            lock (_gate)
            {
                PruneLocked();
                var key = record.Key.ToString();
                if (!IsCurrentRevision(record))
                {
                    throw new InvalidDataException("The publication is below the retained publisher revision.");
                }
                if (!_revisions.ContainsKey(key) && _revisions.Count >= _options.MaxRecords * 4)
                {
                    throw new IOException("The retained revision quota is full.");
                }
                _records.TryGetValue(key, out var existing);
                if (existing == null && _records.Count >= _options.MaxRecords)
                {
                    throw new IOException("The local DHT record quota is full.");
                }
                _records[key] = Newer(existing, record);
                _revisions[key] = (record, DateTimeOffset.UtcNow.AddDays(7).AddMinutes(2));
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
                    providers = new Dictionary<string, DHTPeer>();
                    _providers[record.FileHash] = providers;
                }
                if (providers.Count < 16 || providers.ContainsKey(provider.NodeId))
                {
                    providers[provider.NodeId] = provider;
                }
            }
        }

        /// <summary>Returns a bounded snapshot of live locally indexed providers.</summary>
        /// <param name="fileHash">The whole-file identifier.</param>
        /// <returns>Live provider contacts.</returns>
        private List<DHTPeer> LocalProviders(string fileHash)
        {
            var result = new List<DHTPeer>();
            lock (_gate)
            {
                if (_providers.TryGetValue(fileHash, out var providers))
                {
                    foreach (var peer in providers.Values)
                    {
                        if (!peer.IsExpired && (peer.Capabilities & DHTCapabilities.Provide) != 0)
                        {
                            result.Add(peer.NodeId == NodeId ? _self! : peer);
                        }
                    }
                }
            }
            return result;
        }

        /// <summary>Removes expired records, provider claims and unreferenced local tree metadata under the index lock.</summary>
        private void PruneLocked()
        {
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
                else
                {
                    referenced.Add(entry.Value.FileHash);
                    geometries.Add(ContentId(entry.Value));
                }
            }
            foreach (var key in expired)
            {
                _records.Remove(key);
            }
            expired.Clear();
            foreach (var entry in _providers)
            {
                var peers = new List<string>();
                foreach (var peer in entry.Value)
                {
                    if (peer.Value.IsExpired)
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
                _contents.Remove(key);
            }
        }

        /// <summary>Refreshes contact leases and reannounces locally available content on a cancellable interval.</summary>
        /// <returns>Completion when the node stops.</returns>
        private async Task MaintainAsync()
        {
            try
            {
                while (!_lifetime.IsCancellationRequested)
                {
                    await Task.Delay(_options.MaintenanceInterval, _lifetime.Token).ConfigureAwait(false);
                    var publications = new List<DHTRecord>();
                    lock (_gate)
                    {
                        _self = DHTPeer.Create(_identity, _options.AdvertisedAddress!, _transport.TcpPort, _transport.UdpPort, _options.Capabilities);
                        PruneLocked();
                        foreach (var record in _records.Values)
                        {
                            if ((_options.Capabilities & DHTCapabilities.Provide) != 0 && _contents.ContainsKey(ContentId(record)))
                            {
                                publications.Add(record);
                            }
                        }
                    }
                    await LookupAsync(0, NodeId, _lifetime.Token).ConfigureAwait(false);
                    foreach (var record in publications)
                    {
                        try
                        {
                            if (!record.IsExpired)
                            {
                                await AnnounceRecordAsync(record, _lifetime.Token).ConfigureAwait(false);
                            }
                        }
                        catch (Exception exception) when (IsPeerFailure(exception))
                        {
                            _lifetime.Token.ThrowIfCancellationRequested();
                            Log(LogLevel.Warning, "Maintenance announcement failed: ", exception);
                        }
                    }
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
