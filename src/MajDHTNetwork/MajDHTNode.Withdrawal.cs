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
        /// <summary>
        /// Withdraws a key in this node's publisher namespace: signs a withdrawal whose revision supersedes every known
        /// revision and replicates it near the key and near the withdrawn file hash. Honest nodes that receive it resolve the
        /// key as withdrawn, drop provider claims and local content that no other publication references, and refuse older
        /// revisions afterwards. Copies already downloaded by others cannot be recalled, and the same content can still be
        /// published under other keys.
        /// </summary>
        /// <param name="name">The case-sensitive name in this identity's key namespace.</param>
        /// <param name="revision">
        /// The withdrawal revision, or zero to use one above every revision known locally and found in the DHT; an explicit
        /// revision must exceed both.
        /// </param>
        /// <param name="cancellationToken">Cancels discovery and replication.</param>
        /// <returns>The signed withdrawal; it remains locally effective even if no remote replica accepts it.</returns>
        /// <exception cref="ArgumentException">The name is invalid, or the explicit revision does not supersede a known revision.</exception>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        /// <exception cref="OperationCanceledException">The withdrawal was cancelled.</exception>
        public async Task<DHTRecord> UnpublishAsync(string name, long revision = 0, CancellationToken cancellationToken = default)
        {
            var key = new DHTKey(NodeId, name);
            if (revision < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(revision));
            }
            using var cancellation = OperationCancellation(cancellationToken);
            var remote = await ResolveAsync(key, cancellation.Token).ConfigureAwait(false);
            DHTRecord withdrawal;
            DHTRecord? withdrawn;
            await _publishing.WaitAsync(cancellation.Token).ConfigureAwait(false);
            try
            {
                lock (_gate)
                {
                    _revisions.TryGetValue(key.ToString(), out var retained);
                    withdrawn = Latest(retained.Record, remote);
                }
                var floor = withdrawn?.Revision ?? 0;
                if (revision == 0)
                {
                    revision = floor + 1;
                }
                else if (revision <= floor)
                {
                    throw new ArgumentException("A withdrawal revision must exceed every known revision of the key.", nameof(revision));
                }
                // The withdrawal must outlive every signed publication it supersedes, or an old copy could be reannounced.
                var now = DateTimeOffset.UtcNow;
                var expiresAt = now.Add(_options.RecordLifetime);
                if (withdrawn != null && withdrawn.ExpiresAt > expiresAt)
                {
                    expiresAt = withdrawn.ExpiresAt;
                }
                var limit = now.AddDays(7).AddMinutes(-1);
                withdrawal = DHTRecord.CreateWithdrawal(_identity, name, revision, expiresAt < limit ? expiresAt : limit);
                CacheRecord(withdrawal, null);
            }
            finally
            {
                _publishing.Release();
            }
            var fileHash = withdrawn != null && !withdrawn.IsWithdrawn ? withdrawn.FileHash : null;
            var replicas = await AnnounceWithdrawalAsync(withdrawal, fileHash, cancellation.Token).ConfigureAwait(false);
            Log(replicas == 0 ? LogLevel.Warning : LogLevel.Information,
                replicas == 0 ? "Withdrawal is effective locally; no remote replica accepted it." : "Publication withdrawn.");
            return withdrawal;
        }

        /// <summary>
        /// Stops serving a file locally: forgets its block geometry and this node's provider claims, so block requests are
        /// refused and maintenance no longer announces it. Remote provider indexes keep this node's earlier claims until
        /// they expire, and downloaders fail over to other providers. Stored blocks remain in the caller-owned store.
        /// </summary>
        /// <param name="fileHash">The SHA-256 digest of the complete file.</param>
        /// <returns>Whether this node was providing the file.</returns>
        /// <exception cref="ArgumentException">The hash is invalid.</exception>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        public bool StopProviding(string fileHash)
        {
            Crypto.ParseHash(fileHash);
            EnsureRunning();
            var removed = false;
            lock (_gate)
            {
                var geometries = new List<string>();
                foreach (var entry in _contents)
                {
                    if (entry.Value.Record.FileHash == fileHash)
                    {
                        geometries.Add(entry.Key);
                    }
                }
                foreach (var geometry in geometries)
                {
                    removed |= _contents.Remove(geometry);
                }
                if (_providers.TryGetValue(fileHash, out var providers))
                {
                    removed |= providers.Remove(NodeId);
                }
            }
            if (removed)
            {
                Log(LogLevel.Information, "Stopped providing a file.");
            }
            return removed;
        }

        /// <summary>Replicates a withdrawal near its key and, when known, near the withdrawn file hash.</summary>
        /// <param name="withdrawal">The signed withdrawal.</param>
        /// <param name="fileHash">The file hash of the withdrawn publication, whose nearby nodes also cached it, or null.</param>
        /// <param name="cancellationToken">Cancels lookup and replication.</param>
        /// <returns>The number of remote replicas accepting the withdrawal.</returns>
        /// <exception cref="OperationCanceledException">Replication was cancelled.</exception>
        private async Task<int> AnnounceWithdrawalAsync(DHTRecord withdrawal, string? fileHash, CancellationToken cancellationToken)
        {
            var peers = new Dictionary<string, DHTPeer>();
            foreach (var peer in (await LookupAsync(0, withdrawal.Key.RoutingId, cancellationToken).ConfigureAwait(false)).Peers)
            {
                peers[peer.NodeId] = peer;
            }
            if (fileHash != null)
            {
                foreach (var peer in (await LookupAsync(0, fileHash, cancellationToken).ConfigureAwait(false)).Peers)
                {
                    peers[peer.NodeId] = peer;
                }
            }
            var accepted = 0;
            using var body = new Wire();
            body.Put(withdrawal.Encoded);
            foreach (var peer in peers.Values)
            {
                try
                {
                    using var acceptance = await RequestAsync(peer, Operation.Store, body.WrittenMemory, cancellationToken).ConfigureAwait(false);
                    accepted++;
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Withdrawal replication failed: ", exception);
                }
            }
            return accepted;
        }

        /// <summary>Selects the higher revision of two optional records.</summary>
        /// <param name="first">The first record, or null.</param>
        /// <param name="second">The second record, or null.</param>
        /// <returns>The record with the higher revision, or null when both are null.</returns>
        private static DHTRecord? Latest(DHTRecord? first, DHTRecord? second)
        {
            if (first == null)
            {
                return second;
            }
            if (second == null)
            {
                return first;
            }
            return second.Revision > first.Revision ? second : first;
        }
    }
}
