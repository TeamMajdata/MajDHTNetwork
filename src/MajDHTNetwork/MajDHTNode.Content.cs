using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>Reads a caller-owned stream, signs its manifest and announces it to nearby DHT nodes.</summary>
        /// <param name="name">The case-sensitive name in this identity's key namespace.</param>
        /// <param name="source">A readable stream positioned at the beginning of the intended content; remains open.</param>
        /// <param name="revision">A positive revision strictly greater than any locally observed revision of this key.</param>
        /// <param name="cancellationToken">Cancels reading, storing and announcing content.</param>
        /// <returns>The signed publication; it remains locally usable if no remote replicas are reachable.</returns>
        /// <exception cref="ArgumentException">The name, source, revision or content size is invalid.</exception>
        /// <exception cref="IOException">Storage or metadata quotas prevent publication.</exception>
        /// <exception cref="OperationCanceledException">Publication was cancelled.</exception>
        public async Task<DHTRecord> PublishAsync(string name, Stream source, long revision = 1, CancellationToken cancellationToken = default)
        {
            if (source == null || !source.CanRead)
            {
                throw new ArgumentException("A readable source stream is required.", nameof(source));
            }
            RequireProvider();
            using var cancellation = OperationCancellation(cancellationToken);
            await _publishing.WaitAsync(cancellation.Token).ConfigureAwait(false);
            DHTRecord record;
            try
            {
                ValidateRevision(name, revision);
                using var leaves = new Wire();
                var content = await StoreContentAsync(source, _options.BlockSize, _options.MaxFileSize, leaves, cancellation.Token)
                    .ConfigureAwait(false);
                if (content == null)
                {
                    throw new ArgumentException("Content exceeds the configured file or Merkle metadata limit.", nameof(source));
                }
                var tree = new MerkleTree(leaves.WrittenSpan);
                record = DHTRecord.Create(_identity, name, content.Value.FileHash, tree.Root,
                    content.Value.Length, _options.BlockSize, revision, DateTimeOffset.UtcNow.Add(_options.RecordLifetime));
                RegisterContent(record, tree);
            }
            finally
            {
                _publishing.Release();
            }
            await AnnounceRecordAsync(record, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Content publication completed.");
            return record;
        }

        /// <summary>Publishes another key for already available content without reading or copying the file.</summary>
        /// <param name="name">The new or updated name in this identity's namespace.</param>
        /// <param name="content">A manifest whose exact block geometry is registered locally.</param>
        /// <param name="revision">The new key revision.</param>
        /// <param name="cancellationToken">Cancels announcement.</param>
        /// <returns>The new signed key binding pointing to the same whole-file hash.</returns>
        /// <exception cref="ArgumentException">The revision is invalid or the content is unavailable.</exception>
        /// <exception cref="IOException">The local record quota is full.</exception>
        /// <exception cref="OperationCanceledException">Publication was cancelled.</exception>
        public async Task<DHTRecord> PublishAliasAsync(string name, DHTRecord content, long revision = 1, CancellationToken cancellationToken = default)
        {
            if (content == null)
            {
                throw new ArgumentNullException(nameof(content));
            }
            RequireProvider();
            using var cancellation = OperationCancellation(cancellationToken);
            await _publishing.WaitAsync(cancellation.Token).ConfigureAwait(false);
            DHTRecord record;
            try
            {
                ValidateRevision(name, revision);
                MerkleTree tree;
                lock (_gate)
                {
                    if (!_contents.TryGetValue(ContentId(content), out var local) || !local.Record.SameContent(content))
                    {
                        throw new ArgumentException("The specified content geometry is not registered locally.", nameof(content));
                    }
                    tree = local.Tree;
                }
                record = DHTRecord.Create(_identity, name, content.FileHash, content.MerkleRoot, content.Length,
                    content.BlockSize, revision, DateTimeOffset.UtcNow.Add(_options.RecordLifetime));
                RegisterContent(record, tree);
            }
            finally
            {
                _publishing.Release();
            }
            await AnnounceRecordAsync(record, cancellation.Token).ConfigureAwait(false);
            return record;
        }

        /// <summary>
        /// Reannounces an unexpired signed record for locally registered content, or replicates any publisher's withdrawal.
        /// </summary>
        /// <param name="record">The existing signed publication or withdrawal; its revision and expiry are preserved.</param>
        /// <param name="cancellationToken">Cancels announcement.</param>
        /// <returns>The number of remote nodes accepting a replica.</returns>
        /// <exception cref="ArgumentException">The content is not registered locally.</exception>
        /// <exception cref="InvalidDataException">The record is expired or below a retained revision.</exception>
        /// <exception cref="OperationCanceledException">Announcement was cancelled.</exception>
        public async Task<int> AnnounceAsync(DHTRecord record, CancellationToken cancellationToken = default)
        {
            if (record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }
            if (record.IsWithdrawn)
            {
                using var withdrawal = OperationCancellation(cancellationToken);
                CacheRecord(record, null);
                return await AnnounceWithdrawalAsync(record, null, withdrawal.Token).ConfigureAwait(false);
            }
            RequireProvider();
            using var cancellation = OperationCancellation(cancellationToken);
            MerkleTree tree;
            lock (_gate)
            {
                if (!_contents.TryGetValue(ContentId(record), out var content) || !content.Record.SameContent(record))
                {
                    throw new ArgumentException("Content is not registered locally.", nameof(record));
                }
                tree = content.Tree;
            }
            RegisterContent(record, tree);
            return await AnnounceRecordAsync(record, cancellation.Token).ConfigureAwait(false);
        }

        /// <summary>
        /// Serves locally available content under an existing signed publication, typically another publisher's: reads the
        /// stream into the content store, verifies it against the signed length, Merkle root and complete-file hash, registers
        /// it and announces this node as a provider. Use it to resume serving files that outlived the process, for example a
        /// replica's cache directory, without downloading them again.
        /// </summary>
        /// <param name="record">The publisher-signed, unexpired content manifest.</param>
        /// <param name="source">A readable stream positioned at the beginning of the content; remains open.</param>
        /// <param name="cancellationToken">Cancels reading, storing and announcing content.</param>
        /// <returns>The number of remote nodes accepting this node's provider announcement.</returns>
        /// <remarks>Blocks of rejected content may remain in the caller-owned content store.</remarks>
        /// <exception cref="ArgumentNullException">The record is null.</exception>
        /// <exception cref="ArgumentException">The record is a withdrawal or the source is not readable.</exception>
        /// <exception cref="InvalidOperationException">The local Provide capability is disabled.</exception>
        /// <exception cref="InvalidDataException">
        /// The record is expired, exceeds configured limits or is below a retained revision, or the content differs from it.
        /// </exception>
        /// <exception cref="IOException">Storage or metadata quotas prevent registration.</exception>
        /// <exception cref="OperationCanceledException">The import was cancelled.</exception>
        public async Task<int> ImportContentAsync(DHTRecord record, Stream source, CancellationToken cancellationToken = default)
        {
            if (record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }
            if (source == null || !source.CanRead || record.IsWithdrawn)
            {
                throw new ArgumentException("A signed content manifest, not a withdrawal, and a readable source are required.");
            }
            RequireProvider();
            if (record.IsExpired || record.Length > _options.MaxFileSize || record.BlockCount > _options.MaxLocalLeaves)
            {
                throw new InvalidDataException("The manifest is expired or exceeds configured resource limits.");
            }
            using var cancellation = OperationCancellation(cancellationToken);
            using var leaves = new Wire();
            var content = await StoreContentAsync(source, record.BlockSize, record.Length, leaves, cancellation.Token).ConfigureAwait(false);
            if (content == null || content.Value.Length != record.Length || content.Value.FileHash != record.FileHash)
            {
                throw new InvalidDataException("The local content differs from the signed manifest.");
            }
            RegisterContent(record, new MerkleTree(leaves.WrittenSpan));
            var replicas = await AnnounceRecordAsync(record, cancellation.Token).ConfigureAwait(false);
            Log(LogLevel.Information, "Local content import completed.");
            return replicas;
        }

        /// <summary>Resolves a key and downloads its fully verified file to a caller-owned stream.</summary>
        /// <param name="key">The trusted publisher-scoped key.</param>
        /// <param name="destination">A writable stream; remains open and may contain partial bytes on failure.</param>
        /// <param name="expectedFileHash">An optional independently trusted SHA-256 pin.</param>
        /// <param name="cancellationToken">Cancels discovery, downloading and storage.</param>
        /// <returns>The authenticated manifest after all blocks and the whole-file hash match.</returns>
        /// <exception cref="FileNotFoundException">No publication could be found, or the publisher withdrew the key.</exception>
        /// <exception cref="InvalidDataException">The trusted hash or content verification failed.</exception>
        /// <exception cref="IOException">No usable provider or writable destination is available.</exception>
        /// <exception cref="OperationCanceledException">Download was cancelled.</exception>
        public async Task<DHTRecord> DownloadAsync(DHTKey key, Stream destination, string? expectedFileHash = null, CancellationToken cancellationToken = default)
        {
            RequireDownloader();
            var record = await ResolveAsync(key, cancellationToken).ConfigureAwait(false);
            if (record == null)
            {
                throw new FileNotFoundException("No reachable signed publication exists for the requested key.");
            }
            if (record.IsWithdrawn)
            {
                throw new FileNotFoundException("The publisher withdrew the requested key.");
            }
            return await DownloadAsync(record, destination, expectedFileHash, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Downloads verified blocks concurrently from the discovered providers, preferring providers with lower packet loss,
        /// and checks the complete SHA-256 digest.
        /// </summary>
        /// <param name="record">The verified, unexpired publisher manifest.</param>
        /// <param name="destination">A writable stream; use application-managed staging when atomic publication is required.</param>
        /// <param name="expectedFileHash">An optional independent complete-file hash pin.</param>
        /// <param name="cancellationToken">Cancels the complete operation.</param>
        /// <returns>The manifest after complete verification and optional provider announcement.</returns>
        /// <exception cref="InvalidOperationException">The local Download capability is disabled.</exception>
        /// <exception cref="ArgumentException">The record is a withdrawal or the destination is not writable.</exception>
        /// <exception cref="InvalidDataException">Manifest, block, Merkle or whole-file verification failed.</exception>
        /// <exception cref="IOException">No provider supplied a valid block or a stream/store operation failed.</exception>
        /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
        public async Task<DHTRecord> DownloadAsync(DHTRecord record, Stream destination, string? expectedFileHash = null, CancellationToken cancellationToken = default)
        {
            RequireDownloader();
            if (record == null || destination == null || !destination.CanWrite || record.IsWithdrawn)
            {
                throw new ArgumentException("A signed content manifest, not a withdrawal, and a writable destination are required.");
            }
            if (record.IsExpired || record.Length > _options.MaxFileSize || record.BlockCount > _options.MaxLocalLeaves)
            {
                throw new InvalidDataException("The manifest is expired or exceeds configured resource limits.");
            }
            if (expectedFileHash != null)
            {
                Crypto.ParseHash(expectedFileHash);
                if (expectedFileHash != record.FileHash)
                {
                    throw new InvalidDataException("The signed manifest differs from the independently trusted file hash.");
                }
            }
            using var cancellation = OperationCancellation(cancellationToken);
            var providers = new List<DHTPeer>(await FindProvidersAsync(record.FileHash, cancellation.Token).ConfigureAwait(false));
            lock (_gate)
            {
                if (_contents.ContainsKey(ContentId(record)) && !providers.Exists(peer => peer.NodeId == NodeId))
                {
                    providers.Insert(0, _self!);
                }
            }
            if (providers.Count == 0)
            {
                throw new IOException("No content provider is currently reachable through the DHT.");
            }
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var leaves = new Wire();
            using (var download = new BlockDownload(this, record, providers, destination, digest, leaves, cancellation.Token))
            {
                await download.RunAsync().ConfigureAwait(false);
            }
            if (Crypto.Hex(digest.GetHashAndReset()) != record.FileHash)
            {
                throw new InvalidDataException("Complete file SHA-256 verification failed.");
            }
            RegisterContent(record, new MerkleTree(leaves.WrittenSpan));
            if ((_options.Capabilities & DHTCapabilities.Provide) != 0)
            {
                await AnnounceRecordAsync(record, cancellation.Token).ConfigureAwait(false);
            }
            Log(LogLevel.Information, "Content download and full verification completed.");
            return record;
        }

        /// <summary>Downloads and authenticates one block directly or through a chosen relay.</summary>
        /// <param name="record">The trusted signed manifest.</param>
        /// <param name="provider">The final content provider.</param>
        /// <param name="index">The zero-based block index.</param>
        /// <param name="relay">An optional relay; null permits direct access with automatic relay fallback.</param>
        /// <param name="cancellationToken">Cancels transfer.</param>
        /// <returns>The raw block after exact length, position and Merkle authentication.</returns>
        /// <exception cref="InvalidOperationException">A remote transfer was requested with the local Download capability disabled.</exception>
        /// <exception cref="ArgumentException">The record is a withdrawal.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The index is outside the signed file.</exception>
        /// <exception cref="InvalidDataException">The manifest or returned block is invalid.</exception>
        /// <exception cref="IOException">The provider or relay is unavailable.</exception>
        /// <exception cref="OperationCanceledException">Transfer was cancelled.</exception>
        public async Task<ReadOnlyMemory<byte>> ReadBlockAsync(DHTRecord record, DHTPeer provider, int index, DHTPeer? relay = null,
            CancellationToken cancellationToken = default)
        {
            if (record == null || provider == null)
            {
                throw new ArgumentNullException(nameof(record));
            }
            if (record.IsWithdrawn)
            {
                throw new ArgumentException("A withdrawal has no content blocks.", nameof(record));
            }
            if (index < 0 || index >= record.BlockCount)
            {
                throw new ArgumentOutOfRangeException(nameof(index));
            }
            if (record.IsExpired || record.Length > _options.MaxFileSize)
            {
                throw new InvalidDataException("Invalid or oversized manifest.");
            }
            if (provider.NodeId != NodeId)
            {
                RequireDownloader();
            }
            using var cancellation = OperationCancellation(cancellationToken);
            using var block = await ReadBlockCoreAsync(record, provider, index, relay, cancellation.Token).ConfigureAwait(false);
            // A pooled frame never escapes as a public result: a remote block is copied before its frame is released.
            return block.Preserve();
        }

        /// <summary>Reads one block of a validated manifest with a lifetime the caller already linked to the node.</summary>
        /// <param name="record">The validated signed manifest.</param>
        /// <param name="provider">The final content provider.</param>
        /// <param name="index">The validated block index.</param>
        /// <param name="relay">An optional relay; null permits direct access with automatic relay fallback.</param>
        /// <param name="cancellationToken">The transfer lifetime, already linked to the node lifetime.</param>
        /// <returns>
        /// The raw block after exact length, position and Merkle authentication: a stable store view for a local block, or a
        /// view inside the provider's response frame that the caller releases by disposing it.
        /// </returns>
        private async Task<OwnedMemory> ReadBlockCoreAsync(DHTRecord record, DHTPeer provider, int index, DHTPeer? relay,
            CancellationToken cancellationToken)
        {
            if (provider.NodeId == NodeId && relay == null)
            {
                return new OwnedMemory((await ReadLocalBlockAsync(record, index, cancellationToken).ConfigureAwait(false)).Bytes);
            }
            using var body = new Wire();
            BlockMessage.WriteRequest(body, record, index);
            var response = await RequestAsync(provider, Operation.Block, body.WrittenMemory, cancellationToken, relay).ConfigureAwait(false);
            try
            {
                using var reader = new Wire(response.Bytes);
                return response.Narrow(BlockMessage.ReadResponse(reader, record, index));
            }
            catch
            {
                response.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Reads a block requested by a peer, first asking the content fallback once when the requested geometry is not
        /// registered locally.
        /// </summary>
        /// <param name="record">The requested signed geometry.</param>
        /// <param name="index">The requested block index.</param>
        /// <param name="cancellationToken">The bounded request lifetime.</param>
        /// <returns>The raw block and its authentication path.</returns>
        /// <exception cref="IOException">The content is not available locally, even after the fallback.</exception>
        /// <exception cref="InvalidDataException">The stored block no longer matches its signed geometry.</exception>
        /// <exception cref="OperationCanceledException">The request lifetime ended.</exception>
        private async Task<(ReadOnlyMemory<byte> Bytes, MerkleTree Tree)> ReadServedBlockAsync(DHTRecord record, int index,
            CancellationToken cancellationToken)
        {
            if (_contentFallback != null && !IsContentRegistered(record))
            {
                try
                {
                    var acquired = await _contentFallback.TryAcquireAsync(record, cancellationToken).ConfigureAwait(false);
                    Log(LogLevel.Debug, acquired ? "Content fallback made requested content available." : "Content fallback declined a request.");
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    Log(LogLevel.Warning, "Content fallback failed: ", exception);
                }
            }
            return await ReadLocalBlockAsync(record, index, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Checks whether the exact signed content geometry is registered locally.</summary>
        /// <param name="record">The signed content geometry.</param>
        /// <returns>Whether blocks of this geometry can be served from the local store.</returns>
        private bool IsContentRegistered(DHTRecord record)
        {
            lock (_gate)
            {
                return _contents.TryGetValue(ContentId(record), out var found) && found.Record.SameContent(record);
            }
        }

        /// <summary>Reads and reauthenticates a stored block before serving it.</summary>
        /// <param name="record">The requested signed geometry.</param>
        /// <param name="index">The requested block index.</param>
        /// <param name="cancellationToken">The storage lifetime.</param>
        /// <returns>The raw block and its authentication path.</returns>
        private async Task<(ReadOnlyMemory<byte> Bytes, MerkleTree Tree)> ReadLocalBlockAsync(DHTRecord record, int index, CancellationToken cancellationToken)
        {
            LocalContent content;
            lock (_gate)
            {
                if (!_contents.TryGetValue(ContentId(record), out var found) || !found.Record.SameContent(record))
                {
                    throw new IOException("The requested content geometry is not available locally.");
                }
                content = found;
            }
            var stored = await _store.GetAsync(content.Tree.LeafId(index), cancellationToken).ConfigureAwait(false);
            if (!stored.HasValue)
            {
                throw new IOException("The content block is no longer available in storage.");
            }
            if (stored.Value.Length > record.BlockSize)
            {
                throw new InvalidDataException("The stored block exceeds its signed geometry.");
            }
            var bytes = stored.Value;
            content.Tree.VerifyLocal(record, index, bytes.Span);
            return (bytes, content.Tree);
        }

        /// <summary>Registers verified local content and its signed key within metadata quotas.</summary>
        /// <param name="record">The signed content geometry.</param>
        /// <param name="tree">The verified tree of all content leaves.</param>
        /// <exception cref="IOException">The metadata quota is exhausted.</exception>
        /// <exception cref="InvalidDataException">The tree differs from the signed manifest.</exception>
        private void RegisterContent(DHTRecord record, MerkleTree tree)
        {
            if (tree.Root != record.MerkleRoot || tree.Count != record.BlockCount)
            {
                throw new InvalidDataException("The complete Merkle tree differs from the signed manifest.");
            }
            lock (_gate)
            {
                PruneLocked();
                var id = ContentId(record);
                var leaves = tree.Count;
                foreach (var entry in _contents)
                {
                    if (entry.Key != id)
                    {
                        leaves += entry.Value.Tree.Count;
                    }
                }
                if (leaves > _options.MaxLocalLeaves)
                {
                    throw new IOException("The local Merkle metadata quota is full.");
                }
                CacheRecord(record, (_options.Capabilities & DHTCapabilities.Provide) == 0 ? null : _self);
                _contents[id] = new LocalContent(record, tree);
            }
        }

        /// <summary>Replicates a signed publication near both its key and complete-file hash.</summary>
        /// <param name="record">The unexpired publication.</param>
        /// <param name="cancellationToken">Cancels lookup and replication.</param>
        /// <returns>The number of remote replicas accepting the record.</returns>
        private async Task<int> AnnounceRecordAsync(DHTRecord record, CancellationToken cancellationToken)
        {
            RequireProvider();
            CacheRecord(record, LocalPeer);
            var byKey = await LookupAsync(0, record.Key.RoutingId, cancellationToken).ConfigureAwait(false);
            var byHash = await LookupAsync(0, record.FileHash, cancellationToken).ConfigureAwait(false);
            var peers = new Dictionary<string, DHTPeer>();
            foreach (var peer in byKey.Peers)
            {
                peers[peer.NodeId] = peer;
            }
            foreach (var peer in byHash.Peers)
            {
                peers[peer.NodeId] = peer;
            }
            var accepted = 0;
            using var body = new Wire();
            StoreMessage.WriteRequest(body, record);
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
                    Log(LogLevel.Debug, "Replica announcement failed: ", exception);
                }
            }
            if (accepted == 0)
            {
                Log(LogLevel.Warning, "Publication is available locally; no remote replica accepted the announcement.");
            }
            return accepted;
        }

        /// <summary>Reads a stream into blocks of one geometry, storing every block and appending its Merkle leaf.</summary>
        /// <param name="source">The readable content stream.</param>
        /// <param name="blockSize">The block size of the content geometry.</param>
        /// <param name="maxLength">The maximum accepted content length in bytes.</param>
        /// <param name="leaves">Receives the contiguous leaf digests in block order.</param>
        /// <param name="cancellationToken">Cancels reading and storing.</param>
        /// <returns>The complete-file SHA-256 and length, or null when the content exceeds the length or Merkle metadata limit.</returns>
        /// <exception cref="IOException">The stream or content store failed.</exception>
        /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
        private async Task<(string FileHash, long Length)?> StoreContentAsync(Stream source, int blockSize, long maxLength, Wire leaves,
            CancellationToken cancellationToken)
        {
            using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var bufferOwner = new PooledBuffer(blockSize);
            var buffer = bufferOwner.Memory;
            long length = 0;
            while (true)
            {
                var count = 0;
                while (count < buffer.Length)
                {
                    var read = await source.ReadAsync(buffer.Slice(count), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }
                    count += read;
                }
                if (count == 0 && leaves.Length != 0)
                {
                    break;
                }
                if (length + count > maxLength || (leaves.Length / 32) >= _options.MaxLocalLeaves)
                {
                    return null;
                }
                digest.AppendData(buffer.Span.Slice(0, count));
                length += count;
                var leafId = MerkleTree.AppendLeaf(leaves, buffer.Span.Slice(0, count));
                await _store.PutAsync(leafId, buffer.Slice(0, count), cancellationToken).ConfigureAwait(false);
                if (count < buffer.Length)
                {
                    break;
                }
            }
            return (Crypto.Hex(digest.GetHashAndReset()), length);
        }

        /// <summary>Validates a new locally signed key revision before reading its content.</summary>
        /// <param name="name">The publisher-scoped name.</param>
        /// <param name="revision">The requested positive revision.</param>
        /// <exception cref="ArgumentException">The revision is nonpositive or does not advance the known revision.</exception>
        private void ValidateRevision(string name, long revision)
        {
            var key = new DHTKey(NodeId, name);
            lock (_gate)
            {
                if (revision <= 0 || (_revisions.TryGetValue(key.ToString(), out var observed) && observed.Record.Revision >= revision))
                {
                    throw new ArgumentException("A publication revision must advance the locally observed key revision.", nameof(revision));
                }
            }
        }

        /// <summary>Enforces the local download capability for content transfers.</summary>
        /// <exception cref="InvalidOperationException">Downloading is disabled.</exception>
        private void RequireDownloader()
        {
            if ((_options.Capabilities & DHTCapabilities.Download) == 0)
            {
                throw new InvalidOperationException("Download capability is required for content transfers.");
            }
        }

        /// <summary>Enforces the local content-provider capability.</summary>
        /// <exception cref="InvalidOperationException">Content providing is disabled.</exception>
        private void RequireProvider()
        {
            if ((_options.Capabilities & DHTCapabilities.Provide) == 0)
            {
                throw new InvalidOperationException("Content-providing capability is required for publication.");
            }
        }
    }
}
