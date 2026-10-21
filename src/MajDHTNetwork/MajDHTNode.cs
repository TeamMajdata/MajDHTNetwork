using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Runs an authenticated DHT participant, content provider and optional Traversal node or Forwarder.</summary>
    public sealed partial class MajDHTNode : IDisposable, IAsyncDisposable
    {
        /// <summary>The validated immutable configuration snapshot.</summary>
        private readonly DHTNodeOptions _options;
        /// <summary>The caller-supplied or generated node identity.</summary>
        private readonly DHTIdentity _identity;
        /// <summary>The caller-owned content store.</summary>
        private readonly IDHTContentStore _store;
        /// <summary>The caller-supplied or default routing table.</summary>
        private readonly IDHTRoutingTable _routing;
        /// <summary>The caller-supplied or default route selection.</summary>
        private readonly IDHTRouteSelector _routeSelector;
        /// <summary>The optional caller-supplied source of content that is requested but not served locally.</summary>
        private readonly IDHTContentFallback? _contentFallback;
        /// <summary>Serializes state and in-memory index updates.</summary>
        private readonly object _gate = new object();
        /// <summary>Serializes start and stop operations.</summary>
        private readonly SemaphoreSlim _lifecycle = new SemaphoreSlim(1, 1);
        /// <summary>Serializes local publication revisions and tree registration.</summary>
        private readonly SemaphoreSlim _publishing = new SemaphoreSlim(1, 1);
        /// <summary>
        /// Bounds the record replications in flight to <see cref="MaxConcurrentReplications"/>, so many publications, imports
        /// and maintenance announcements at once stay within the outgoing exchange budget of
        /// <see cref="DHTNodeOptions.MaxConcurrentRequests"/> instead of failing requests and evicting routing contacts.
        /// </summary>
        private readonly SemaphoreSlim _replications;
        /// <summary>The node shutdown token, also linked to all public operations.</summary>
        private readonly CancellationTokenSource _lifetime = new CancellationTokenSource();
        /// <summary>The signed records keyed by canonical lookup key.</summary>
        private readonly Dictionary<string, DHTRecord> _records = new Dictionary<string, DHTRecord>();
        /// <summary>The bounded revision high-water marks retained through the maximum publication lease.</summary>
        private readonly Dictionary<string, (DHTRecord Record, DateTimeOffset RetainUntil)> _revisions = new Dictionary<string, (DHTRecord, DateTimeOffset)>();
        /// <summary>The bounded provider claims indexed by whole-file hash.</summary>
        private readonly Dictionary<string, Dictionary<string, ProviderClaim>> _providers = new Dictionary<string, Dictionary<string, ProviderClaim>>();
        /// <summary>The locally available Merkle trees indexed by file hash and block size.</summary>
        private readonly Dictionary<string, LocalContent> _contents = new Dictionary<string, LocalContent>();
        /// <summary>
        /// The Merkle leaves of every tree in <see cref="_contents"/>, kept in step with it by
        /// <see cref="SetLocalContentLocked"/> and <see cref="RemoveLocalContentLocked"/>, so registering content checks the
        /// leaf quota without walking every tree; that walk made registering N contents quadratic under the index lock.
        /// </summary>
        private long _localLeaves;
        /// <summary>
        /// The revision and <see cref="Stopwatch"/> timestamp with which each record last reached a remote replica, keyed by
        /// canonical lookup key, so maintenance does not reannounce a record that a publication, import, renewal or the
        /// previous maintenance pass announced less than one maintenance interval ago. Entries leave with their records.
        /// </summary>
        private readonly Dictionary<string, (long Revision, long Timestamp)> _announced = new Dictionary<string, (long, long)>();
        /// <summary>
        /// The shortest interval between two opportunistic prunes of the index, in <see cref="Stopwatch"/> ticks. A prune
        /// walks every record, revision, provider claim and local tree, so pruning on every cached record made a node with
        /// many records quadratic; postponing the walk is safe because every reader checks expiry itself and the quota
        /// checks prune before refusing.
        /// </summary>
        private static readonly long s_pruneInterval = Stopwatch.Frequency;
        /// <summary>The <see cref="Stopwatch"/> timestamp of the last prune, which lets the hot paths prune at most once per interval.</summary>
        private long _lastPrune = Stopwatch.GetTimestamp() - s_pruneInterval;
        /// <summary>The bounded request replay cache, keyed without strings so every request can be matched allocation-free.</summary>
        private readonly Dictionary<ReplayKey, CachedReply> _replies = new Dictionary<ReplayKey, CachedReply>();
        /// <summary>The owned socket listeners and exchange implementation.</summary>
        private readonly SocketTransport _transport;
        /// <summary>The current signed contact, refreshed during maintenance.</summary>
        private DHTContact? _self;
        /// <summary>The maintenance loop task.</summary>
        private Task _maintenance = Task.CompletedTask;
        /// <summary>The initial background bootstrap through the configured endpoints.</summary>
        private Task _bootstrap = Task.CompletedTask;
        /// <summary>Tracks whether this single-use node has started.</summary>
        private volatile bool _started;
        /// <summary>Tracks whether the node has stopped permanently.</summary>
        private volatile bool _stopped;
        /// <summary>The cancellation callback for an external lifetime token.</summary>
        private CancellationTokenRegistration _externalCancellation;

        /// <summary>Gets the node's stable public identity fingerprint.</summary>
        public string NodeId => _identity.NodeId;
        /// <summary>Gets the currently signed local contact after startup.</summary>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        public DHTContact LocalContact
        {
            get
            {
                EnsureRunning();
                lock (_gate)
                {
                    return _self!;
                }
            }
        }
        /// <summary>
        /// Gets the currently signed local contact paired with the endpoints this node listens on, for handing to another node
        /// out of band, such as a bootstrap contact passed between processes on one host. Remote nodes learn this node's
        /// endpoints by observing its packets, never from the contact; a wildcard listener is paired with its loopback address.
        /// </summary>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        public DHTPeer LocalPeer
        {
            get
            {
                EnsureRunning();
                lock (_gate)
                {
                    return new DHTPeer(_self!, ListenerEndpoints());
                }
            }
        }
        /// <summary>Gets a snapshot of all known live peers, each at the endpoints this node observed for it.</summary>
        public IReadOnlyList<DHTPeer> KnownPeers => RoutedPeers(NodeId, 4096).AsReadOnly();
        /// <summary>
        /// Gets copies of the external addresses of this node, at most one per address family, as confirmed by Traversal nodes,
        /// Forwarders and Hello responders in at least two distinct networks; empty until confirmed.
        /// </summary>
        public IReadOnlyList<IPAddress> ExternalAddresses
        {
            get
            {
                lock (_gate)
                {
                    var result = new List<IPAddress>(_externalAddresses.Count);
                    foreach (var address in _externalAddresses.Values)
                    {
                        result.Add(NetworkScope.CopyAddress(address));
                    }
                    return result.AsReadOnly();
                }
            }
        }

        /// <summary>Constructs an unstarted node without performing filesystem access.</summary>
        /// <param name="options">Listener, resource and protocol limits, or defaults.</param>
        /// <param name="identity">
        /// A stable identity reaching <see cref="DHTNodeOptions.IdentityWorkBits"/>, or null to create one with
        /// <see cref="DHTIdentity.Create"/>, which can take seconds; create and persist identities ahead of time instead.
        /// </param>
        /// <param name="contentStore">A concurrent caller-owned block store, or a bounded 64 MiB memory cache.</param>
        /// <param name="routingTable">
        /// An unbound thread-safe routing table that this node initializes and owns, or a new <see cref="KademliaDHTRoutingTable"/>.
        /// </param>
        /// <param name="routeSelector">A thread-safe route selection, or a <see cref="DefaultDHTRouteSelector"/>; it may be shared.</param>
        /// <param name="contentFallback">
        /// An optional thread-safe source that can make requested but locally unavailable content available on demand, or null
        /// to refuse such block requests.
        /// </param>
        /// <exception cref="ArgumentException">The supplied options are invalid, or the identity does not reach the required work.</exception>
        /// <exception cref="InvalidOperationException">The routing table is already bound to another node.</exception>
        public MajDHTNode(DHTNodeOptions? options = null, DHTIdentity? identity = null, IDHTContentStore? contentStore = null,
            IDHTRoutingTable? routingTable = null, IDHTRouteSelector? routeSelector = null, IDHTContentFallback? contentFallback = null)
        {
            _options = (options ?? new DHTNodeOptions()).Snapshot();
            _identity = identity ?? DHTIdentity.Create(_options.IdentityWorkBits);
            if (_options.IdentityWorkBits != 0 && _identity.IdentityWork < _options.IdentityWorkBits)
            {
                throw new ArgumentException("The identity does not reach the configured identity work; create it with DHTIdentity.Create.",
                    nameof(identity));
            }
            _store = contentStore ?? new MemoryDHTContentStore();
            _routing = routingTable ?? new KademliaDHTRoutingTable();
            _routing.Initialize(NodeId, _options.BucketSize);
            _routeSelector = routeSelector ?? new DefaultDHTRouteSelector();
            _contentFallback = contentFallback;
            _replications = new SemaphoreSlim(MaxConcurrentReplications, MaxConcurrentReplications);
            _transport = new SocketTransport(_options, HandleAsync, _options.Logger);
        }

        /// <summary>
        /// Binds listeners and starts a single-use node, its background maintenance and, when bootstrap endpoints are
        /// configured, a background bootstrap.
        /// </summary>
        /// <param name="cancellationToken">An optional lifetime token; cancellation stops listener work.</param>
        /// <returns>Completion once listeners are bound and the signed contact is available.</returns>
        /// <exception cref="InvalidOperationException">The node was already started or stopped.</exception>
        /// <exception cref="System.Net.Sockets.SocketException">A requested port could not be bound.</exception>
        /// <exception cref="OperationCanceledException">Startup was cancelled.</exception>
        public async Task StartAsync(CancellationToken cancellationToken = default)
        {
            await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_started || _stopped)
                {
                    throw new InvalidOperationException("A MajDHTNode instance can only be started once.");
                }
                _transport.Bind();
                lock (_gate)
                {
                    RefreshLocalContactLocked();
                    _started = true;
                }
                _transport.Run();
                _externalCancellation = cancellationToken.Register(() =>
                {
                    _lifetime.Cancel();
                    _transport.Stop();
                });
                _maintenance = MaintainAsync();
                if (_options.BootstrapEndpoints.Count != 0)
                {
                    _bootstrap = BootstrapInBackgroundAsync();
                }
                Log(LogLevel.Information, "Node listeners started.");
            }
            catch
            {
                if (!_started)
                {
                    _stopped = true;
                    _lifetime.Cancel();
                    await _transport.DisposeAsync().ConfigureAwait(false);
                }
                throw;
            }
            finally
            {
                _lifecycle.Release();
            }
        }

        /// <summary>Stops listeners, cancels pending node work and drains incoming handlers.</summary>
        /// <returns>Completion after transport and maintenance shutdown.</returns>
        public async Task StopAsync()
        {
            await _lifecycle.WaitAsync().ConfigureAwait(false);
            try
            {
                if (_stopped)
                {
                    return;
                }
                _stopped = true;
                _lifetime.Cancel();
                _externalCancellation.Dispose();
                await _transport.DisposeAsync().ConfigureAwait(false);
                await _maintenance.ConfigureAwait(false);
                await _bootstrap.ConfigureAwait(false);
                await DrainAssistanceAsync().ConfigureAwait(false);
                Log(LogLevel.Information, "Node stopped.");
            }
            finally
            {
                _lifecycle.Release();
            }
        }

        /// <summary>Stops and drains the node asynchronously; caller-owned identity and store remain usable.</summary>
        /// <returns>Completion after shutdown.</returns>
        public async ValueTask DisposeAsync()
        {
            await StopAsync().ConfigureAwait(false);
        }

        /// <summary>Stops and drains the node synchronously; asynchronous disposal is preferred.</summary>
        public void Dispose()
        {
            StopAsync().GetAwaiter().GetResult();
        }

        /// <summary>Rejects operations outside the running node lifetime.</summary>
        /// <exception cref="InvalidOperationException">The node is unstarted or stopped.</exception>
        private void EnsureRunning()
        {
            lock (_gate)
            {
                if (!_started || _stopped || _lifetime.IsCancellationRequested)
                {
                    throw new InvalidOperationException("The node is not running.");
                }
            }
        }

        /// <summary>Lists the endpoints this node listens on, pairing a wildcard listener with its loopback address.</summary>
        /// <returns>At most one endpoint per listener address family with the bound TCP and UDP ports.</returns>
        private List<DHTEndpoint> ListenerEndpoints()
        {
            var result = new List<DHTEndpoint>();
            foreach (var address in _options.ListenAddresses)
            {
                var tcp = _transport.TcpPortFor(address.AddressFamily);
                var udp = _transport.UdpPortFor(address.AddressFamily);
                if (tcp == 0 && udp == 0)
                {
                    continue;
                }
                var local = NetworkScope.IsWildcard(address)
                    ? address.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Loopback : IPAddress.Loopback
                    : address;
                result.Add(new DHTEndpoint(local, tcp, udp));
            }
            return result;
        }

        /// <summary>Links an operation to explicit cancellation and the node lifetime.</summary>
        /// <param name="token">The caller cancellation token.</param>
        /// <returns>A caller-disposed linked cancellation source.</returns>
        private CancellationTokenSource OperationCancellation(CancellationToken token)
        {
            EnsureRunning();
            return CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        }

        /// <summary>Writes structured diagnostics through the configured standard logger.</summary>
        /// <param name="level">The severity.</param>
        /// <param name="message">The static operation context.</param>
        /// <param name="failure">An optional failure whose type is logged without private exception text.</param>
        private void Log(LogLevel level, string message, Exception? failure = null)
        {
            DHTLog.Write(_options.Logger, level, message, failure);
        }

        /// <summary>Gets the local geometry identifier for a signed content record.</summary>
        /// <param name="record">The content record.</param>
        /// <returns>The whole-file hash and canonical block size.</returns>
        private static string ContentId(DHTRecord record)
        {
            return record.ContentId;
        }

        /// <summary>Applies an asynchronous operation to every item in order, keeping at most a given number in flight.</summary>
        /// <typeparam name="T">The item type.</typeparam>
        /// <param name="items">The items.</param>
        /// <param name="parallelism">The maximum operations in flight, at least one.</param>
        /// <param name="operation">The operation applied to one item; it must handle the failures it wants to tolerate.</param>
        /// <returns>Completion after every operation ended; an escaping failure propagates once the other workers ended.</returns>
        private static async Task ForEachAsync<T>(IReadOnlyList<T> items, int parallelism, Func<T, Task> operation)
        {
            var next = -1;
            var workers = new Task[Math.Min(Math.Max(1, parallelism), items.Count)];
            for (var index = 0; index < workers.Length; index++)
            {
                workers[index] = RunAsync();
            }
            await Task.WhenAll(workers).ConfigureAwait(false);

            async Task RunAsync()
            {
                while (true)
                {
                    var index = Interlocked.Increment(ref next);
                    if (index >= items.Count)
                    {
                        return;
                    }
                    await operation(items[index]).ConfigureAwait(false);
                }
            }
        }

        /// <summary>Keeps the signed content geometry with its Merkle authentication tree.</summary>
        private sealed class LocalContent
        {
            /// <summary>The content geometry, with an associated signed key.</summary>
            internal DHTRecord Record { get; }
            /// <summary>The precomputed authentication paths.</summary>
            internal MerkleTree Tree { get; }

            /// <summary>Associates a record and immutable tree.</summary>
            /// <param name="record">The signed geometry.</param>
            /// <param name="tree">The corresponding Merkle tree.</param>
            internal LocalContent(DHTRecord record, MerkleTree tree)
            {
                Record = record;
                Tree = tree;
            }
        }

        /// <summary>Coalesces UDP retries and bounds replay retention.</summary>
        private sealed class CachedReply
        {
            /// <summary>The authenticated operation fingerprint.</summary>
            internal RequestFingerprint Fingerprint { get; }
            /// <summary>The insertion time used for expiry.</summary>
            internal DateTimeOffset Created { get; } = DateTimeOffset.UtcNow;
            /// <summary>The single completion shared by duplicate requests.</summary>
            internal TaskCompletionSource<ReadOnlyMemory<byte>> Completion { get; } = new TaskCompletionSource<ReadOnlyMemory<byte>>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Creates a pending replay entry.</summary>
            /// <param name="fingerprint">The operation and body fingerprint.</param>
            internal CachedReply(RequestFingerprint fingerprint)
            {
                Fingerprint = fingerprint;
            }
        }

        /// <summary>Identifies a request by its sender digest and correlation identifier without strings.</summary>
        private readonly struct ReplayKey : IEquatable<ReplayKey>
        {
            /// <summary>The sender's node digest.</summary>
            private readonly DigestKey _sender;
            /// <summary>The first correlation identifier word.</summary>
            private readonly ulong _high;
            /// <summary>The second correlation identifier word.</summary>
            private readonly ulong _low;

            /// <summary>Copies the sender digest and correlation identifier into inline storage.</summary>
            /// <param name="senderHash">The 32-byte sender node digest.</param>
            /// <param name="requestId">The 16-byte correlation identifier.</param>
            internal ReplayKey(ReadOnlySpan<byte> senderHash, ReadOnlySpan<byte> requestId)
            {
                _sender = new DigestKey(senderHash);
                _high = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(requestId);
                _low = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(requestId.Slice(8));
            }

            /// <inheritdoc />
            public bool Equals(ReplayKey other)
            {
                return _high == other._high && _low == other._low && _sender.Equals(other._sender);
            }

            /// <inheritdoc />
            public override bool Equals(object? obj)
            {
                return obj is ReplayKey other && Equals(other);
            }

            /// <inheritdoc />
            public override int GetHashCode()
            {
                return HashCode.Combine(_sender, _high, _low);
            }
        }

        /// <summary>Fingerprints the operation and body of a request, so a reused identifier with different content is rejected.</summary>
        private readonly struct RequestFingerprint : IEquatable<RequestFingerprint>
        {
            /// <summary>The operation with its response bit.</summary>
            private readonly byte _kind;
            /// <summary>The body digest.</summary>
            private readonly DigestKey _body;

            /// <summary>Hashes a request body and retains its operation.</summary>
            /// <param name="kind">The operation with its response bit.</param>
            /// <param name="body">The operation body.</param>
            internal RequestFingerprint(byte kind, ReadOnlySpan<byte> body)
            {
                _kind = kind;
                _body = DigestKey.Of(body);
            }

            /// <inheritdoc />
            public bool Equals(RequestFingerprint other)
            {
                return _kind == other._kind && _body.Equals(other._body);
            }

            /// <inheritdoc />
            public override bool Equals(object? obj)
            {
                return obj is RequestFingerprint other && Equals(other);
            }

            /// <inheritdoc />
            public override int GetHashCode()
            {
                return HashCode.Combine(_kind, _body);
            }
        }
    }
}
