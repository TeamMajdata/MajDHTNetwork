using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Runs an authenticated DHT participant, content provider and optional opaque relay.</summary>
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
        /// <summary>Serializes state and in-memory index updates.</summary>
        private readonly object _gate = new object();
        /// <summary>Serializes start and stop operations.</summary>
        private readonly SemaphoreSlim _lifecycle = new SemaphoreSlim(1, 1);
        /// <summary>Serializes local publication revisions and tree registration.</summary>
        private readonly SemaphoreSlim _publishing = new SemaphoreSlim(1, 1);
        /// <summary>The node shutdown token, also linked to all public operations.</summary>
        private readonly CancellationTokenSource _lifetime = new CancellationTokenSource();
        /// <summary>The signed records keyed by canonical lookup key.</summary>
        private readonly Dictionary<string, DHTRecord> _records = new Dictionary<string, DHTRecord>();
        /// <summary>The bounded revision high-water marks retained through the maximum publication lease.</summary>
        private readonly Dictionary<string, (DHTRecord Record, DateTimeOffset RetainUntil)> _revisions = new Dictionary<string, (DHTRecord, DateTimeOffset)>();
        /// <summary>The bounded provider claims indexed by whole-file hash.</summary>
        private readonly Dictionary<string, Dictionary<string, DHTPeer>> _providers = new Dictionary<string, Dictionary<string, DHTPeer>>();
        /// <summary>The locally available Merkle trees indexed by file hash and block size.</summary>
        private readonly Dictionary<string, LocalContent> _contents = new Dictionary<string, LocalContent>();
        /// <summary>The bounded request replay cache.</summary>
        private readonly Dictionary<string, CachedReply> _replies = new Dictionary<string, CachedReply>();
        /// <summary>The owned socket listeners and exchange implementation.</summary>
        private readonly SocketTransport _transport;
        /// <summary>The current signed contact, refreshed during maintenance.</summary>
        private DHTPeer? _self;
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
        /// <summary>Gets the currently signed bootstrap contact after startup.</summary>
        /// <exception cref="InvalidOperationException">The node is not running.</exception>
        public DHTPeer LocalPeer
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
        /// <summary>Gets a snapshot of all known live peers.</summary>
        public IReadOnlyList<DHTPeer> KnownPeers => RoutedPeers(NodeId, 4096).AsReadOnly();

        /// <summary>Constructs an unstarted node without performing filesystem access.</summary>
        /// <param name="options">Listener, resource and protocol limits, or defaults.</param>
        /// <param name="identity">A stable identity, or a newly generated identity.</param>
        /// <param name="contentStore">A concurrent caller-owned block store, or a bounded 64 MiB memory cache.</param>
        /// <param name="routingTable">
        /// An unbound thread-safe routing table that this node initializes and owns, or a new <see cref="KademliaDHTRoutingTable"/>.
        /// </param>
        /// <param name="routeSelector">A thread-safe route selection, or a <see cref="DefaultDHTRouteSelector"/>; it may be shared.</param>
        /// <exception cref="ArgumentException">The supplied options are invalid.</exception>
        /// <exception cref="InvalidOperationException">The routing table is already bound to another node.</exception>
        public MajDHTNode(DHTNodeOptions? options = null, DHTIdentity? identity = null, IDHTContentStore? contentStore = null,
            IDHTRoutingTable? routingTable = null, IDHTRouteSelector? routeSelector = null)
        {
            _options = (options ?? new DHTNodeOptions()).Snapshot();
            _identity = identity ?? new DHTIdentity();
            _store = contentStore ?? new MemoryDHTContentStore();
            _routing = routingTable ?? new KademliaDHTRoutingTable();
            _routing.Initialize(NodeId, _options.BucketSize);
            _routeSelector = routeSelector ?? new DefaultDHTRouteSelector();
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
                    RefreshLocalPeerLocked();
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
                await DrainNatAsync().ConfigureAwait(false);
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
            return record.FileHash + ":" + record.BlockSize.ToString(System.Globalization.CultureInfo.InvariantCulture);
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
            internal string Fingerprint { get; }
            /// <summary>The insertion time used for expiry.</summary>
            internal DateTimeOffset Created { get; } = DateTimeOffset.UtcNow;
            /// <summary>The single completion shared by duplicate requests.</summary>
            internal TaskCompletionSource<ReadOnlyMemory<byte>> Completion { get; } = new TaskCompletionSource<ReadOnlyMemory<byte>>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Creates a pending replay entry.</summary>
            /// <param name="fingerprint">The operation and body fingerprint.</param>
            internal CachedReply(string fingerprint)
            {
                Fingerprint = fingerprint;
            }
        }
    }
}
