#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// A complete MajDHT participant written only against the library's public protocol API, without <see cref="MajDHTNode"/>:
    /// it listens on TCP, answers Hello, Ping, Find, Store and Block, serves one in-memory file, indexes records it is asked to
    /// store, and can query other nodes. It demonstrates and verifies that third parties can implement their own node.
    /// </summary>
    internal sealed class MinimalProtocolNode : IAsyncDisposable
    {
        /// <summary>The node identity.</summary>
        private readonly DHTIdentity _identity;
        /// <summary>The socket transport that frames, retries and delivers envelopes.</summary>
        private readonly SocketTransport _transport;
        /// <summary>The served file.</summary>
        private readonly byte[] _content;
        /// <summary>The Merkle tree of the served file.</summary>
        private readonly MerkleTree _tree;
        /// <summary>Protects the index and the request log.</summary>
        private readonly object _gate = new object();
        /// <summary>The records this node indexes, keyed by canonical key, with the providers that announced them.</summary>
        private readonly Dictionary<string, (DHTRecord Record, List<DHTPeer> Providers)> _index =
            new Dictionary<string, (DHTRecord, List<DHTPeer>)>(StringComparer.Ordinal);
        /// <summary>The contacts learned from authenticated requests, keyed by node identifier.</summary>
        private readonly Dictionary<string, DHTPeer> _known = new Dictionary<string, DHTPeer>(StringComparer.Ordinal);
        /// <summary>The operations received so far.</summary>
        private readonly List<Operation> _received = new List<Operation>();

        /// <summary>Gets the node identity.</summary>
        internal DHTIdentity Identity => _identity;
        /// <summary>Gets the signed local contact.</summary>
        internal DHTPeer LocalPeer { get; }
        /// <summary>Gets the bound TCP listener endpoint.</summary>
        internal IPEndPoint Endpoint { get; }
        /// <summary>Gets the signed record of the served file.</summary>
        internal DHTRecord Record { get; }

        /// <summary>Binds a node that serves one file.</summary>
        /// <param name="address">The loopback listener address.</param>
        /// <param name="name">The published name in this identity's key namespace.</param>
        /// <param name="content">The file to serve.</param>
        /// <param name="blockSize">The publication block size.</param>
        internal MinimalProtocolNode(IPAddress address, string name, byte[] content, int blockSize = 1024)
        {
            _identity = new DHTIdentity();
            _content = (byte[])content.Clone();
            var options = new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { address },
                TcpPort = 0,
                UdpPort = null,
                RequestTimeout = TimeSpan.FromSeconds(2)
            };
            _transport = new SocketTransport(options, HandleAsync);
            _transport.Bind();
            Endpoint = new IPEndPoint(address, _transport.TcpPort);
            // The contact carries no endpoint; this node pairs it with its own listener for the peers it lists itself to.
            var contact = DHTContact.Create(_identity, DHTCapabilities.Download | DHTCapabilities.Provide, DHTReachability.Public, false,
                Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
            LocalPeer = new DHTPeer(contact, new[] { new DHTEndpoint(address, _transport.TcpPort, 0) });
            using var leaves = new Wire();
            var blockCount = Math.Max(1, (_content.Length + blockSize - 1) / blockSize);
            for (var index = 0; index < blockCount; index++)
            {
                MerkleTree.AppendLeaf(leaves, Block(index, blockSize));
            }
            _tree = new MerkleTree(leaves.WrittenSpan);
            Record = DHTRecord.Create(_identity, name, Crypto.Hex(Crypto.Hash(_content)), _tree.Root, _content.Length, blockSize, 1,
                DateTimeOffset.UtcNow.AddHours(1));
            _transport.Run();
        }

        /// <summary>Counts received requests of one operation.</summary>
        /// <param name="operation">The operation.</param>
        /// <returns>The number of requests received.</returns>
        internal int Received(Operation operation)
        {
            lock (_gate)
            {
                return _received.FindAll(entry => entry == operation).Count;
            }
        }

        /// <summary>Learns the contact listening at an endpoint through a signed plaintext Hello exchange.</summary>
        /// <param name="endpoint">The remote TCP endpoint.</param>
        /// <param name="token">The exchange deadline.</param>
        /// <returns>The authenticated remote contact.</returns>
        /// <exception cref="CryptographicException">The response was not a correlated Hello response.</exception>
        internal async Task<DHTPeer> HelloAsync(IPEndPoint endpoint, CancellationToken token)
        {
            var request = new Packet(LocalPeer, Crypto.Random(Packet.RequestIdLength), (byte)Operation.Hello, ReadOnlyMemory<byte>.Empty);
            using var encoded = await _transport.ExchangeAtAsync(DHTTransport.Tcp, endpoint, request.SealHello(_identity), token);
            var response = Packet.Open(_identity, encoded.Bytes);
            if (response.Kind != (request.Kind | 128) || !response.RequestId.Span.SequenceEqual(request.RequestId.Span))
            {
                throw new CryptographicException("The Hello response was not correlated with the request.");
            }
            using var reader = new Wire(ResponseStatus.ReadResult(response.Body));
            HelloMessage.ReadResponse(reader);
            // The contact answered at this endpoint, which is how this node learns where the contact can be reached.
            var peer = DHTPeer.Observed(response.Sender, DHTTransport.Tcp, endpoint);
            Remember(peer);
            return peer;
        }

        /// <summary>Performs one Find lookup at a peer.</summary>
        /// <param name="peer">The queried node.</param>
        /// <param name="mode">The lookup mode.</param>
        /// <param name="target">The lookup target.</param>
        /// <param name="token">The exchange deadline.</param>
        /// <returns>The verified lookup result.</returns>
        internal async Task<FindResponse> FindAsync(DHTPeer peer, FindMode mode, string target, CancellationToken token)
        {
            using var body = new Wire();
            FindMessage.WriteRequest(body, mode, target);
            var result = await RequestAsync(peer, Operation.Find, body.WrittenMemory, token);
            using var reader = new Wire(result);
            return FindMessage.ReadResponse(reader);
        }

        /// <summary>Announces a record to a peer, which records this node as a provider.</summary>
        /// <param name="peer">The index node.</param>
        /// <param name="record">The signed record.</param>
        /// <param name="token">The exchange deadline.</param>
        /// <returns>Completion after the peer accepted the announcement.</returns>
        internal async Task StoreAsync(DHTPeer peer, DHTRecord record, CancellationToken token)
        {
            using var body = new Wire();
            StoreMessage.WriteRequest(body, record);
            await RequestAsync(peer, Operation.Store, body.WrittenMemory, token);
        }

        /// <summary>Downloads and verifies a complete file block by block from one provider.</summary>
        /// <param name="provider">The content provider.</param>
        /// <param name="record">The trusted signed record.</param>
        /// <param name="token">The download deadline.</param>
        /// <returns>The verified file bytes.</returns>
        /// <exception cref="InvalidDataException">A block or the complete file failed verification.</exception>
        internal async Task<byte[]> DownloadAsync(DHTPeer provider, DHTRecord record, CancellationToken token)
        {
            using var destination = new MemoryStream();
            for (var index = 0; index < record.BlockCount; index++)
            {
                using var body = new Wire();
                BlockMessage.WriteRequest(body, record, index);
                var result = await RequestAsync(provider, Operation.Block, body.WrittenMemory, token);
                using var reader = new Wire(result);
                var block = BlockMessage.ReadResponse(reader, record, index);
                destination.Write(block.Span);
            }
            var file = destination.ToArray();
            if (Crypto.Hex(Crypto.Hash(file)) != record.FileHash)
            {
                throw new InvalidDataException("The assembled file does not match the signed file hash.");
            }
            return file;
        }

        /// <summary>Sends one encrypted request to a peer's first TCP endpoint and authenticates the response.</summary>
        /// <param name="peer">The recipient.</param>
        /// <param name="operation">The operation.</param>
        /// <param name="body">The request body.</param>
        /// <param name="token">The exchange deadline.</param>
        /// <returns>The successful result, copied out of the transport frame.</returns>
        /// <exception cref="CryptographicException">The response was not sent by the peer for this request.</exception>
        /// <exception cref="IOException">The peer rejected the request or could not be reached.</exception>
        private async Task<byte[]> RequestAsync(DHTPeer peer, Operation operation, ReadOnlyMemory<byte> body, CancellationToken token)
        {
            var request = new Packet(LocalPeer, Crypto.Random(Packet.RequestIdLength), (byte)operation, body);
            var endpoint = new IPEndPoint(peer.Endpoints[0].Address, peer.Endpoints[0].TcpPort);
            using var encoded = await _transport.ExchangeAtAsync(DHTTransport.Tcp, endpoint, request.Seal(_identity, peer), token);
            var response = Packet.Open(_identity, encoded.Bytes);
            if (response.Sender.NodeId != peer.NodeId || response.Kind != (request.Kind | 128)
                || !CryptographicOperations.FixedTimeEquals(response.RequestId.Span, request.RequestId.Span))
            {
                throw new CryptographicException("Response sender, operation or correlation mismatch.");
            }
            Remember(DHTPeer.Observed(response.Sender, DHTTransport.Tcp, endpoint));
            // The frame is released when this method returns, so the result is copied.
            return ResponseStatus.ReadResult(response.Body).ToArray();
        }

        /// <summary>Opens, dispatches and seals one received envelope.</summary>
        /// <param name="envelope">The received envelope.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <param name="token">The handler lifetime.</param>
        /// <returns>The sealed response.</returns>
        private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> envelope, DHTTransport transport, IPEndPoint source, CancellationToken token)
        {
            var packet = Packet.Open(_identity, envelope);
            if (packet.Kind >= 128 || packet.Sender.NodeId == _identity.NodeId)
            {
                throw new InvalidDataException("Unexpected response or self request.");
            }
            lock (_gate)
            {
                _received.Add((Operation)packet.Kind);
            }
            // The sender is remembered at the source its request came from; no node announces its own endpoints.
            var sender = DHTPeer.Observed(packet.Sender, transport, source);
            Remember(sender);
            using var body = new Wire();
            using var result = new Wire();
            try
            {
                Dispatch(packet, sender, source, result);
                ResponseStatus.WriteSuccess(body, result.WrittenSpan);
            }
            catch (Exception exception) when (exception is IOException || exception is InvalidDataException)
            {
                ResponseStatus.WriteRejection(body);
            }
            var reply = new Packet(LocalPeer, packet.RequestId, (byte)(packet.Kind | 128), body.WrittenMemory);
            return Task.FromResult<ReadOnlyMemory<byte>>(reply.Seal(_identity, packet.Sender));
        }

        /// <summary>Executes one authenticated request and writes its result.</summary>
        /// <param name="packet">The authenticated request.</param>
        /// <param name="sender">The sender at the source its request came from.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <param name="result">The result encoder.</param>
        /// <exception cref="InvalidDataException">The request is malformed or asks for content this node does not hold.</exception>
        /// <exception cref="IOException">The operation is not supported by this node.</exception>
        private void Dispatch(Packet packet, DHTPeer sender, IPEndPoint source, Wire result)
        {
            using var request = new Wire(packet.Body);
            switch ((Operation)packet.Kind)
            {
                case Operation.Ping:
                    request.End();
                    return;
                case Operation.Hello:
                    HelloMessage.ReadRequest(request);
                    HelloMessage.WriteResponse(result, source);
                    return;
                case Operation.Find:
                    DispatchFind(FindMessage.ReadRequest(request), packet.Sender, result);
                    return;
                case Operation.Store:
                    DispatchStore(StoreMessage.ReadRequest(request), sender);
                    return;
                case Operation.Block:
                {
                    var block = BlockMessage.ReadRequest(request);
                    if (block.Record.FileHash != Record.FileHash || block.Record.BlockSize != Record.BlockSize)
                    {
                        throw new InvalidDataException("This node does not hold the requested content.");
                    }
                    BlockMessage.WriteResponse(result, Block(block.Index, Record.BlockSize), _tree, block.Index);
                    return;
                }
                default:
                    throw new IOException("Unsupported operation.");
            }
        }

        /// <summary>Answers a lookup from the local index and the peers learned so far, each at the endpoints observed for it.</summary>
        /// <param name="find">The lookup arguments.</param>
        /// <param name="sender">The requester, which is never referred back to itself.</param>
        /// <param name="result">The result encoder.</param>
        private void DispatchFind(FindRequest find, DHTContact sender, Wire result)
        {
            DHTRecord? record = null;
            var providers = new List<DHTPeer>();
            var peers = new List<DHTPeer>();
            lock (_gate)
            {
                if (find.Mode == FindMode.Record && find.Target == Record.Key.ToString())
                {
                    record = Record;
                    providers.Add(LocalPeer);
                }
                else if (find.Mode == FindMode.Record && _index.TryGetValue(find.Target, out var indexed))
                {
                    record = indexed.Record;
                    providers.AddRange(indexed.Providers);
                }
                else if (find.Mode == FindMode.Providers && find.Target == Record.FileHash)
                {
                    providers.Add(LocalPeer);
                }
                foreach (var peer in _known.Values)
                {
                    if (peer.NodeId != sender.NodeId && !peer.IsExpired)
                    {
                        peers.Add(peer);
                    }
                }
            }
            FindMessage.WriteResponse(result, record, peers, providers);
        }

        /// <summary>Indexes an announced record and its provider at the source the announcement came from.</summary>
        /// <param name="record">The announced record.</param>
        /// <param name="provider">The authenticated announcing peer at its observed source.</param>
        /// <exception cref="InvalidDataException">The sender cannot provide content.</exception>
        private void DispatchStore(DHTRecord record, DHTPeer provider)
        {
            if (!record.IsWithdrawn && (provider.Capabilities & DHTCapabilities.Provide) == 0)
            {
                throw new InvalidDataException("A provider capability is required to announce content.");
            }
            lock (_gate)
            {
                var key = record.Key.ToString();
                if (!_index.TryGetValue(key, out var indexed) || indexed.Record.Revision < record.Revision)
                {
                    indexed = (record, new List<DHTPeer>());
                    _index[key] = indexed;
                }
                indexed.Providers.RemoveAll(peer => peer.NodeId == provider.NodeId);
                if (!record.IsWithdrawn)
                {
                    indexed.Providers.Add(provider);
                }
            }
        }

        /// <summary>Retains the newest contact of an authenticated peer together with every endpoint it was observed at.</summary>
        /// <param name="peer">The authenticated peer at its observed endpoint.</param>
        private void Remember(DHTPeer peer)
        {
            lock (_gate)
            {
                if (!_known.TryGetValue(peer.NodeId, out var existing))
                {
                    _known[peer.NodeId] = peer;
                    return;
                }
                var newest = existing.Sequence < peer.Sequence ? peer.Contact : existing.Contact;
                var merged = new DHTPeer(newest, existing.Endpoints);
                foreach (var endpoint in peer.Endpoints)
                {
                    merged = merged.WithEndpoint(endpoint);
                }
                _known[peer.NodeId] = merged;
            }
        }

        /// <summary>Gets one block of the served file.</summary>
        /// <param name="index">The block index.</param>
        /// <param name="blockSize">The block size.</param>
        /// <returns>The raw block, which is shorter than the block size only for the final block.</returns>
        private ReadOnlySpan<byte> Block(int index, int blockSize)
        {
            var offset = index * blockSize;
            return _content.AsSpan(offset, Math.Min(blockSize, _content.Length - offset));
        }

        /// <summary>Stops the transport.</summary>
        /// <returns>Completion after the transport drains.</returns>
        public ValueTask DisposeAsync()
        {
            return _transport.DisposeAsync();
        }
    }
}
