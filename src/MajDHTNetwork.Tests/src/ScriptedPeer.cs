#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Microsoft.Extensions.Logging.Abstractions;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// A protocol-level test peer on a real loopback TCP listener whose replies are scripted by the test, for playing a
    /// malicious relay, helper or client.
    /// </summary>
    internal sealed class ScriptedPeer : IAsyncDisposable
    {
        /// <summary>The raw transport.</summary>
        private readonly SocketTransport _transport;
        /// <summary>Protects the received-request log.</summary>
        private readonly object _gate = new object();
        /// <summary>The operations received so far.</summary>
        private readonly List<Operation> _received = new List<Operation>();
        /// <summary>The script that answers each authenticated request with a status and a result body.</summary>
        private Func<Packet, IPEndPoint, (byte Status, byte[] Body)> _script = (packet, source) => (0, Array.Empty<byte>());

        /// <summary>Gets the peer identity.</summary>
        internal DHTIdentity Identity { get; }
        /// <summary>Gets the signed contact for the listener.</summary>
        internal DHTPeer Peer { get; }
        /// <summary>Gets the bound listener endpoint.</summary>
        internal IPEndPoint Endpoint { get; }

        /// <summary>Binds a scripted peer.</summary>
        /// <param name="address">The loopback listener address.</param>
        /// <param name="capabilities">The advertised capabilities.</param>
        /// <param name="reachability">The advertised reachability; Public advertises a configured endpoint.</param>
        /// <param name="identity">The peer identity, or null for a random identity.</param>
        internal ScriptedPeer(IPAddress address, DHTCapabilities capabilities, DHTReachability reachability = DHTReachability.Public,
            DHTIdentity? identity = null)
        {
            Identity = identity ?? new DHTIdentity();
            var options = new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { address },
                UdpPort = null,
                RequestTimeout = TimeSpan.FromMilliseconds(700)
            }.Snapshot();
            _transport = new SocketTransport(options, HandleAsync, NullLogger.Instance);
            _transport.Bind();
            Endpoint = new IPEndPoint(address, _transport.TcpPort);
            var flags = reachability == DHTReachability.Public ? DHTEndpointFlags.Configured : DHTEndpointFlags.None;
            Peer = DHTPeer.Create(Identity, new[] { new DHTEndpoint(address, _transport.TcpPort, 0, flags) }, capabilities, reachability,
                false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
            _transport.Run();
        }

        /// <summary>Replaces the reply script.</summary>
        /// <param name="script">Answers an authenticated request and its observed source with a status and result body.</param>
        internal void Script(Func<Packet, IPEndPoint, (byte Status, byte[] Body)> script)
        {
            _script = script;
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

        /// <summary>Sends an authenticated request, optionally under another identity, and returns its status and result.</summary>
        /// <param name="receiver">The receiving node's contact.</param>
        /// <param name="operation">The operation.</param>
        /// <param name="body">The request body.</param>
        /// <param name="token">The test deadline.</param>
        /// <param name="identity">An alternative sender identity; its contact advertises this listener unless overridden.</param>
        /// <param name="advertised">An endpoint the alternative identity claims instead of this listener.</param>
        /// <returns>The response status and result.</returns>
        /// <exception cref="InvalidDataException">The response was not authenticated by the receiver.</exception>
        internal async Task<(byte Status, ReadOnlyMemory<byte> Result)> SendAsync(DHTPeer receiver, Operation operation, ReadOnlyMemory<byte> body,
            CancellationToken token, DHTIdentity? identity = null, IPEndPoint? advertised = null)
        {
            var sender = identity ?? Identity;
            var claimed = advertised ?? Endpoint;
            var contact = identity == null ? Peer : DHTPeer.Create(identity, claimed.Address, claimed.Port, 0, Peer.Capabilities);
            var packet = new Packet(contact, Crypto.Random(16), (byte)operation, body);
            var endpoint = new IPEndPoint(receiver.Endpoints[0].Address, receiver.Endpoints[0].TcpPort);
            using var encoded = await _transport.ExchangeAtAsync(DHTTransport.Tcp, endpoint, packet.Seal(sender, receiver), token);
            var response = Packet.Open(sender, encoded.Bytes);
            if (response.Sender.NodeId != receiver.NodeId || response.Kind != (byte)(packet.Kind | 128)
                || !response.RequestId.Span.SequenceEqual(packet.RequestId.Span))
            {
                throw new InvalidDataException("The scripted request received an unauthenticated response.");
            }
            using var reader = new Wire(response.Body);
            var status = reader.Byte();
            var result = reader.Bytes(Wire.MaxPacket);
            reader.End();
            // The result outlives the pooled response frame, so it is copied.
            return (status, result.ToArray());
        }

        /// <summary>Answers each request with the current script.</summary>
        /// <param name="encoded">The sealed request.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <param name="token">The handler lifetime.</param>
        /// <returns>The sealed response.</returns>
        private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, DHTTransport transport, IPEndPoint source, CancellationToken token)
        {
            var packet = Packet.Open(Identity, encoded);
            lock (_gate)
            {
                _received.Add((Operation)packet.Kind);
            }
            var (status, result) = _script(packet, source);
            using var body = new Wire();
            body.PutByte(status);
            body.Put(result);
            var response = new Packet(Peer, packet.RequestId, (byte)(packet.Kind | 0x80), body.ToArray());
            return Task.FromResult<ReadOnlyMemory<byte>>(response.Seal(Identity, packet.Sender));
        }

        /// <summary>Stops the transport.</summary>
        /// <returns>Completion after the transport drains.</returns>
        public ValueTask DisposeAsync()
        {
            return _transport.DisposeAsync();
        }
    }
}
