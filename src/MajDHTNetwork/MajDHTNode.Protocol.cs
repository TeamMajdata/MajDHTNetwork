using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>Authenticates and deduplicates an incoming encrypted request.</summary>
        /// <param name="encoded">The opaque envelope.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The actual socket source endpoint.</param>
        /// <param name="cancellationToken">The bounded handler lifetime.</param>
        /// <returns>The final encrypted reply.</returns>
        private async Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, DHTTransport transport, IPEndPoint source, CancellationToken cancellationToken)
        {
            var packet = Packet.Open(_identity, encoded);
            if (packet.Kind >= 128 || packet.Sender.NodeId == NodeId || !HasRequiredWork(packet.Sender))
            {
                throw new InvalidDataException("Unexpected incoming response or self request.");
            }
            AdmitInbound(packet.Sender, transport, source);
            var id = packet.Sender.NodeId + ":" + Crypto.Hex(packet.RequestId.Span);
            var fingerprint = packet.Kind.ToString(System.Globalization.CultureInfo.InvariantCulture) + ":" + Crypto.Hex(Crypto.Hash(packet.Body.Span));
            CachedReply cached;
            var owner = false;
            lock (_gate)
            {
                if (_replies.TryGetValue(id, out var found))
                {
                    cached = found;
                    if (cached.Fingerprint != fingerprint)
                    {
                        throw new InvalidDataException("A request identifier was reused for different content.");
                    }
                }
                else
                {
                    var removals = new List<string>();
                    foreach (var entry in _replies)
                    {
                        if (entry.Value.Completion.Task.IsCompleted && entry.Value.Created < DateTimeOffset.UtcNow.AddMinutes(-2))
                        {
                            removals.Add(entry.Key);
                        }
                    }
                    foreach (var key in removals)
                    {
                        _replies.Remove(key);
                    }
                    var limit = _options.MaxConcurrentRequests * 4;
                    if (_replies.Count >= limit)
                    {
                        string? oldest = null;
                        var time = DateTimeOffset.MaxValue;
                        foreach (var entry in _replies)
                        {
                            if (entry.Value.Completion.Task.IsCompleted && entry.Value.Created < time)
                            {
                                oldest = entry.Key;
                                time = entry.Value.Created;
                            }
                        }
                        if (oldest == null)
                        {
                            throw new IOException("Request replay cache is busy.");
                        }
                        _replies.Remove(oldest);
                    }
                    cached = new CachedReply(fingerprint);
                    _replies.Add(id, cached);
                    owner = true;
                }
            }
            if (owner)
            {
                try
                {
                    using var body = new Wire();
                    try
                    {
                        var response = await DispatchAsync(packet, transport, source, cancellationToken).ConfigureAwait(false);
                        body.PutByte(0);
                        body.Put(response.Span);
                    }
                    catch (Exception exception)
                    {
                        Log(LogLevel.Debug, "Request rejected: ", exception);
                        body.PutByte(1);
                        body.Put(Array.Empty<byte>());
                    }
                    var reply = new Packet(LocalPeer, packet.RequestId, (byte)(packet.Kind | 128), body.WrittenMemory);
                    cached.Completion.TrySetResult(reply.Seal(_identity, packet.Sender));
                }
                catch (Exception exception)
                {
                    cached.Completion.TrySetException(exception);
                }
            }
            return await cached.Completion.Task.ConfigureAwait(false);
        }

        /// <summary>Executes a bounded authenticated node operation.</summary>
        /// <param name="packet">The authenticated request.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed socket source endpoint.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>The unencrypted operation result, to be sealed by the caller.</returns>
        private async Task<ReadOnlyMemory<byte>> DispatchAsync(Packet packet, DHTTransport transport, IPEndPoint source, CancellationToken cancellationToken)
        {
            using var request = new Wire(packet.Body);
            using var response = new Wire();
            switch ((Operation)packet.Kind)
            {
                case Operation.Ping:
                    request.End();
                    return Array.Empty<byte>();
                case Operation.Find:
                {
                    var mode = request.Byte();
                    var target = request.Text(1024);
                    request.End();
                    if (mode > 2)
                    {
                        throw new InvalidDataException("Invalid lookup mode.");
                    }
                    var routingId = mode == 1 ? DHTKey.Parse(target).RoutingId : target;
                    Crypto.ParseHash(routingId);
                    DHTRecord? record = null;
                    lock (_gate)
                    {
                        if (mode == 1 && _records.TryGetValue(target, out var found) && !found.IsExpired)
                        {
                            record = found;
                        }
                    }
                    if (record == null)
                    {
                        response.Put(ReadOnlySpan<byte>.Empty);
                    }
                    else
                    {
                        response.Put(record.Encoded);
                    }
                    PutPeers(response, RoutedPeers(routingId, _options.BucketSize), ContactListBudget);
                    PutPeers(response, mode == 2 ? LocalProviders(target)
                        : record == null || record.IsWithdrawn ? new List<DHTPeer>() : LocalProviders(record.FileHash),
                        ContactListBudget);
                    return response.ToArray();
                }
                case Operation.Store:
                {
                    var record = DHTRecord.Parse(request.Bytes(2200).Span);
                    request.End();
                    // A withdrawal is signed by its publisher and claims no content, so any node may replicate it.
                    if (!record.IsWithdrawn && (packet.Sender.Capabilities & DHTCapabilities.Provide) == 0)
                    {
                        throw new InvalidDataException("A provider capability is required to announce content.");
                    }
                    CacheRecord(record, record.IsWithdrawn ? null : packet.Sender, source.Address);
                    return Array.Empty<byte>();
                }
                case Operation.Block:
                {
                    if ((_options.Capabilities & DHTCapabilities.Provide) == 0)
                    {
                        throw new IOException("Content serving is disabled.");
                    }
                    var record = DHTRecord.Parse(request.Bytes(2200).Span);
                    var index = request.Long();
                    request.End();
                    if (index < 0 || index >= record.BlockCount || record.Length > _options.MaxFileSize)
                    {
                        throw new InvalidDataException("Invalid requested block geometry.");
                    }
                    var result = await ReadLocalBlockAsync(record, (int)index, cancellationToken).ConfigureAwait(false);
                    response.Put(result.Bytes.Span);
                    result.Tree.WriteProof(response, (int)index);
                    return response.ToArray();
                }
                case Operation.Rendezvous:
                    return await DispatchRendezvousAsync(packet, request, transport, source, cancellationToken).ConfigureAwait(false);
                case Operation.Punch:
                    return DispatchPunch(packet, transport, source);
                case Operation.Hello:
                    request.End();
                    PutNatEndpoint(response, source);
                    return response.ToArray();
                case Operation.Probe:
                    return DispatchProbe(packet, transport);
                case Operation.Relay:
                {
                    if ((_options.Capabilities & DHTCapabilities.Relay) == 0)
                    {
                        throw new IOException("Relaying is disabled.");
                    }
                    var target = request.Text(64);
                    var inner = request.Bytes(Wire.MaxPacket);
                    request.End();
                    Packet.CheckForward(inner, target);
                    var destination = KnownRelayDestination(target);
                    if (destination == null || destination.NodeId == packet.Sender.NodeId)
                    {
                        throw new IOException("Relay destination must be an already known peer.");
                    }
                    var result = (await ExchangeDirectAsync(destination, inner, cancellationToken).ConfigureAwait(false)).Response;
                    response.Put(result.Span);
                    return response.ToArray();
                }
                default:
                    throw new InvalidDataException("Unsupported operation.");
            }
        }

        /// <summary>Performs an authenticated RPC with optional explicit or automatic one-hop relaying.</summary>
        /// <param name="peer">The final recipient.</param>
        /// <param name="operation">The operation.</param>
        /// <param name="body">The encoded operation arguments.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <param name="relay">An explicit relay, or null to try direct access first.</param>
        /// <param name="allowRelay">Whether direct failure may fall back to known relays.</param>
        /// <returns>The authenticated response body.</returns>
        /// <exception cref="IOException">All permitted routes failed or a peer rejected the request.</exception>
        private async Task<ReadOnlyMemory<byte>> RequestAsync(DHTPeer peer, Operation operation, ReadOnlyMemory<byte> body, CancellationToken cancellationToken,
            DHTPeer? relay = null, bool allowRelay = true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = new Packet(LocalPeer, Crypto.Random(16), (byte)operation, body);
            var envelope = request.Seal(_identity, peer);
            ReadOnlyMemory<byte> result;
            Packet? authenticated = null;
            IPAddress? verifiedAddress = null;
            if (relay != null)
            {
                result = await ForwardAsync(relay, peer, envelope, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                try
                {
                    var direct = await ExchangeDirectAsync(peer, envelope, cancellationToken).ConfigureAwait(false);
                    result = direct.Response;
                    authenticated = AuthenticateResponse(result, peer, request);
                    verifiedAddress = direct.VerifiedAddress;
                }
                catch (Exception exception) when (IsPeerFailure(exception) && allowRelay && operation != Operation.Relay)
                {
                    result = await FindRelayAsync(peer, envelope, request, cancellationToken).ConfigureAwait(false);
                }
            }
            var response = authenticated ?? AuthenticateResponse(result, peer, request);
            ObservePeer(response.Sender, verifiedAddress);
            return ReadResponseBody(response);
        }

        /// <summary>Finds a relay destination among routed peers and live rendezvous registrations.</summary>
        /// <param name="target">The destination node identifier.</param>
        /// <returns>The destination contact, or null when it is unknown.</returns>
        private DHTPeer? KnownRelayDestination(string target)
        {
            foreach (var peer in RoutedPeers(target, _options.BucketSize))
            {
                if (peer.NodeId == target)
                {
                    return peer;
                }
            }
            lock (_gate)
            {
                PruneNatState();
                return _natRegistrations.TryGetValue(target, out var registration) ? registration.Peer : null;
            }
        }

        /// <summary>Validates the operation status and extracts its bounded response body.</summary>
        /// <param name="response">The already authenticated response.</param>
        /// <returns>The operation payload retained by its owned decrypted memory.</returns>
        /// <exception cref="IOException">The authenticated peer rejected the request.</exception>
        /// <exception cref="InvalidDataException">The response framing is malformed.</exception>
        private static ReadOnlyMemory<byte> ReadResponseBody(Packet response)
        {
            using var reader = new Wire(response.Body);
            var status = reader.Byte();
            var payload = reader.Bytes(Wire.MaxPacket);
            reader.End();
            if (status != 0)
            {
                throw new IOException("The authenticated peer rejected the request.");
            }
            return payload;
        }

        /// <summary>Authenticates response identity, operation and correlation independently of the chosen route.</summary>
        /// <param name="encoded">The sealed response.</param>
        /// <param name="peer">The expected final provider or index node.</param>
        /// <param name="request">The originating request.</param>
        /// <returns>The authenticated response.</returns>
        /// <exception cref="CryptographicException">The response was substituted or miscorrelated.</exception>
        private Packet AuthenticateResponse(ReadOnlyMemory<byte> encoded, DHTPeer peer, Packet request)
        {
            var response = Packet.Open(_identity, encoded);
            if (response.Sender.NodeId != peer.NodeId || !HasRequiredWork(response.Sender)
                || !CryptographicOperations.FixedTimeEquals(response.RequestId.Span, request.RequestId.Span)
                || response.Kind != (request.Kind | 128))
            {
                throw new CryptographicException("Response sender, work, operation or correlation mismatch.");
            }
            return response;
        }

        /// <summary>Wraps an already sealed request in a relay RPC.</summary>
        /// <param name="relay">The forwarding peer.</param>
        /// <param name="destination">The final recipient.</param>
        /// <param name="envelope">The end-to-end encrypted inner request.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>The opaque end-to-end encrypted reply.</returns>
        private async Task<ReadOnlyMemory<byte>> ForwardAsync(DHTPeer relay, DHTPeer destination, ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            if (relay.NodeId == destination.NodeId || relay.NodeId == NodeId || (relay.Capabilities & DHTCapabilities.Relay) == 0)
            {
                throw new IOException("The selected peer cannot relay this request.");
            }
            using var body = new Wire();
            body.PutText(destination.NodeId);
            body.Put(envelope.Span);
            var response = await RequestAsync(relay, Operation.Relay, body.WrittenMemory, cancellationToken, allowRelay: false).ConfigureAwait(false);
            using var reader = new Wire(response);
            var result = reader.Bytes(Wire.MaxPacket);
            reader.End();
            return result;
        }

        /// <summary>Tries the relay routes chosen by the route selector after every direct route failed.</summary>
        /// <param name="destination">The unreachable final recipient.</param>
        /// <param name="envelope">The final recipient's ciphertext.</param>
        /// <param name="request">The request whose response must be authenticated.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>A response from the first successful relay.</returns>
        /// <exception cref="IOException">No selected relay could reach the destination.</exception>
        private async Task<ReadOnlyMemory<byte>> FindRelayAsync(DHTPeer destination, ReadOnlyMemory<byte> envelope, Packet request, CancellationToken cancellationToken)
        {
            foreach (var route in SelectRelayRoutes(destination))
            {
                try
                {
                    return await RelayRouteAsync(route.Relay, destination, envelope, request, route.AttemptPunch && _options.EnableNatTraversal,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Relay route failed: ", exception);
                }
            }
            throw new IOException("No known relay could reach the destination.");
        }

        /// <summary>Tries an introduced direct path through one relay, then opaque forwarding through the same relay.</summary>
        /// <param name="relay">The assisting relay.</param>
        /// <param name="destination">The final recipient.</param>
        /// <param name="envelope">The final recipient's ciphertext.</param>
        /// <param name="request">The request whose response must be authenticated.</param>
        /// <param name="punch">Whether to attempt hole punching first.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>The authenticated encrypted response.</returns>
        /// <exception cref="IOException">The relay could not reach the destination.</exception>
        private async Task<ReadOnlyMemory<byte>> RelayRouteAsync(DHTPeer relay, DHTPeer destination, ReadOnlyMemory<byte> envelope, Packet request,
            bool punch, CancellationToken cancellationToken)
        {
            if (punch)
            {
                var preferred = _options.PreferredTransport;
                if (await TryPunchAsync(destination, relay, preferred, cancellationToken).ConfigureAwait(false)
                    || await TryPunchAsync(destination, relay, OtherTransport(preferred), cancellationToken).ConfigureAwait(false))
                {
                    try
                    {
                        var direct = (await ExchangeDirectAsync(destination, envelope, cancellationToken).ConfigureAwait(false)).Response;
                        AuthenticateResponse(direct, destination, request);
                        return direct;
                    }
                    catch (Exception exception) when (IsPeerFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        Log(LogLevel.Debug, "Introduced path failed; trying its assisting relay: ", exception);
                    }
                }
            }
            var result = await ForwardAsync(relay, destination, envelope, cancellationToken).ConfigureAwait(false);
            AuthenticateResponse(result, destination, request);
            return result;
        }

        /// <summary>Identifies recoverable peer-specific protocol and transport failures.</summary>
        /// <param name="exception">The failure.</param>
        /// <returns>Whether another peer may be attempted.</returns>
        private static bool IsPeerFailure(Exception exception)
        {
            return exception is IOException || exception is InvalidDataException || exception is CryptographicException || exception is ArgumentException
                || exception is System.Net.Sockets.SocketException;
        }

        /// <summary>Encodes a contact list bounded by count and encoded size.</summary>
        /// <param name="writer">The destination encoder.</param>
        /// <param name="peers">The ordered candidate contacts; at most sixteen are written.</param>
        /// <param name="budget">The maximum encoded bytes of the written contacts, including their length prefixes.</param>
        private static void PutPeers(Wire writer, List<DHTPeer> peers, int budget)
        {
            var count = 0;
            var used = 0;
            while (count < Math.Min(16, peers.Count) && used + 8 + peers[count].Encoded.Length <= budget)
            {
                used += 8 + peers[count].Encoded.Length;
                count++;
            }
            writer.PutLong(count);
            for (var i = 0; i < count; i++)
            {
                writer.Put(peers[i].Encoded);
            }
        }

        /// <summary>Decodes and verifies a bounded contact list.</summary>
        /// <param name="reader">The source decoder.</param>
        /// <returns>Verified, unexpired contacts.</returns>
        private static List<DHTPeer> ReadPeers(Wire reader)
        {
            var count = reader.Long();
            if (count < 0 || count > 16)
            {
                throw new InvalidDataException("Invalid contact list size.");
            }
            var peers = new List<DHTPeer>((int)count);
            for (var i = 0; i < count; i++)
            {
                peers.Add(new DHTPeer(reader.Bytes(DHTPeer.MaxEncodedLength)));
            }
            return peers;
        }
    }
}
