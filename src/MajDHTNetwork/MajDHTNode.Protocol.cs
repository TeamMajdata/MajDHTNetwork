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
        /// <param name="encoded">
        /// The opaque envelope in a pooled frame owned by the transport, decrypted in place and released once this method's task
        /// completes, so nothing parsed from it may be retained without a copy.
        /// </param>
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
            var cached = ClaimReply(packet, out var owner);
            if (owner)
            {
                try
                {
                    using var body = new Wire();
                    using var response = new Wire();
                    try
                    {
                        await DispatchAsync(packet, transport, source, response, cancellationToken).ConfigureAwait(false);
                        body.PutByte(0);
                        body.Put(response.WrittenSpan);
                    }
                    catch (Exception exception)
                    {
                        Log(LogLevel.Debug, "Request rejected: ", exception);
                        body.PutByte(1);
                        body.Put(ReadOnlySpan<byte>.Empty);
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

        /// <summary>Finds the replay entry of a request, or creates one and makes the caller responsible for producing its reply.</summary>
        /// <param name="packet">The authenticated request.</param>
        /// <param name="owner">Whether the caller created the entry and must complete it.</param>
        /// <returns>The shared replay entry.</returns>
        /// <exception cref="InvalidDataException">The request identifier was reused with different content.</exception>
        /// <exception cref="IOException">The replay cache holds only pending requests.</exception>
        private CachedReply ClaimReply(Packet packet, out bool owner)
        {
            var key = new ReplayKey(packet.Sender.NodeHash, packet.RequestId.Span);
            var fingerprint = new RequestFingerprint(packet.Kind, packet.Body.Span);
            lock (_gate)
            {
                if (_replies.TryGetValue(key, out var found))
                {
                    if (!found.Fingerprint.Equals(fingerprint))
                    {
                        throw new InvalidDataException("A request identifier was reused for different content.");
                    }
                    owner = false;
                    return found;
                }
                PruneRepliesLocked();
                var cached = new CachedReply(fingerprint);
                _replies.Add(key, cached);
                owner = true;
                return cached;
            }
        }

        /// <summary>Removes expired replay entries and, when the cache is full, the oldest completed entry.</summary>
        /// <exception cref="IOException">The cache is full of pending requests.</exception>
        /// <remarks>The caller must hold the state lock.</remarks>
        private void PruneRepliesLocked()
        {
            var expiry = DateTimeOffset.UtcNow.AddMinutes(-2);
            List<ReplayKey>? removals = null;
            foreach (var entry in _replies)
            {
                if (entry.Value.Completion.Task.IsCompleted && entry.Value.Created < expiry)
                {
                    removals ??= new List<ReplayKey>();
                    removals.Add(entry.Key);
                }
            }
            if (removals != null)
            {
                foreach (var key in removals)
                {
                    _replies.Remove(key);
                }
            }
            if (_replies.Count < _options.MaxConcurrentRequests * 4)
            {
                return;
            }
            var found = false;
            var oldest = default(ReplayKey);
            var time = DateTimeOffset.MaxValue;
            foreach (var entry in _replies)
            {
                if (entry.Value.Completion.Task.IsCompleted && entry.Value.Created < time)
                {
                    found = true;
                    oldest = entry.Key;
                    time = entry.Value.Created;
                }
            }
            if (!found)
            {
                throw new IOException("Request replay cache is busy.");
            }
            _replies.Remove(oldest);
        }

        /// <summary>Executes a bounded authenticated node operation and writes its unencrypted result into a pooled encoder.</summary>
        /// <param name="packet">The authenticated request.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed socket source endpoint.</param>
        /// <param name="response">The encoder receiving the operation result, to be sealed by the caller.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>Completion after the result was written.</returns>
        private async Task DispatchAsync(Packet packet, DHTTransport transport, IPEndPoint source, Wire response, CancellationToken cancellationToken)
        {
            using var request = new Wire(packet.Body);
            switch ((Operation)packet.Kind)
            {
                case Operation.Ping:
                    request.End();
                    return;
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
                    IReadOnlyList<DHTPeer> providers = mode == 2 ? LocalProviders(target)
                        : record == null || record.IsWithdrawn ? Array.Empty<DHTPeer>() : LocalProviders(record.FileHash);
                    PutPeers(response, providers, ContactListBudget);
                    return;
                }
                case Operation.Store:
                {
                    var record = DHTRecord.ParseCached(request.Bytes(DHTRecord.MaxEncodedLength));
                    request.End();
                    // A withdrawal is signed by its publisher and claims no content, so any node may replicate it.
                    if (!record.IsWithdrawn && (packet.Sender.Capabilities & DHTCapabilities.Provide) == 0)
                    {
                        throw new InvalidDataException("A provider capability is required to announce content.");
                    }
                    CacheRecord(record, record.IsWithdrawn ? null : packet.Sender, source.Address);
                    return;
                }
                case Operation.Block:
                {
                    if ((_options.Capabilities & DHTCapabilities.Provide) == 0)
                    {
                        throw new IOException("Content serving is disabled.");
                    }
                    var record = DHTRecord.ParseCached(request.Bytes(DHTRecord.MaxEncodedLength));
                    var index = request.Long();
                    request.End();
                    if (index < 0 || index >= record.BlockCount || record.Length > _options.MaxFileSize)
                    {
                        throw new InvalidDataException("Invalid requested block geometry.");
                    }
                    var result = await ReadServedBlockAsync(record, (int)index, cancellationToken).ConfigureAwait(false);
                    response.Put(result.Bytes.Span);
                    result.Tree.WriteProof(response, (int)index);
                    return;
                }
                case Operation.Rendezvous:
                    await DispatchRendezvousAsync(packet, request, transport, source, response, cancellationToken).ConfigureAwait(false);
                    return;
                case Operation.Punch:
                    DispatchPunch(packet, transport, source);
                    return;
                case Operation.Hello:
                    request.End();
                    PutNatEndpoint(response, source);
                    return;
                case Operation.Probe:
                    DispatchProbe(packet, transport);
                    return;
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
                    using var relayed = (await ExchangeDirectAsync(destination, inner, cancellationToken).ConfigureAwait(false)).Response;
                    response.Put(relayed.Bytes.Span);
                    return;
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
        /// <returns>The authenticated response body, which the caller releases by disposing it after copying whatever it keeps.</returns>
        /// <exception cref="IOException">All permitted routes failed or a peer rejected the request.</exception>
        private async Task<OwnedMemory> RequestAsync(DHTPeer peer, Operation operation, ReadOnlyMemory<byte> body, CancellationToken cancellationToken,
            DHTPeer? relay = null, bool allowRelay = true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = new Packet(LocalPeer, Crypto.Random(16), (byte)operation, body);
            var envelope = request.Seal(_identity, peer);
            OwnedPacket response;
            IPAddress? verifiedAddress = null;
            if (relay != null)
            {
                response = AuthenticateResponse(await ForwardAsync(relay, peer, envelope, cancellationToken).ConfigureAwait(false), peer, request);
            }
            else
            {
                try
                {
                    var direct = await ExchangeDirectAsync(peer, envelope, cancellationToken).ConfigureAwait(false);
                    response = AuthenticateResponse(direct.Response, peer, request);
                    verifiedAddress = direct.VerifiedAddress;
                }
                catch (Exception exception) when (IsPeerFailure(exception) && allowRelay && operation != Operation.Relay)
                {
                    response = await FindRelayAsync(peer, envelope, request, cancellationToken).ConfigureAwait(false);
                }
            }
            try
            {
                ObservePeer(response.Packet.Sender, verifiedAddress);
            }
            catch
            {
                response.Dispose();
                throw;
            }
            return TakeResponseBody(response);
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
        /// <returns>The operation payload, borrowing the decrypted envelope buffer.</returns>
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

        /// <summary>Validates the operation status and takes over the response frame as a view of the bounded response body.</summary>
        /// <param name="response">The already authenticated response, which must not be disposed afterwards.</param>
        /// <returns>The operation payload, releasing the response frame when disposed.</returns>
        /// <exception cref="IOException">The authenticated peer rejected the request; the frame has been released.</exception>
        /// <exception cref="InvalidDataException">The response framing is malformed; the frame has been released.</exception>
        private static OwnedMemory TakeResponseBody(OwnedPacket response)
        {
            try
            {
                return response.Narrow(ReadResponseBody(response.Packet));
            }
            catch
            {
                response.Dispose();
                throw;
            }
        }

        /// <summary>Authenticates response identity, operation and correlation independently of the chosen route.</summary>
        /// <param name="encoded">
        /// The sealed response in its received frame, which is decrypted in place and must not be authenticated again. The
        /// authenticated packet takes over the frame; a failed authentication releases it before the exception propagates.
        /// </param>
        /// <param name="peer">The expected final provider or index node.</param>
        /// <param name="request">The originating request.</param>
        /// <returns>The authenticated response, released by disposing it.</returns>
        /// <exception cref="CryptographicException">The response was substituted or miscorrelated.</exception>
        private OwnedPacket AuthenticateResponse(OwnedMemory encoded, DHTPeer peer, Packet request)
        {
            try
            {
                var response = Packet.Open(_identity, encoded.Bytes);
                if (response.Sender.NodeId != peer.NodeId || !HasRequiredWork(response.Sender)
                    || !CryptographicOperations.FixedTimeEquals(response.RequestId.Span, request.RequestId.Span)
                    || response.Kind != (request.Kind | 128))
                {
                    throw new CryptographicException("Response sender, work, operation or correlation mismatch.");
                }
                return new OwnedPacket(response, encoded);
            }
            catch
            {
                encoded.Dispose();
                throw;
            }
        }

        /// <summary>Wraps an already sealed request in a relay RPC.</summary>
        /// <param name="relay">The forwarding peer.</param>
        /// <param name="destination">The final recipient.</param>
        /// <param name="envelope">The end-to-end encrypted inner request.</param>
        /// <param name="cancellationToken">The request lifetime.</param>
        /// <returns>The opaque end-to-end encrypted reply, a view inside the relay's response frame that releases the frame.</returns>
        private async Task<OwnedMemory> ForwardAsync(DHTPeer relay, DHTPeer destination, ReadOnlyMemory<byte> envelope, CancellationToken cancellationToken)
        {
            if (relay.NodeId == destination.NodeId || relay.NodeId == NodeId || (relay.Capabilities & DHTCapabilities.Relay) == 0)
            {
                throw new IOException("The selected peer cannot relay this request.");
            }
            using var body = new Wire();
            body.PutText(destination.NodeId);
            body.Put(envelope.Span);
            var response = await RequestAsync(relay, Operation.Relay, body.WrittenMemory, cancellationToken, allowRelay: false).ConfigureAwait(false);
            try
            {
                using var reader = new Wire(response.Bytes);
                var result = reader.Bytes(Wire.MaxPacket);
                reader.End();
                return response.Narrow(result);
            }
            catch
            {
                response.Dispose();
                throw;
            }
        }

        /// <summary>Tries the relay routes chosen by the route selector after every direct route failed.</summary>
        /// <param name="destination">The unreachable final recipient.</param>
        /// <param name="envelope">The final recipient's ciphertext.</param>
        /// <param name="request">The request whose response must be authenticated.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>The authenticated response from the first successful relay, released by disposing it.</returns>
        /// <exception cref="IOException">No selected relay could reach the destination.</exception>
        private async Task<OwnedPacket> FindRelayAsync(DHTPeer destination, ReadOnlyMemory<byte> envelope, Packet request, CancellationToken cancellationToken)
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
        /// <returns>The authenticated response, released by disposing it.</returns>
        /// <exception cref="IOException">The relay could not reach the destination.</exception>
        private async Task<OwnedPacket> RelayRouteAsync(DHTPeer relay, DHTPeer destination, ReadOnlyMemory<byte> envelope, Packet request,
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
                        return AuthenticateResponse(direct, destination, request);
                    }
                    catch (Exception exception) when (IsPeerFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        Log(LogLevel.Debug, "Introduced path failed; trying its assisting relay: ", exception);
                    }
                }
            }
            var result = await ForwardAsync(relay, destination, envelope, cancellationToken).ConfigureAwait(false);
            return AuthenticateResponse(result, destination, request);
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
        private static void PutPeers(Wire writer, IReadOnlyList<DHTPeer> peers, int budget)
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

        /// <summary>Decodes and verifies a bounded contact list, reusing cached verifications of repeated contacts.</summary>
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
                peers.Add(DHTPeer.Parse(reader.Bytes(DHTPeer.MaxEncodedLength)));
            }
            return peers;
        }
    }
}
