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
        /// <summary>Authenticates and deduplicates an incoming encrypted request that arrived directly from its sender.</summary>
        /// <param name="encoded">
        /// The opaque envelope in a pooled frame owned by the transport, decrypted in place and released once this method's task
        /// completes, so nothing parsed from it may be retained without a copy.
        /// </param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The actual socket source endpoint.</param>
        /// <param name="cancellationToken">The bounded handler lifetime.</param>
        /// <returns>The final encrypted reply.</returns>
        private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, DHTTransport transport, IPEndPoint source, CancellationToken cancellationToken)
        {
            return HandleAsync(encoded, new RequestOrigin(transport, source, null), cancellationToken);
        }

        /// <summary>Authenticates and deduplicates an incoming encrypted request from a direct sender or from a Forwarder.</summary>
        /// <param name="encoded">The exclusively owned opaque envelope, decrypted in place; nothing parsed from it may be retained without a copy.</param>
        /// <param name="origin">The transport and socket source the envelope arrived from, and the Forwarder that delivered it, if any.</param>
        /// <param name="cancellationToken">The bounded handler lifetime.</param>
        /// <returns>The final encrypted reply, sealed to the authenticated sender.</returns>
        private async Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, RequestOrigin origin, CancellationToken cancellationToken)
        {
            var packet = Packet.Open(_identity, encoded);
            if (packet.Kind >= 128 || packet.Sender.NodeId == NodeId || !HasRequiredWork(packet.Sender))
            {
                throw new InvalidDataException("Unexpected incoming response or self request.");
            }
            if (origin.IsDirect)
            {
                AdmitInbound(packet.Sender, origin.Transport, origin.Endpoint);
            }
            else
            {
                // The socket source is the Forwarder, so the sender is refreshed without learning an endpoint for it.
                ObservePeer(packet.Sender, null);
            }
            var cached = ClaimReply(packet, out var owner);
            if (owner)
            {
                try
                {
                    using var body = new Wire();
                    using var response = new Wire();
                    try
                    {
                        await DispatchAsync(packet, origin, response, cancellationToken).ConfigureAwait(false);
                        ResponseStatus.WriteSuccess(body, response.WrittenSpan);
                    }
                    catch (Exception exception)
                    {
                        Log(LogLevel.Debug, "Request rejected: ", exception);
                        ResponseStatus.WriteRejection(body);
                    }
                    var reply = new Packet(LocalContact, packet.RequestId, (byte)(packet.Kind | 128), body.WrittenMemory);
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
        /// <param name="origin">The transport, socket source and delivering Forwarder of the request.</param>
        /// <param name="response">The encoder receiving the operation result, to be sealed by the caller.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>Completion after the result was written.</returns>
        private async Task DispatchAsync(Packet packet, RequestOrigin origin, Wire response, CancellationToken cancellationToken)
        {
            using var request = new Wire(packet.Body);
            switch ((Operation)packet.Kind)
            {
                case Operation.Ping:
                    request.End();
                    return;
                case Operation.Find:
                {
                    var find = FindMessage.ReadRequest(request);
                    var target = find.Target;
                    var routingId = find.Mode == FindMode.Record ? DHTKey.Parse(target).RoutingId : target;
                    Crypto.ParseHash(routingId);
                    DHTRecord? record = null;
                    lock (_gate)
                    {
                        if (find.Mode == FindMode.Record && _records.TryGetValue(target, out var found) && !found.IsExpired)
                        {
                            record = found;
                        }
                    }
                    IReadOnlyList<DHTPeer> providers = find.Mode == FindMode.Providers ? LocalProviders(target)
                        : record == null || record.IsWithdrawn ? Array.Empty<DHTPeer>() : LocalProviders(record.FileHash);
                    FindMessage.WriteResponse(response, record, RoutedPeers(routingId, _options.BucketSize), providers);
                    return;
                }
                case Operation.Store:
                {
                    var record = StoreMessage.ReadRequest(request);
                    // A withdrawal is signed by its publisher and claims no content, so any node may replicate it.
                    if (!record.IsWithdrawn && (packet.Sender.Capabilities & DHTCapabilities.Provide) == 0)
                    {
                        throw new InvalidDataException("A provider capability is required to announce content.");
                    }
                    // A forwarded announcement reveals no endpoint of the provider; its forwarder's network counts towards the limit.
                    var provider = record.IsWithdrawn ? null
                        : origin.IsDirect ? DHTPeer.Observed(packet.Sender, origin.Transport, origin.Endpoint)
                        : new DHTPeer(packet.Sender, Array.Empty<DHTEndpoint>());
                    CacheRecord(record, provider, origin.Endpoint.Address);
                    return;
                }
                case Operation.Block:
                {
                    if ((_options.Capabilities & DHTCapabilities.Provide) == 0)
                    {
                        throw new IOException("Content serving is disabled.");
                    }
                    var block = BlockMessage.ReadRequest(request);
                    if (block.Record.Length > _options.MaxFileSize)
                    {
                        throw new InvalidDataException("The requested file exceeds the node's file limit.");
                    }
                    var result = await ReadServedBlockAsync(block.Record, block.Index, cancellationToken).ConfigureAwait(false);
                    BlockMessage.WriteResponse(response, result.Bytes.Span, result.Tree, block.Index);
                    return;
                }
                case Operation.Forward:
                    await DispatchForwardAsync(packet, request, origin, response, cancellationToken).ConfigureAwait(false);
                    return;
                case Operation.Traversal:
                    RequireDirect(origin);
                    await DispatchTraversalAsync(packet, request, origin.Transport, origin.Endpoint, response, cancellationToken).ConfigureAwait(false);
                    return;
                case Operation.Punch:
                    RequireDirect(origin);
                    DispatchPunch(packet, origin.Transport, origin.Endpoint);
                    return;
                case Operation.Hello:
                    RequireDirect(origin);
                    HelloMessage.ReadRequest(request);
                    HelloMessage.WriteResponse(response, origin.Endpoint);
                    return;
                case Operation.Probe:
                    RequireDirect(origin);
                    DispatchProbe(packet, origin.Transport);
                    return;
                default:
                    throw new InvalidDataException("Unsupported operation.");
            }
        }

        /// <summary>Rejects a control operation whose observed source would be a Forwarder instead of the sender.</summary>
        /// <param name="origin">The request origin.</param>
        /// <exception cref="InvalidDataException">The request was delivered by a Forwarder.</exception>
        private static void RequireDirect(RequestOrigin origin)
        {
            if (!origin.IsDirect)
            {
                throw new InvalidDataException("Endpoint-observing operations cannot be forwarded.");
            }
        }

        /// <summary>Performs an authenticated RPC, directly or with explicit or automatic assistance.</summary>
        /// <param name="peer">The final recipient at its observed endpoints.</param>
        /// <param name="operation">The operation.</param>
        /// <param name="body">The encoded operation arguments.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <param name="forwarder">An explicit Forwarder, or null to try direct access first.</param>
        /// <param name="allowAssisted">Whether direct failure may fall back to hinted and routed Traversal and Forwarder nodes.</param>
        /// <returns>The authenticated response body, which the caller releases by disposing it after copying whatever it keeps.</returns>
        /// <exception cref="IOException">All permitted routes failed or a peer rejected the request.</exception>
        private async Task<OwnedMemory> RequestAsync(DHTPeer peer, Operation operation, ReadOnlyMemory<byte> body, CancellationToken cancellationToken,
            DHTPeer? forwarder = null, bool allowAssisted = true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var request = new Packet(LocalContact, Crypto.Random(16), (byte)operation, body);
            var envelope = request.Seal(_identity, peer.Contact);
            OwnedPacket response;
            DHTEndpoint? observed = null;
            if (forwarder != null)
            {
                response = AuthenticateResponse(await RelayThroughAsync(forwarder, peer, envelope, cancellationToken).ConfigureAwait(false), peer.Contact, request);
            }
            else
            {
                try
                {
                    var direct = await ExchangeDirectAsync(peer, envelope, cancellationToken).ConfigureAwait(false);
                    response = AuthenticateResponse(direct.Response, peer.Contact, request);
                    observed = direct.Observed;
                }
                catch (Exception exception) when (IsPeerFailure(exception) && allowAssisted && operation != Operation.Forward)
                {
                    response = await FindAssistedAsync(peer, envelope, request, cancellationToken).ConfigureAwait(false);
                }
            }
            try
            {
                ObservePeer(response.Packet.Sender, observed);
            }
            catch
            {
                response.Dispose();
                throw;
            }
            return TakeResponseBody(response);
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
                return response.Narrow(ResponseStatus.ReadResult(response.Packet.Body));
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
        /// <param name="peer">The expected final responder.</param>
        /// <param name="request">The originating request.</param>
        /// <returns>The authenticated response, released by disposing it.</returns>
        /// <exception cref="CryptographicException">The response was substituted or miscorrelated.</exception>
        private OwnedPacket AuthenticateResponse(OwnedMemory encoded, DHTContact peer, Packet request)
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

        /// <summary>Tries the assisted routes chosen by the route selector after every direct route failed.</summary>
        /// <param name="destination">The unreachable final recipient.</param>
        /// <param name="envelope">The final recipient's ciphertext.</param>
        /// <param name="request">The request whose response must be authenticated.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>The authenticated response from the first successful route, released by disposing it.</returns>
        /// <exception cref="IOException">No selected Traversal or Forwarder node could reach the destination.</exception>
        private async Task<OwnedPacket> FindAssistedAsync(DHTPeer destination, ReadOnlyMemory<byte> envelope, Packet request, CancellationToken cancellationToken)
        {
            foreach (var route in SelectAssistedRoutes(destination))
            {
                try
                {
                    return await AssistedRouteAsync(route.Assistant, destination, envelope, request, route.AttemptPunch && _options.EnableNatTraversal,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Assisted route failed: ", exception);
                }
            }
            throw new IOException("No known Traversal or Forwarder node could reach the destination.");
        }

        /// <summary>
        /// Tries an introduced direct path through an assistant that coordinates traversal, then forwarding through the same
        /// assistant when it is a Forwarder.
        /// </summary>
        /// <param name="assistant">The assisting Traversal or Forwarder node.</param>
        /// <param name="destination">The final recipient.</param>
        /// <param name="envelope">The final recipient's ciphertext.</param>
        /// <param name="request">The request whose response must be authenticated.</param>
        /// <param name="punch">Whether to attempt hole punching first.</param>
        /// <param name="cancellationToken">The operation lifetime.</param>
        /// <returns>The authenticated response, released by disposing it.</returns>
        /// <exception cref="IOException">The assistant could not reach the destination.</exception>
        private async Task<OwnedPacket> AssistedRouteAsync(DHTPeer assistant, DHTPeer destination, ReadOnlyMemory<byte> envelope, Packet request,
            bool punch, CancellationToken cancellationToken)
        {
            if (punch && (assistant.Capabilities & DHTCapabilities.Traversal) != 0)
            {
                var preferred = _options.PreferredTransport;
                if (await TryPunchAsync(destination, assistant, preferred, cancellationToken).ConfigureAwait(false)
                    || await TryPunchAsync(destination, assistant, OtherTransport(preferred), cancellationToken).ConfigureAwait(false))
                {
                    try
                    {
                        var direct = (await ExchangeDirectAsync(destination, envelope, cancellationToken).ConfigureAwait(false)).Response;
                        return AuthenticateResponse(direct, destination.Contact, request);
                    }
                    catch (Exception exception) when (IsPeerFailure(exception))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        Log(LogLevel.Debug, "Introduced path failed; trying the assistant as forwarder: ", exception);
                    }
                }
            }
            if ((assistant.Capabilities & DHTCapabilities.Forwarder) == 0)
            {
                throw new IOException("The assistant does not forward traffic.");
            }
            var result = await RelayThroughAsync(assistant, destination, envelope, cancellationToken).ConfigureAwait(false);
            return AuthenticateResponse(result, destination.Contact, request);
        }

        /// <summary>Identifies recoverable peer-specific protocol and transport failures.</summary>
        /// <param name="exception">The failure.</param>
        /// <returns>Whether another peer may be attempted.</returns>
        private static bool IsPeerFailure(Exception exception)
        {
            return exception is IOException || exception is InvalidDataException || exception is CryptographicException || exception is ArgumentException
                || exception is System.Net.Sockets.SocketException;
        }

        /// <summary>Describes where an incoming request came from: its socket source and, for a forwarded request, the Forwarder.</summary>
        private readonly struct RequestOrigin
        {
            /// <summary>Gets the receiving transport.</summary>
            internal DHTTransport Transport { get; }
            /// <summary>Gets the observed socket source: the sender itself, or the Forwarder that delivered the request.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the authenticated Forwarder that delivered the request, or null when the sender sent it directly.</summary>
            internal DHTContact? Forwarder { get; }
            /// <summary>Gets whether the socket source is the sender, so the source endpoint is an observation of the sender.</summary>
            internal bool IsDirect => Forwarder == null;

            /// <summary>Creates a request origin.</summary>
            /// <param name="transport">The receiving transport.</param>
            /// <param name="endpoint">The observed socket source.</param>
            /// <param name="forwarder">The delivering Forwarder, or null.</param>
            internal RequestOrigin(DHTTransport transport, IPEndPoint endpoint, DHTContact? forwarder)
            {
                Transport = transport;
                Endpoint = endpoint;
                Forwarder = forwarder;
            }
        }
    }
}
