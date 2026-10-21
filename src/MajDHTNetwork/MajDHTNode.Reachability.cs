using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    public sealed partial class MajDHTNode
    {
        /// <summary>The lease of a public contact.</summary>
        private static readonly TimeSpan s_publicContactLifetime = TimeSpan.FromDays(1);
        /// <summary>The lease of a contact whose reachability is unknown or that depends on hinted forwarders.</summary>
        private static readonly TimeSpan s_unverifiedContactLifetime = TimeSpan.FromHours(1);
        /// <summary>How long an observed endpoint counts towards the external-address vote.</summary>
        private static readonly TimeSpan s_observationLifetime = TimeSpan.FromMinutes(10);
        /// <summary>The window of the helper-side dial-back quotas.</summary>
        private static readonly TimeSpan s_probeQuotaWindow = TimeSpan.FromMinutes(1);
        /// <summary>The pause between rounds of rejected or unanswered dial-back probes.</summary>
        private static readonly TimeSpan s_probeRetryInterval = TimeSpan.FromMilliseconds(100);
        /// <summary>The maximum dial-back delegations accepted from one Traversal node per quota window.</summary>
        private const int ProbesPerDelegator = 10;
        /// <summary>The maximum dial-backs sent to one target address per quota window.</summary>
        private const int ProbesPerTarget = 4;
        /// <summary>The maximum dial-back requests a Traversal node accepts from one requester per quota window.</summary>
        internal const int DialBacksPerRequester = 3;
        /// <summary>The maximum probe rounds a helper sends for one delegation, bounding traffic towards an arbitrary target.</summary>
        internal const int MaxProbeRounds = 5;
        /// <summary>The number of helpers a Traversal node asks before rejecting a dial-back request.</summary>
        private const int DialBackHelperAttempts = 3;
        /// <summary>The number of failed dial-backs, from distinct Traversal node networks, that marks the node private.</summary>
        private const int PrivateFailureThreshold = 2;
        /// <summary>The observed endpoints of this node keyed by reporter, address family and transport.</summary>
        private readonly Dictionary<(string Reporter, AddressFamily Family, DHTTransport Transport), EndpointObservation> _observations =
            new Dictionary<(string, AddressFamily, DHTTransport), EndpointObservation>();
        /// <summary>The external addresses confirmed by independent observers, indexed by address family.</summary>
        private readonly Dictionary<AddressFamily, IPAddress> _externalAddresses = new Dictionary<AddressFamily, IPAddress>();
        /// <summary>The endpoints verified by dial-back in the current epoch, indexed by address family.</summary>
        private readonly Dictionary<AddressFamily, VerifiedEndpoint> _verifiedEndpoints = new Dictionary<AddressFamily, VerifiedEndpoint>();
        /// <summary>The Traversal node addresses whose dial-back timed out in the current epoch.</summary>
        private readonly List<IPAddress> _dialBackFailures = new List<IPAddress>();
        /// <summary>The pending local dial-back jobs keyed by their hexadecimal nonce.</summary>
        private readonly Dictionary<string, DialBackJob> _dialBacks = new Dictionary<string, DialBackJob>();
        /// <summary>The helper-side dial-back quotas keyed by delegator identifier or target address.</summary>
        private readonly Dictionary<string, Queue<DateTimeOffset>> _probeQuotas = new Dictionary<string, Queue<DateTimeOffset>>();
        /// <summary>The helper-side probes still running.</summary>
        private readonly List<Task> _probeWork = new List<Task>();
        /// <summary>The running reachability check.</summary>
        private Task _reachabilityWork = Task.CompletedTask;
        /// <summary>Whether another reachability check was requested while one was running.</summary>
        private bool _reachabilityRerun;
        /// <summary>The start of the most recent reachability check.</summary>
        private DateTimeOffset _lastReachabilityCheck = DateTimeOffset.MinValue;
        /// <summary>The pending announcement of a changed local contact.</summary>
        private Task _contactAnnouncement = Task.CompletedTask;

        /// <summary>Gets the delay that coalesces several contact changes into one announcement.</summary>
        internal static TimeSpan ContactAnnouncementDelay { get; } = TimeSpan.FromSeconds(5);

        /// <summary>Re-signs the local contact and schedules an announcement when its advertisement changed.</summary>
        /// <remarks>The caller must hold the state lock.</remarks>
        private void RefreshLocalContactLocked()
        {
            var next = BuildLocalContactLocked();
            var changed = _self != null && !_self.SameAdvertisement(next);
            _self = next;
            if (changed)
            {
                Log(LogLevel.Information, "Local contact advertisement changed.");
                if (_contactAnnouncement.IsCompleted && !_lifetime.IsCancellationRequested)
                {
                    _contactAnnouncement = AnnounceContactAsync();
                }
            }
        }

        /// <summary>Builds the signed local contact from configuration, live assistant sessions and reachability evidence.</summary>
        /// <returns>The freshly signed contact.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private DHTContact BuildLocalContactLocked()
        {
            var reachable = _options.PubliclyReachable || HasVerifiedEndpointLocked();
            // Public contacts carry no hints: a hinted node must itself be hint-free, so a public assistant stays usable as a hint.
            var hints = reachable ? new List<DHTPeer>() : HintsLocked();
            var reachability = DHTReachability.Unknown;
            if (reachable)
            {
                reachability = DHTReachability.Public;
            }
            else if (_dialBackFailures.Count >= PrivateFailureThreshold && HasForwarder(hints))
            {
                reachability = DHTReachability.Private;
            }
            while (true)
            {
                try
                {
                    return DHTContact.Create(_identity, _options.Capabilities, reachability, HasEndpointDependentMappingLocked(), hints,
                        reachable ? s_publicContactLifetime : s_unverifiedContactLifetime);
                }
                catch (InvalidDataException) when (hints.Count > 1)
                {
                    // Unusually long hinted contacts can exceed the payload limit; one hint always fits, and forwarders come first.
                    hints.RemoveAt(hints.Count - 1);
                }
            }
        }

        /// <summary>Checks whether a dial-back verified this node in the current epoch at its confirmed external address.</summary>
        /// <returns>Whether an independent helper reached this node at the address confirmed by two independent observers.</returns>
        /// <remarks>
        /// A single Traversal node chooses both the reported address and the helper, so a colluding pair could otherwise make this
        /// node claim public reachability at an attacker's address; only the address confirmed by independent observers counts.
        /// The caller must hold the state lock.
        /// </remarks>
        private bool HasVerifiedEndpointLocked()
        {
            foreach (var verified in _verifiedEndpoints.Values)
            {
                if (_externalAddresses.TryGetValue(verified.Address.AddressFamily, out var external) && external.Equals(verified.Address))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Checks whether a hint list contains a Forwarder, which a private contact needs to stay reachable.</summary>
        /// <param name="hints">The hints.</param>
        /// <returns>Whether a Forwarder is hinted.</returns>
        private static bool HasForwarder(List<DHTPeer> hints)
        {
            foreach (var hint in hints)
            {
                if ((hint.Capabilities & DHTCapabilities.Forwarder) != 0)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Selects public assistants with live sessions as hints: Forwarders first, preferring distinct networks.</summary>
        /// <returns>At most three hints.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private List<DHTPeer> HintsLocked()
        {
            var result = new List<DHTPeer>();
            var deferred = new List<DHTPeer>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var now = DateTimeOffset.UtcNow;
            foreach (var sessions in new[] { _forwarders.Values, _traversalNodes.Values })
            {
                foreach (var session in sessions)
                {
                    var peer = session.Peer;
                    if (peer.IsExpired || peer.ExpiresAt <= now.AddMinutes(1) || peer.Reachability != DHTReachability.Public
                        || peer.Hints.Count != 0 || peer.Endpoints.Count == 0 || peer.Contact.Encoded.Length > DHTContact.MaxHintLength
                        || session.LastSuccess + _options.NatRegistrationLifetime <= now || !seen.Add(peer.NodeId))
                    {
                        continue;
                    }
                    var distinct = true;
                    foreach (var selected in result)
                    {
                        distinct &= !SharesNetwork(selected, peer);
                    }
                    (distinct ? result : deferred).Add(peer);
                }
            }
            result.AddRange(deferred);
            if (result.Count > DHTContact.MaxHints)
            {
                result.RemoveRange(DHTContact.MaxHints, result.Count - DHTContact.MaxHints);
            }
            return result;
        }

        /// <summary>Checks whether two peers were observed in the same network.</summary>
        /// <param name="left">The first peer.</param>
        /// <param name="right">The second peer.</param>
        /// <returns>Whether any pair of observed endpoints shares a network prefix.</returns>
        private static bool SharesNetwork(DHTPeer left, DHTPeer right)
        {
            foreach (var a in left.Endpoints)
            {
                foreach (var b in right.Endpoints)
                {
                    if (NetworkScope.SameNetwork(a.NetworkAddress, b.NetworkAddress))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        /// <summary>Checks whether observers reported different ports for the confirmed external address.</summary>
        /// <returns>Whether the NAT mapping depends on the destination endpoint.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private bool HasEndpointDependentMappingLocked()
        {
            foreach (var external in _externalAddresses)
            {
                for (var index = 0; index < 2; index++)
                {
                    var transport = index == 0 ? DHTTransport.Tcp : DHTTransport.Udp;
                    var port = 0;
                    foreach (var observation in _observations)
                    {
                        if (observation.Key.Family != external.Key || observation.Key.Transport != transport
                            || !observation.Value.Endpoint.Address.Equals(external.Value))
                        {
                            continue;
                        }
                        if (port != 0 && port != observation.Value.Endpoint.Port)
                        {
                            return true;
                        }
                        port = observation.Value.Endpoint.Port;
                    }
                }
            }
            return false;
        }

        /// <summary>Records an endpoint observed for this node by an authenticated remote node and updates the external-address vote.</summary>
        /// <param name="reporter">The authenticated observing node.</param>
        /// <param name="reporterAddress">The address this node used to reach the reporter.</param>
        /// <param name="transport">The transport whose mapping was observed.</param>
        /// <param name="observed">The observed source endpoint of this node.</param>
        private void RecordObservation(DHTContact reporter, IPAddress reporterAddress, DHTTransport transport, IPEndPoint observed)
        {
            var family = observed.AddressFamily;
            lock (_gate)
            {
                var now = DateTimeOffset.UtcNow;
                _observations[(reporter.NodeId, family, transport)] = new EndpointObservation(observed, reporterAddress, now);
                var expired = new List<(string, AddressFamily, DHTTransport)>();
                foreach (var entry in _observations)
                {
                    if (entry.Value.ObservedAt + s_observationLifetime <= now)
                    {
                        expired.Add(entry.Key);
                    }
                }
                foreach (var key in expired)
                {
                    _observations.Remove(key);
                }
                _externalAddresses.TryGetValue(family, out var previous);
                var current = VoteExternalAddressLocked(family);
                var addressChanged = current != null && !current.Equals(previous);
                if (addressChanged)
                {
                    _externalAddresses[family] = current!;
                    if (previous != null)
                    {
                        // A new external address starts a new epoch: earlier dial-back evidence no longer applies.
                        _verifiedEndpoints.Remove(family);
                        _dialBackFailures.Clear();
                        Log(LogLevel.Information, "External address changed; reachability will be checked again.");
                        TriggerReachabilityCheck();
                    }
                    else
                    {
                        Log(LogLevel.Information, "External address confirmed by independent observers.");
                    }
                }
                if (_self != null && (addressChanged || _self.HasEndpointDependentMapping != HasEndpointDependentMappingLocked()))
                {
                    RefreshLocalContactLocked();
                }
            }
        }

        /// <summary>Selects the observed address reported by the largest number of distinct networks.</summary>
        /// <param name="family">The address family.</param>
        /// <returns>An address reported by at least two distinct networks, or null.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private IPAddress? VoteExternalAddressLocked(AddressFamily family)
        {
            IPAddress? best = null;
            var bestVotes = 1;
            foreach (var candidate in _observations)
            {
                if (candidate.Key.Family != family)
                {
                    continue;
                }
                var address = candidate.Value.Endpoint.Address;
                var networks = new List<IPAddress>();
                foreach (var observation in _observations)
                {
                    if (observation.Key.Family != family || !observation.Value.Endpoint.Address.Equals(address))
                    {
                        continue;
                    }
                    var distinct = true;
                    foreach (var network in networks)
                    {
                        distinct &= !NetworkScope.SameNetwork(network, observation.Value.ReporterAddress);
                    }
                    if (distinct)
                    {
                        networks.Add(observation.Value.ReporterAddress);
                    }
                }
                if (networks.Count > bestVotes)
                {
                    best = address;
                    bestVotes = networks.Count;
                }
            }
            return best;
        }

        /// <summary>Starts a reachability check, or schedules another pass when one is already running.</summary>
        private void TriggerReachabilityCheck()
        {
            lock (_gate)
            {
                if (!_options.EnableNatTraversal || _options.PubliclyReachable || !_started || _stopped || _lifetime.IsCancellationRequested)
                {
                    return;
                }
                if (!_reachabilityWork.IsCompleted)
                {
                    _reachabilityRerun = true;
                    return;
                }
                _reachabilityWork = RunReachabilityChecksAsync();
            }
        }

        /// <summary>Asks the registered Traversal nodes to arrange dial-backs until each transport is verified or every node was tried.</summary>
        /// <returns>Completion after the requested passes.</returns>
        private async Task RunReachabilityChecksAsync()
        {
            await Task.Yield();
            try
            {
                while (true)
                {
                    var traversalNodes = new List<DHTPeer>();
                    lock (_gate)
                    {
                        _reachabilityRerun = false;
                        _lastReachabilityCheck = DateTimeOffset.UtcNow;
                        foreach (var session in _traversalNodes.Values)
                        {
                            traversalNodes.Add(session.Peer);
                        }
                    }
                    for (var index = 0; index < 2; index++)
                    {
                        var transport = index == 0 ? _options.PreferredTransport : OtherTransport(_options.PreferredTransport);
                        foreach (var traversal in traversalNodes)
                        {
                            if (!SupportsAssistantTransport(traversal, transport))
                            {
                                continue;
                            }
                            try
                            {
                                if (await DialBackAsync(traversal, transport, _lifetime.Token).ConfigureAwait(false))
                                {
                                    break;
                                }
                            }
                            catch (Exception exception) when (IsPeerFailure(exception))
                            {
                                _lifetime.Token.ThrowIfCancellationRequested();
                                Log(LogLevel.Debug, "Dial-back request was inconclusive: ", exception);
                            }
                        }
                    }
                    lock (_gate)
                    {
                        if (!_reachabilityRerun || _lifetime.IsCancellationRequested)
                        {
                            return;
                        }
                    }
                }
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Log(LogLevel.Warning, "Reachability check stopped: ", exception);
            }
        }

        /// <summary>Asks one Traversal node to have an independent helper dial this node back.</summary>
        /// <param name="traversal">The registered Traversal node.</param>
        /// <param name="transport">The transport to verify.</param>
        /// <param name="cancellationToken">The node lifetime.</param>
        /// <returns>True when the helper reached this node; false when the dial-back timed out.</returns>
        /// <exception cref="IOException">The Traversal node could not arrange a dial-back; the result is inconclusive.</exception>
        /// <exception cref="InvalidDataException">The response is malformed.</exception>
        private async Task<bool> DialBackAsync(DHTPeer traversal, DHTTransport transport, CancellationToken cancellationToken)
        {
            var endpoint = AssistantEndpoint(traversal, transport) ?? throw new IOException("The Traversal node has no endpoint for this transport.");
            var localPort = _transport.PortFor(transport, endpoint.AddressFamily);
            if (localPort == 0)
            {
                throw new IOException("This node has no listener for the transport being verified.");
            }
            using var body = new Wire();
            TraversalMessage.WriteDialBackRequest(body, new[] { localPort });
            var response = await RequestAssistantAsync(traversal, Operation.Traversal, transport, body.WrittenMemory, cancellationToken).ConfigureAwait(false);
            DialBackJob job;
            string id;
            using (var arrangementBody = response.Body)
            using (var reader = new Wire(arrangementBody.Bytes))
            {
                var arrangement = TraversalMessage.ReadDialBackResponse(reader);
                var helper = arrangement.HelperId;
                var expiresAt = arrangement.ExpiresAt;
                if (helper == NodeId || helper == traversal.NodeId || expiresAt > DateTimeOffset.UtcNow.AddMinutes(2))
                {
                    throw new InvalidDataException("Invalid dial-back arrangement.");
                }
                RecordObservation(response.Peer, response.Endpoint.Address, transport, arrangement.Observed);
                id = Crypto.Hex(arrangement.Nonce.Span);
                job = new DialBackJob(helper, transport, arrangement.Observed.Address, arrangement.Ports, expiresAt);
                lock (_gate)
                {
                    if (_dialBacks.Count >= _options.MaxConcurrentRequests || _dialBacks.ContainsKey(id))
                    {
                        throw new IOException("The local dial-back limit was reached.");
                    }
                    _dialBacks.Add(id, job);
                }
            }
            try
            {
                var remaining = job.ExpiresAt - DateTimeOffset.UtcNow;
                if (remaining > _options.NatTraversalTimeout)
                {
                    remaining = _options.NatTraversalTimeout;
                }
                if (remaining > TimeSpan.Zero)
                {
                    await Task.WhenAny(job.Success.Task, Task.Delay(remaining, cancellationToken)).ConfigureAwait(false);
                }
                cancellationToken.ThrowIfCancellationRequested();
                lock (_gate)
                {
                    if (job.Success.Task.IsCompleted)
                    {
                        RecordVerifiedLocked(job.Address, transport, job.Ports[job.Success.Task.Result]);
                        Log(LogLevel.Information, "Independent dial-back verified public reachability.");
                        return true;
                    }
                    var distinct = true;
                    foreach (var failure in _dialBackFailures)
                    {
                        distinct &= !NetworkScope.SameNetwork(failure, response.Endpoint.Address);
                    }
                    if (distinct)
                    {
                        _dialBackFailures.Add(response.Endpoint.Address);
                    }
                    RefreshLocalContactLocked();
                }
                Log(LogLevel.Information, "Independent dial-back did not reach this node.");
                return false;
            }
            finally
            {
                lock (_gate)
                {
                    _dialBacks.Remove(id);
                }
            }
        }

        /// <summary>Records one verified external endpoint and re-signs the local contact.</summary>
        /// <param name="address">The observed external address.</param>
        /// <param name="transport">The verified transport.</param>
        /// <param name="port">The verified external port.</param>
        /// <remarks>The caller must hold the state lock.</remarks>
        private void RecordVerifiedLocked(IPAddress address, DHTTransport transport, int port)
        {
            if (!_verifiedEndpoints.TryGetValue(address.AddressFamily, out var verified) || !verified.Address.Equals(address))
            {
                verified = new VerifiedEndpoint(address);
                _verifiedEndpoints[address.AddressFamily] = verified;
            }
            if (transport == DHTTransport.Tcp)
            {
                verified.TcpPort = port;
            }
            else
            {
                verified.UdpPort = port;
            }
            RefreshLocalContactLocked();
        }

        /// <summary>Arranges a dial-back by an independent helper on behalf of a registered client.</summary>
        /// <param name="packet">The authenticated client request.</param>
        /// <param name="request">The remaining request arguments.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The client's observed endpoint, which is the only permitted dial-back address.</param>
        /// <param name="response">The encoder receiving the observed endpoint, helper identity, nonce, expiry and candidate ports.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>Completion after a helper accepted the dial-back and the arrangement was written.</returns>
        /// <exception cref="IOException">The requester exceeded its quota or no helper accepted the dial-back.</exception>
        /// <exception cref="InvalidDataException">The request is malformed.</exception>
        private async Task DispatchDialBackAsync(Packet packet, Wire request, DHTTransport transport, IPEndPoint source, Wire response,
            CancellationToken cancellationToken)
        {
            lock (_gate)
            {
                // Each request makes this node contact helpers, so a requester cannot use it as a traffic multiplier.
                if (!TakeProbeQuotaLocked("requester:" + packet.Sender.NodeId, DialBacksPerRequester))
                {
                    throw new IOException("The dial-back request quota was reached.");
                }
            }
            var ports = new List<int> { source.Port };
            foreach (var port in TraversalMessage.ReadDialBackRequest(request))
            {
                if (!ports.Contains(port))
                {
                    ports.Add(port);
                }
            }
            var nonce = Crypto.Random(16);
            var expiresAt = DateTimeOffset.UtcNow + _options.NatTraversalTimeout;
            using var assist = new Wire();
            TraversalMessage.WriteDialBackAssistRequest(assist, new DialBackDelegation(packet.Sender, transport, source.Address, ports, nonce, expiresAt));
            var attempts = 0;
            foreach (var helper in DialBackHelpers(packet.Sender, source, transport))
            {
                if (attempts++ >= DialBackHelperAttempts)
                {
                    break;
                }
                try
                {
                    using var acceptance = await RequestAsync(helper, Operation.Traversal, assist.WrittenMemory, cancellationToken, allowAssisted: false)
                        .ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Dial-back helper declined: ", exception);
                    continue;
                }
                TraversalMessage.WriteDialBackResponse(response, new DialBackArrangement(source, helper.NodeId, nonce, expiresAt, ports));
                return;
            }
            throw new IOException("No independent dial-back helper is available.");
        }

        /// <summary>Lists public Traversal nodes observed in networks distinct from the client and this node as dial-back helpers.</summary>
        /// <param name="client">The client requesting the dial-back.</param>
        /// <param name="source">The client's observed endpoint.</param>
        /// <param name="transport">The transport to dial.</param>
        /// <returns>Candidate helpers, one per network, in random order.</returns>
        private List<DHTPeer> DialBackHelpers(DHTContact client, IPEndPoint source, DHTTransport transport)
        {
            var own = new List<IPAddress>();
            lock (_gate)
            {
                own.AddRange(_externalAddresses.Values);
            }
            foreach (var address in _options.ListenAddresses)
            {
                if (!NetworkScope.IsWildcard(address))
                {
                    own.Add(address);
                }
            }
            // One candidate per network, in random order: a client cannot steer the choice by minting identities near its own
            // node identifier, and one operator network cannot supply every helper.
            var byNetwork = new Dictionary<string, List<DHTPeer>>(StringComparer.Ordinal);
            foreach (var peer in RoutedPeers(client.NodeId, 256))
            {
                if (peer.NodeId == client.NodeId || peer.NodeId == NodeId || peer.Reachability != DHTReachability.Public
                    || (peer.Capabilities & DHTCapabilities.Traversal) == 0)
                {
                    continue;
                }
                foreach (var endpoint in peer.Endpoints)
                {
                    var address = endpoint.NetworkAddress;
                    if (endpoint.Port(transport) == 0 || address.AddressFamily != source.AddressFamily || NetworkScope.SameNetwork(address, source.Address))
                    {
                        continue;
                    }
                    var distinct = true;
                    foreach (var local in own)
                    {
                        distinct &= !NetworkScope.SameNetwork(address, local);
                    }
                    if (distinct)
                    {
                        var key = NetworkScope.NetworkKey(address);
                        if (!byNetwork.TryGetValue(key, out var members))
                        {
                            members = new List<DHTPeer>();
                            byNetwork.Add(key, members);
                        }
                        members.Add(peer);
                        break;
                    }
                }
            }
            var result = new List<DHTPeer>(byNetwork.Count);
            foreach (var members in byNetwork.Values)
            {
                result.Add(members[RandomNumberGenerator.GetInt32(members.Count)]);
            }
            Crypto.Shuffle(result);
            return result;
        }

        /// <summary>Accepts a Traversal node's dial-back delegation and probes the client's observed address in the background.</summary>
        /// <param name="packet">The authenticated delegation request.</param>
        /// <param name="request">The remaining request arguments.</param>
        /// <exception cref="IOException">The delegator or target exceeded a quota, or the target scope is not permitted.</exception>
        /// <exception cref="InvalidDataException">The delegation is malformed, expired or not sent by a Traversal node.</exception>
        private void DispatchDialBackAssist(Packet packet, Wire request)
        {
            if ((packet.Sender.Capabilities & DHTCapabilities.Traversal) == 0)
            {
                throw new InvalidDataException("Only Traversal nodes may delegate dial-backs.");
            }
            var delegation = TraversalMessage.ReadDialBackAssistRequest(request);
            var owner = delegation.Owner;
            var target = delegation.TargetAddress;
            var expiresAt = delegation.ExpiresAt;
            if (owner.NodeId == NodeId || !HasRequiredWork(owner) || owner.NodeId == packet.Sender.NodeId
                || expiresAt <= DateTimeOffset.UtcNow || expiresAt > DateTimeOffset.UtcNow.AddMinutes(2))
            {
                throw new InvalidDataException("Invalid dial-back delegation.");
            }
            if (!IsPermittedProbeTarget(target))
            {
                throw new IOException("The dial-back target scope is not reachable from this helper.");
            }
            lock (_gate)
            {
                if (!TakeProbeQuotaLocked("delegator:" + packet.Sender.NodeId, ProbesPerDelegator)
                    || !TakeProbeQuotaLocked("target:" + target, ProbesPerTarget))
                {
                    throw new IOException("The dial-back quota was reached.");
                }
                _probeWork.RemoveAll(work => work.IsCompleted);
                if (_probeWork.Count >= _options.MaxConcurrentRequests)
                {
                    throw new IOException("The dial-back helper is busy.");
                }
                // The probes outlive the request frame, so the nonce is copied out of it.
                _probeWork.Add(SendProbesAsync(owner, delegation.Transport, target, delegation.Ports, delegation.Nonce.ToArray(), expiresAt));
            }
        }

        /// <summary>Checks whether this helper may send probes to an address scope.</summary>
        /// <param name="target">The client's observed address.</param>
        /// <returns>Whether the target is global, or shares a non-global scope with one of this node's listeners.</returns>
        private bool IsPermittedProbeTarget(IPAddress target)
        {
            var scope = NetworkScope.Classify(target);
            if (scope == NetworkScope.Scope.Global)
            {
                return true;
            }
            if (scope == NetworkScope.Scope.LinkLocal)
            {
                return false;
            }
            foreach (var address in _options.ListenAddresses)
            {
                if (!NetworkScope.IsWildcard(address) && NetworkScope.Classify(address) == scope)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Consumes one slot of a sliding-window quota.</summary>
        /// <param name="key">The quota key.</param>
        /// <param name="limit">The maximum uses per window.</param>
        /// <returns>Whether a slot was available.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private bool TakeProbeQuotaLocked(string key, int limit)
        {
            var now = DateTimeOffset.UtcNow;
            var empty = new List<string>();
            foreach (var entry in _probeQuotas)
            {
                while (entry.Value.Count != 0 && entry.Value.Peek() + s_probeQuotaWindow <= now)
                {
                    entry.Value.Dequeue();
                }
                if (entry.Value.Count == 0)
                {
                    empty.Add(entry.Key);
                }
            }
            foreach (var stale in empty)
            {
                _probeQuotas.Remove(stale);
            }
            if (!_probeQuotas.TryGetValue(key, out var uses))
            {
                if (_probeQuotas.Count >= _options.MaxNatRegistrations)
                {
                    return false;
                }
                uses = new Queue<DateTimeOffset>();
                _probeQuotas.Add(key, uses);
            }
            if (uses.Count >= limit)
            {
                return false;
            }
            uses.Enqueue(now);
            return true;
        }

        /// <summary>
        /// Probes each candidate port of the client's observed address until one probe is accepted, the bounded rounds are
        /// used up or the dial-back expires.
        /// </summary>
        /// <param name="owner">The client whose reachability is checked.</param>
        /// <param name="transport">The transport to dial.</param>
        /// <param name="target">The observed client address.</param>
        /// <param name="ports">The candidate ports.</param>
        /// <param name="nonce">The nonce issued by the Traversal node.</param>
        /// <param name="expiresAt">The dial-back expiry.</param>
        /// <returns>Completion after a probe was accepted or the probe budget was spent.</returns>
        /// <remarks>
        /// The client registers its pending job only after the Traversal node answers, which can be later than the first probe,
        /// so a rejected probe is retried with a fresh request identifier. A delegator can name any target, so the helper never
        /// sends more than <see cref="MaxProbeRounds"/> rounds and never probes longer than its own traversal budget.
        /// </remarks>
        private async Task SendProbesAsync(DHTContact owner, DHTTransport transport, IPAddress target, IReadOnlyList<int> ports, byte[] nonce,
            DateTimeOffset expiresAt)
        {
            await Task.Yield();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            var remaining = expiresAt - DateTimeOffset.UtcNow;
            if (remaining > _options.NatTraversalTimeout)
            {
                remaining = _options.NatTraversalTimeout;
            }
            timeout.CancelAfter(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
            try
            {
                for (var round = 0; round < MaxProbeRounds; round++)
                {
                    for (var index = 0; index < ports.Count; index++)
                    {
                        if (await SendProbeAsync(owner, transport, new IPEndPoint(target, ports[index]), nonce, index, timeout.Token)
                            .ConfigureAwait(false))
                        {
                            Log(LogLevel.Debug, "Dial-back probe reached its target.");
                            return;
                        }
                    }
                    if (round + 1 < MaxProbeRounds)
                    {
                        await Task.Delay(s_probeRetryInterval, timeout.Token).ConfigureAwait(false);
                    }
                }
                Log(LogLevel.Debug, "Dial-back probes did not reach their target.");
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                Log(LogLevel.Debug, "Dial-back probes expired without reaching their target.");
            }
        }

        /// <summary>Sends one authenticated probe.</summary>
        /// <param name="owner">The client whose reachability is checked.</param>
        /// <param name="transport">The transport to dial.</param>
        /// <param name="endpoint">The candidate endpoint.</param>
        /// <param name="nonce">The nonce issued by the Traversal node.</param>
        /// <param name="index">The candidate port index.</param>
        /// <param name="cancellationToken">The dial-back lifetime.</param>
        /// <returns>Whether the client accepted the probe.</returns>
        /// <exception cref="OperationCanceledException">The dial-back expired or the node stopped.</exception>
        private async Task<bool> SendProbeAsync(DHTContact owner, DHTTransport transport, IPEndPoint endpoint, byte[] nonce, int index,
            CancellationToken cancellationToken)
        {
            try
            {
                using var body = new Wire();
                ProbeMessage.WriteRequest(body, nonce, index);
                var probe = new Packet(LocalContact, Crypto.Random(16), (byte)Operation.Probe, body.ToArray());
                var encoded = await _transport.ExchangeAtAsync(transport, endpoint, probe.Seal(_identity, owner), cancellationToken)
                    .ConfigureAwait(false);
                using var response = AuthenticateResponse(encoded, owner, probe);
                ResponseStatus.ReadResult(response.Packet.Body);
                return true;
            }
            catch (Exception exception) when (IsPeerFailure(exception) || exception is InvalidOperationException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return false;
            }
        }

        /// <summary>Accepts a helper's dial-back probe for a pending local job; the response body stays empty.</summary>
        /// <param name="packet">The authenticated probe.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <exception cref="InvalidDataException">The probe does not match a pending job.</exception>
        private void DispatchProbe(Packet packet, DHTTransport transport)
        {
            using var reader = new Wire(packet.Body);
            var probe = ProbeMessage.ReadRequest(reader);
            lock (_gate)
            {
                if (!_dialBacks.TryGetValue(Crypto.Hex(probe.Nonce.Span), out var job)
                    || job.HelperId != packet.Sender.NodeId || job.Transport != transport
                    || probe.PortIndex >= job.Ports.Count || job.ExpiresAt <= DateTimeOffset.UtcNow)
                {
                    throw new InvalidDataException("The probe does not match a pending dial-back.");
                }
                job.Success.TrySetResult(probe.PortIndex);
            }
        }

        /// <summary>Announces local publications soon after the local contact changed, so provider indexes hold the new contact.</summary>
        /// <returns>Completion after the announcement.</returns>
        private async Task AnnounceContactAsync()
        {
            try
            {
                await Task.Delay(ContactAnnouncementDelay, _lifetime.Token).ConfigureAwait(false);
                await ReannounceLocalRecordsAsync(false, _lifetime.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Log(LogLevel.Warning, "Contact change announcement failed: ", exception);
            }
        }

        /// <summary>Gets every pending reachability and contact task for shutdown draining.</summary>
        /// <returns>The pending tasks.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private List<Task> ReachabilityWorkLocked()
        {
            var work = new List<Task>(_probeWork) { _reachabilityWork, _contactAnnouncement };
            work.AddRange(_verificationWork);
            return work;
        }

        /// <summary>Stores one endpoint observed for this node and its reporter.</summary>
        private readonly struct EndpointObservation
        {
            /// <summary>Gets the observed endpoint of this node.</summary>
            internal IPEndPoint Endpoint { get; }
            /// <summary>Gets the address this node used to reach the reporter.</summary>
            internal IPAddress ReporterAddress { get; }
            /// <summary>Gets the observation time.</summary>
            internal DateTimeOffset ObservedAt { get; }

            /// <summary>Creates an observation.</summary>
            /// <param name="endpoint">The observed endpoint.</param>
            /// <param name="reporterAddress">The reporter's address.</param>
            /// <param name="observedAt">The observation time.</param>
            internal EndpointObservation(IPEndPoint endpoint, IPAddress reporterAddress, DateTimeOffset observedAt)
            {
                Endpoint = endpoint;
                ReporterAddress = reporterAddress;
                ObservedAt = observedAt;
            }
        }

        /// <summary>Holds the external endpoint verified for one address family.</summary>
        private sealed class VerifiedEndpoint
        {
            /// <summary>Gets the verified external address.</summary>
            internal IPAddress Address { get; }
            /// <summary>Gets or sets the verified TCP port, or zero.</summary>
            internal int TcpPort { get; set; }
            /// <summary>Gets or sets the verified UDP port, or zero.</summary>
            internal int UdpPort { get; set; }

            /// <summary>Creates an entry with no verified ports.</summary>
            /// <param name="address">The verified external address.</param>
            internal VerifiedEndpoint(IPAddress address)
            {
                Address = address;
            }
        }

        /// <summary>Tracks one pending dial-back requested by this node.</summary>
        private sealed class DialBackJob
        {
            /// <summary>Gets the helper expected to send the probe.</summary>
            internal string HelperId { get; }
            /// <summary>Gets the transport being verified.</summary>
            internal DHTTransport Transport { get; }
            /// <summary>Gets the observed address being verified.</summary>
            internal IPAddress Address { get; }
            /// <summary>Gets the candidate ports.</summary>
            internal IReadOnlyList<int> Ports { get; }
            /// <summary>Gets the job expiry.</summary>
            internal DateTimeOffset ExpiresAt { get; }
            /// <summary>Gets the signal carrying the index of the first port that a probe reached.</summary>
            internal TaskCompletionSource<int> Success { get; } = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Creates a pending job.</summary>
            /// <param name="helperId">The expected helper.</param>
            /// <param name="transport">The transport.</param>
            /// <param name="address">The observed address.</param>
            /// <param name="ports">The candidate ports.</param>
            /// <param name="expiresAt">The expiry.</param>
            internal DialBackJob(string helperId, DHTTransport transport, IPAddress address, IReadOnlyList<int> ports, DateTimeOffset expiresAt)
            {
                HelperId = helperId;
                Transport = transport;
                Address = address;
                Ports = ports;
                ExpiresAt = expiresAt;
            }
        }
    }
}
