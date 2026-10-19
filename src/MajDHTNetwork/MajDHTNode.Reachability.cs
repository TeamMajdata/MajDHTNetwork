using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
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
        /// <summary>The lease of a contact that depends on relay hints or unverified endpoints.</summary>
        private static readonly TimeSpan s_relayedContactLifetime = TimeSpan.FromHours(1);
        /// <summary>How long a relay-observed endpoint counts towards the external-address vote.</summary>
        private static readonly TimeSpan s_observationLifetime = TimeSpan.FromMinutes(10);
        /// <summary>The window of the helper-side dial-back quotas.</summary>
        private static readonly TimeSpan s_probeQuotaWindow = TimeSpan.FromMinutes(1);
        /// <summary>The pause between rounds of rejected or unanswered dial-back probes.</summary>
        private static readonly TimeSpan s_probeRetryInterval = TimeSpan.FromMilliseconds(100);
        /// <summary>The maximum dial-back delegations accepted from one relay per quota window.</summary>
        private const int ProbesPerRelay = 10;
        /// <summary>The maximum dial-backs sent to one target address per quota window.</summary>
        private const int ProbesPerTarget = 4;
        /// <summary>The number of helpers a relay asks before rejecting a dial-back request.</summary>
        private const int DialBackHelperAttempts = 3;
        /// <summary>The number of failed dial-backs, from distinct relay networks, that marks the node private.</summary>
        private const int PrivateFailureThreshold = 2;
        /// <summary>The maximum contacts byte budget of one Find response list.</summary>
        private const int ContactListBudget = 26000;
        /// <summary>The relay-observed endpoints keyed by reporter, address family and transport.</summary>
        private readonly Dictionary<(string Reporter, AddressFamily Family, DHTTransport Transport), ObservedEndpoint> _observations =
            new Dictionary<(string, AddressFamily, DHTTransport), ObservedEndpoint>();
        /// <summary>The external addresses confirmed by independent relays, indexed by address family.</summary>
        private readonly Dictionary<AddressFamily, IPAddress> _externalAddresses = new Dictionary<AddressFamily, IPAddress>();
        /// <summary>The endpoints verified by dial-back in the current epoch, indexed by address family.</summary>
        private readonly Dictionary<AddressFamily, VerifiedEndpoint> _verifiedEndpoints = new Dictionary<AddressFamily, VerifiedEndpoint>();
        /// <summary>The relay addresses whose dial-back timed out in the current epoch.</summary>
        private readonly List<IPAddress> _dialBackFailures = new List<IPAddress>();
        /// <summary>The pending local dial-back jobs keyed by their hexadecimal nonce.</summary>
        private readonly Dictionary<string, DialBackJob> _dialBacks = new Dictionary<string, DialBackJob>();
        /// <summary>The helper-side dial-back quotas keyed by relay identifier or target address.</summary>
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
        private void RefreshLocalPeerLocked()
        {
            var next = BuildLocalPeerLocked();
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

        /// <summary>Builds the signed local contact from listeners, configuration and reachability evidence.</summary>
        /// <returns>The freshly signed contact.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private DHTPeer BuildLocalPeerLocked()
        {
            var endpoints = new List<DHTEndpoint>();
            foreach (var address in _options.AdvertisedAddresses)
            {
                AddLocalEndpoint(endpoints, address, _transport.TcpPortFor(address.AddressFamily),
                    _transport.UdpPortFor(address.AddressFamily), DHTEndpointFlags.Configured);
            }
            foreach (var verified in _verifiedEndpoints.Values)
            {
                AddLocalEndpoint(endpoints, verified.Address, verified.TcpPort, verified.UdpPort, DHTEndpointFlags.Verified);
            }
            if (_options.AdvertisedAddresses.Count == 0)
            {
                foreach (var address in _options.ListenAddresses)
                {
                    if (!NetworkScope.IsWildcard(address))
                    {
                        var flags = NetworkScope.Classify(address) == NetworkScope.Scope.Global ? DHTEndpointFlags.None : DHTEndpointFlags.Local;
                        AddLocalEndpoint(endpoints, address, _transport.TcpPortFor(address.AddressFamily),
                            _transport.UdpPortFor(address.AddressFamily), flags);
                    }
                }
            }
            var reachable = false;
            foreach (var endpoint in endpoints)
            {
                reachable |= endpoint.IsReachable;
            }
            var hints = reachable ? new List<DHTPeer>() : RelayHintsLocked();
            var reachability = DHTReachability.Unknown;
            if (reachable)
            {
                reachability = DHTReachability.Public;
            }
            else if (_dialBackFailures.Count >= PrivateFailureThreshold && hints.Count != 0)
            {
                reachability = DHTReachability.Private;
                endpoints.RemoveAll(endpoint => (endpoint.Flags & DHTEndpointFlags.Local) == 0);
            }
            while (true)
            {
                try
                {
                    return DHTPeer.Create(_identity, endpoints, _options.Capabilities, reachability, HasEndpointDependentMappingLocked(),
                        PreferredExternalAddressLocked(), hints, reachable ? s_publicContactLifetime : s_relayedContactLifetime);
                }
                catch (InvalidDataException) when (hints.Count > 1)
                {
                    // Unusually long relay contacts can exceed the payload limit; one hint always fits.
                    hints.RemoveAt(hints.Count - 1);
                }
            }
        }

        /// <summary>Adds a distinct endpoint with at least one bound port while respecting the endpoint limit.</summary>
        /// <param name="endpoints">The endpoint list under construction.</param>
        /// <param name="address">The advertised address.</param>
        /// <param name="tcpPort">The TCP port or zero.</param>
        /// <param name="udpPort">The UDP port or zero.</param>
        /// <param name="flags">The endpoint flags.</param>
        private static void AddLocalEndpoint(List<DHTEndpoint> endpoints, IPAddress address, int tcpPort, int udpPort, DHTEndpointFlags flags)
        {
            if (endpoints.Count >= DHTPeer.MaxEndpoints || (tcpPort == 0 && udpPort == 0))
            {
                return;
            }
            foreach (var existing in endpoints)
            {
                if (existing.NetworkAddress.Equals(address))
                {
                    return;
                }
            }
            endpoints.Add(new DHTEndpoint(address, tcpPort, udpPort, flags));
        }

        /// <summary>Selects public relays with live registrations, preferring distinct networks.</summary>
        /// <returns>At most three relay hint contacts.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private List<DHTPeer> RelayHintsLocked()
        {
            var result = new List<DHTPeer>();
            var deferred = new List<DHTPeer>();
            var now = DateTimeOffset.UtcNow;
            foreach (var relay in _natRelays.Values)
            {
                var peer = relay.Peer;
                if (peer.IsExpired || peer.ExpiresAt <= now.AddMinutes(1) || peer.Reachability != DHTReachability.Public
                    || peer.RelayHints.Count != 0 || peer.Encoded.Length > DHTPeer.MaxHintLength
                    || relay.LastSuccess + _options.NatRegistrationLifetime <= now)
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
            result.AddRange(deferred);
            if (result.Count > DHTPeer.MaxRelayHints)
            {
                result.RemoveRange(DHTPeer.MaxRelayHints, result.Count - DHTPeer.MaxRelayHints);
            }
            return result;
        }

        /// <summary>Checks whether two contacts advertise an endpoint in the same network.</summary>
        /// <param name="left">The first contact.</param>
        /// <param name="right">The second contact.</param>
        /// <returns>Whether any pair of advertised endpoints shares a network prefix.</returns>
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

        /// <summary>Gets the confirmed external address to advertise, preferring IPv4 because IPv4 is usually translated.</summary>
        /// <returns>The confirmed external address, or null.</returns>
        /// <remarks>The caller must hold the state lock.</remarks>
        private IPAddress? PreferredExternalAddressLocked()
        {
            if (_externalAddresses.TryGetValue(AddressFamily.InterNetwork, out var address))
            {
                return address;
            }
            return _externalAddresses.TryGetValue(AddressFamily.InterNetworkV6, out address) ? address : null;
        }

        /// <summary>Checks whether a confirmed external address belongs to this node.</summary>
        /// <param name="address">The remote contact's external address.</param>
        /// <returns>Whether this node and the remote node share an external address.</returns>
        private bool IsLocalExternalAddress(IPAddress address)
        {
            lock (_gate)
            {
                foreach (var external in _externalAddresses.Values)
                {
                    if (external.Equals(address))
                    {
                        return true;
                    }
                }
                return false;
            }
        }

        /// <summary>Checks whether relays observed different ports for the confirmed external address.</summary>
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

        /// <summary>Records an endpoint observed by an authenticated remote node and updates the external-address vote.</summary>
        /// <param name="reporter">The authenticated observing node.</param>
        /// <param name="reporterAddress">The address this node used to reach the reporter.</param>
        /// <param name="transport">The transport whose mapping was observed.</param>
        /// <param name="observed">The observed source endpoint of this node.</param>
        private void RecordObservation(DHTPeer reporter, IPAddress reporterAddress, DHTTransport transport, IPEndPoint observed)
        {
            var family = observed.AddressFamily;
            lock (_gate)
            {
                var now = DateTimeOffset.UtcNow;
                _observations[(reporter.NodeId, family, transport)] = new ObservedEndpoint(observed, reporterAddress, now);
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
                        Log(LogLevel.Information, "External address confirmed by independent relays.");
                    }
                }
                if (_self != null && (addressChanged || _self.HasEndpointDependentMapping != HasEndpointDependentMappingLocked()))
                {
                    RefreshLocalPeerLocked();
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
                if (!_options.EnableNatTraversal || _options.AdvertisedAddresses.Count != 0 || !_started || _stopped
                    || _lifetime.IsCancellationRequested)
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

        /// <summary>Asks the registered relays to arrange dial-backs until each transport is verified or every relay was tried.</summary>
        /// <returns>Completion after the requested passes.</returns>
        private async Task RunReachabilityChecksAsync()
        {
            await Task.Yield();
            try
            {
                while (true)
                {
                    var relays = new List<DHTPeer>();
                    lock (_gate)
                    {
                        _reachabilityRerun = false;
                        _lastReachabilityCheck = DateTimeOffset.UtcNow;
                        foreach (var relay in _natRelays.Values)
                        {
                            relays.Add(relay.Peer);
                        }
                    }
                    for (var index = 0; index < 2; index++)
                    {
                        var transport = index == 0 ? _options.PreferredTransport : OtherTransport(_options.PreferredTransport);
                        foreach (var relay in relays)
                        {
                            if (!SupportsNatTransport(relay, transport))
                            {
                                continue;
                            }
                            try
                            {
                                if (await DialBackAsync(relay, transport, _lifetime.Token).ConfigureAwait(false))
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

        /// <summary>Asks one relay to have an independent helper dial this node back.</summary>
        /// <param name="relay">The registered relay.</param>
        /// <param name="transport">The transport to verify.</param>
        /// <param name="cancellationToken">The node lifetime.</param>
        /// <returns>True when the helper reached this node; false when the dial-back timed out.</returns>
        /// <exception cref="IOException">The relay could not arrange a dial-back; the result is inconclusive.</exception>
        /// <exception cref="InvalidDataException">The relay response is malformed.</exception>
        private async Task<bool> DialBackAsync(DHTPeer relay, DHTTransport transport, CancellationToken cancellationToken)
        {
            var relayEndpoint = NatEndpoint(relay, transport) ?? throw new IOException("The relay has no endpoint for this transport.");
            using var body = new Wire();
            body.PutByte(2);
            body.PutLong(1);
            body.PutLong(_transport.PortFor(transport, relayEndpoint.AddressFamily));
            var response = await RequestNatAsync(relay, transport, body.WrittenMemory, cancellationToken).ConfigureAwait(false);
            DialBackJob job;
            string id;
            using (var reader = new Wire(response.Body))
            {
                var observed = ReadNatEndpoint(reader);
                var helper = reader.Text(64);
                var nonce = reader.Bytes(16);
                var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.Long());
                var ports = ReadProbePorts(reader);
                reader.End();
                Crypto.ParseHash(helper);
                if (nonce.Length != 16 || helper == NodeId || helper == relay.NodeId || expiresAt > DateTimeOffset.UtcNow.AddMinutes(2))
                {
                    throw new InvalidDataException("Invalid dial-back arrangement.");
                }
                RecordObservation(response.Peer, response.Endpoint.Address, transport, observed);
                id = Crypto.Hex(nonce.Span);
                job = new DialBackJob(helper, transport, observed.Address, ports, expiresAt);
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
                        Log(LogLevel.Information, "Independent dial-back verified a public endpoint.");
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
                    RefreshLocalPeerLocked();
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
        /// <param name="address">The relay-observed external address.</param>
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
            RefreshLocalPeerLocked();
        }

        /// <summary>Arranges a dial-back by an independent helper on behalf of a registered client.</summary>
        /// <param name="packet">The authenticated client request.</param>
        /// <param name="request">The remaining request arguments.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The client's observed endpoint, which is the only permitted dial-back address.</param>
        /// <param name="cancellationToken">The handler lifetime.</param>
        /// <returns>The observed endpoint, helper identity, nonce, expiry and candidate ports.</returns>
        /// <exception cref="IOException">No helper accepted the dial-back.</exception>
        /// <exception cref="InvalidDataException">The request is malformed.</exception>
        private async Task<ReadOnlyMemory<byte>> DispatchDialBackAsync(Packet packet, Wire request, DHTTransport transport, IPEndPoint source,
            CancellationToken cancellationToken)
        {
            var count = request.Long();
            if (count < 0 || count > 2)
            {
                throw new InvalidDataException("Invalid dial-back candidate count.");
            }
            var ports = new List<int> { source.Port };
            for (var index = 0; index < count; index++)
            {
                var port = request.Long();
                if (port < 1 || port > 65535)
                {
                    throw new InvalidDataException("Invalid dial-back candidate port.");
                }
                if (!ports.Contains((int)port))
                {
                    ports.Add((int)port);
                }
            }
            request.End();
            var nonce = Crypto.Random(16);
            var expiresAt = DateTimeOffset.UtcNow + _options.NatTraversalTimeout;
            using var assist = new Wire();
            assist.PutByte(3);
            assist.Put(packet.Sender.Encoded);
            assist.PutByte((byte)transport);
            assist.PutText(source.Address.ToString());
            WriteProbePorts(assist, ports);
            assist.Put(nonce);
            assist.PutLong(expiresAt.ToUnixTimeMilliseconds());
            var attempts = 0;
            foreach (var helper in DialBackHelpers(packet.Sender, source, transport))
            {
                if (attempts++ >= DialBackHelperAttempts)
                {
                    break;
                }
                try
                {
                    await RequestAsync(helper, Operation.Rendezvous, assist.WrittenMemory, cancellationToken, allowRelay: false).ConfigureAwait(false);
                }
                catch (Exception exception) when (IsPeerFailure(exception))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    Log(LogLevel.Debug, "Dial-back helper declined: ", exception);
                    continue;
                }
                using var response = new Wire();
                PutNatEndpoint(response, source);
                response.PutText(helper.NodeId);
                response.Put(nonce);
                response.PutLong(expiresAt.ToUnixTimeMilliseconds());
                WriteProbePorts(response, ports);
                return response.ToArray();
            }
            throw new IOException("No independent dial-back helper is available.");
        }

        /// <summary>Lists public relay-capable helpers in networks distinct from the client and this relay.</summary>
        /// <param name="client">The client requesting the dial-back.</param>
        /// <param name="source">The client's observed endpoint.</param>
        /// <param name="transport">The transport to dial.</param>
        /// <returns>Candidate helpers ordered by routing distance to the client.</returns>
        private List<DHTPeer> DialBackHelpers(DHTPeer client, IPEndPoint source, DHTTransport transport)
        {
            var own = new List<IPAddress>();
            lock (_gate)
            {
                foreach (var endpoint in _self!.Endpoints)
                {
                    own.Add(endpoint.NetworkAddress);
                }
                own.AddRange(_externalAddresses.Values);
            }
            foreach (var address in _options.ListenAddresses)
            {
                if (!NetworkScope.IsWildcard(address))
                {
                    own.Add(address);
                }
            }
            var result = new List<DHTPeer>();
            foreach (var peer in _routing.Closest(client.NodeId, 256))
            {
                if (peer.NodeId == client.NodeId || peer.NodeId == NodeId || peer.Reachability != DHTReachability.Public
                    || (peer.Capabilities & DHTCapabilities.Relay) == 0)
                {
                    continue;
                }
                foreach (var endpoint in peer.Endpoints)
                {
                    var address = endpoint.NetworkAddress;
                    if (!endpoint.IsReachable || endpoint.Port(transport) == 0 || address.AddressFamily != source.AddressFamily
                        || NetworkScope.SameNetwork(address, source.Address))
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
                        result.Add(peer);
                        break;
                    }
                }
            }
            return result;
        }

        /// <summary>Accepts a relay's dial-back delegation and probes the client's observed address in the background.</summary>
        /// <param name="packet">The authenticated relay request.</param>
        /// <param name="request">The remaining request arguments.</param>
        /// <returns>An empty result once the probes are scheduled.</returns>
        /// <exception cref="IOException">The relay or target exceeded a quota, or the target scope is not permitted.</exception>
        /// <exception cref="InvalidDataException">The delegation is malformed or expired.</exception>
        private ReadOnlyMemory<byte> DispatchDialBackAssist(Packet packet, Wire request)
        {
            if ((packet.Sender.Capabilities & DHTCapabilities.Relay) == 0)
            {
                throw new InvalidDataException("Only relays may delegate dial-backs.");
            }
            var owner = new DHTPeer(request.Bytes(DHTPeer.MaxEncodedLength));
            var transport = request.Byte();
            var targetText = request.Text(96);
            var ports = ReadProbePorts(request);
            var nonce = request.Bytes(16).ToArray();
            var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(request.Long());
            request.End();
            if (transport > 1 || nonce.Length != 16 || owner.NodeId == NodeId || owner.NodeId == packet.Sender.NodeId
                || !IPAddress.TryParse(targetText, out var target) || target.ToString() != targetText || !NetworkScope.IsUnicast(target)
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
                if (!TakeProbeQuotaLocked("relay:" + packet.Sender.NodeId, ProbesPerRelay)
                    || !TakeProbeQuotaLocked("target:" + target, ProbesPerTarget))
                {
                    throw new IOException("The dial-back quota was reached.");
                }
                _probeWork.RemoveAll(work => work.IsCompleted);
                if (_probeWork.Count >= _options.MaxConcurrentRequests)
                {
                    throw new IOException("The dial-back helper is busy.");
                }
                _probeWork.Add(SendProbesAsync(owner, (DHTTransport)transport, target, ports, nonce, expiresAt));
            }
            return Array.Empty<byte>();
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
        /// Probes each candidate port of the client's observed address until one probe is accepted or the dial-back expires.
        /// </summary>
        /// <param name="owner">The client whose reachability is checked.</param>
        /// <param name="transport">The transport to dial.</param>
        /// <param name="target">The relay-observed client address.</param>
        /// <param name="ports">The candidate ports.</param>
        /// <param name="nonce">The relay-issued nonce.</param>
        /// <param name="expiresAt">The dial-back expiry.</param>
        /// <returns>Completion after a probe was accepted or the dial-back expired.</returns>
        /// <remarks>
        /// The client registers its pending job only after the relay answers, which can be later than the first probe, so a
        /// rejected probe is retried with a fresh request identifier.
        /// </remarks>
        private async Task SendProbesAsync(DHTPeer owner, DHTTransport transport, IPAddress target, List<int> ports, byte[] nonce,
            DateTimeOffset expiresAt)
        {
            await Task.Yield();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            var remaining = expiresAt - DateTimeOffset.UtcNow;
            timeout.CancelAfter(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero);
            try
            {
                while (true)
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
                    await Task.Delay(s_probeRetryInterval, timeout.Token).ConfigureAwait(false);
                }
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
        /// <param name="nonce">The relay-issued nonce.</param>
        /// <param name="index">The candidate port index.</param>
        /// <param name="cancellationToken">The dial-back lifetime.</param>
        /// <returns>Whether the client accepted the probe.</returns>
        /// <exception cref="OperationCanceledException">The dial-back expired or the node stopped.</exception>
        private async Task<bool> SendProbeAsync(DHTPeer owner, DHTTransport transport, IPEndPoint endpoint, byte[] nonce, int index,
            CancellationToken cancellationToken)
        {
            try
            {
                using var body = new Wire();
                body.Put(nonce);
                body.PutLong(index);
                var probe = new Packet(LocalPeer, Crypto.Random(16), (byte)Operation.Probe, body.ToArray());
                var encoded = await _transport.ExchangeAtAsync(transport, endpoint, probe.Seal(_identity, owner), cancellationToken)
                    .ConfigureAwait(false);
                ReadResponseBody(AuthenticateResponse(encoded, owner, probe));
                return true;
            }
            catch (Exception exception) when (IsPeerFailure(exception) || exception is InvalidOperationException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return false;
            }
        }

        /// <summary>Accepts a helper's dial-back probe for a pending local job.</summary>
        /// <param name="packet">The authenticated probe.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <returns>An empty successful result.</returns>
        /// <exception cref="InvalidDataException">The probe does not match a pending job.</exception>
        private ReadOnlyMemory<byte> DispatchProbe(Packet packet, DHTTransport transport)
        {
            using var reader = new Wire(packet.Body);
            var nonce = reader.Bytes(16);
            var index = reader.Long();
            reader.End();
            lock (_gate)
            {
                if (nonce.Length != 16 || !_dialBacks.TryGetValue(Crypto.Hex(nonce.Span), out var job)
                    || job.HelperId != packet.Sender.NodeId || job.Transport != transport
                    || index < 0 || index >= job.Ports.Count || job.ExpiresAt <= DateTimeOffset.UtcNow)
                {
                    throw new InvalidDataException("The probe does not match a pending dial-back.");
                }
                job.Success.TrySetResult((int)index);
            }
            return Array.Empty<byte>();
        }

        /// <summary>Encodes a bounded dial-back candidate port list.</summary>
        /// <param name="writer">The destination encoder.</param>
        /// <param name="ports">One to three candidate ports.</param>
        private static void WriteProbePorts(Wire writer, List<int> ports)
        {
            writer.PutLong(ports.Count);
            foreach (var port in ports)
            {
                writer.PutLong(port);
            }
        }

        /// <summary>Decodes a bounded dial-back candidate port list.</summary>
        /// <param name="reader">The source decoder.</param>
        /// <returns>One to three valid ports.</returns>
        /// <exception cref="InvalidDataException">The list is empty, too long or contains an invalid port.</exception>
        private static List<int> ReadProbePorts(Wire reader)
        {
            var count = reader.Long();
            if (count < 1 || count > 3)
            {
                throw new InvalidDataException("Invalid dial-back port count.");
            }
            var ports = new List<int>((int)count);
            for (var index = 0; index < count; index++)
            {
                var port = reader.Long();
                if (port < 1 || port > 65535)
                {
                    throw new InvalidDataException("Invalid dial-back port.");
                }
                ports.Add((int)port);
            }
            return ports;
        }

        /// <summary>Announces local publications soon after the local contact changed, so provider indexes hold the new contact.</summary>
        /// <returns>Completion after the announcement.</returns>
        private async Task AnnounceContactAsync()
        {
            try
            {
                await Task.Delay(ContactAnnouncementDelay, _lifetime.Token).ConfigureAwait(false);
                await ReannounceLocalRecordsAsync(_lifetime.Token).ConfigureAwait(false);
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
            return work;
        }

        /// <summary>Stores one relay-observed endpoint and its reporter.</summary>
        private readonly struct ObservedEndpoint
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
            internal ObservedEndpoint(IPEndPoint endpoint, IPAddress reporterAddress, DateTimeOffset observedAt)
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
            /// <summary>Gets the relay-observed address being verified.</summary>
            internal IPAddress Address { get; }
            /// <summary>Gets the candidate ports.</summary>
            internal List<int> Ports { get; }
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
            internal DialBackJob(string helperId, DHTTransport transport, IPAddress address, List<int> ports, DateTimeOffset expiresAt)
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
