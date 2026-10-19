#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>
    /// Adversarial regressions for the reachability, Hello, Probe, relay-hint, statistics and concurrent-download surfaces,
    /// using real loopback sockets and scripted malicious peers.
    /// </summary>
    [Trait("Category", "Security")]
    public sealed class AttackSurfaceTests
    {
        /// <summary>
        /// A malicious relay reports a foreign observed address and has a colluding helper identity probe the node's real
        /// listener; the node must neither confirm nor advertise that address.
        /// </summary>
        /// <returns>Completion after the hijack attempt has been rejected.</returns>
        [Fact]
        public async Task ColludingRelayCannotMakeANodeAdvertiseAForeignAddress()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var owner = new MajDHTNode(NodeOptions("127.0.0.2", DHTCapabilities.Download | DHTCapabilities.Provide, advertise: false));
            await owner.StartAsync(token);
            await using var relay = new ScriptedPeer(IPAddress.Loopback, DHTCapabilities.Relay);
            var helper = new DHTIdentity();
            var stranger = new DHTIdentity();
            var strangerRejected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var helperAccepted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            relay.Script((packet, source) =>
            {
                if (packet.Kind != (byte)Operation.Rendezvous)
                {
                    return (1, Array.Empty<byte>());
                }
                using var body = new Wire();
                body.PutText("203.0.113.66");
                body.PutLong(40000);
                if (packet.Body.Span[0] == 0)
                {
                    body.PutByte(0);
                    return (0, body.ToArray());
                }
                var nonce = Crypto.Random(16);
                body.PutText(helper.NodeId);
                body.Put(nonce);
                body.PutLong(DateTimeOffset.UtcNow.AddSeconds(20).ToUnixTimeMilliseconds());
                body.PutLong(1);
                body.PutLong(source.Port);
                var victim = packet.Sender;
                _ = Task.Run(async () =>
                {
                    using var probe = new Wire();
                    probe.Put(nonce);
                    probe.PutLong(0);
                    for (var attempt = 0; attempt < 50 && !helperAccepted.Task.IsCompleted; attempt++)
                    {
                        await Task.Delay(50, token);
                        var wrong = await relay.SendAsync(victim, Operation.Probe, probe.ToArray(), token, stranger);
                        if (wrong.Status == 1)
                        {
                            strangerRejected.TrySetResult(true);
                        }
                        var right = await relay.SendAsync(victim, Operation.Probe, probe.ToArray(), token, helper);
                        if (right.Status == 0)
                        {
                            helperAccepted.TrySetResult(true);
                        }
                    }
                }, token);
                return (0, body.ToArray());
            });
            await owner.RegisterRelayAsync(relay.Peer, token);
            await helperAccepted.Task.WaitAsync(token);
            Assert.True(await strangerRejected.Task.WaitAsync(token), "A probe from an identity other than the named helper must be rejected.");
            await Task.Delay(300, token);
            var contact = owner.LocalPeer;
            Assert.Null(contact.ExternalAddress);
            Assert.NotEqual(DHTReachability.Public, contact.Reachability);
            Assert.DoesNotContain(contact.Endpoints, endpoint => endpoint.Address.Equals(IPAddress.Parse("203.0.113.66")));
        }

        /// <summary>A relay can name any probe target, so one delegation must cause only a bounded number of probes.</summary>
        /// <returns>Completion after the probe count stopped growing.</returns>
        [Fact]
        public async Task HelperProbeTrafficPerDelegationIsBounded()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var helperOptions = NodeOptions("127.0.0.3", DHTCapabilities.Relay, advertise: true);
            helperOptions.NatTraversalTimeout = TimeSpan.FromSeconds(30);
            await using var helper = new MajDHTNode(helperOptions);
            await helper.StartAsync(token);
            await using var relay = new ScriptedPeer(IPAddress.Loopback, DHTCapabilities.Relay);
            await using var victim = new ScriptedPeer(IPAddress.Parse("127.0.0.4"), DHTCapabilities.Download, DHTReachability.Unknown);
            victim.Script((packet, source) => (1, Array.Empty<byte>()));
            var response = await relay.SendAsync(helper.LocalPeer, Operation.Rendezvous,
                Delegation(victim.Peer, "127.0.0.4", victim.Endpoint.Port, TimeSpan.FromSeconds(60)), token);
            Assert.Equal(0, response.Status);
            await Task.Delay(TimeSpan.FromSeconds(2), token);
            var probes = victim.Received(Operation.Probe);
            Assert.InRange(probes, 1, MajDHTNode.MaxProbeRounds);
            await Task.Delay(TimeSpan.FromSeconds(1), token);
            Assert.Equal(probes, victim.Received(Operation.Probe));
        }

        /// <summary>Helpers refuse delegations from non-relays, towards out-of-scope targets, with distant expiries or beyond quota.</summary>
        /// <returns>Completion after every refusal was observed.</returns>
        [Fact]
        public async Task HelpersRejectUnauthorizedOrOutOfScopeDelegations()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var helper = new MajDHTNode(NodeOptions("127.0.0.3", DHTCapabilities.Relay, advertise: true));
            await helper.StartAsync(token);
            await using var relay = new ScriptedPeer(IPAddress.Loopback, DHTCapabilities.Relay);
            await using var outsider = new ScriptedPeer(IPAddress.Parse("127.0.0.5"), DHTCapabilities.Download, DHTReachability.Unknown);
            await using var victim = new ScriptedPeer(IPAddress.Parse("127.0.0.4"), DHTCapabilities.Download, DHTReachability.Unknown);
            victim.Script((packet, source) => (1, Array.Empty<byte>()));
            var port = victim.Endpoint.Port;
            var valid = Delegation(victim.Peer, "127.0.0.4", port, TimeSpan.FromSeconds(5));
            Assert.Equal(1, (await outsider.SendAsync(helper.LocalPeer, Operation.Rendezvous, valid, token)).Status);
            Assert.Equal(1, (await relay.SendAsync(helper.LocalPeer, Operation.Rendezvous,
                Delegation(victim.Peer, "169.254.10.10", port, TimeSpan.FromSeconds(5)), token)).Status);
            Assert.Equal(1, (await relay.SendAsync(helper.LocalPeer, Operation.Rendezvous,
                Delegation(victim.Peer, "10.20.30.40", port, TimeSpan.FromSeconds(5)), token)).Status);
            Assert.Equal(1, (await relay.SendAsync(helper.LocalPeer, Operation.Rendezvous,
                Delegation(victim.Peer, "127.0.0.4", port, TimeSpan.FromMinutes(10)), token)).Status);
            for (var accepted = 0; accepted < 4; accepted++)
            {
                Assert.Equal(0, (await relay.SendAsync(helper.LocalPeer, Operation.Rendezvous,
                    Delegation(victim.Peer, "127.0.0.4", port, TimeSpan.FromSeconds(5)), token)).Status);
            }
            Assert.Equal(1, (await relay.SendAsync(helper.LocalPeer, Operation.Rendezvous,
                Delegation(victim.Peer, "127.0.0.4", port, TimeSpan.FromSeconds(5)), token)).Status);
        }

        /// <summary>A relay accepts only a few dial-back requests per requester, so it cannot be used to multiply traffic.</summary>
        /// <returns>Completion after the quota was observed at the relay and its helper.</returns>
        [Fact]
        public async Task RelaysLimitDialBackRequestsPerRequester()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NodeOptions("127.0.0.1", DHTCapabilities.Relay, advertise: true));
            await relay.StartAsync(token);
            await using var helper = new ScriptedPeer(IPAddress.Parse("127.0.0.3"), DHTCapabilities.Relay);
            Assert.Equal(0, (await helper.SendAsync(relay.LocalPeer, Operation.Ping, ReadOnlyMemory<byte>.Empty, token)).Status);
            await using var requester = new ScriptedPeer(IPAddress.Parse("127.0.0.2"), DHTCapabilities.Download, DHTReachability.Unknown);
            var request = new byte[] { 2, 0, 0, 0, 0, 0, 0, 0, 0 };
            var statuses = new List<byte>();
            for (var attempt = 0; attempt < MajDHTNode.DialBacksPerRequester + 2; attempt++)
            {
                statuses.Add((await requester.SendAsync(relay.LocalPeer, Operation.Rendezvous, request, token)).Status);
            }
            Assert.Equal(MajDHTNode.DialBacksPerRequester, statuses.FindAll(status => status == 0).Count);
            Assert.All(statuses.GetRange(MajDHTNode.DialBacksPerRequester, 2), status => Assert.Equal(1, status));
            Assert.Equal(MajDHTNode.DialBacksPerRequester, helper.Received(Operation.Rendezvous));
        }

        /// <summary>Rejects unsolicited probes, refuses to relay control operations and rejects Hello envelopes naming a recipient.</summary>
        /// <returns>Completion after the rejections were observed.</returns>
        [Fact]
        public async Task ProbeAndHelloControlMessagesCannotBeAbused()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var node = new MajDHTNode(NodeOptions("127.0.0.1", DHTCapabilities.Download, advertise: false));
            await node.StartAsync(token);
            await using var attacker = new ScriptedPeer(IPAddress.Parse("127.0.0.6"), DHTCapabilities.Download, DHTReachability.Unknown);
            using var probe = new Wire();
            probe.Put(Crypto.Random(16));
            probe.PutLong(0);
            Assert.Equal(1, (await attacker.SendAsync(node.LocalPeer, Operation.Probe, probe.ToArray(), token)).Status);
            var sealedProbe = new Packet(attacker.Peer, Crypto.Random(16), (byte)Operation.Probe, probe.ToArray()).Seal(attacker.Identity, node.LocalPeer);
            Assert.ThrowsAny<InvalidDataException>(() => Packet.CheckForward(sealedProbe, node.NodeId));
            var receiver = new DHTIdentity();
            var named = NamedHello(attacker.Identity, attacker.Peer, receiver.NodeId);
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(receiver, named));
            Assert.Null(node.GetPeerStatistics(attacker.Peer.NodeId));
        }

        /// <summary>
        /// A forged private contact that names a genuine public relay as its hint cannot make that relay forward to an unknown
        /// destination, and the request fails promptly.
        /// </summary>
        /// <returns>Completion after the bounded failure.</returns>
        [Fact]
        public async Task CopiedRelayHintsCannotRedirectTrafficToUnknownNodes()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var relay = new MajDHTNode(NodeOptions("127.0.0.1", DHTCapabilities.Relay, advertise: true));
            await using var client = new MajDHTNode(NodeOptions("127.0.0.2", DHTCapabilities.Download, advertise: false));
            await Task.WhenAll(relay.StartAsync(token), client.StartAsync(token));
            await client.JoinAsync(relay.LocalPeer, token);
            var forger = new DHTIdentity();
            var forged = DHTPeer.Create(forger, Array.Empty<DHTEndpoint>(), DHTCapabilities.Provide, DHTReachability.Private, false, null,
                new[] { relay.LocalPeer }, TimeSpan.FromMinutes(30));
            var content = new byte[] { 1, 2, 3 };
            var record = DHTRecord.Create(forger, "forged", Crypto.Hex(Crypto.Hash(content)), Crypto.Hex(MerkleTree.Leaf(content)),
                content.Length, 1024, 1, DateTimeOffset.UtcNow.AddHours(1));
            var started = DateTimeOffset.UtcNow;
            await Assert.ThrowsAnyAsync<IOException>(() => client.ReadBlockAsync(record, forged, 0, cancellationToken: token));
            Assert.True(DateTimeOffset.UtcNow - started < TimeSpan.FromSeconds(10), "The failed relay route must not stall the request.");
        }

        /// <summary>A concurrent download fails over from a provider that went offline and records its losses.</summary>
        /// <returns>Completion after the verified download.</returns>
        [Fact]
        public async Task ConcurrentDownloadsFailOverFromAnOfflineProvider()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            var token = deadline.Token;
            var providerOptions = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            providerOptions.BlockSize = 1024;
            await using var first = new MajDHTNode(providerOptions);
            await using var second = new MajDHTNode(providerOptions);
            await using var client = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(first.StartAsync(token), second.StartAsync(token), client.StartAsync(token));
            var content = Crypto.Random(12 * 1024);
            using var source = new MemoryStream(content);
            var record = await first.PublishAsync("failover/file", source, cancellationToken: token);
            await second.JoinAsync(first.LocalPeer, token);
            using (var copy = new MemoryStream())
            {
                await second.DownloadAsync(record, copy, record.FileHash, token);
            }
            await client.JoinAsync(first.LocalPeer, token);
            var providers = await client.FindProvidersAsync(record.FileHash, token);
            Assert.Equal(2, providers.Count);
            await second.StopAsync();
            using var destination = new MemoryStream();
            await client.DownloadAsync(record, destination, record.FileHash, token);
            Assert.True(BytesEqual(content, destination.ToArray()), "The remaining provider must deliver the verified file.");
            var offline = client.GetPeerStatistics(second.NodeId);
            Assert.NotNull(offline);
            Assert.True(offline!.LostPackets > 0, "Failed transmissions to the offline provider must be recorded.");
        }

        /// <summary>Rejects contacts with too many endpoints or an undefined reachability state.</summary>
        [Fact]
        public void MalformedContactAdvertisementsAreRejected()
        {
            var identity = new DHTIdentity();
            var endpoints = new List<DHTEndpoint>();
            for (var index = 0; index < 5; index++)
            {
                endpoints.Add(new DHTEndpoint(IPAddress.Parse("198.51.100." + (index + 1)), 1000, 0, DHTEndpointFlags.None));
            }
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, endpoints, DHTCapabilities.Download, DHTReachability.Unknown,
                false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1)));
            Assert.ThrowsAny<InvalidDataException>(() => DHTPeer.Create(identity, Array.Empty<DHTEndpoint>(), DHTCapabilities.Download,
                (DHTReachability)3, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1)));
        }

        /// <summary>Creates fast single-transport TCP options bound to one loopback host.</summary>
        /// <param name="address">The loopback address that models a distinct host.</param>
        /// <param name="capabilities">The advertised services.</param>
        /// <param name="advertise">Whether the listener address is configured as directly reachable.</param>
        /// <returns>Independent node options.</returns>
        private static DHTNodeOptions NodeOptions(string address, DHTCapabilities capabilities, bool advertise)
        {
            var listen = IPAddress.Parse(address);
            return new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { listen },
                AdvertisedAddresses = advertise ? new List<IPAddress> { listen } : new List<IPAddress>(),
                UdpPort = null,
                Capabilities = capabilities,
                RequestTimeout = TimeSpan.FromMilliseconds(700),
                NatTraversalTimeout = TimeSpan.FromSeconds(2),
                NatPollInterval = TimeSpan.FromMilliseconds(75),
                NatRegistrationLifetime = TimeSpan.FromSeconds(3)
            };
        }

        /// <summary>Encodes a Rendezvous action 3 dial-back delegation over TCP.</summary>
        /// <param name="owner">The contact whose reachability is supposedly checked.</param>
        /// <param name="target">The target address text.</param>
        /// <param name="port">The single candidate port.</param>
        /// <param name="lifetime">The delegation lifetime.</param>
        /// <returns>The request body.</returns>
        private static byte[] Delegation(DHTPeer owner, string target, int port, TimeSpan lifetime)
        {
            using var body = new Wire();
            body.PutByte(3);
            body.Put(owner.Encoded);
            body.PutByte((byte)DHTTransport.Tcp);
            body.PutText(target);
            body.PutLong(1);
            body.PutLong(port);
            body.Put(Crypto.Random(16));
            body.PutLong(DateTimeOffset.UtcNow.Add(lifetime).ToUnixTimeMilliseconds());
            return body.ToArray();
        }

        /// <summary>Builds a signed plaintext Hello envelope that illegally names its recipient.</summary>
        /// <param name="identity">The sender identity.</param>
        /// <param name="sender">The sender contact.</param>
        /// <param name="recipient">The named recipient identifier.</param>
        /// <returns>The envelope bytes.</returns>
        private static byte[] NamedHello(DHTIdentity identity, DHTPeer sender, string recipient)
        {
            using var header = new Wire();
            header.PutText("MajDHT/1/envelope");
            header.PutByte((byte)Operation.Hello);
            header.PutText(recipient);
            header.Put(new byte[32]);
            header.Put(Crypto.Random(12));
            using var message = new Wire();
            message.Put(sender.Encoded);
            message.Put(Crypto.Random(16));
            message.PutLong(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            message.Put(ReadOnlySpan<byte>.Empty);
            using var signed = new Wire();
            signed.Put(header.WrittenSpan);
            signed.Put(message.WrittenSpan);
            using var payload = new Wire();
            payload.Put(message.WrittenSpan);
            payload.Put(identity.Sign(signed.WrittenMemory));
            using var outer = new Wire();
            outer.Put(header.WrittenSpan);
            outer.Put(payload.WrittenSpan);
            return outer.ToArray();
        }
    }
}
