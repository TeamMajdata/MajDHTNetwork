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
    /// A UDP Traversal node written against the public protocol codecs that serves registration and introductions for nodes
    /// behind simulated NATs. Every peer endpoint it reports is translated into the endpoint at which the requester, identified
    /// by its observed endpoint, reaches that peer through its own NAT; the requester's own observed endpoint stays untranslated.
    /// </summary>
    internal sealed class TranslatingTraversalNode : IAsyncDisposable
    {
        /// <summary>The lifetime of an introduction ticket.</summary>
        private static readonly TimeSpan s_ticketLifetime = TimeSpan.FromSeconds(8);
        /// <summary>The node identity.</summary>
        private readonly DHTIdentity _identity = new DHTIdentity();
        /// <summary>The real UDP listener.</summary>
        private readonly SocketTransport _transport;
        /// <summary>Serializes the registry.</summary>
        private readonly object _gate = new object();
        /// <summary>The registrants indexed by node identifier.</summary>
        private readonly Dictionary<string, Registration> _registrations = new Dictionary<string, Registration>(StringComparer.Ordinal);
        /// <summary>Translates a peer endpoint into the endpoint at which a requester, given by its observed endpoint, reaches it.</summary>
        private readonly Func<IPEndPoint, IPEndPoint, IPEndPoint> _translate;

        /// <summary>Gets the signed Traversal contact.</summary>
        internal DHTContact Contact { get; }
        /// <summary>Gets the real listener endpoint.</summary>
        internal IPEndPoint Endpoint { get; }

        /// <summary>Binds a Traversal node.</summary>
        /// <param name="address">The loopback listener address.</param>
        /// <param name="translate">Translates a peer endpoint into the endpoint at which a requester, given by its observed endpoint, reaches it.</param>
        internal TranslatingTraversalNode(IPAddress address, Func<IPEndPoint, IPEndPoint, IPEndPoint> translate)
        {
            _translate = translate;
            var options = new DHTNodeOptions
            {
                ListenAddresses = new List<IPAddress> { address },
                TcpPort = null,
                UdpPort = 0,
                PreferredTransport = DHTTransport.Udp,
                Capabilities = DHTCapabilities.Traversal,
                RequestTimeout = TimeSpan.FromMilliseconds(700),
                UdpAttempts = 2,
                EnableNatTraversal = false
            }.Snapshot();
            _transport = new SocketTransport(options, HandleAsync, NullLogger.Instance);
            _transport.Bind();
            Endpoint = new IPEndPoint(address, _transport.UdpPort);
            Contact = DHTContact.Create(_identity, DHTCapabilities.Traversal, DHTReachability.Public, false, Array.Empty<DHTPeer>(), TimeSpan.FromHours(1));
            _transport.Run();
        }

        /// <summary>Describes this Traversal node as a host reaches it, through its NAT.</summary>
        /// <param name="endpoint">The endpoint at which the host reaches this node.</param>
        /// <returns>The Traversal peer at that endpoint.</returns>
        internal DHTPeer PeerAt(IPEndPoint endpoint)
        {
            return new DHTPeer(Contact, new[] { new DHTEndpoint(endpoint.Address, 0, endpoint.Port) });
        }

        /// <summary>Stops the listener.</summary>
        /// <returns>Completion after the transport drains.</returns>
        public ValueTask DisposeAsync()
        {
            return _transport.DisposeAsync();
        }

        /// <summary>Serves one authenticated Traversal request.</summary>
        /// <param name="encoded">The sealed request.</param>
        /// <param name="transport">The receiving transport.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <param name="token">The handler lifetime.</param>
        /// <returns>The sealed response.</returns>
        private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> encoded, DHTTransport transport, IPEndPoint source, CancellationToken token)
        {
            var packet = Packet.Open(_identity, encoded);
            using var body = new Wire();
            try
            {
                if (packet.Kind != (byte)Operation.Traversal)
                {
                    throw new IOException("Only Traversal requests are served.");
                }
                ResponseStatus.WriteSuccess(body, Serve(packet, new IPEndPoint(source.Address, source.Port)));
            }
            catch (Exception exception) when (exception is IOException || exception is InvalidDataException)
            {
                ResponseStatus.WriteRejection(body);
            }
            var response = new Packet(Contact, packet.RequestId, (byte)(packet.Kind | 0x80), body.ToArray());
            return Task.FromResult<ReadOnlyMemory<byte>>(response.Seal(_identity, packet.Sender));
        }

        /// <summary>Executes a registration or introduction.</summary>
        /// <param name="packet">The authenticated request.</param>
        /// <param name="source">The observed source endpoint, owned by this node.</param>
        /// <returns>The encoded result.</returns>
        /// <exception cref="IOException">The action is unsupported or a party is not registered.</exception>
        /// <exception cref="InvalidDataException">The request is malformed.</exception>
        private byte[] Serve(Packet packet, IPEndPoint source)
        {
            using var request = new Wire(packet.Body);
            using var result = new Wire();
            var action = TraversalMessage.ReadAction(request);
            lock (_gate)
            {
                if (action == TraversalAction.Register)
                {
                    TraversalMessage.ReadRegisterRequest(request);
                    Register(packet.Sender, source, result);
                }
                else if (action == TraversalAction.Introduce)
                {
                    Introduce(packet.Sender, TraversalMessage.ReadIntroduceRequest(request), source, result);
                }
                else
                {
                    throw new IOException("The translating Traversal node serves no dial-backs.");
                }
            }
            return result.ToArray();
        }

        /// <summary>Records a registrant's contact and observed endpoint and hands out one queued introduction.</summary>
        /// <param name="registrant">The authenticated registrant.</param>
        /// <param name="source">The observed source endpoint.</param>
        /// <param name="result">The result encoder.</param>
        /// <remarks>The caller must hold the registry lock.</remarks>
        private void Register(DHTContact registrant, IPEndPoint source, Wire result)
        {
            if (!_registrations.TryGetValue(registrant.NodeId, out var registration))
            {
                registration = new Registration(registrant, source);
                _registrations.Add(registrant.NodeId, registration);
            }
            registration.Contact = registrant;
            registration.Observed = source;
            TraversalIntroduction? pending = null;
            if (registration.Inbox.Count != 0)
            {
                var queued = registration.Inbox.Dequeue();
                pending = new TraversalIntroduction(queued.Contact, _translate(source, queued.Observed), queued.Ticket, queued.ExpiresAt);
            }
            TraversalMessage.WritePollResponse(result, source, pending);
        }

        /// <summary>Queues the requester's introduction for the target and returns the target's introduction with a shared ticket.</summary>
        /// <param name="requester">The authenticated requester.</param>
        /// <param name="targetId">The introduced node.</param>
        /// <param name="source">The requester's observed source endpoint.</param>
        /// <param name="result">The result encoder.</param>
        /// <exception cref="IOException">The requester or target is not registered.</exception>
        /// <remarks>The caller must hold the registry lock.</remarks>
        private void Introduce(DHTContact requester, string targetId, IPEndPoint source, Wire result)
        {
            if (!_registrations.ContainsKey(requester.NodeId) || !_registrations.TryGetValue(targetId, out var target))
            {
                throw new IOException("Both parties must hold a registration.");
            }
            var ticket = Crypto.Random(TraversalMessage.TicketLength);
            var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds((DateTimeOffset.UtcNow + s_ticketLifetime).ToUnixTimeMilliseconds());
            target.Inbox.Enqueue(new Registration(requester, source) { Ticket = ticket, ExpiresAt = expiresAt });
            TraversalMessage.WriteIntroduction(result, new TraversalIntroduction(target.Contact, _translate(source, target.Observed), ticket, expiresAt));
        }

        /// <summary>A registrant's latest contact and observed endpoint, or a queued introduction of a requester to a target.</summary>
        private sealed class Registration
        {
            /// <summary>Gets or sets the latest contact.</summary>
            internal DHTContact Contact { get; set; }
            /// <summary>Gets or sets the latest observed endpoint.</summary>
            internal IPEndPoint Observed { get; set; }
            /// <summary>Gets the ticket of a queued introduction.</summary>
            internal byte[] Ticket { get; init; } = Array.Empty<byte>();
            /// <summary>Gets the ticket expiry of a queued introduction.</summary>
            internal DateTimeOffset ExpiresAt { get; init; }
            /// <summary>Gets the introductions queued for this registrant.</summary>
            internal Queue<Registration> Inbox { get; } = new Queue<Registration>();

            /// <summary>Creates a registration or queued introduction.</summary>
            /// <param name="contact">The contact.</param>
            /// <param name="observed">The observed endpoint.</param>
            internal Registration(DHTContact contact, IPEndPoint observed)
            {
                Contact = contact;
                Observed = observed;
            }
        }
    }
}
