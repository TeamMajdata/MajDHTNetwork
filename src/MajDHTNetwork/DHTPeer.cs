using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using MajDHTNetwork.Protocol;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// A node as another node knows it: its signed <see cref="DHTContact"/> together with the endpoints at which that node, or
    /// the node that referred it, observed it. The contact is the owner's signed statement; the endpoints are the observer's.
    /// </summary>
    public sealed class DHTPeer
    {
        /// <summary>The maximum number of observed endpoints kept for one node.</summary>
        public const int MaxEndpoints = 4;
        /// <summary>The observed endpoints, at most one per address.</summary>
        private readonly DHTEndpoint[] _endpoints;

        /// <summary>Gets the signed contact.</summary>
        public DHTContact Contact { get; }
        /// <summary>Gets the observed endpoints, most recently observed last; at most one per address.</summary>
        public IReadOnlyList<DHTEndpoint> Endpoints => _endpoints;
        /// <summary>Gets the stable node fingerprint.</summary>
        public string NodeId => Contact.NodeId;
        /// <summary>Gets the cached node digest without allocation.</summary>
        public ReadOnlySpan<byte> NodeHash => Contact.NodeHash;
        /// <summary>Gets the advertised and signed node capabilities.</summary>
        public DHTCapabilities Capabilities => Contact.Capabilities;
        /// <summary>Gets how other nodes can reach this node.</summary>
        public DHTReachability Reachability => Contact.Reachability;
        /// <summary>Gets whether the owner observed an endpoint-dependent NAT mapping.</summary>
        public bool HasEndpointDependentMapping => Contact.HasEndpointDependentMapping;
        /// <summary>Gets the Traversal and Forwarder nodes hinted by the contact.</summary>
        public IReadOnlyList<DHTPeer> Hints => Contact.Hints;
        /// <summary>Gets the owner's strictly increasing issue sequence.</summary>
        public long Sequence => Contact.Sequence;
        /// <summary>Gets the expiry of the contact.</summary>
        public DateTimeOffset ExpiresAt => Contact.ExpiresAt;
        /// <summary>Gets whether the contact lease is still valid.</summary>
        public bool IsExpired => Contact.IsExpired;
        /// <summary>Gets the identity work of the contact owner.</summary>
        public int IdentityWork => Contact.IdentityWork;

        /// <summary>Pairs a contact with the endpoints at which it was observed.</summary>
        /// <param name="contact">The signed contact.</param>
        /// <param name="endpoints">At most four observed endpoints with distinct addresses; the list is copied.</param>
        /// <exception cref="ArgumentNullException">The contact or list is null.</exception>
        /// <exception cref="ArgumentException">The list has more than four endpoints, a null entry or repeated addresses.</exception>
        public DHTPeer(DHTContact contact, IReadOnlyList<DHTEndpoint> endpoints)
        {
            Contact = contact ?? throw new ArgumentNullException(nameof(contact));
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }
            if (endpoints.Count > MaxEndpoints)
            {
                throw new ArgumentException("At most four observed endpoints are kept for one node.", nameof(endpoints));
            }
            _endpoints = new DHTEndpoint[endpoints.Count];
            for (var index = 0; index < _endpoints.Length; index++)
            {
                var endpoint = endpoints[index] ?? throw new ArgumentException("An observed endpoint is null.", nameof(endpoints));
                for (var previous = 0; previous < index; previous++)
                {
                    if (_endpoints[previous].NetworkAddress.Equals(endpoint.NetworkAddress))
                    {
                        throw new ArgumentException("Observed endpoints must have distinct addresses.", nameof(endpoints));
                    }
                }
                _endpoints[index] = endpoint;
            }
        }

        /// <summary>Pairs a contact with the single endpoint at which it was observed over one transport.</summary>
        /// <param name="contact">The signed contact.</param>
        /// <param name="transport">The transport the packet travelled over.</param>
        /// <param name="endpoint">The observed socket endpoint.</param>
        /// <returns>The peer with that one endpoint.</returns>
        /// <exception cref="ArgumentNullException">The contact is null.</exception>
        /// <exception cref="ArgumentException">The transport or endpoint is invalid.</exception>
        public static DHTPeer Observed(DHTContact contact, DHTTransport transport, IPEndPoint endpoint)
        {
            return new DHTPeer(contact, new[] { DHTEndpoint.Observed(transport, endpoint) });
        }

        /// <summary>
        /// Signs a contact with unknown reachability and pairs it with the endpoint the caller knows the node listens at, for a
        /// contact handed to another node out of band, such as a test fixture or an application's own channel.
        /// </summary>
        /// <param name="identity">The contact owner.</param>
        /// <param name="address">The listening address.</param>
        /// <param name="tcpPort">The TCP port or zero.</param>
        /// <param name="udpPort">The UDP port or zero.</param>
        /// <param name="capabilities">The permitted node services.</param>
        /// <returns>The peer with that one endpoint.</returns>
        /// <exception cref="ArgumentException">The address or ports are invalid.</exception>
        public static DHTPeer Create(DHTIdentity identity, IPAddress address, int tcpPort, int udpPort, DHTCapabilities capabilities)
        {
            return new DHTPeer(DHTContact.Create(identity, capabilities), new[] { new DHTEndpoint(address, tcpPort, udpPort) });
        }

        /// <summary>Gets a copy of this peer with another contact of the same node, keeping the observed endpoints.</summary>
        /// <param name="contact">The newer contact of the same node.</param>
        /// <returns>The peer with the new contact.</returns>
        /// <exception cref="ArgumentException">The contact belongs to another node.</exception>
        public DHTPeer WithContact(DHTContact contact)
        {
            if (contact == null || contact.NodeId != NodeId)
            {
                throw new ArgumentException("The contact must belong to the same node.", nameof(contact));
            }
            return new DHTPeer(contact, _endpoints);
        }

        /// <summary>Gets a copy of this peer with one more observation merged into its endpoints.</summary>
        /// <param name="observed">The newly observed endpoint.</param>
        /// <returns>The peer with the merged endpoints, dropping the oldest address when more than four are known.</returns>
        public DHTPeer WithEndpoint(DHTEndpoint observed)
        {
            return new DHTPeer(Contact, Merge(_endpoints, observed));
        }

        /// <summary>Merges one observation into an endpoint list: a known address combines ports, a new address is appended.</summary>
        /// <param name="endpoints">The known endpoints.</param>
        /// <param name="observed">The newly observed endpoint.</param>
        /// <returns>A new list with the observation last, dropping the oldest address beyond <see cref="MaxEndpoints"/>.</returns>
        /// <exception cref="ArgumentNullException">The list or endpoint is null.</exception>
        public static DHTEndpoint[] Merge(IReadOnlyList<DHTEndpoint> endpoints, DHTEndpoint observed)
        {
            if (endpoints == null)
            {
                throw new ArgumentNullException(nameof(endpoints));
            }
            if (observed == null)
            {
                throw new ArgumentNullException(nameof(observed));
            }
            var result = new List<DHTEndpoint>(endpoints.Count + 1);
            var merged = observed;
            foreach (var endpoint in endpoints)
            {
                if (endpoint.NetworkAddress.Equals(observed.NetworkAddress))
                {
                    merged = endpoint.Merge(observed);
                }
                else
                {
                    result.Add(endpoint);
                }
            }
            result.Add(merged);
            if (result.Count > MaxEndpoints)
            {
                result.RemoveRange(0, result.Count - MaxEndpoints);
            }
            return result.ToArray();
        }

        /// <summary>Checks whether another peer lists the same endpoints in the same order.</summary>
        /// <param name="other">The other peer.</param>
        /// <returns>Whether the endpoints are equal.</returns>
        public bool SameEndpoints(DHTPeer other)
        {
            if (other == null || other._endpoints.Length != _endpoints.Length)
            {
                return false;
            }
            for (var index = 0; index < _endpoints.Length; index++)
            {
                if (!_endpoints[index].Equals(other._endpoints[index]))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>Checks whether one of the observed endpoints is a socket endpoint over one transport.</summary>
        /// <param name="transport">The transport.</param>
        /// <param name="endpoint">The socket endpoint.</param>
        /// <returns>Whether the node was observed there.</returns>
        public bool WasObservedAt(DHTTransport transport, IPEndPoint endpoint)
        {
            foreach (var observed in _endpoints)
            {
                if (observed.NetworkAddress.Equals(endpoint.Address) && observed.Port(transport) == endpoint.Port)
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>Writes the canonical peer encoding: the signed contact bytes followed by the observed endpoint list.</summary>
        /// <param name="writer">The destination encoder.</param>
        public void Write(Wire writer)
        {
            writer.Put(Contact.Encoded);
            WriteEndpoints(writer);
        }

        /// <summary>Writes only the observed endpoint list: an integer count followed by that many endpoints.</summary>
        /// <param name="writer">The destination encoder.</param>
        public void WriteEndpoints(Wire writer)
        {
            writer.PutLong(_endpoints.Length);
            foreach (var endpoint in _endpoints)
            {
                endpoint.Write(writer);
            }
        }

        /// <summary>Reads and verifies a canonical peer written by <see cref="Write"/>, reusing cached contact verifications.</summary>
        /// <param name="reader">The source decoder.</param>
        /// <returns>The peer; the reader of the whole body still validates the referrer's claims against its own policy.</returns>
        /// <exception cref="InvalidDataException">The contact is malformed, expired or forged, or the endpoint list is invalid.</exception>
        public static DHTPeer Read(Wire reader)
        {
            return ReadEndpoints(DHTContact.Parse(reader.Bytes(DHTContact.MaxEncodedLength)), reader);
        }

        /// <summary>Reads an observed endpoint list written by <see cref="WriteEndpoints"/> and pairs it with a contact.</summary>
        /// <param name="contact">The already verified contact.</param>
        /// <param name="reader">The source decoder positioned at the endpoint count.</param>
        /// <returns>The peer.</returns>
        /// <exception cref="InvalidDataException">The count is out of range, an endpoint is malformed or addresses repeat.</exception>
        public static DHTPeer ReadEndpoints(DHTContact contact, Wire reader)
        {
            var count = reader.Long();
            if (count < 0 || count > MaxEndpoints)
            {
                throw new InvalidDataException("Invalid observed endpoint count.");
            }
            var endpoints = new DHTEndpoint[count];
            for (var index = 0; index < endpoints.Length; index++)
            {
                endpoints[index] = DHTEndpoint.Read(reader);
            }
            try
            {
                return new DHTPeer(contact, endpoints);
            }
            catch (ArgumentException exception)
            {
                throw new InvalidDataException("Invalid observed endpoint list.", exception);
            }
        }
    }
}
