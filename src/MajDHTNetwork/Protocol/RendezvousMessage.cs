using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>The first byte of every Rendezvous request.</summary>
    public enum RendezvousAction : byte
    {
        /// <summary>Registers or refreshes the sender's observed endpoint and polls for a pending introduction.</summary>
        Register = 0,
        /// <summary>Asks the relay to introduce the sender to another registered node.</summary>
        Introduce = 1,
        /// <summary>Asks the relay to arrange an independent dial-back of the sender's observed address.</summary>
        DialBack = 2,
        /// <summary>Delegates a dial-back from a relay to an independent helper.</summary>
        DialBackAssist = 3
    }

    /// <summary>A relay's introduction of one registered peer to another, shared only by that pair and transport.</summary>
    public readonly struct RendezvousIntroduction
    {
        /// <summary>Gets the introduced peer's signed contact.</summary>
        public DHTPeer Peer { get; }
        /// <summary>Gets the endpoint the relay observed for the introduced peer on the introduced transport.</summary>
        public IPEndPoint Endpoint { get; }
        /// <summary>Gets the random 16-byte ticket both peers send in their Punch probes.</summary>
        public ReadOnlyMemory<byte> Ticket { get; }
        /// <summary>Gets the ticket expiry.</summary>
        public DateTimeOffset ExpiresAt { get; }

        /// <summary>Creates an introduction.</summary>
        /// <param name="peer">The introduced peer's contact.</param>
        /// <param name="endpoint">The relay-observed endpoint of the introduced peer.</param>
        /// <param name="ticket">The 16-byte ticket.</param>
        /// <param name="expiresAt">The ticket expiry.</param>
        /// <exception cref="ArgumentNullException">The peer or endpoint is null.</exception>
        /// <exception cref="ArgumentException">The ticket is not 16 bytes long.</exception>
        public RendezvousIntroduction(DHTPeer peer, IPEndPoint endpoint, ReadOnlyMemory<byte> ticket, DateTimeOffset expiresAt)
        {
            if (ticket.Length != RendezvousMessage.TicketLength)
            {
                throw new ArgumentException("An introduction ticket must contain 16 bytes.", nameof(ticket));
            }
            Peer = peer ?? throw new ArgumentNullException(nameof(peer));
            Endpoint = endpoint ?? throw new ArgumentNullException(nameof(endpoint));
            Ticket = ticket;
            ExpiresAt = expiresAt;
        }
    }

    /// <summary>The result of a <see cref="RendezvousAction.Register"/> request.</summary>
    public readonly struct RendezvousPollResponse
    {
        /// <summary>Gets the endpoint the relay observed for the requester on the request's transport.</summary>
        public IPEndPoint Observed { get; }
        /// <summary>Gets the introduction queued for the requester, or null when none is pending.</summary>
        public RendezvousIntroduction? Introduction { get; }

        /// <summary>Creates a poll result.</summary>
        /// <param name="observed">The observed requester endpoint.</param>
        /// <param name="introduction">The pending introduction, or null.</param>
        /// <exception cref="ArgumentNullException">The observed endpoint is null.</exception>
        public RendezvousPollResponse(IPEndPoint observed, RendezvousIntroduction? introduction)
        {
            Observed = observed ?? throw new ArgumentNullException(nameof(observed));
            Introduction = introduction;
        }
    }

    /// <summary>The result of a <see cref="RendezvousAction.DialBack"/> request once a helper accepted the dial-back.</summary>
    public readonly struct DialBackArrangement
    {
        /// <summary>Gets the endpoint the relay observed for the requester; its address is the only address the helper probes.</summary>
        public IPEndPoint Observed { get; }
        /// <summary>Gets the node identifier of the helper that will send the probes.</summary>
        public string HelperId { get; }
        /// <summary>Gets the 16-byte nonce the probes carry.</summary>
        public ReadOnlyMemory<byte> Nonce { get; }
        /// <summary>Gets the dial-back expiry.</summary>
        public DateTimeOffset ExpiresAt { get; }
        /// <summary>Gets the one to three candidate ports the helper probes, in index order.</summary>
        public IReadOnlyList<int> Ports { get; }

        /// <summary>Creates a dial-back arrangement.</summary>
        /// <param name="observed">The observed requester endpoint.</param>
        /// <param name="helperId">The helper's node identifier.</param>
        /// <param name="nonce">The 16-byte nonce.</param>
        /// <param name="expiresAt">The dial-back expiry.</param>
        /// <param name="ports">The candidate ports.</param>
        /// <exception cref="ArgumentNullException">The endpoint, helper or port list is null.</exception>
        /// <exception cref="ArgumentException">The nonce length or the port list is invalid.</exception>
        public DialBackArrangement(IPEndPoint observed, string helperId, ReadOnlyMemory<byte> nonce, DateTimeOffset expiresAt, IReadOnlyList<int> ports)
        {
            if (nonce.Length != RendezvousMessage.NonceLength)
            {
                throw new ArgumentException("A dial-back nonce must contain 16 bytes.", nameof(nonce));
            }
            RendezvousMessage.CheckPorts(ports);
            Observed = observed ?? throw new ArgumentNullException(nameof(observed));
            HelperId = helperId ?? throw new ArgumentNullException(nameof(helperId));
            Nonce = nonce;
            ExpiresAt = expiresAt;
            Ports = ports;
        }
    }

    /// <summary>The arguments of a <see cref="RendezvousAction.DialBackAssist"/> request from a relay to a helper.</summary>
    public readonly struct DialBackDelegation
    {
        /// <summary>Gets the signed contact of the node whose reachability is checked.</summary>
        public DHTPeer Owner { get; }
        /// <summary>Gets the transport to probe.</summary>
        public DHTTransport Transport { get; }
        /// <summary>Gets the address the relay observed for the owner, which is the only address to probe.</summary>
        public IPAddress TargetAddress { get; }
        /// <summary>Gets the one to three candidate ports, in index order.</summary>
        public IReadOnlyList<int> Ports { get; }
        /// <summary>Gets the 16-byte nonce the probes carry.</summary>
        public ReadOnlyMemory<byte> Nonce { get; }
        /// <summary>Gets the dial-back expiry.</summary>
        public DateTimeOffset ExpiresAt { get; }

        /// <summary>Creates a dial-back delegation.</summary>
        /// <param name="owner">The contact of the node to probe.</param>
        /// <param name="transport">The transport to probe.</param>
        /// <param name="targetAddress">The relay-observed address.</param>
        /// <param name="ports">The candidate ports.</param>
        /// <param name="nonce">The 16-byte nonce.</param>
        /// <param name="expiresAt">The dial-back expiry.</param>
        /// <exception cref="ArgumentNullException">The owner, address or port list is null.</exception>
        /// <exception cref="ArgumentException">The transport, nonce length or port list is invalid.</exception>
        public DialBackDelegation(DHTPeer owner, DHTTransport transport, IPAddress targetAddress, IReadOnlyList<int> ports, ReadOnlyMemory<byte> nonce,
            DateTimeOffset expiresAt)
        {
            if (transport != DHTTransport.Tcp && transport != DHTTransport.Udp)
            {
                throw new ArgumentException("A TCP or UDP transport is required.", nameof(transport));
            }
            if (nonce.Length != RendezvousMessage.NonceLength)
            {
                throw new ArgumentException("A dial-back nonce must contain 16 bytes.", nameof(nonce));
            }
            RendezvousMessage.CheckPorts(ports);
            Owner = owner ?? throw new ArgumentNullException(nameof(owner));
            Transport = transport;
            TargetAddress = targetAddress ?? throw new ArgumentNullException(nameof(targetAddress));
            Ports = ports;
            Nonce = nonce;
            ExpiresAt = expiresAt;
        }
    }

    /// <summary>
    /// Encodes the Rendezvous operation, which a relay serves for registration, introductions and dial-backs. Every request
    /// starts with a <see cref="RendezvousAction"/> byte, read with <see cref="ReadAction"/> before the action's own reader.
    /// Readers of complete bodies reject trailing data; <see cref="ReadIntroduction"/> and <see cref="ReadPorts"/> read one
    /// value inside a larger body.
    /// </summary>
    public static class RendezvousMessage
    {
        /// <summary>The introduction ticket length in bytes.</summary>
        public const int TicketLength = 16;
        /// <summary>The dial-back nonce length in bytes.</summary>
        public const int NonceLength = 16;
        /// <summary>The maximum number of extra ports a dial-back requester may name besides its observed source port.</summary>
        public const int MaxRequestedPorts = 2;
        /// <summary>The maximum number of candidate ports a helper probes.</summary>
        public const int MaxProbePorts = 3;

        /// <summary>Reads the action byte that starts every Rendezvous request body.</summary>
        /// <param name="reader">The request body decoder.</param>
        /// <returns>The action; the caller continues with that action's reader.</returns>
        /// <exception cref="InvalidDataException">The action is unknown.</exception>
        public static RendezvousAction ReadAction(Wire reader)
        {
            var action = reader.Byte();
            if (action > (byte)RendezvousAction.DialBackAssist)
            {
                throw new InvalidDataException("Invalid rendezvous action.");
            }
            return (RendezvousAction)action;
        }

        /// <summary>Writes a complete <see cref="RendezvousAction.Register"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        public static void WriteRegisterRequest(Wire writer)
        {
            writer.PutByte((byte)RendezvousAction.Register);
        }

        /// <summary>Reads the remainder of a <see cref="RendezvousAction.Register"/> request body, which is empty.</summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <exception cref="InvalidDataException">The body has trailing data.</exception>
        public static void ReadRegisterRequest(Wire reader)
        {
            reader.End();
        }

        /// <summary>Writes a complete <see cref="RendezvousAction.Introduce"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="targetId">The node identifier of the registered peer to be introduced to.</param>
        public static void WriteIntroduceRequest(Wire writer, string targetId)
        {
            writer.PutByte((byte)RendezvousAction.Introduce);
            writer.PutText(targetId);
        }

        /// <summary>Reads the remainder of a <see cref="RendezvousAction.Introduce"/> request body.</summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <returns>The target node identifier.</returns>
        /// <exception cref="InvalidDataException">The identifier is not 64 lowercase hexadecimal digits or the body has trailing data.</exception>
        public static string ReadIntroduceRequest(Wire reader)
        {
            var target = reader.Text(Crypto.DigestLength * 2);
            reader.End();
            if (!Crypto.IsHash(target))
            {
                throw new InvalidDataException("Invalid rendezvous target.");
            }
            return target;
        }

        /// <summary>Writes a complete <see cref="RendezvousAction.DialBack"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="requestedPorts">
        /// At most two extra candidate ports; the relay always probes the observed source port first and deduplicates the list.
        /// </param>
        /// <exception cref="ArgumentNullException">The port list is null.</exception>
        /// <exception cref="ArgumentException">The list is too long or contains an invalid port.</exception>
        public static void WriteDialBackRequest(Wire writer, IReadOnlyList<int> requestedPorts)
        {
            if (requestedPorts == null)
            {
                throw new ArgumentNullException(nameof(requestedPorts));
            }
            if (requestedPorts.Count > MaxRequestedPorts)
            {
                throw new ArgumentException("At most two extra dial-back ports may be requested.", nameof(requestedPorts));
            }
            foreach (var port in requestedPorts)
            {
                if (port < 1 || port > 65535)
                {
                    throw new ArgumentException("Invalid dial-back candidate port.", nameof(requestedPorts));
                }
            }
            writer.PutByte((byte)RendezvousAction.DialBack);
            writer.PutLong(requestedPorts.Count);
            foreach (var port in requestedPorts)
            {
                writer.PutLong(port);
            }
        }

        /// <summary>Reads the remainder of a <see cref="RendezvousAction.DialBack"/> request body.</summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <returns>The zero to two extra candidate ports, not yet deduplicated.</returns>
        /// <exception cref="InvalidDataException">The count or a port is out of range, or the body has trailing data.</exception>
        public static List<int> ReadDialBackRequest(Wire reader)
        {
            var count = reader.Long();
            if (count < 0 || count > MaxRequestedPorts)
            {
                throw new InvalidDataException("Invalid dial-back candidate count.");
            }
            var ports = new List<int>((int)count);
            for (var index = 0; index < count; index++)
            {
                var port = reader.Long();
                if (port < 1 || port > 65535)
                {
                    throw new InvalidDataException("Invalid dial-back candidate port.");
                }
                ports.Add((int)port);
            }
            reader.End();
            return ports;
        }

        /// <summary>Writes a complete <see cref="RendezvousAction.DialBackAssist"/> request body.</summary>
        /// <param name="writer">The request body encoder.</param>
        /// <param name="delegation">The dial-back to delegate.</param>
        public static void WriteDialBackAssistRequest(Wire writer, DialBackDelegation delegation)
        {
            writer.PutByte((byte)RendezvousAction.DialBackAssist);
            writer.Put(delegation.Owner.Encoded);
            writer.PutByte((byte)delegation.Transport);
            writer.PutText(delegation.TargetAddress.ToString());
            WritePorts(writer, delegation.Ports);
            writer.Put(delegation.Nonce.Span);
            writer.PutLong(delegation.ExpiresAt.ToUnixTimeMilliseconds());
        }

        /// <summary>Reads the remainder of a <see cref="RendezvousAction.DialBackAssist"/> request body.</summary>
        /// <param name="reader">The request body decoder after the action byte.</param>
        /// <returns>The structurally valid delegation; the helper still applies its scope, quota and expiry policies.</returns>
        /// <exception cref="InvalidDataException">A contact, transport, address, port, nonce or the framing is invalid.</exception>
        public static DialBackDelegation ReadDialBackAssistRequest(Wire reader)
        {
            var owner = DHTPeer.Parse(reader.Bytes(DHTPeer.MaxEncodedLength));
            var transport = reader.Byte();
            var targetText = reader.Text(ObservedEndpoint.MaxAddressLength);
            var ports = ReadPorts(reader);
            var nonce = reader.Bytes(NonceLength);
            var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.Long());
            reader.End();
            if (transport > (byte)DHTTransport.Udp || nonce.Length != NonceLength || !IPAddress.TryParse(targetText, out var target)
                || target.ToString() != targetText || !NetworkScope.IsUnicast(target))
            {
                throw new InvalidDataException("Invalid dial-back delegation.");
            }
            return new DialBackDelegation(owner, (DHTTransport)transport, target, ports, nonce, expiresAt);
        }

        /// <summary>Writes a successful <see cref="RendezvousAction.Register"/> result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="observed">The endpoint observed for the requester on this transport.</param>
        /// <param name="introduction">The pending introduction for the requester, or null.</param>
        public static void WritePollResponse(Wire writer, IPEndPoint observed, RendezvousIntroduction? introduction)
        {
            ObservedEndpoint.Write(writer, observed);
            writer.PutByte((byte)(introduction.HasValue ? 1 : 0));
            if (introduction.HasValue)
            {
                WriteIntroduction(writer, introduction.Value);
            }
        }

        /// <summary>Reads a complete <see cref="RendezvousAction.Register"/> result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The observed endpoint and the optional introduction; the requester still validates the introduction's expiry and peer.</returns>
        /// <exception cref="InvalidDataException">The endpoint, flag or introduction is malformed, or the result has trailing data.</exception>
        public static RendezvousPollResponse ReadPollResponse(Wire reader)
        {
            var observed = ObservedEndpoint.Read(reader);
            var hasIntroduction = reader.Byte();
            if (hasIntroduction > 1)
            {
                throw new InvalidDataException("Invalid rendezvous poll response.");
            }
            RendezvousIntroduction? introduction = hasIntroduction == 0 ? null : ReadIntroduction(reader);
            reader.End();
            return new RendezvousPollResponse(observed, introduction);
        }

        /// <summary>Writes one introduction, which is also the complete successful <see cref="RendezvousAction.Introduce"/> result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="introduction">The introduction.</param>
        public static void WriteIntroduction(Wire writer, RendezvousIntroduction introduction)
        {
            writer.Put(introduction.Peer.Encoded);
            ObservedEndpoint.Write(writer, introduction.Endpoint);
            writer.Put(introduction.Ticket.Span);
            writer.PutLong(introduction.ExpiresAt.ToUnixTimeMilliseconds());
        }

        /// <summary>Reads one introduction inside a larger body without rejecting trailing data.</summary>
        /// <param name="reader">The decoder positioned at the introduction.</param>
        /// <returns>The verified contact, observed endpoint, ticket and expiry; the caller validates them against its own state.</returns>
        /// <exception cref="InvalidDataException">The contact, endpoint or ticket is malformed.</exception>
        public static RendezvousIntroduction ReadIntroduction(Wire reader)
        {
            var peer = DHTPeer.Parse(reader.Bytes(DHTPeer.MaxEncodedLength));
            var endpoint = ObservedEndpoint.Read(reader);
            var ticket = reader.Bytes(TicketLength);
            var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.Long());
            if (ticket.Length != TicketLength)
            {
                throw new InvalidDataException("Invalid rendezvous introduction ticket.");
            }
            return new RendezvousIntroduction(peer, endpoint, ticket, expiresAt);
        }

        /// <summary>Reads a complete <see cref="RendezvousAction.Introduce"/> result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The introduction to the requested target.</returns>
        /// <exception cref="InvalidDataException">The introduction is malformed or the result has trailing data.</exception>
        public static RendezvousIntroduction ReadIntroduceResponse(Wire reader)
        {
            var introduction = ReadIntroduction(reader);
            reader.End();
            return introduction;
        }

        /// <summary>Writes a successful <see cref="RendezvousAction.DialBack"/> result.</summary>
        /// <param name="writer">The result encoder.</param>
        /// <param name="arrangement">The accepted dial-back.</param>
        public static void WriteDialBackResponse(Wire writer, DialBackArrangement arrangement)
        {
            ObservedEndpoint.Write(writer, arrangement.Observed);
            writer.PutText(arrangement.HelperId);
            writer.Put(arrangement.Nonce.Span);
            writer.PutLong(arrangement.ExpiresAt.ToUnixTimeMilliseconds());
            WritePorts(writer, arrangement.Ports);
        }

        /// <summary>Reads a complete <see cref="RendezvousAction.DialBack"/> result.</summary>
        /// <param name="reader">The result decoder.</param>
        /// <returns>The arrangement; the requester still checks the helper identity and expiry against its own policy.</returns>
        /// <exception cref="InvalidDataException">The endpoint, helper identifier, nonce, ports or framing is invalid.</exception>
        public static DialBackArrangement ReadDialBackResponse(Wire reader)
        {
            var observed = ObservedEndpoint.Read(reader);
            var helper = reader.Text(Crypto.DigestLength * 2);
            var nonce = reader.Bytes(NonceLength);
            var expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(reader.Long());
            var ports = ReadPorts(reader);
            reader.End();
            if (nonce.Length != NonceLength || !Crypto.IsHash(helper))
            {
                throw new InvalidDataException("Invalid dial-back arrangement.");
            }
            return new DialBackArrangement(observed, helper, nonce, expiresAt, ports);
        }

        /// <summary>Writes a candidate port list of one to three ports.</summary>
        /// <param name="writer">The destination encoder.</param>
        /// <param name="ports">The candidate ports in index order.</param>
        /// <exception cref="ArgumentNullException">The list is null.</exception>
        /// <exception cref="ArgumentException">The list is empty, too long or contains an invalid port.</exception>
        public static void WritePorts(Wire writer, IReadOnlyList<int> ports)
        {
            CheckPorts(ports);
            writer.PutLong(ports.Count);
            foreach (var port in ports)
            {
                writer.PutLong(port);
            }
        }

        /// <summary>Reads a candidate port list of one to three ports inside a larger body.</summary>
        /// <param name="reader">The source decoder.</param>
        /// <returns>The candidate ports in index order.</returns>
        /// <exception cref="InvalidDataException">The list is empty, too long or contains an invalid port.</exception>
        public static List<int> ReadPorts(Wire reader)
        {
            var count = reader.Long();
            if (count < 1 || count > MaxProbePorts)
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

        /// <summary>Validates a candidate port list.</summary>
        /// <param name="ports">The list to validate.</param>
        /// <exception cref="ArgumentNullException">The list is null.</exception>
        /// <exception cref="ArgumentException">The list is empty, too long or contains an invalid port.</exception>
        internal static void CheckPorts(IReadOnlyList<int> ports)
        {
            if (ports == null)
            {
                throw new ArgumentNullException(nameof(ports));
            }
            if (ports.Count < 1 || ports.Count > MaxProbePorts)
            {
                throw new ArgumentException("A dial-back names one to three candidate ports.", nameof(ports));
            }
            foreach (var port in ports)
            {
                if (port < 1 || port > 65535)
                {
                    throw new ArgumentException("Invalid dial-back candidate port.", nameof(ports));
                }
            }
        }
    }
}
