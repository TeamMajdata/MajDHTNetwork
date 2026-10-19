using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Identifies a signed encrypted request operation.</summary>
    internal enum Operation : byte
    {
        /// <summary>Returns the current authenticated contact.</summary>
        Ping = 1,
        /// <summary>Looks up nodes, records or providers.</summary>
        Find = 2,
        /// <summary>Stores a signed record and authenticated provider claim.</summary>
        Store = 3,
        /// <summary>Returns an authenticated content block.</summary>
        Block = 4,
        /// <summary>Forwards one opaque request without permitting nested forwarding.</summary>
        Relay = 5,
        /// <summary>Registers observed endpoints and coordinates an authenticated introduction.</summary>
        Rendezvous = 6,
        /// <summary>Confirms an introduced direct path.</summary>
        Punch = 7
    }

    /// <summary>An immutable request or response view, encrypted to its final recipient.</summary>
    /// <remarks>Copies share their memory. Borrowed constructor buffers must remain stable until encryption finishes.</remarks>
    internal readonly struct Packet
    {
        /// <summary>The sender contact, or null for an uninitialized packet.</summary>
        private readonly DHTPeer? _sender;

        /// <summary>Gets the authenticated sender contact.</summary>
        /// <exception cref="InvalidOperationException">The packet is uninitialized.</exception>
        internal DHTPeer Sender
        {
            get
            {
                return _sender ?? throw new InvalidOperationException("An uninitialized packet has no sender.");
            }
        }
        /// <summary>Gets the random 128-bit correlation identifier.</summary>
        internal ReadOnlyMemory<byte> RequestId { get; }
        /// <summary>Gets the operation with the high bit set for responses.</summary>
        internal byte Kind { get; }
        /// <summary>Gets the decrypted operation body.</summary>
        internal ReadOnlyMemory<byte> Body { get; }

        /// <summary>Creates an immutable view of borrowed message memory before encryption.</summary>
        /// <param name="sender">The sender contact.</param>
        /// <param name="requestId">The borrowed 16-byte random correlation identifier.</param>
        /// <param name="kind">The operation and response bit.</param>
        /// <param name="body">The borrowed operation body.</param>
        /// <exception cref="ArgumentNullException">The sender is null.</exception>
        /// <exception cref="ArgumentException">The correlation identifier is not 16 bytes long.</exception>
        internal Packet(DHTPeer sender, ReadOnlyMemory<byte> requestId, byte kind, ReadOnlyMemory<byte> body)
        {
            if (requestId.Length != 16)
            {
                throw new ArgumentException("A packet correlation identifier must contain 16 bytes.", nameof(requestId));
            }
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
            RequestId = requestId;
            Kind = kind;
            Body = body;
        }

        /// <summary>Encrypts and signs a fresh envelope using an ephemeral X25519 sender key.</summary>
        /// <param name="identity">The sending identity.</param>
        /// <param name="recipient">The final recipient contact.</param>
        /// <returns>The bounded encrypted envelope.</returns>
        /// <exception cref="InvalidDataException">The encoded packet exceeds protocol limits.</exception>
        /// <exception cref="InvalidOperationException">The packet is uninitialized.</exception>
        /// <exception cref="CryptographicException">The cryptographic provider cannot seal the packet.</exception>
        internal byte[] Seal(DHTIdentity identity, DHTPeer recipient)
        {
            var sender = Sender;
            var ephemeral = new X25519PrivateKeyParameters(Crypto.Random(32), 0);
            var nonce = Crypto.Random(12);
            using var header = new Wire();
            header.PutText("MajDHT/1/envelope");
            header.PutByte(Kind);
            header.PutText(recipient.NodeId);
            header.Put(ephemeral.GeneratePublicKey().GetEncoded());
            header.Put(nonce);
            var headerBytes = header.WrittenMemory;
            using var plain = new Wire();
            plain.Put(sender.Encoded);
            plain.Put(RequestId.Span);
            plain.PutLong(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            plain.Put(Body.Span);
            using var signed = new Wire();
            signed.Put(headerBytes.Span);
            signed.Put(plain.WrittenSpan);
            using var payload = new Wire();
            payload.Put(plain.WrittenSpan);
            payload.Put(identity.Sign(signed.WrittenMemory));
            var key = Crypto.Derive(ephemeral, recipient.AgreementKey, headerBytes);
            using var outer = new Wire();
            outer.Put(headerBytes.Span);
            Crypto.EncryptTo(outer, key, nonce, headerBytes, payload.WrittenMemory);
            var result = outer.ToArray();
            if (result.Length > Wire.MaxPacket)
            {
                throw new InvalidDataException("Encrypted packet exceeds the datagram budget.");
            }
            return result;
        }

        /// <summary>Verifies an envelope header and obtains routing metadata without decrypting it.</summary>
        /// <param name="encoded">The encrypted packet.</param>
        /// <returns>The operation, final recipient, ephemeral key, nonce and authenticated header bytes.</returns>
        /// <exception cref="InvalidDataException">The envelope header is invalid.</exception>
        private static (byte Kind, string Recipient, ReadOnlyMemory<byte> PublicKey, ReadOnlyMemory<byte> Nonce, ReadOnlyMemory<byte> Header, ReadOnlyMemory<byte> Cipher) Header(ReadOnlyMemory<byte> encoded)
        {
            if (encoded.Length > Wire.MaxPacket)
            {
                throw new InvalidDataException("Oversized encrypted packet.");
            }
            using var outer = new Wire(encoded);
            var header = outer.Bytes(256);
            var cipher = outer.Bytes(Wire.MaxPacket);
            outer.End();
            using var reader = new Wire(header);
            if (reader.Text(32) != "MajDHT/1/envelope")
            {
                throw new InvalidDataException("Unsupported envelope version.");
            }
            var kind = reader.Byte();
            var recipient = reader.Text(64);
            var publicKey = reader.Bytes(32);
            var nonce = reader.Bytes(12);
            reader.End();
            Crypto.ParseHash(recipient);
            if ((kind & 0x7f) < (byte)Operation.Ping || (kind & 0x7f) > (byte)Operation.Punch
                || publicKey.Length != 32 || nonce.Length != 12 || cipher.Length < 16)
            {
                throw new InvalidDataException("Invalid envelope header.");
            }
            return (kind, recipient, publicKey, nonce, header, cipher);
        }

        /// <summary>Allows only data requests to the declared recipient through an opaque relay.</summary>
        /// <param name="encoded">The opaque inner packet.</param>
        /// <param name="recipient">The expected final node identifier.</param>
        /// <exception cref="InvalidDataException">The packet is a response, a control operation or addressed elsewhere.</exception>
        internal static void CheckForward(ReadOnlyMemory<byte> encoded, string recipient)
        {
            var header = Header(encoded);
            if (header.Recipient != recipient || header.Kind < (byte)Operation.Ping || header.Kind > (byte)Operation.Block)
            {
                throw new InvalidDataException("Only Ping, Find, Store and Block requests to the declared recipient may be relayed.");
            }
        }

        /// <summary>Authenticates and decrypts a message addressed to this node.</summary>
        /// <param name="identity">The receiving identity.</param>
        /// <param name="encoded">The encrypted envelope.</param>
        /// <returns>The verified sender and plaintext operation.</returns>
        /// <exception cref="CryptographicException">Recipient, signature or ciphertext authentication failed.</exception>
        /// <exception cref="InvalidDataException">The message is malformed or outside the clock-skew window.</exception>
        internal static Packet Open(DHTIdentity identity, ReadOnlyMemory<byte> encoded)
        {
            var header = Header(encoded);
            if (header.Recipient != identity.NodeId)
            {
                throw new CryptographicException("Envelope recipient mismatch.");
            }
            var key = Crypto.Derive(identity.Agreement, header.PublicKey, header.Header);
            var bytes = Crypto.Transform(false, key, header.Nonce, header.Header, header.Cipher);
            using var payload = new Wire(bytes);
            var plain = payload.Bytes(Wire.MaxPacket);
            var signature = payload.Bytes(64);
            payload.End();
            using var reader = new Wire(plain);
            var sender = new DHTPeer(reader.Bytes(1200));
            var requestId = reader.Bytes(16);
            var timestamp = reader.Long();
            var body = reader.Bytes(Wire.MaxPacket);
            reader.End();
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (requestId.Length != 16 || timestamp < now - 120 || timestamp > now + 120)
            {
                throw new InvalidDataException("Invalid request identity or timestamp.");
            }
            using var signed = new Wire();
            signed.Put(header.Header.Span);
            signed.Put(plain.Span);
            if (!Crypto.Verify(sender.SigningKey, signed.WrittenMemory, signature))
            {
                throw new CryptographicException("Envelope sender signature verification failed.");
            }
            return new Packet(sender, requestId, header.Kind, body);
        }
    }
}
