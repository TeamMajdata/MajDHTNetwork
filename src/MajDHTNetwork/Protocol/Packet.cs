using System;
using System.IO;
using System.Security.Cryptography;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Identifies a signed encrypted request operation.</summary>
    public enum Operation : byte
    {
        /// <summary>Returns the current authenticated contact.</summary>
        Ping = 1,
        /// <summary>Looks up nodes, records or providers.</summary>
        Find = 2,
        /// <summary>Stores a signed record and authenticated provider claim.</summary>
        Store = 3,
        /// <summary>Returns an authenticated content block.</summary>
        Block = 4,
        /// <summary>Opens a forwarding session, relays one opaque request through a Forwarder or delivers one to its destination.</summary>
        Forward = 5,
        /// <summary>Registers observed endpoints, coordinates an authenticated introduction or arranges a dial-back.</summary>
        Traversal = 6,
        /// <summary>Confirms an introduced direct path.</summary>
        Punch = 7,
        /// <summary>Learns an unknown endpoint's signed contact; the request is signed but not encrypted.</summary>
        Hello = 8,
        /// <summary>Delivers an independent dial-back that proves an observed endpoint is reachable.</summary>
        Probe = 9
    }

    /// <summary>An immutable request or response view, encrypted to its final recipient.</summary>
    /// <remarks>Copies share their memory. Borrowed constructor buffers must remain stable until encryption finishes.</remarks>
    public readonly struct Packet
    {
        /// <summary>The Ed25519 signature length.</summary>
        private const int SignatureLength = 64;
        /// <summary>The correlation identifier length.</summary>
        public const int RequestIdLength = 16;
        /// <summary>The sender contact, or null for an uninitialized packet.</summary>
        private readonly DHTContact? _sender;

        /// <summary>Gets the authenticated sender contact.</summary>
        /// <exception cref="InvalidOperationException">The packet is uninitialized.</exception>
        public DHTContact Sender
        {
            get
            {
                return _sender ?? throw new InvalidOperationException("An uninitialized packet has no sender.");
            }
        }
        /// <summary>Gets the random 128-bit correlation identifier.</summary>
        public ReadOnlyMemory<byte> RequestId { get; }
        /// <summary>Gets the operation with the high bit set for responses.</summary>
        public byte Kind { get; }
        /// <summary>Gets the decrypted operation body.</summary>
        public ReadOnlyMemory<byte> Body { get; }

        /// <summary>Creates an immutable view of borrowed message memory before encryption.</summary>
        /// <param name="sender">The sender contact.</param>
        /// <param name="requestId">The borrowed 16-byte random correlation identifier.</param>
        /// <param name="kind">The operation and response bit.</param>
        /// <param name="body">The borrowed operation body.</param>
        /// <exception cref="ArgumentNullException">The sender is null.</exception>
        /// <exception cref="ArgumentException">The correlation identifier is not 16 bytes long.</exception>
        public Packet(DHTContact sender, ReadOnlyMemory<byte> requestId, byte kind, ReadOnlyMemory<byte> body)
        {
            if (requestId.Length != RequestIdLength)
            {
                throw new ArgumentException("A packet correlation identifier must contain 16 bytes.", nameof(requestId));
            }
            _sender = sender ?? throw new ArgumentNullException(nameof(sender));
            RequestId = requestId;
            Kind = kind;
            Body = body;
        }

        /// <summary>Creates an immutable view of borrowed message memory before encryption, sent under a peer's contact.</summary>
        /// <param name="sender">The sender, whose contact becomes the packet's sender.</param>
        /// <param name="requestId">The borrowed 16-byte random correlation identifier.</param>
        /// <param name="kind">The operation and response bit.</param>
        /// <param name="body">The borrowed operation body.</param>
        /// <exception cref="ArgumentNullException">The sender is null.</exception>
        /// <exception cref="ArgumentException">The correlation identifier is not 16 bytes long.</exception>
        public Packet(DHTPeer sender, ReadOnlyMemory<byte> requestId, byte kind, ReadOnlyMemory<byte> body)
            : this((sender ?? throw new ArgumentNullException(nameof(sender))).Contact, requestId, kind, body)
        {
        }

        /// <summary>Encrypts and signs a fresh envelope to a peer using an ephemeral X25519 sender key.</summary>
        /// <param name="identity">The sending identity.</param>
        /// <param name="recipient">The final recipient, whose contact seals the envelope.</param>
        /// <returns>The bounded encrypted envelope.</returns>
        /// <exception cref="ArgumentNullException">The recipient is null.</exception>
        /// <exception cref="InvalidDataException">The encoded packet exceeds protocol limits.</exception>
        /// <exception cref="InvalidOperationException">The packet is uninitialized.</exception>
        /// <exception cref="CryptographicException">The cryptographic provider cannot seal the packet.</exception>
        public byte[] Seal(DHTIdentity identity, DHTPeer recipient)
        {
            return Seal(identity, (recipient ?? throw new ArgumentNullException(nameof(recipient))).Contact);
        }

        /// <summary>Encrypts and signs a fresh envelope using an ephemeral X25519 sender key.</summary>
        /// <param name="identity">The sending identity.</param>
        /// <param name="recipient">The final recipient contact.</param>
        /// <returns>The bounded encrypted envelope.</returns>
        /// <exception cref="InvalidDataException">The encoded packet exceeds protocol limits.</exception>
        /// <exception cref="InvalidOperationException">The packet is uninitialized.</exception>
        /// <exception cref="CryptographicException">The cryptographic provider cannot seal the packet.</exception>
        public byte[] Seal(DHTIdentity identity, DHTContact recipient)
        {
            using var header = new Wire();
            WriteHeader(header, recipient.NodeHash);
            header.PutLong(Crypto.AgreementKeyLength);
            // The ephemeral public key is written into the header before anything else is appended, so the reservation is valid.
            var scalar = Crypto.EphemeralAgreement(header.Allocate(Crypto.AgreementKeyLength));
            try
            {
                var nonce = WriteNonce(header);
                var headerBytes = header.WrittenMemory;
                using var signed = new Wire();
                var payload = WriteSignedPayload(signed, identity, headerBytes);
                using var outer = new Wire();
                outer.Put(headerBytes.Span);
                Crypto.EncryptTo(outer, scalar, recipient.AgreementKey, headerBytes, nonce, payload);
                return Finish(outer);
            }
            finally
            {
                Crypto.ReturnSecret(scalar);
            }
        }

        /// <summary>Signs a Hello request without encryption because the recipient's keys are not yet known.</summary>
        /// <param name="identity">The sending identity.</param>
        /// <returns>The bounded signed plaintext envelope.</returns>
        /// <exception cref="InvalidDataException">The packet is not a Hello request or exceeds protocol limits.</exception>
        /// <exception cref="InvalidOperationException">The packet is uninitialized.</exception>
        public byte[] SealHello(DHTIdentity identity)
        {
            if (Kind != (byte)Operation.Hello)
            {
                throw new InvalidDataException("Only Hello requests may be sent without encryption.");
            }
            using var header = new Wire();
            // The placeholder recipient is the hexadecimal form of 32 zero bytes, and the placeholder key is 32 zero bytes.
            WriteHeader(header, ProtocolTags.EmptyKey);
            header.Put(ProtocolTags.EmptyKey);
            WriteNonce(header);
            using var signed = new Wire();
            var payload = WriteSignedPayload(signed, identity, header.WrittenMemory);
            using var outer = new Wire();
            outer.Put(header.WrittenSpan);
            outer.Put(payload.Span);
            return Finish(outer);
        }

        /// <summary>Writes the canonical envelope header up to the recipient identifier.</summary>
        /// <param name="header">The destination encoder.</param>
        /// <param name="recipientHash">The final recipient's node digest, formatted as its identifier.</param>
        private void WriteHeader(Wire header, ReadOnlySpan<byte> recipientHash)
        {
            header.Put(ProtocolTags.Envelope);
            header.PutByte(Kind);
            header.PutHex(recipientHash);
        }

        /// <summary>Appends a random nonce as the last header field.</summary>
        /// <param name="header">The header encoder.</param>
        /// <returns>The borrowed nonce, valid while the header is not written further.</returns>
        private static ReadOnlyMemory<byte> WriteNonce(Wire header)
        {
            header.PutLong(Crypto.NonceLength);
            Crypto.Fill(header.Allocate(Crypto.NonceLength).Span);
            var written = header.WrittenMemory;
            return written.Slice(written.Length - Crypto.NonceLength);
        }

        /// <summary>
        /// Writes the signed message into one pooled writer: the header and plaintext fields form the signature input, and the
        /// plaintext fields followed by the signature form the payload that is encrypted, or sent as is for Hello.
        /// </summary>
        /// <param name="signed">The destination encoder, which must be empty.</param>
        /// <param name="identity">The sending identity.</param>
        /// <param name="header">The canonical header covered by the signature.</param>
        /// <returns>The borrowed payload view, valid until the writer is disposed.</returns>
        private ReadOnlyMemory<byte> WriteSignedPayload(Wire signed, DHTIdentity identity, ReadOnlyMemory<byte> header)
        {
            signed.Put(header.Span);
            var start = signed.Length;
            var sender = Sender.Encoded;
            signed.PutLong(8 + sender.Length + 8 + RequestId.Length + 8 + 8 + Body.Length);
            signed.Put(sender);
            signed.Put(RequestId.Span);
            signed.PutLong(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            signed.Put(Body.Span);
            var messageLength = signed.Length;
            signed.PutLong(SignatureLength);
            // Reserve first: growing the writer would otherwise invalidate the message view.
            var signature = signed.Allocate(SignatureLength);
            identity.SignTo(signed.WrittenMemory.Slice(0, messageLength), signature);
            return signed.WrittenMemory.Slice(start);
        }

        /// <summary>Copies a complete envelope and enforces the datagram budget.</summary>
        /// <param name="outer">The completed envelope encoder.</param>
        /// <returns>The owned envelope bytes.</returns>
        /// <exception cref="InvalidDataException">The envelope exceeds the datagram budget.</exception>
        private static byte[] Finish(Wire outer)
        {
            var result = outer.ToArray();
            if (result.Length > Wire.MaxPacket)
            {
                throw new InvalidDataException("Encrypted packet exceeds the datagram budget.");
            }
            return result;
        }

        /// <summary>Verifies an envelope header and obtains routing metadata without decrypting it.</summary>
        /// <param name="encoded">The encrypted packet.</param>
        /// <returns>The parsed header views.</returns>
        /// <exception cref="InvalidDataException">The envelope header is invalid.</exception>
        private static EnvelopeHeader Header(ReadOnlyMemory<byte> encoded)
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
            if (!reader.Tag(ProtocolTags.Envelope))
            {
                throw new InvalidDataException("Unsupported envelope version.");
            }
            var kind = reader.Byte();
            var recipient = reader.Bytes(Crypto.DigestLength * 2);
            var publicKey = reader.Bytes(Crypto.AgreementKeyLength);
            var nonce = reader.Bytes(Crypto.NonceLength);
            reader.End();
            if (!Crypto.IsHash(recipient.Span) || (kind & 0x7f) < (byte)Operation.Ping || (kind & 0x7f) > (byte)Operation.Probe
                || publicKey.Length != Crypto.AgreementKeyLength || nonce.Length != Crypto.NonceLength || cipher.Length < Crypto.TagLength)
            {
                throw new InvalidDataException("Invalid envelope header.");
            }
            return new EnvelopeHeader(kind, recipient, publicKey, nonce, header, cipher);
        }

        /// <summary>Allows only data requests to the declared recipient through a Forwarder.</summary>
        /// <param name="encoded">The opaque inner packet.</param>
        /// <param name="recipient">The expected final node identifier.</param>
        /// <exception cref="InvalidDataException">The packet is a response, a control operation or addressed elsewhere.</exception>
        public static void CheckForward(ReadOnlyMemory<byte> encoded, string recipient)
        {
            var header = Header(encoded);
            if (!Crypto.AsciiEquals(header.Recipient.Span, recipient) || header.Kind < (byte)Operation.Ping || header.Kind > (byte)Operation.Block)
            {
                throw new InvalidDataException("Only Ping, Find, Store and Block requests to the declared recipient may be forwarded.");
            }
        }

        /// <summary>Authenticates and decrypts a message addressed to this node, or authenticates a plaintext Hello request.</summary>
        /// <param name="identity">The receiving identity.</param>
        /// <param name="encoded">
        /// The exclusively owned envelope. Its ciphertext is decrypted in place, so the returned packet borrows this buffer,
        /// the ciphertext cannot be opened a second time, and a failed authentication leaves the ciphertext region zeroed.
        /// </param>
        /// <returns>The verified sender and plaintext operation, borrowing the envelope buffer.</returns>
        /// <exception cref="CryptographicException">Recipient, signature or ciphertext authentication failed.</exception>
        /// <exception cref="InvalidDataException">The message is malformed or outside the clock-skew window.</exception>
        public static Packet Open(DHTIdentity identity, ReadOnlyMemory<byte> encoded)
        {
            var header = Header(encoded);
            ReadOnlyMemory<byte> bytes;
            if (header.Kind == (byte)Operation.Hello)
            {
                if (!header.Recipient.Span.SequenceEqual(ProtocolTags.UnknownRecipient) || !header.PublicKey.Span.SequenceEqual(ProtocolTags.EmptyKey))
                {
                    throw new CryptographicException("A Hello request must not name a recipient key.");
                }
                bytes = header.Cipher;
            }
            else
            {
                if (!IsRecipient(header.Recipient.Span, identity))
                {
                    throw new CryptographicException("Envelope recipient mismatch.");
                }
                bytes = Crypto.DecryptInPlace(identity.AgreementScalar, header.PublicKey, header.Bytes, header.Nonce, header.Cipher);
            }
            using var payload = new Wire(bytes);
            var plain = payload.Bytes(Wire.MaxPacket);
            var signature = payload.Bytes(SignatureLength);
            payload.End();
            using var reader = new Wire(plain);
            var sender = DHTContact.Parse(reader.Bytes(DHTContact.MaxEncodedLength));
            var requestId = reader.Bytes(RequestIdLength);
            var timestamp = reader.Long();
            var body = reader.Bytes(Wire.MaxPacket);
            reader.End();
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (requestId.Length != RequestIdLength || timestamp < now - 120 || timestamp > now + 120)
            {
                throw new InvalidDataException("Invalid request identity or timestamp.");
            }
            using var signed = new Wire();
            signed.Put(header.Bytes.Span);
            signed.Put(plain.Span);
            if (!Crypto.Verify(sender.SigningKey, signed.WrittenMemory, signature))
            {
                throw new CryptographicException("Envelope sender signature verification failed.");
            }
            return new Packet(sender, requestId, header.Kind, body);
        }

        /// <summary>Checks whether a header names an identity as the final recipient, comparing digests instead of strings.</summary>
        /// <param name="recipient">The 64-digit recipient identifier from the header.</param>
        /// <param name="identity">The receiving identity.</param>
        /// <returns>Whether the identifier is the identity's node identifier.</returns>
        private static bool IsRecipient(ReadOnlySpan<byte> recipient, DHTIdentity identity)
        {
            Span<byte> digest = stackalloc byte[Crypto.DigestLength];
            Crypto.ParseHash(recipient, digest);
            return digest.SequenceEqual(identity.NodeHash);
        }

        /// <summary>The borrowed views of one parsed envelope header.</summary>
        private readonly struct EnvelopeHeader
        {
            /// <summary>Gets the operation with the response bit.</summary>
            public byte Kind { get; }
            /// <summary>Gets the 64-digit recipient identifier.</summary>
            public ReadOnlyMemory<byte> Recipient { get; }
            /// <summary>Gets the ephemeral public key, or zeros for a Hello request.</summary>
            public ReadOnlyMemory<byte> PublicKey { get; }
            /// <summary>Gets the nonce.</summary>
            public ReadOnlyMemory<byte> Nonce { get; }
            /// <summary>Gets the complete authenticated header bytes.</summary>
            public ReadOnlyMemory<byte> Bytes { get; }
            /// <summary>Gets the ciphertext, or the plaintext payload of a Hello request.</summary>
            public ReadOnlyMemory<byte> Cipher { get; }

            /// <summary>Retains the parsed views.</summary>
            /// <param name="kind">The operation with the response bit.</param>
            /// <param name="recipient">The recipient identifier.</param>
            /// <param name="publicKey">The ephemeral public key.</param>
            /// <param name="nonce">The nonce.</param>
            /// <param name="bytes">The complete header.</param>
            /// <param name="cipher">The ciphertext or Hello payload.</param>
            public EnvelopeHeader(byte kind, ReadOnlyMemory<byte> recipient, ReadOnlyMemory<byte> publicKey, ReadOnlyMemory<byte> nonce,
                ReadOnlyMemory<byte> bytes, ReadOnlyMemory<byte> cipher)
            {
                Kind = kind;
                Recipient = recipient;
                PublicKey = publicKey;
                Nonce = nonce;
                Bytes = bytes;
                Cipher = cipher;
            }
        }
    }
}
