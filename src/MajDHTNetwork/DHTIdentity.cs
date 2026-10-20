using System;
using System.Threading;
using MajDHTNetwork.Protocol;
using Org.BouncyCastle.Crypto.Parameters;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Owns stable Ed25519 signing and domain-separated X25519 agreement keys.</summary>
    public sealed class DHTIdentity
    {
        /// <summary>The private signing seed, never serialized into network messages.</summary>
        private readonly byte[] _seed;
        /// <summary>The cached signing key, avoiding reconstruction for every message.</summary>
        private readonly Ed25519PrivateKeyParameters _signingKey;
        /// <summary>The signing public key.</summary>
        private readonly byte[] _publicKey;
        /// <summary>The last contact sequence issued by this process for this identity.</summary>
        private long _lastSequence;
        /// <summary>Protects the cached proof of work.</summary>
        private readonly object _workGate = new object();
        /// <summary>The cached proof-of-work nonce, or minus one before any work was computed.</summary>
        private long _workNonce = -1;
        /// <summary>The proof-of-work bits achieved by the cached nonce.</summary>
        private int _workBits;
        /// <summary>The agreement private key.</summary>
        internal X25519PrivateKeyParameters Agreement { get; }
        /// <summary>Gets the SHA-256 signing-key fingerprint used as the node identifier.</summary>
        public string NodeId { get; }
        /// <summary>Gets a non-allocating read-only view of the signing public key.</summary>
        public ReadOnlySpan<byte> PublicKey => _publicKey;

        /// <summary>Creates a new random identity.</summary>
        public DHTIdentity() : this(Crypto.Random(32))
        {
        }

        /// <summary>Restores an identity from a caller-managed secret seed.</summary>
        /// <param name="seed">Exactly 32 private bytes; persist securely outside the library.</param>
        /// <exception cref="ArgumentException">The seed length is invalid.</exception>
        public DHTIdentity(ReadOnlySpan<byte> seed)
        {
            if (seed.Length != 32)
            {
                throw new ArgumentException("An identity seed must contain 32 bytes.", nameof(seed));
            }
            _seed = seed.ToArray();
            _signingKey = new Ed25519PrivateKeyParameters(_seed, 0);
            _publicKey = _signingKey.GeneratePublicKey().GetEncoded();
            Agreement = Crypto.AgreementKey(_seed);
            NodeId = Crypto.Hex(Crypto.Hash(_publicKey));
        }

        /// <summary>Exports a copy of the private seed for secure caller-managed persistence.</summary>
        /// <returns>The 32-byte secret seed; never publish it as an invitation.</returns>
        public byte[] ExportSeed()
        {
            return (byte[])_seed.Clone();
        }

        /// <summary>Copies the private seed into caller-owned storage without allocating.</summary>
        /// <param name="destination">At least 32 writable bytes; protect these secret bytes after export.</param>
        /// <exception cref="ArgumentException">The destination is too short.</exception>
        public void ExportSeed(Span<byte> destination)
        {
            _seed.AsSpan().CopyTo(destination);
        }

        /// <summary>Signs canonical protocol bytes.</summary>
        /// <param name="bytes">The canonical message.</param>
        /// <returns>The Ed25519 signature.</returns>
        internal byte[] Sign(ReadOnlyMemory<byte> bytes)
        {
            return Crypto.Sign(_signingKey, bytes);
        }

        /// <summary>
        /// Computes, once per process and difficulty, a nonce proving that this identity cost work to create; contacts carry it
        /// so that minting many identities is expensive.
        /// </summary>
        /// <param name="bits">The required number of leading zero bits, from 0 to 32; each extra bit doubles the expected cost.</param>
        /// <returns>A nonce whose proof of work reaches at least <paramref name="bits"/>.</returns>
        /// <exception cref="ArgumentOutOfRangeException">The difficulty is outside 0 to 32.</exception>
        public long ComputeProofOfWork(int bits)
        {
            if (bits < 0 || bits > 32)
            {
                throw new ArgumentOutOfRangeException(nameof(bits));
            }
            lock (_workGate)
            {
                if (_workNonce < 0 || _workBits < bits)
                {
                    var nodeHash = Crypto.ParseHash(NodeId);
                    _workNonce = Crypto.FindIdentityWork(nodeHash, bits);
                    _workBits = Crypto.IdentityWork(nodeHash, _workNonce);
                }
                return _workNonce;
            }
        }

        /// <summary>Issues a strictly increasing contact sequence based on the current Unix time in milliseconds.</summary>
        /// <returns>A sequence larger than every sequence previously issued for this instance.</returns>
        internal long NextSequence()
        {
            while (true)
            {
                var last = Interlocked.Read(ref _lastSequence);
                var next = Math.Max(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), last + 1);
                if (Interlocked.CompareExchange(ref _lastSequence, next, last) == last)
                {
                    return next;
                }
            }
        }
    }
}
