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
        /// <summary>The cached node digest, so envelope recipients compare 32 bytes instead of strings.</summary>
        private readonly byte[] _nodeHash;
        /// <summary>The private X25519 scalar derived from the seed.</summary>
        private readonly byte[] _agreementScalar;
        /// <summary>The cached X25519 public key advertised in signed contacts.</summary>
        private readonly byte[] _agreementPublicKey;
        /// <summary>The last contact sequence issued by this process for this identity.</summary>
        private long _lastSequence;
        /// <summary>Protects the cached identity work.</summary>
        private readonly object _workGate = new object();
        /// <summary>The cached identity work, or minus one before it was evaluated.</summary>
        private int _work = -1;
        /// <summary>Gets the private agreement scalar for envelope decryption; it is read in place and must never be modified or exposed.</summary>
        internal byte[] AgreementScalar => _agreementScalar;
        /// <summary>Gets a borrowed view of the agreement public key.</summary>
        public ReadOnlySpan<byte> AgreementPublicKey => _agreementPublicKey;
        /// <summary>Gets a borrowed view of the node digest that <see cref="NodeId"/> formats.</summary>
        public ReadOnlySpan<byte> NodeHash => _nodeHash;
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
            _agreementScalar = Crypto.AgreementScalar(_seed);
            _agreementPublicKey = new byte[Crypto.AgreementKeyLength];
            Crypto.AgreementPublicKey(_agreementScalar, _agreementPublicKey);
            _nodeHash = Crypto.Hash(_publicKey);
            NodeId = Crypto.Hex(_nodeHash);
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
        public byte[] Sign(ReadOnlyMemory<byte> bytes)
        {
            return Crypto.Sign(_signingKey, bytes);
        }

        /// <summary>Signs canonical protocol bytes directly into array-backed destination memory.</summary>
        /// <param name="bytes">The canonical message.</param>
        /// <param name="destination">Exactly 64 writable bytes.</param>
        /// <exception cref="ArgumentException">The destination is not 64 bytes long.</exception>
        public void SignTo(ReadOnlyMemory<byte> bytes, Memory<byte> destination)
        {
            Crypto.SignTo(_signingKey, bytes, destination);
        }

        /// <summary>
        /// Gets the identity work of this identity: the leading zero bits of Argon2id over its node digest. It is a property of
        /// the seed, so it is computed once per process and survives restarts together with the persisted seed.
        /// </summary>
        public int IdentityWork
        {
            get
            {
                lock (_workGate)
                {
                    if (_work < 0)
                    {
                        _work = IdentityPuzzle.Evaluate(_nodeHash);
                        IdentityPuzzle.Remember(NodeId, _work);
                    }
                    return _work;
                }
            }
        }

        /// <summary>
        /// Creates a new random identity whose identity work reaches a difficulty, searching seeds on every processor. Each
        /// extra bit doubles the expected cost; at the default of 12 bits expect seconds to tens of seconds. Persist the
        /// seed with <see cref="ExportSeed()"/> so the cost is paid only once.
        /// </summary>
        /// <param name="workBits">The required identity work, from 0 to 20; normally <see cref="DHTNodeOptions.IdentityWorkBits"/>.</param>
        /// <param name="cancellationToken">Cancels the search.</param>
        /// <returns>The qualifying identity.</returns>
        /// <exception cref="ArgumentOutOfRangeException">The difficulty is outside 0 to 20.</exception>
        /// <exception cref="OperationCanceledException">The search was cancelled.</exception>
        public static DHTIdentity Create(int workBits, CancellationToken cancellationToken = default)
        {
            if (workBits < 0 || workBits > 20)
            {
                throw new ArgumentOutOfRangeException(nameof(workBits));
            }
            var (seed, work) = IdentityPuzzle.Search(workBits, cancellationToken);
            var identity = new DHTIdentity(seed);
            if (workBits > 0)
            {
                lock (identity._workGate)
                {
                    identity._work = work;
                }
                IdentityPuzzle.Remember(identity.NodeId, work);
            }
            return identity;
        }

        /// <summary>Issues a strictly increasing contact sequence based on the current Unix time in milliseconds.</summary>
        /// <returns>A sequence larger than every sequence previously issued for this instance.</returns>
        public long NextSequence()
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
