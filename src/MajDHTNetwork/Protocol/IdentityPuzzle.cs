using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// Evaluates the static, memory-hard identity puzzle: the work of an identity is the number of leading zero bits of
    /// Argon2id over its node digest. Because the puzzle has no separate nonce, every candidate key costs one evaluation, so
    /// grinding an identifier towards a chosen position multiplies the cost instead of adding to it.
    /// </summary>
    public static class IdentityPuzzle
    {
        /// <summary>The Argon2id memory cost in KiB, which limits the advantage of massively parallel hardware.</summary>
        public const int MemoryKiB = 1024;
        /// <summary>The Argon2id iteration count.</summary>
        public const int Iterations = 1;
        /// <summary>The maximum process-wide evaluations of uncached identities per second; excess identities count as zero work.</summary>
        public const int EvaluationsPerSecond = 128;
        /// <summary>The maximum cached identities.</summary>
        private const int CacheCapacity = 16384;
        /// <summary>The domain-separating Argon2id salt.</summary>
        private static readonly byte[] s_salt = Encoding.ASCII.GetBytes("MajDHT/1/identity-work");
        /// <summary>Protects the cache and the evaluation budget.</summary>
        private static readonly object s_gate = new object();
        /// <summary>The cached work of recently evaluated node digests, keyed by node identifier.</summary>
        private static readonly Dictionary<string, int> s_cache = new Dictionary<string, int>(StringComparer.Ordinal);
        /// <summary>The cached identifiers in insertion order, for eviction.</summary>
        private static readonly Queue<string> s_order = new Queue<string>();
        /// <summary>Measures the evaluation budget window.</summary>
        private static readonly Stopwatch s_clock = Stopwatch.StartNew();
        /// <summary>The start of the current one-second budget window, in stopwatch ticks.</summary>
        private static long s_windowStart;
        /// <summary>The uncached evaluations performed in the current window.</summary>
        private static int s_windowCount;

        /// <summary>Computes the work of a node digest without caching or rate limiting.</summary>
        /// <param name="nodeHash">The 32-byte node digest.</param>
        /// <returns>The number of leading zero bits of the Argon2id output.</returns>
        public static int Evaluate(ReadOnlySpan<byte> nodeHash)
        {
            var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
                .WithVersion(Argon2Parameters.Version13)
                .WithMemoryAsKB(MemoryKiB)
                .WithIterations(Iterations)
                .WithParallelism(1)
                .WithSalt(s_salt)
                .Build();
            var generator = new Argon2BytesGenerator();
            generator.Init(parameters);
            var output = new byte[32];
            generator.GenerateBytes(nodeHash.ToArray(), output);
            return LeadingZeroBits(output);
        }

        /// <summary>
        /// Gets the work of a remote identity from the cache, evaluating it within the process-wide budget when needed.
        /// </summary>
        /// <param name="nodeId">The node identifier used as the cache key.</param>
        /// <param name="nodeHash">The 32-byte node digest.</param>
        /// <returns>The work, or zero when the identity is uncached and the evaluation budget of this second is spent.</returns>
        public static int Work(string nodeId, ReadOnlySpan<byte> nodeHash)
        {
            lock (s_gate)
            {
                if (s_cache.TryGetValue(nodeId, out var cached))
                {
                    return cached;
                }
                var now = s_clock.ElapsedTicks;
                if (now - s_windowStart >= Stopwatch.Frequency)
                {
                    s_windowStart = now;
                    s_windowCount = 0;
                }
                if (s_windowCount >= EvaluationsPerSecond)
                {
                    // A flood of fresh identities cannot exhaust the CPU; the identity is evaluated again on a later contact.
                    return 0;
                }
                s_windowCount++;
            }
            var work = Evaluate(nodeHash);
            lock (s_gate)
            {
                if (!s_cache.ContainsKey(nodeId))
                {
                    if (s_cache.Count >= CacheCapacity)
                    {
                        s_cache.Remove(s_order.Dequeue());
                    }
                    s_cache.Add(nodeId, work);
                    s_order.Enqueue(nodeId);
                }
            }
            return work;
        }

        /// <summary>Records the known work of an identity, for example one this process generated.</summary>
        /// <param name="nodeId">The node identifier.</param>
        /// <param name="work">The evaluated work.</param>
        public static void Remember(string nodeId, int work)
        {
            lock (s_gate)
            {
                if (s_cache.ContainsKey(nodeId))
                {
                    return;
                }
                if (s_cache.Count >= CacheCapacity)
                {
                    s_cache.Remove(s_order.Dequeue());
                }
                s_cache.Add(nodeId, work);
                s_order.Enqueue(nodeId);
            }
        }

        /// <summary>Searches random identity seeds in parallel until one reaches a difficulty.</summary>
        /// <param name="bits">The required leading zero bits.</param>
        /// <param name="cancellationToken">Cancels the search.</param>
        /// <returns>The 32-byte seed of a qualifying identity and its work.</returns>
        /// <exception cref="OperationCanceledException">The search was cancelled.</exception>
        public static (byte[] Seed, int Work) Search(int bits, CancellationToken cancellationToken)
        {
            if (bits <= 0)
            {
                return (Crypto.Random(32), 0);
            }
            var found = new TaskCompletionSource<(byte[], int)>(TaskCreationOptions.RunContinuationsAsynchronously);
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var workers = new Task[Math.Max(1, Environment.ProcessorCount)];
            for (var index = 0; index < workers.Length; index++)
            {
                workers[index] = Task.Run(() =>
                {
                    while (!stop.IsCancellationRequested)
                    {
                        var seed = Crypto.Random(32);
                        var publicKey = new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();
                        var work = Evaluate(Crypto.Hash(publicKey));
                        if (work >= bits && found.TrySetResult((seed, work)))
                        {
                            stop.Cancel();
                        }
                    }
                });
            }
            try
            {
                Task.WaitAll(workers);
            }
            catch (AggregateException exception) when (exception.InnerException is OperationCanceledException)
            {
            }
            cancellationToken.ThrowIfCancellationRequested();
            return found.Task.Result;
        }

        /// <summary>Counts the leading zero bits of a digest.</summary>
        /// <param name="digest">The digest.</param>
        /// <returns>The number of leading zero bits.</returns>
        private static int LeadingZeroBits(ReadOnlySpan<byte> digest)
        {
            var bits = 0;
            foreach (var value in digest)
            {
                if (value == 0)
                {
                    bits += 8;
                    continue;
                }
                var mask = 0x80;
                while ((value & mask) == 0)
                {
                    bits++;
                    mask >>= 1;
                }
                break;
            }
            return bits;
        }
    }
}
