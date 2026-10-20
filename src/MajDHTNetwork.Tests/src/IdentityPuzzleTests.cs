#nullable enable

using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Runs tests that consume the process-wide identity evaluation budget without concurrent tests.</summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class IdentityPuzzleCollection
    {
        /// <summary>The runner collection that exclusively owns the identity evaluation budget.</summary>
        public const string Name = "Exclusive identity puzzle budget";
    }

    /// <summary>Checks that floods of fresh identities cannot exhaust the CPU through identity work evaluation.</summary>
    [Collection(IdentityPuzzleCollection.Name)]
    [Trait("Category", "Security")]
    public sealed class IdentityPuzzleTests
    {
        /// <summary>Reports zero work for uncached identities once the per-second evaluation budget is spent.</summary>
        [Fact]
        public void UncachedEvaluationsAreRateLimited()
        {
            var count = IdentityPuzzle.EvaluationsPerSecond * 3;
            var budgetExhausted = 0;
            var evaluated = 0;
            Parallel.For(0, count, index =>
            {
                var digest = Crypto.Random(32);
                var work = IdentityPuzzle.Work(Crypto.Hex(digest), digest);
                if (work == 0 && IdentityPuzzle.Evaluate(digest) != 0)
                {
                    Interlocked.Increment(ref budgetExhausted);
                }
                Interlocked.Increment(ref evaluated);
            });
            Assert.Equal(count, evaluated);
            // Without the budget, zero work would only be reported for digests whose real work is zero.
            Assert.True(budgetExhausted > 0, "Evaluations beyond the per-second budget must not be computed.");
        }
    }
}
