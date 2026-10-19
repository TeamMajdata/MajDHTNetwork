#nullable enable

using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Runs allocation measurements without concurrent tests or background node work.</summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class AllocationCollection
    {
        /// <summary>The runner collection that exclusively owns managed allocation measurements.</summary>
        public const string Name = "Exclusive allocation measurements";
    }
}
