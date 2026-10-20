#nullable enable

using System.Runtime.CompilerServices;

namespace MajDHTNetwork.Tests
{
    /// <summary>Configures library defaults for the test host before any test runs.</summary>
    internal static class TestDefaults
    {
        /// <summary>
        /// Disables the default identity proof of work, which would otherwise be computed for every short-lived test node;
        /// proof-of-work behavior is covered by tests that set <see cref="DHTNodeOptions.IdentityWorkBits"/> explicitly.
        /// </summary>
        [ModuleInitializer]
        internal static void Initialize()
        {
            DHTNodeOptions.DefaultIdentityWorkBits = 0;
        }
    }
}
