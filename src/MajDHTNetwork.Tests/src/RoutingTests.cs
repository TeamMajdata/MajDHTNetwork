#nullable enable

using System;
using System.Collections.Generic;
using System.Net;
using MajDHTNetwork.Protocol;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Verifies sparse routing removal and canonical XOR distance ordering.</summary>
    public sealed class RoutingTests
    {
        /// <summary>Compares production pooled sorting with an independent XOR implementation.</summary>
        [Fact]
        public void ClosestPeersUseCanonicalXorOrderAndRemovalUpdatesCount()
        {
            var identity = new DHTIdentity();
            var routing = new RoutingTable(identity.NodeId, 2);
            var all = new List<DHTPeer>();
            for (var i = 0; i < 20; i++)
            {
                var peer = DHTPeer.Create(new DHTIdentity(), IPAddress.Loopback, 23000 + i, 0, DHTCapabilities.Download);
                all.Add(peer);
                routing.Observe(peer);
            }
            var target = Crypto.Hex(Crypto.Random(32));
            var nearest = routing.Closest(target, 512);
            Assert.NotEmpty(nearest);
            var expected = new List<DHTPeer>(nearest);
            expected.Sort((a, b) => string.CompareOrdinal(Xor(a.NodeId, target), Xor(b.NodeId, target)));
            for (var i = 0; i < nearest.Count; i++)
            {
                Assert.True(nearest[i].NodeId == expected[i].NodeId, "Pooled XOR sorting differs from canonical distance ordering.");
            }
            if (nearest.Count > 0)
            {
                routing.Remove(nearest[0].NodeId);
                Assert.True(routing.Closest(target, 512).Count == nearest.Count - 1, "Sparse routing removal must update its count.");
            }
        }

        /// <summary>Computes a simple independent XOR ordering for the routing regression.</summary>
        /// <param name="a">The first canonical identifier.</param>
        /// <param name="b">The second canonical identifier.</param>
        /// <returns>The XOR identifier.</returns>
        private static string Xor(string a, string b)
        {
            var left = Convert.FromHexString(a);
            var right = Convert.FromHexString(b);
            for (var i = 0; i < left.Length; i++)
            {
                left[i] ^= right[i];
            }
            return Convert.ToHexString(left);
        }
    }
}
