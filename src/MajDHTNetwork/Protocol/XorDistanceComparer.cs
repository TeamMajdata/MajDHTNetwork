using System.Collections.Generic;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Orders contacts by XOR distance to one target using their cached digests.</summary>
    internal sealed class XorDistanceComparer : IComparer<DHTPeer>
    {
        /// <summary>The target digest reused for every comparison.</summary>
        private readonly byte[] _target;

        /// <summary>Parses a target once for an entire sort.</summary>
        /// <param name="target">The canonical target.</param>
        internal XorDistanceComparer(string target)
        {
            _target = Crypto.ParseHash(target);
        }

        /// <summary>Sorts a caller-owned candidate list without parsing each peer ID again.</summary>
        /// <param name="peers">The candidate list.</param>
        /// <param name="target">The routing target.</param>
        internal static void Sort(List<DHTPeer> peers, string target)
        {
            peers.Sort(new XorDistanceComparer(target));
        }

        /// <inheritdoc />
        public int Compare(DHTPeer? left, DHTPeer? right)
        {
            if (ReferenceEquals(left, right))
            {
                return 0;
            }
            if (left == null)
            {
                return -1;
            }
            if (right == null)
            {
                return 1;
            }
            var a = left.NodeHash;
            var b = right.NodeHash;
            for (var i = 0; i < _target.Length; i++)
            {
                var order = (a[i] ^ _target[i]).CompareTo(b[i] ^ _target[i]);
                if (order != 0)
                {
                    return order;
                }
            }
            return 0;
        }
    }
}
