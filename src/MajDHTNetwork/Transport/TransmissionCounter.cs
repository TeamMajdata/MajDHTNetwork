#nullable enable

namespace MajDHTNetwork.Transport
{
    /// <summary>Counts the request transmissions of one exchange and how many of them received no response.</summary>
    /// <remarks>An exchange updates its counter sequentially; read it only after the exchange task has completed.</remarks>
    internal sealed class TransmissionCounter
    {
        /// <summary>Gets the number of completed transmissions, answered or not.</summary>
        internal int Sent { get; private set; }
        /// <summary>Gets the number of transmissions that received no response before their attempt timeout.</summary>
        internal int Lost { get; private set; }

        /// <summary>Records an answered transmission.</summary>
        internal void Delivered()
        {
            Sent++;
        }

        /// <summary>Records a transmission that timed out or whose connection failed.</summary>
        internal void Dropped()
        {
            Sent++;
            Lost++;
        }
    }
}
