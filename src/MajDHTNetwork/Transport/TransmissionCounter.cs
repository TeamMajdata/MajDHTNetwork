#nullable enable

namespace MajDHTNetwork.Transport
{
    /// <summary>Counts the request transmissions of one exchange and how many of them received no response.</summary>
    /// <remarks>An exchange updates its counter sequentially; read it only after the exchange task has completed.</remarks>
    public sealed class TransmissionCounter
    {
        /// <summary>Gets the number of completed transmissions, answered or not.</summary>
        public int Sent { get; private set; }
        /// <summary>Gets the number of transmissions that received no response before their attempt timeout.</summary>
        public int Lost { get; private set; }

        /// <summary>Records an answered transmission.</summary>
        public void Delivered()
        {
            Sent++;
        }

        /// <summary>Records a transmission that timed out or whose connection failed.</summary>
        public void Dropped()
        {
            Sent++;
            Lost++;
        }
    }
}
