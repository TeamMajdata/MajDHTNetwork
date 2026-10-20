using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace MajDHTNetwork.Transport
{
    /// <summary>
    /// Answers one received envelope. A node implementation opens the envelope with <see cref="Protocol.Packet.Open"/>,
    /// executes the operation and returns the sealed response envelope, which the transport sends back unchanged.
    /// </summary>
    /// <param name="envelope">
    /// The received envelope in a pooled frame owned by the transport; it is released once the returned task completes, so
    /// nothing parsed from it may be retained without a copy.
    /// </param>
    /// <param name="transport">The transport the envelope arrived on.</param>
    /// <param name="source">The observed socket source endpoint, already validated by the UDP cookie exchange for datagrams.</param>
    /// <param name="cancellationToken">The bounded handler lifetime.</param>
    /// <returns>The sealed response envelope; a faulted task drops the request without answering.</returns>
    public delegate Task<ReadOnlyMemory<byte>> DHTEnvelopeHandler(ReadOnlyMemory<byte> envelope, DHTTransport transport, IPEndPoint source,
        CancellationToken cancellationToken);
}
