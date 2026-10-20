using System;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>
    /// Lets an application make signed content available on demand when a peer requests a block that this node does not
    /// serve yet, for example a pull-through replica that fetches the file from its origin. Implementations must be
    /// thread-safe and should coalesce concurrent requests for the same content.
    /// </summary>
    public interface IDHTContentFallback
    {
        /// <summary>
        /// Tries to register the requested content locally, typically through
        /// <see cref="MajDHTNode.ImportContentAsync"/> or <see cref="MajDHTNode.DownloadAsync(DHTRecord, System.IO.Stream, string, CancellationToken)"/>.
        /// The node serves the block afterwards when the content geometry is registered; otherwise the peer receives an
        /// error and fails over to other providers.
        /// </summary>
        /// <param name="record">The publisher-signed, signature-verified manifest named by the block request.</param>
        /// <param name="cancellationToken">The bounded lifetime of the incoming request; work may continue after it ends.</param>
        /// <returns>Whether the content was made available locally within the request lifetime.</returns>
        /// <exception cref="OperationCanceledException">The request lifetime ended.</exception>
        ValueTask<bool> TryAcquireAsync(DHTRecord record, CancellationToken cancellationToken);
    }
}
