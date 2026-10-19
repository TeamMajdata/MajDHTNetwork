using System;
using System.Threading;
using System.Threading.Tasks;

#nullable enable

namespace MajDHTNetwork
{
    /// <summary>Stores content-addressed raw blocks; implementations must support concurrent access.</summary>
    public interface IDHTContentStore
    {
        /// <summary>Copies a verified block into application-managed storage.</summary>
        /// <param name="blockHash">The domain-separated SHA-256 leaf identifier.</param>
        /// <param name="content">The raw block; copy it before returning if retaining it.</param>
        /// <param name="cancellationToken">Cancels storage work.</param>
        /// <returns>Completion of the block write.</returns>
        /// <exception cref="ArgumentException">The hash, content length or content digest is invalid.</exception>
        /// <exception cref="System.IO.IOException">The backend cannot store the content.</exception>
        /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
        ValueTask PutAsync(string blockHash, ReadOnlyMemory<byte> content, CancellationToken cancellationToken);

        /// <summary>Reads a block without accessing unrelated file locations.</summary>
        /// <param name="blockHash">The domain-separated SHA-256 leaf identifier.</param>
        /// <param name="cancellationToken">Cancels storage work.</param>
        /// <returns>A stable block snapshot, or null if the block is unavailable.</returns>
        /// <exception cref="System.IO.IOException">The backend cannot read the content.</exception>
        /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
        ValueTask<ReadOnlyMemory<byte>?> GetAsync(string blockHash, CancellationToken cancellationToken);
    }
}
