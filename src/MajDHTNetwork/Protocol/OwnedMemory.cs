using System;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>
    /// A read-only view of received bytes together with the pooled frame they borrow, which disposing the view releases.
    /// </summary>
    /// <remarks>
    /// Transports hand every received frame to its consumer as an owned view, and the consumer releases the frame once it has
    /// copied or finished reading whatever it keeps. A view may instead borrow stable GC-owned memory, such as a block served
    /// from the local store, in which case disposing it releases nothing. Narrowing a view transfers the frame to the
    /// narrower view, so the wider view must not be disposed afterwards. Releasing is idempotent, but a released view must
    /// not be read: its storage is cleared and reused for later frames.
    /// </remarks>
    internal readonly struct OwnedMemory : IDisposable
    {
        /// <summary>The pooled frame to release, or null for GC-owned memory.</summary>
        private readonly PooledBuffer? _frame;

        /// <summary>Gets the borrowed bytes, valid until the view is disposed.</summary>
        internal ReadOnlyMemory<byte> Bytes { get; }
        /// <summary>Gets whether the bytes borrow a pooled frame that disposal releases.</summary>
        internal bool IsPooled => _frame != null;

        /// <summary>Views a complete pooled frame.</summary>
        /// <param name="frame">The frame, released when the view is disposed.</param>
        internal OwnedMemory(PooledBuffer frame)
            : this(frame.Memory, frame)
        {
        }

        /// <summary>Views stable GC-owned memory that no disposal releases.</summary>
        /// <param name="bytes">The GC-owned bytes.</param>
        internal OwnedMemory(ReadOnlyMemory<byte> bytes)
            : this(bytes, null)
        {
        }

        /// <summary>Views bytes inside an optional pooled frame.</summary>
        /// <param name="bytes">The bytes to view.</param>
        /// <param name="frame">The frame the bytes lie in, or null for GC-owned bytes.</param>
        private OwnedMemory(ReadOnlyMemory<byte> bytes, PooledBuffer? frame)
        {
            Bytes = bytes;
            _frame = frame;
        }

        /// <summary>Transfers the frame to a view of some of its bytes, such as one decoded field.</summary>
        /// <param name="bytes">The bytes to view, which must lie inside this view's frame or GC-owned memory.</param>
        /// <returns>The narrower view, which now releases the frame; this view must not be disposed afterwards.</returns>
        internal OwnedMemory Narrow(ReadOnlyMemory<byte> bytes)
        {
            return new OwnedMemory(bytes, _frame);
        }

        /// <summary>Gets bytes that stay valid after the view is released: GC-owned bytes as they are, or a copy of a pooled frame.</summary>
        /// <returns>GC-owned memory that never aliases a pooled frame.</returns>
        internal ReadOnlyMemory<byte> Preserve()
        {
            return _frame == null ? Bytes : Bytes.ToArray();
        }

        /// <summary>Releases the pooled frame, if any, exactly once.</summary>
        public void Dispose()
        {
            _frame?.Dispose();
        }
    }
}
