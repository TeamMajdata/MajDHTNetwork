using System;
using System.Buffers;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Owns a bounded pooled buffer and clears its contents before returning storage.</summary>
    public sealed class PooledBuffer : IMemoryOwner<byte>
    {
        /// <summary>The rented array while ownership is active.</summary>
        private byte[]? _buffer;
        /// <summary>The requested logical length.</summary>
        private readonly int _length;

        /// <summary>Rents one buffer for a complete operation.</summary>
        /// <param name="length">The logical byte count.</param>
        public PooledBuffer(int length)
        {
            _length = length;
            _buffer = ArrayPool<byte>.Shared.Rent(length);
        }

        /// <summary>Gets the live logical memory range.</summary>
        /// <exception cref="ObjectDisposedException">The owner has been disposed.</exception>
        public Memory<byte> Memory => (_buffer ?? throw new ObjectDisposedException(nameof(PooledBuffer))).AsMemory(0, _length);

        /// <summary>Rents a buffer of exactly the given length and copies bytes into it.</summary>
        /// <param name="bytes">The bytes to copy, such as a datagram in a reusable receive buffer.</param>
        /// <returns>An owned buffer holding the copy.</returns>
        public static PooledBuffer Copy(ReadOnlySpan<byte> bytes)
        {
            var buffer = new PooledBuffer(bytes.Length);
            bytes.CopyTo(buffer.Memory.Span);
            return buffer;
        }

        /// <summary>Clears and returns owned storage exactly once.</summary>
        public void Dispose()
        {
            if (_buffer != null)
            {
                ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = null;
            }
        }
    }
}
