using System;
using System.Buffers;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Owns a bounded pooled buffer and clears its contents before returning storage.</summary>
    internal sealed class PooledBuffer : IMemoryOwner<byte>
    {
        /// <summary>The rented array while ownership is active.</summary>
        private byte[]? _buffer;
        /// <summary>The requested logical length.</summary>
        private readonly int _length;

        /// <summary>Rents one buffer for a complete operation.</summary>
        /// <param name="length">The logical byte count.</param>
        internal PooledBuffer(int length)
        {
            _length = length;
            _buffer = ArrayPool<byte>.Shared.Rent(length);
        }

        /// <summary>Gets the live logical memory range.</summary>
        /// <exception cref="ObjectDisposedException">The owner has been disposed.</exception>
        public Memory<byte> Memory => (_buffer ?? throw new ObjectDisposedException(nameof(PooledBuffer))).AsMemory(0, _length);

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
