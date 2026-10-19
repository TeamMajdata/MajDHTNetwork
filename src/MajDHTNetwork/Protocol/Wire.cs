using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Writes canonical values into a pooled buffer or reads borrowed immutable memory without copying fields.</summary>
    internal sealed class Wire : IDisposable
    {
        /// <summary>The protocol-wide maximum encrypted datagram size.</summary>
        internal const int MaxPacket = 60000;
        /// <summary>The strict UTF-8 codec used by canonical signatures.</summary>
        private static readonly UTF8Encoding s_utf8 = new UTF8Encoding(false, true);
        /// <summary>The owned pooled writer buffer, or null for a reader or disposed writer.</summary>
        private byte[]? _buffer;
        /// <summary>The borrowed input memory for a reader.</summary>
        private readonly ReadOnlyMemory<byte> _input;
        /// <summary>Whether this instance is a reader.</summary>
        private readonly bool _reading;
        /// <summary>The read cursor or written byte count.</summary>
        private int _position;
        /// <summary>Whether owned memory has been returned.</summary>
        private bool _disposed;

        /// <summary>Creates an initially small pooled writer.</summary>
        internal Wire()
        {
            _buffer = ArrayPool<byte>.Shared.Rent(256);
        }

        /// <summary>Creates a zero-copy reader whose source must remain stable throughout use.</summary>
        /// <param name="bytes">The borrowed input memory.</param>
        internal Wire(ReadOnlyMemory<byte> bytes)
        {
            _input = bytes;
            _reading = true;
        }

        /// <summary>Gets the unread input byte count.</summary>
        internal int Remaining => _reading ? _input.Length - _position : 0;
        /// <summary>Gets the number of encoded bytes.</summary>
        internal int Length => _position;
        /// <summary>Gets borrowed encoded memory, valid until the writer grows or is disposed.</summary>
        internal ReadOnlyMemory<byte> WrittenMemory => Buffer.AsMemory(0, _position);
        /// <summary>Gets borrowed encoded bytes, valid until the writer grows or is disposed.</summary>
        internal ReadOnlySpan<byte> WrittenSpan => Buffer.AsSpan(0, _position);
        /// <summary>Gets the live writer buffer while rejecting mode or lifetime misuse.</summary>
        private byte[] Buffer
        {
            get
            {
                if (_reading || _disposed)
                {
                    throw new InvalidOperationException("The codec is not a live writer.");
                }
                return _buffer!;
            }
        }

        /// <summary>Reserves writable bytes, growing with pooled storage only when required.</summary>
        /// <param name="count">The additional byte count.</param>
        /// <returns>The borrowed destination span.</returns>
        private Span<byte> Reserve(int count)
        {
            var buffer = Buffer;
            var required = checked(_position + count);
            if (required > buffer.Length)
            {
                var replacement = ArrayPool<byte>.Shared.Rent(Math.Max(required, buffer.Length * 2));
                buffer.AsSpan(0, _position).CopyTo(replacement);
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                _buffer = replacement;
                buffer = replacement;
            }
            var destination = buffer.AsSpan(_position, count);
            _position = required;
            return destination;
        }

        /// <summary>Reserves writable array-backed memory for a legacy cryptographic provider.</summary>
        /// <param name="count">The exact byte count to reserve.</param>
        /// <returns>A borrowed destination valid until the writer grows or is disposed.</returns>
        internal Memory<byte> Allocate(int count)
        {
            var offset = _position;
            Reserve(count);
            return Buffer.AsMemory(offset, count);
        }

        /// <summary>Writes one byte.</summary>
        /// <param name="value">The value.</param>
        internal void PutByte(byte value)
        {
            Reserve(1)[0] = value;
        }

        /// <summary>Reads one byte.</summary>
        /// <returns>The next byte.</returns>
        /// <exception cref="InvalidDataException">The input is truncated.</exception>
        internal byte Byte()
        {
            if (!_reading || _disposed || Remaining < 1)
            {
                throw new InvalidDataException("Truncated protocol value.");
            }
            return _input.Span[_position++];
        }

        /// <summary>Writes a signed 64-bit big-endian integer.</summary>
        /// <param name="value">The integer.</param>
        internal void PutLong(long value)
        {
            BinaryPrimitives.WriteInt64BigEndian(Reserve(8), value);
        }

        /// <summary>Reads a signed 64-bit big-endian integer.</summary>
        /// <returns>The decoded integer.</returns>
        /// <exception cref="InvalidDataException">The integer is truncated.</exception>
        internal long Long()
        {
            if (!_reading || _disposed || Remaining < 8)
            {
                throw new InvalidDataException("Truncated protocol integer.");
            }
            var value = BinaryPrimitives.ReadInt64BigEndian(_input.Span.Slice(_position, 8));
            _position += 8;
            return value;
        }

        /// <summary>Writes a length-prefixed borrowed byte sequence.</summary>
        /// <param name="bytes">The sequence.</param>
        internal void Put(ReadOnlySpan<byte> bytes)
        {
            PutLong(bytes.Length);
            PutRaw(bytes);
        }

        /// <summary>Writes raw bytes without a prefix.</summary>
        /// <param name="bytes">The raw sequence.</param>
        internal void PutRaw(ReadOnlySpan<byte> bytes)
        {
            bytes.CopyTo(Reserve(bytes.Length));
        }

        /// <summary>Reads a bounded length-prefixed view without allocating or copying its contents.</summary>
        /// <param name="limit">The maximum accepted length.</param>
        /// <returns>A borrowed immutable slice retaining its input owner.</returns>
        /// <exception cref="InvalidDataException">The value is negative, too large or truncated.</exception>
        internal ReadOnlyMemory<byte> Bytes(int limit)
        {
            var length = Long();
            if (length < 0 || length > limit || length > Remaining)
            {
                throw new InvalidDataException("Invalid protocol value length.");
            }
            var result = _input.Slice(_position, (int)length);
            _position += (int)length;
            return result;
        }

        /// <summary>Writes UTF-8 directly into the destination without a temporary encoded array.</summary>
        /// <param name="text">The text.</param>
        internal void PutText(string text)
        {
            var count = s_utf8.GetByteCount(text);
            PutLong(count);
            s_utf8.GetBytes(text.AsSpan(), Reserve(count));
        }

        /// <summary>Reads a bounded strict UTF-8 string.</summary>
        /// <param name="limit">The byte limit.</param>
        /// <returns>The decoded text.</returns>
        internal string Text(int limit)
        {
            return s_utf8.GetString(Bytes(limit).Span);
        }

        /// <summary>Rejects trailing bytes in a canonical input value.</summary>
        /// <exception cref="InvalidDataException">Unconsumed bytes remain.</exception>
        internal void End()
        {
            if (Remaining != 0)
            {
                throw new InvalidDataException("Unexpected trailing protocol data.");
            }
        }

        /// <summary>Makes one owned copy when bytes must outlive the pooled writer.</summary>
        /// <returns>An independently owned encoded array.</returns>
        internal byte[] ToArray()
        {
            return WrittenSpan.ToArray();
        }

        /// <summary>Returns the owned writer storage after clearing all pooled data.</summary>
        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }
            _disposed = true;
            if (_buffer != null)
            {
                ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = null;
            }
        }
    }
}
