using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

#nullable enable

namespace MajDHTNetwork.Tests
{
    /// <summary>A standard logger used to verify capture, disabled events and provider failures.</summary>
    internal sealed class TestLogger : ILogger
    {
        /// <summary>The caller-owned severity collection.</summary>
        private readonly List<LogLevel> _levels;
        /// <summary>Whether writes deliberately throw after being recorded.</summary>
        private readonly bool _throwOnWrite;
        /// <summary>Gets or sets whether events are enabled.</summary>
        internal bool Enabled { get; set; } = true;
        /// <summary>Gets the last structured state supplied to the logger.</summary>
        internal object? LastState { get; private set; }
        /// <summary>Gets the formatted last message.</summary>
        internal string? LastMessage { get; private set; }

        /// <summary>Creates an isolated log capture.</summary>
        /// <param name="levels">The thread-safe-by-lock capture destination.</param>
        /// <param name="throwOnWrite">Whether to simulate a failing provider.</param>
        internal TestLogger(List<LogLevel> levels, bool throwOnWrite = false)
        {
            _levels = levels;
            _throwOnWrite = throwOnWrite;
        }

        /// <inheritdoc />
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            return null;
        }

        /// <inheritdoc />
        public bool IsEnabled(LogLevel logLevel)
        {
            return Enabled;
        }

        /// <inheritdoc />
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            lock (_levels)
            {
                _levels.Add(logLevel);
                LastState = state;
                LastMessage = formatter(state, exception);
            }
            if (_throwOnWrite)
            {
                throw new InvalidOperationException("Logger provider failure.");
            }
        }
    }
}
