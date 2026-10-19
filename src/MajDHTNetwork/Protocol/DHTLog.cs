using System;
using Microsoft.Extensions.Logging;

#nullable enable

namespace MajDHTNetwork.Protocol
{
    /// <summary>Uses cached strongly typed logger delegates and isolates host logger failures.</summary>
    internal static class DHTLog
    {
        /// <summary>The cached debug event writer.</summary>
        private static readonly Action<ILogger, string, string, Exception?> s_debug = Create(LogLevel.Debug, 100);
        /// <summary>The cached informational event writer.</summary>
        private static readonly Action<ILogger, string, string, Exception?> s_info = Create(LogLevel.Information, 101);
        /// <summary>The cached warning event writer.</summary>
        private static readonly Action<ILogger, string, string, Exception?> s_warning = Create(LogLevel.Warning, 102);
        /// <summary>The cached error event writer.</summary>
        private static readonly Action<ILogger, string, string, Exception?> s_error = Create(LogLevel.Error, 103);

        /// <summary>Creates a typed event delegate once for a severity.</summary>
        /// <param name="level">The severity.</param>
        /// <param name="id">The stable event identifier.</param>
        /// <returns>The allocation-efficient writer.</returns>
        private static Action<ILogger, string, string, Exception?> Create(LogLevel level, int id)
        {
            return LoggerMessage.Define<string, string>(level, new EventId(id, nameof(MajDHTNode)), "[Network] {Message} {Failure}");
        }

        /// <summary>Logs static context and a failure category without formatting strings on disabled paths.</summary>
        /// <param name="logger">The caller-owned logger.</param>
        /// <param name="level">The event severity.</param>
        /// <param name="message">The operation context.</param>
        /// <param name="failure">The optional failure, restricted to its type name for privacy.</param>
        internal static void Write(ILogger logger, LogLevel level, string message, Exception? failure = null)
        {
            try
            {
                if (!logger.IsEnabled(level))
                {
                    return;
                }
                var category = failure?.GetType().Name ?? string.Empty;
                switch (level)
                {
                    case LogLevel.Debug:
                        s_debug(logger, message, category, null);
                        break;
                    case LogLevel.Information:
                        s_info(logger, message, category, null);
                        break;
                    case LogLevel.Warning:
                        s_warning(logger, message, category, null);
                        break;
                    case LogLevel.Error:
                    case LogLevel.Critical:
                        s_error(logger, message, category, null);
                        break;
                }
            }
            catch
            {
                // Host diagnostics must not prevent request completion or socket cleanup.
            }
        }
    }
}
