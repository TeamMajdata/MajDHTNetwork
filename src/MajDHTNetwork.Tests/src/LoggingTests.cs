#nullable enable

using System.Collections.Generic;
using System.IO;
using MajDHTNetwork.Protocol;
using Microsoft.Extensions.Logging;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Verifies structured logger state, redaction, severity and disabled events.</summary>
    public sealed class LoggingTests
    {
        /// <summary>Emits structured failure classifications and suppresses disabled logger events.</summary>
        [Fact]
        public void StructuredEventsPreserveSeverityWithoutPrivateExceptionText()
        {
            var levels = new List<LogLevel>();
            var logger = new TestLogger(levels);
            DHTLog.Write(logger, LogLevel.Warning, "Validation context", new IOException("private-secret"));
            Assert.True(levels.Count == 1 && levels[0] == LogLevel.Warning, "ILogger must receive the event severity.");
            Assert.True(logger.LastState is IReadOnlyList<KeyValuePair<string, object?>>, "ILogger must receive structured state.");
            Assert.True(logger.LastMessage != null && logger.LastMessage.Contains("IOException") && !logger.LastMessage.Contains("private-secret"),
                "Structured diagnostics must retain failure classification without private exception text.");
            logger.Enabled = false;
            DHTLog.Write(logger, LogLevel.Error, "Disabled event");
            Assert.True(levels.Count == 1, "Disabled ILogger events must not be emitted.");
        }
    }
}
