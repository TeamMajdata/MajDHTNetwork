#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Microsoft.Extensions.Logging;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Checks that publications read, register and replicate concurrently without exceeding the request budget.</summary>
    public sealed class PublicationConcurrencyTests
    {
        /// <summary>A publication blocked on its source stream does not delay another publication.</summary>
        /// <returns>Completion after both publications were resolved.</returns>
        [Fact]
        public async Task SlowSourcesDoNotBlockOtherPublications()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var provider = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await using var reader = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            await Task.WhenAll(provider.StartAsync(token), reader.StartAsync(token));
            await reader.JoinAsync(provider.LocalPeer, token);
            using var gated = new GatedStream(Crypto.Random(20000));
            var slow = provider.PublishAsync("songs/slow", gated, cancellationToken: token);
            await gated.Entered.Task.WaitAsync(token);
            using var source = new MemoryStream(Crypto.Random(3000));
            var fast = await provider.PublishAsync("songs/fast", source, cancellationToken: token);
            Assert.False(slow.IsCompleted, "A publication must not wait for another publication's stream.");
            gated.Release();
            var record = await slow;
            Assert.NotNull(await reader.ResolveAsync(fast.Key, token));
            Assert.NotNull(await reader.ResolveAsync(record.Key, token));
        }

        /// <summary>Two concurrent publications of one key at one revision register exactly one of them.</summary>
        /// <returns>Completion after the winner was resolved and the loser was rejected.</returns>
        [Fact]
        public async Task ConcurrentPublicationsOfOneKeyAdmitExactlyOneRevision()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            await using var provider = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide));
            await provider.StartAsync(token);
            using var firstSource = new GatedStream(Crypto.Random(2000));
            using var secondSource = new GatedStream(Crypto.Random(2000));
            var first = provider.PublishAsync("songs/raced", firstSource, 1, token);
            var second = provider.PublishAsync("songs/raced", secondSource, 1, token);
            // Both publications passed the early revision check and are reading; only the first registration may win.
            await Task.WhenAll(firstSource.Entered.Task, secondSource.Entered.Task).WaitAsync(token);
            firstSource.Release();
            secondSource.Release();
            var outcomes = await Task.WhenAll(OutcomeAsync(first), OutcomeAsync(second));
            DHTRecord? winner = null;
            var rejections = 0;
            foreach (var (record, failure) in outcomes)
            {
                if (record != null)
                {
                    winner = record;
                }
                else if (failure is ArgumentException)
                {
                    rejections++;
                }
            }
            Assert.NotNull(winner);
            Assert.Equal(1, rejections);
            var resolved = await provider.ResolveAsync(winner!.Key, token);
            Assert.True(resolved != null && resolved.FileHash == winner.FileHash, "The registered publication must be the one that won.");
        }

        /// <summary>
        /// Publishes many files at once: every publication succeeds, no lookup or announcement fails for lack of an outgoing
        /// request slot, and the publisher keeps every routing contact.
        /// </summary>
        /// <returns>Completion after every publication was resolved through a peer.</returns>
        [Fact]
        public async Task ManyConcurrentPublicationsStayWithinTheRequestBudget()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var token = deadline.Token;
            var messages = new List<string>();
            var publisherOptions = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            publisherOptions.Logger = new CapturingLogger(messages);
            await using var publisher = new MajDHTNode(publisherOptions);
            var peers = new List<MajDHTNode>();
            for (var index = 0; index < 5; index++)
            {
                peers.Add(new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download)));
            }
            try
            {
                await publisher.StartAsync(token);
                foreach (var peer in peers)
                {
                    await peer.StartAsync(token);
                    await publisher.JoinAsync(peer.LocalPeer, token);
                }
                Assert.Equal(peers.Count, publisher.KnownPeers.Count);
                var sources = new List<MemoryStream>();
                var publications = new List<Task<DHTRecord>>();
                for (var index = 0; index < 24; index++)
                {
                    var source = new MemoryStream(Crypto.Random(1500 + index));
                    sources.Add(source);
                    publications.Add(publisher.PublishAsync("songs/bulk-" + index, source, cancellationToken: token));
                }
                var records = await Task.WhenAll(publications);
                foreach (var source in sources)
                {
                    source.Dispose();
                }
                Assert.Equal(peers.Count, publisher.KnownPeers.Count);
                lock (messages)
                {
                    Assert.DoesNotContain(messages, message => message.Contains("Lookup peer was unusable")
                        || message.Contains("Replica announcement failed") || message.Contains("no remote replica accepted"));
                }
                foreach (var record in records)
                {
                    Assert.NotNull(await peers[0].ResolveAsync(record.Key, token));
                }
            }
            finally
            {
                foreach (var peer in peers)
                {
                    await peer.DisposeAsync();
                }
            }
        }

        /// <summary>
        /// Leaves a record that reached a replica less than one maintenance interval ago out of the maintenance pass, so the
        /// passes during a long bulk publication do not repeat its announcements, while a contact change still reannounces
        /// it; once the interval has passed without another accepted announcement, maintenance includes it again.
        /// </summary>
        /// <returns>Completion after the selections were checked.</returns>
        [Fact]
        public async Task MaintenanceSkipsRecordsAnnouncedWithinOneInterval()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var token = deadline.Token;
            var options = Options(DHTTransport.Tcp, DHTCapabilities.Download | DHTCapabilities.Provide);
            options.MaintenanceInterval = TimeSpan.FromSeconds(1);
            await using var publisher = new MajDHTNode(options);
            var peer = new MajDHTNode(Options(DHTTransport.Tcp, DHTCapabilities.Download));
            DHTRecord record;
            try
            {
                await Task.WhenAll(publisher.StartAsync(token), peer.StartAsync(token));
                await publisher.JoinAsync(peer.LocalPeer, token);
                using var source = new MemoryStream(Crypto.Random(100));
                record = await publisher.PublishAsync("songs/recent", source, cancellationToken: token);
                Assert.DoesNotContain(publisher.LocalRecordsToReannounce(true), listed => listed.Key.Equals(record.Key));
                Assert.Contains(publisher.LocalRecordsToReannounce(false), listed => listed.Key.Equals(record.Key));
            }
            finally
            {
                await peer.DisposeAsync();
            }
            // Without the peer no later announcement is accepted, so the last accepted one ages past the interval.
            await Task.Delay(TimeSpan.FromSeconds(1.5), token);
            Assert.Contains(publisher.LocalRecordsToReannounce(true), listed => listed.Key.Equals(record.Key));
        }

        /// <summary>Awaits a publication and captures its record or failure.</summary>
        /// <param name="publication">The publication.</param>
        /// <returns>The record, or the failure.</returns>
        private static async Task<(DHTRecord? Record, Exception? Failure)> OutcomeAsync(Task<DHTRecord> publication)
        {
            try
            {
                return (await publication, null);
            }
            catch (Exception exception)
            {
                return (null, exception);
            }
        }

        /// <summary>A readable stream whose reads wait until the test releases them.</summary>
        private sealed class GatedStream : Stream
        {
            /// <summary>The content.</summary>
            private readonly MemoryStream _inner;
            /// <summary>Completed by the test to let reads proceed.</summary>
            private readonly TaskCompletionSource<bool> _gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Gets a completion that signals the first read attempt.</summary>
            internal TaskCompletionSource<bool> Entered { get; } = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

            /// <summary>Creates a gated stream over content.</summary>
            /// <param name="content">The content.</param>
            internal GatedStream(byte[] content)
            {
                _inner = new MemoryStream(content);
            }

            /// <summary>Lets every pending and future read proceed.</summary>
            internal void Release()
            {
                _gate.TrySetResult(true);
            }

            /// <inheritdoc />
            public override bool CanRead => true;
            /// <inheritdoc />
            public override bool CanSeek => false;
            /// <inheritdoc />
            public override bool CanWrite => false;
            /// <inheritdoc />
            public override long Length => _inner.Length;
            /// <inheritdoc />
            public override long Position
            {
                get => _inner.Position;
                set => throw new NotSupportedException();
            }

            /// <inheritdoc />
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                Entered.TrySetResult(true);
                await _gate.Task.WaitAsync(cancellationToken);
                return await _inner.ReadAsync(buffer, cancellationToken);
            }

            /// <inheritdoc />
            public override int Read(byte[] buffer, int offset, int count)
            {
                Entered.TrySetResult(true);
                _gate.Task.GetAwaiter().GetResult();
                return _inner.Read(buffer, offset, count);
            }

            /// <inheritdoc />
            public override void Flush()
            {
            }

            /// <inheritdoc />
            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            /// <inheritdoc />
            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            /// <inheritdoc />
            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

            /// <inheritdoc />
            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _gate.TrySetResult(true);
                    _inner.Dispose();
                }
                base.Dispose(disposing);
            }
        }

        /// <summary>A logger that keeps every formatted message.</summary>
        private sealed class CapturingLogger : ILogger
        {
            /// <summary>The caller-owned message collection, locked while written.</summary>
            private readonly List<string> _messages;

            /// <summary>Creates a capturing logger.</summary>
            /// <param name="messages">The destination of every formatted message.</param>
            internal CapturingLogger(List<string> messages)
            {
                _messages = messages;
            }

            /// <inheritdoc />
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                return null;
            }

            /// <inheritdoc />
            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            /// <inheritdoc />
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                lock (_messages)
                {
                    _messages.Add(formatter(state, exception));
                }
            }
        }
    }
}
