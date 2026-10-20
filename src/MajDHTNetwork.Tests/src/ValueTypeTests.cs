#nullable enable

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;

namespace MajDHTNetwork.Tests
{
    /// <summary>Verifies key value semantics and packet copies without transferring buffer ownership.</summary>
    [Collection(AllocationCollection.Name)]
    public sealed class ValueTypeTests
    {
        /// <summary>A canonical publisher fingerprint used independently of signing identities.</summary>
        private const string PublisherId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        /// <summary>A distinct canonical fingerprint for namespace comparisons.</summary>
        private const string OtherPublisherId = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        /// <summary>The runner-owned sink used only after allocation measurements finish.</summary>
        private readonly ITestOutputHelper _output;

        /// <summary>Creates a test instance with allocation diagnostics.</summary>
        /// <param name="output">The diagnostic sink supplied by xUnit.</param>
        public ValueTypeTests(ITestOutputHelper output)
        {
            _output = output;
        }

        /// <summary>Keeps uninitialized keys safe to format, compare and hash.</summary>
        [Fact]
        public void DefaultKeysHaveSafeValueSemantics()
        {
            var key = default(DHTKey);
            var another = new DHTKey();
            var initialized = new DHTKey(PublisherId, "songs/example");

            Assert.False(key.IsValid);
            Assert.Equal(string.Empty, key.ToString());
            Assert.Equal(0, key.GetHashCode());
            Assert.True(key.Equals(another));
            Assert.True(key == another);
            Assert.False(key != another);
            Assert.True(key.Equals((object)another));
            Assert.False(key.Equals((object?)null));
            Assert.False(key.Equals("songs/example"));
            Assert.False(key.Equals(initialized));
            Assert.False(initialized.Equals(key));
            Assert.False(key == initialized);
            Assert.True(key != initialized);
        }

        /// <summary>Rejects reading identity components from an uninitialized key with explicit exceptions.</summary>
        [Fact]
        public void DefaultKeyComponentsCannotBeRead()
        {
            var key = default(DHTKey);

            Assert.Throws<InvalidOperationException>(() =>
            {
                _ = key.PublisherId;
            });
            Assert.Throws<InvalidOperationException>(() =>
            {
                _ = key.Name;
            });
            Assert.Throws<InvalidOperationException>(() =>
            {
                _ = key.RoutingId;
            });
        }

        /// <summary>Finds equivalent keys across independent strings, value copies and hash collections.</summary>
        [Fact]
        public void EqualKeysUseValueSemanticsInCollections()
        {
            var firstPublisher = new string(PublisherId.ToCharArray());
            var secondPublisher = new string(PublisherId.ToCharArray());
            var firstName = new string("songs:Example".ToCharArray());
            var secondName = new string("songs:Example".ToCharArray());
            var first = new DHTKey(firstPublisher, firstName);
            var second = new DHTKey(secondPublisher, secondName);
            var copy = first;

            Assert.NotSame(firstPublisher, secondPublisher);
            Assert.NotSame(firstName, secondName);
            Assert.True(first.IsValid);
            Assert.True(first.Equals(second));
            Assert.True(first == second);
            Assert.False(first != second);
            Assert.True(first.Equals((object)second));
            Assert.Equal(first.GetHashCode(), second.GetHashCode());

            var dictionary = new Dictionary<DHTKey, string>
            {
                [first] = "publication",
                [default] = "uninitialized"
            };
            var set = new HashSet<DHTKey> { first, second, copy, default, new DHTKey() };
            first = default;

            Assert.True(copy.IsValid);
            Assert.Equal(PublisherId, copy.PublisherId);
            Assert.Equal(secondName, copy.Name);
            Assert.Equal(second.RoutingId, copy.RoutingId);
            Assert.Equal("publication", dictionary[second]);
            Assert.Equal("publication", dictionary[copy]);
            Assert.Equal("uninitialized", dictionary[first]);
            Assert.Equal(2, set.Count);
            Assert.Contains(copy, set);
            Assert.Contains(default(DHTKey), set);
        }

        /// <summary>Preserves exact case and Unicode spelling instead of culture or normalization equivalence.</summary>
        /// <param name="firstName">The first valid name.</param>
        /// <param name="secondName">A distinct spelling of the name.</param>
        [Theory]
        [InlineData("Songs:Track", "songs:Track")]
        [InlineData("songs:Track", "songs:track")]
        [InlineData("é", "é")]
        public void KeyNamesUseOrdinalEquality(string firstName, string secondName)
        {
            var first = new DHTKey(PublisherId, firstName);
            var second = new DHTKey(PublisherId, secondName);

            Assert.False(first.Equals(second));
            Assert.False(first == second);
            Assert.True(first != second);
            Assert.Equal(2, new HashSet<DHTKey> { first, second }.Count);
        }

        /// <summary>Keeps identical names in separate publisher namespaces distinct.</summary>
        [Fact]
        public void PublisherNamespacesArePartOfKeyEquality()
        {
            var first = new DHTKey(PublisherId, "songs/example");
            var second = new DHTKey(OtherPublisherId, first.Name);

            Assert.False(first.Equals(second));
            Assert.False(first == second);
            Assert.True(first != second);
            Assert.Equal(2, new HashSet<DHTKey> { first, second }.Count);
        }

        /// <summary>Preserves canonical parsing and derives routing identifiers from the exact UTF-8 key.</summary>
        /// <param name="name">A valid name, including Unicode, colons or surrounding spaces.</param>
        [Theory]
        [InlineData("songs:Track")]
        [InlineData(":nested:track")]
        [InlineData("谱面/歌曲")]
        [InlineData("\U0001f3b5")]
        [InlineData(" a ")]
        public void CanonicalKeysRoundTripAndDeriveTheExpectedRoutingHash(string name)
        {
            var canonical = PublisherId + ":" + name;
            var key = new DHTKey(PublisherId, name);
            var parsed = DHTKey.Parse(canonical);
            var expected = Convert.ToHexString(SHA256.HashData(new UTF8Encoding(false, true).GetBytes(canonical))).ToLowerInvariant();

            Assert.True(parsed.IsValid);
            Assert.Equal(PublisherId, parsed.PublisherId);
            Assert.Equal(name, parsed.Name);
            Assert.Equal(canonical, key.ToString());
            Assert.Equal(canonical, parsed.ToString());
            Assert.Equal(key, parsed);
            Assert.Equal(expected, key.RoutingId);
            Assert.Equal(expected, parsed.RoutingId);
        }

        /// <summary>Accepts names at the byte limit for ASCII, multibyte and supplementary Unicode text.</summary>
        /// <param name="scalar">The Unicode text to repeat.</param>
        /// <param name="repetitions">The number of repetitions producing exactly 256 UTF-8 bytes.</param>
        [Theory]
        [InlineData("a", 256)]
        [InlineData("é", 128)]
        [InlineData("\U0001f3b5", 64)]
        public void KeyNamesAcceptExactly256Utf8Bytes(string scalar, int repetitions)
        {
            var name = RepeatText(scalar, repetitions);
            var key = new DHTKey(PublisherId, name);
            var canonical = PublisherId + ":" + name;
            var expected = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();

            Assert.Equal(256, Encoding.UTF8.GetByteCount(name));
            Assert.True(key.IsValid);
            Assert.Equal(name, key.Name);
            Assert.Equal(expected, key.RoutingId);
            Assert.Equal(key, DHTKey.Parse(canonical));
        }

        /// <summary>Rejects oversized names by encoded byte count rather than UTF-16 character count.</summary>
        /// <param name="scalar">The Unicode text to repeat.</param>
        /// <param name="repetitions">The number of repetitions exceeding 256 UTF-8 bytes.</param>
        [Theory]
        [InlineData("a", 257)]
        [InlineData("é", 129)]
        [InlineData("\U0001f3b5", 65)]
        public void KeyNamesRejectMoreThan256Utf8Bytes(string scalar, int repetitions)
        {
            var name = RepeatText(scalar, repetitions);

            Assert.Throws<ArgumentException>(() => new DHTKey(PublisherId, name));
        }

        /// <summary>Rejects empty, whitespace-only and control-bearing names.</summary>
        /// <param name="name">The invalid name.</param>
        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData("\t")]
        [InlineData("bad\nname")]
        [InlineData("bad\0name")]
        [InlineData("bad\u007fname")]
        [InlineData("bad\u0085name")]
        public void KeyNamesRejectBlankOrControlCharacters(string name)
        {
            Assert.ThrowsAny<ArgumentException>(() => new DHTKey(PublisherId, name));
        }

        /// <summary>Rejects malformed UTF-16 instead of silently substituting a replacement character.</summary>
        /// <param name="surrogate">An unpaired high or low surrogate represented without attribute string encoding.</param>
        [Theory]
        [InlineData(0xd800)]
        [InlineData(0xdc00)]
        public void KeyNamesRejectUnpairedSurrogates(int surrogate)
        {
            var name = new string((char)surrogate, 1);

            Assert.Throws<EncoderFallbackException>(() => new DHTKey(PublisherId, name));
        }

        /// <summary>Rejects publisher fingerprints with incorrect length, uppercase or nonhexadecimal text.</summary>
        /// <param name="length">The supplied fingerprint length.</param>
        /// <param name="character">The character used throughout the fingerprint.</param>
        [Theory]
        [InlineData(0, 'a')]
        [InlineData(63, 'a')]
        [InlineData(65, 'a')]
        [InlineData(64, 'A')]
        [InlineData(64, 'g')]
        public void KeyPublishersRequireCanonicalLowercaseSha256(int length, char character)
        {
            var publisher = new string(character, length);

            Assert.Throws<ArgumentException>(() => new DHTKey(publisher, "songs/example"));
        }

        /// <summary>Rejects absent publisher or name arguments through the public constructor.</summary>
        [Fact]
        public void KeyConstructorRejectsNullComponents()
        {
            Assert.ThrowsAny<ArgumentException>(() => new DHTKey(null!, "songs/example"));
            Assert.ThrowsAny<ArgumentException>(() => new DHTKey(PublisherId, null!));
        }

        /// <summary>Rejects missing or malformed canonical key text before returning a value.</summary>
        /// <param name="canonical">The invalid encoded key, including null.</param>
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(PublisherId)]
        [InlineData(PublisherId + ":")]
        [InlineData(PublisherId + "/name")]
        [InlineData(PublisherId + ":bad\nname")]
        public void KeyParsingRejectsMalformedCanonicalValues(string? canonical)
        {
            Assert.ThrowsAny<ArgumentException>(() => DHTKey.Parse(canonical!));
        }

        /// <summary>Rejects an uninitialized lookup key at the public API boundary before querying peers.</summary>
        /// <returns>Completion after the rejected lookup and node cleanup.</returns>
        [Fact]
        public async Task ResolveRejectsDefaultKeysAtTheArgumentBoundary()
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var node = new MajDHTNode(TestSupport.Options(DHTTransport.Udp, DHTCapabilities.Download));
            await node.StartAsync(deadline.Token);

            var exception = await Assert.ThrowsAsync<ArgumentException>(() => node.ResolveAsync(default, deadline.Token));

            Assert.Equal("key", exception.ParamName);
        }

        /// <summary>Keeps default packet metadata readable while rejecting operations that require a sender.</summary>
        [Fact]
        public void DefaultPacketsRejectSenderDependentOperations()
        {
            var packet = default(Packet);
            var identity = new DHTIdentity();
            var recipient = CreatePeer(identity);

            Assert.True(packet.RequestId.IsEmpty);
            Assert.True(packet.Body.IsEmpty);
            Assert.Equal((byte)0, packet.Kind);
            Assert.Throws<InvalidOperationException>(() =>
            {
                _ = packet.Sender;
            });
            Assert.Throws<InvalidOperationException>(() => packet.Seal(identity, recipient));
        }

        /// <summary>Rejects a missing sender instead of constructing an invalid nondefault packet.</summary>
        [Fact]
        public void PacketConstructorRejectsMissingSenders()
        {
            var exception = Assert.Throws<ArgumentNullException>(() =>
                new Packet(null!, new byte[16], (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty));

            Assert.Equal("sender", exception.ParamName);
        }

        /// <summary>Rejects correlation identifiers outside the protocol's 128-bit width.</summary>
        /// <param name="length">The invalid correlation identifier length.</param>
        [Theory]
        [InlineData(0)]
        [InlineData(15)]
        [InlineData(17)]
        public void PacketConstructorRequiresExactly16CorrelationBytes(int length)
        {
            var sender = CreatePeer(new DHTIdentity());

            var exception = Assert.Throws<ArgumentException>(() =>
                new Packet(sender, new byte[length], (byte)Operation.Ping, ReadOnlyMemory<byte>.Empty));

            Assert.Equal("requestId", exception.ParamName);
        }

        /// <summary>Preserves borrowed array slices, offsets and sender references when packet values are copied.</summary>
        [Fact]
        public void PacketCopiesBorrowConstructorMemoryWithoutCloning()
        {
            var sender = CreatePeer(new DHTIdentity());
            var requestBytes = new byte[24];
            var bodyBytes = new byte[] { 10, 11, 12, 13, 14, 15, 16, 17 };
            var original = new Packet(sender, requestBytes.AsMemory(4, 16), (byte)Operation.Find, bodyBytes.AsMemory(2, 3));
            var copy = original;
            original = default;

            Assert.Same(sender, copy.Sender);
            Assert.Equal((byte)Operation.Find, copy.Kind);
            Assert.True(MemoryMarshal.TryGetArray(copy.RequestId, out var requestView));
            Assert.Same(requestBytes, requestView.Array);
            Assert.Equal(4, requestView.Offset);
            Assert.Equal(16, requestView.Count);
            Assert.True(MemoryMarshal.TryGetArray(copy.Body, out var bodyView));
            Assert.Same(bodyBytes, bodyView.Array);
            Assert.Equal(2, bodyView.Offset);
            Assert.Equal(3, bodyView.Count);

            requestBytes[4] = 0x82;
            bodyBytes[2] = 0x56;

            Assert.Equal((byte)0x82, copy.RequestId.Span[0]);
            Assert.Equal((byte)0x56, copy.Body.Span[0]);
            Assert.True(original.Body.IsEmpty);
        }

        /// <summary>
        /// Shares an opened packet's plaintext across copies: the plaintext lives in the envelope buffer, which opening consumes,
        /// and never aliases the sender's request or body inputs.
        /// </summary>
        [Fact]
        public void DecodedPacketCopiesShareEnvelopePlaintextWithoutAliasingSenderBuffers()
        {
            var senderIdentity = new DHTIdentity();
            var recipientIdentity = new DHTIdentity();
            var sender = CreatePeer(senderIdentity);
            var recipient = CreatePeer(recipientIdentity);
            var requestBytes = new byte[20];
            var bodyBytes = new byte[] { 10, 11, 12, 13, 14, 15 };
            requestBytes.AsSpan(2, 16).Fill(0x31);
            var request = new Packet(sender, requestBytes.AsMemory(2, 16), (byte)Operation.Find, bodyBytes.AsMemory(1, 3));
            var encrypted = request.Seal(senderIdentity, recipient);
            var cipherText = (byte[])encrypted.Clone();
            var opened = Packet.Open(recipientIdentity, encrypted);
            var copy = opened;

            Assert.Equal(opened.RequestId, copy.RequestId);
            Assert.Equal(opened.Body, copy.Body);
            Assert.Same(opened.Sender, copy.Sender);
            Assert.True(MemoryMarshal.TryGetArray(copy.RequestId, out var requestView));
            Assert.NotSame(requestBytes, requestView.Array);
            Assert.Same(encrypted, requestView.Array);
            Assert.True(MemoryMarshal.TryGetArray(copy.Body, out var bodyView));
            Assert.NotSame(bodyBytes, bodyView.Array);
            Assert.Same(encrypted, bodyView.Array);
            Assert.False(encrypted.AsSpan().SequenceEqual(cipherText), "Opening must decrypt the envelope in place.");

            opened = default;
            Array.Clear(requestBytes, 0, requestBytes.Length);
            Array.Clear(bodyBytes, 0, bodyBytes.Length);

            Assert.True(opened.Body.IsEmpty);
            Assert.Equal(sender.NodeId, copy.Sender.NodeId);
            Assert.Equal((byte)Operation.Find, copy.Kind);
            Assert.Equal(new byte[] { 11, 12, 13 }, copy.Body.ToArray());
            Assert.Equal(new string('1', 16), Encoding.ASCII.GetString(copy.RequestId.Span));
            // A consumed envelope cannot be opened again; the failed authentication zeroes the plaintext it now holds.
            Assert.ThrowsAny<CryptographicException>(() => Packet.Open(recipientIdentity, encrypted));
            Assert.True(copy.Body.Span.SequenceEqual(new byte[3]), "A failed reopen must zero the consumed envelope.");
        }

        /// <summary>Uses the authenticated packet value when present and the fallback only when the nullable is absent.</summary>
        /// <param name="hasAuthenticatedPacket">Whether the optional response already contains a packet.</param>
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void NullablePacketsPreserveCoalescingSemantics(bool hasAuthenticatedPacket)
        {
            var sender = CreatePeer(new DHTIdentity());
            var authenticated = new Packet(sender, new byte[16], (byte)Operation.Find, new byte[] { 3 });
            var fallback = new Packet(sender, new byte[16], (byte)Operation.Block, new byte[] { 7 });
            Packet? optional = hasAuthenticatedPacket ? authenticated : (Packet?)null;

            var selected = optional ?? fallback;
            var expected = hasAuthenticatedPacket ? authenticated : fallback;

            Assert.Same(sender, selected.Sender);
            Assert.Equal(expected.Kind, selected.Kind);
            Assert.Equal(expected.RequestId, selected.RequestId);
            Assert.Equal(expected.Body, selected.Body);
        }

        /// <summary>Requires warmed typed and generic key equality and hashing to allocate no managed memory.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void KeyEqualityAndHashingDoNotAllocate()
        {
            var first = new DHTKey(new string(PublisherId.ToCharArray()), new string("songs/example".ToCharArray()));
            var second = new DHTKey(new string(PublisherId.ToCharArray()), new string("songs/example".ToCharArray()));
            ExerciseKeyEqualityAndHashing(first, second, 256);

            var before = GC.GetAllocatedBytesForCurrentThread();
            var checksum = ExerciseKeyEqualityAndHashing(first, second, 10000);
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

            _output.WriteLine("Key equality and hashing: " + allocated + " bytes for 10000 iterations.");
            GC.KeepAlive(checksum);
            Assert.Equal(0L, allocated);
        }

        /// <summary>Requires packet construction and copying to reuse prepared references without allocating wrappers.</summary>
        [Fact]
        [Trait("Category", "Allocation")]
        public void PacketConstructionAndCopyingDoNotAllocate()
        {
            var sender = CreatePeer(new DHTIdentity());
            var requestId = new byte[16].AsMemory();
            var body = new byte[64].AsMemory();
            var packets = new Packet[256];
            for (var i = 0; i < packets.Length; i++)
            {
                packets[i] = new Packet(sender, requestId, (byte)Operation.Find, body);
            }

            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var i = 0; i < 10000; i++)
            {
                var packet = new Packet(sender, requestId, (byte)Operation.Find, body);
                var copy = packet;
                packets[i % packets.Length] = copy;
            }
            var allocated = GC.GetAllocatedBytesForCurrentThread() - before;

            _output.WriteLine("Packet construction and copying: " + allocated + " bytes for 10000 iterations.");
            var retained = packets[9999 % packets.Length];
            Assert.Same(sender, retained.Sender);
            Assert.Equal((ReadOnlyMemory<byte>)requestId, retained.RequestId);
            Assert.Equal((ReadOnlyMemory<byte>)body, retained.Body);
            Assert.Equal(0L, allocated);
        }

        /// <summary>Creates repeated valid Unicode text for byte-boundary tests.</summary>
        /// <param name="text">The text to append on each repetition.</param>
        /// <param name="count">The number of repetitions.</param>
        /// <returns>The concatenated text.</returns>
        private static string RepeatText(string text, int count)
        {
            var result = new StringBuilder(text.Length * count);
            for (var i = 0; i < count; i++)
            {
                result.Append(text);
            }
            return result.ToString();
        }

        /// <summary>Creates a signed contact without opening network listeners.</summary>
        /// <param name="identity">The identity signing the contact.</param>
        /// <returns>A live loopback contact usable in packet tests.</returns>
        private static DHTPeer CreatePeer(DHTIdentity identity)
        {
            return DHTPeer.Create(identity, IPAddress.Loopback, 22000, 22001, DHTCapabilities.Download);
        }

        /// <summary>Exercises typed, operator and generic equality together with valid and default key hashes.</summary>
        /// <param name="first">The first initialized key.</param>
        /// <param name="second">An independently constructed key with matching components.</param>
        /// <param name="iterations">The number of repeated comparisons and hashes.</param>
        /// <returns>A checksum that keeps hash computations observable.</returns>
        /// <exception cref="InvalidOperationException">Equivalent or default keys compare as unequal.</exception>
        private static int ExerciseKeyEqualityAndHashing(DHTKey first, DHTKey second, int iterations)
        {
            var comparer = EqualityComparer<DHTKey>.Default;
            var empty = default(DHTKey);
            var anotherEmpty = new DHTKey();
            var checksum = 0;
            for (var i = 0; i < iterations; i++)
            {
                if (!first.Equals(second) || !(first == second) || first != second || !comparer.Equals(first, second)
                    || !empty.Equals(anotherEmpty) || !(empty == anotherEmpty) || empty != anotherEmpty || !comparer.Equals(empty, anotherEmpty))
                {
                    throw new InvalidOperationException("Equivalent keys must compare equally without boxing.");
                }
                checksum = unchecked(checksum + first.GetHashCode() + second.GetHashCode() + comparer.GetHashCode(second)
                    + empty.GetHashCode() + comparer.GetHashCode(empty));
            }
            return checksum;
        }
    }
}
