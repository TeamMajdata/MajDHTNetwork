#nullable enable

using System;
using System.Net;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Exercises non-amplifying UDP cookies bound to observed endpoints and request digests.</summary>
    public sealed class UdpCookieTests
    {
        /// <summary>Rejects source-port substitution, ciphertext modification and unrelated request digests.</summary>
        [Fact]
        public void CookiesBindSourcePortAndCompleteCiphertext()
        {
            var cookies = new UdpCookies();
            var packetDigest = Crypto.Random(32);
            var hello = UdpCookies.Hello(packetDigest);
            var endpoint = new IPEndPoint(IPAddress.Loopback, 12000);
            var challenge = cookies.Challenge(hello, endpoint)!;
            Assert.True(challenge.Length == hello.Length, "Address-validation replies must not amplify requests.");
            var fakePacket = Crypto.Random(100);
            hello = UdpCookies.Hello(Crypto.Hash(fakePacket));
            challenge = cookies.Challenge(hello, endpoint)!;
            var authenticated = UdpCookies.Request(challenge, fakePacket, Crypto.Hash(fakePacket))!;
            Assert.True(BytesEqual(cookies.OpenRequest(authenticated, endpoint)!.Value, fakePacket), "Cookie must validate the observed source and ciphertext.");
            Assert.True(cookies.OpenRequest(authenticated, new IPEndPoint(IPAddress.Loopback, 12001)) == null, "A UDP cookie must reject source-port substitution.");
            authenticated[authenticated.Length - 1] ^= 1;
            Assert.True(cookies.OpenRequest(authenticated, endpoint) == null, "A UDP cookie must bind the complete ciphertext.");
            Assert.True(UdpCookies.Request(challenge, fakePacket, Crypto.Random(32)) == null, "A challenge for a different request must be rejected.");
        }
    }
}
