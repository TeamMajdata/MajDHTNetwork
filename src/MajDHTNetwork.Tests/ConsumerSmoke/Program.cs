using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using MajDHTNetwork;
using Microsoft.Extensions.Logging.Abstractions;

#nullable enable

namespace MajDHTNetwork.Tests.PackageConsumer
{
    /// <summary>Exercises only the public API supplied by an external binary artifact.</summary>
    internal static class Program
    {
        /// <summary>Runs a verified two-node transfer using a package or loose DLL reference.</summary>
        /// <returns>Completion of the consumer smoke test.</returns>
        private static async Task Main()
        {
            // Identities must reach the network's identity work; real applications create one once and persist its seed.
            var identity = DHTIdentity.Create(new DHTNodeOptions().IdentityWorkBits);
            await using var provider = new MajDHTNode(new DHTNodeOptions
            {
                UdpPort = null,
                Logger = NullLogger.Instance
            }, identity);
            await provider.StartAsync().ConfigureAwait(false);
            await using var consumer = new MajDHTNode(new DHTNodeOptions
            {
                UdpPort = null,
                Capabilities = DHTCapabilities.Download,
                BootstrapEndpoints = { new IPEndPoint(IPAddress.Loopback, provider.LocalPeer.Endpoints[0].TcpPort) }
            });
            await consumer.StartAsync().ConfigureAwait(false);
            await consumer.BootstrapAsync().ConfigureAwait(false);
            var content = Encoding.UTF8.GetBytes("External package consumer verified content.");
            using var source = new MemoryStream(content);
            var record = await provider.PublishAsync("package-smoke", source).ConfigureAwait(false);
            using var destination = new MemoryStream();
            await consumer.DownloadAsync(record.Key, destination, record.FileHash).ConfigureAwait(false);
            if (!destination.ToArray().AsSpan().SequenceEqual(content))
            {
                throw new InvalidOperationException("External consumer content mismatch.");
            }
            VerifySpanApi(identity, record);
            Console.WriteLine("PASS external consumer using " + typeof(MajDHTNode).Assembly.GetName().Name);
        }

        /// <summary>Checks public span exports and root namespace resolution from the artifact.</summary>
        /// <param name="identity">The consumer identity.</param>
        /// <param name="record">The verified publication.</param>
        private static void VerifySpanApi(DHTIdentity identity, DHTRecord record)
        {
            Span<byte> seed = stackalloc byte[32];
            identity.ExportSeed(seed);
            if (new DHTIdentity(seed).NodeId != identity.NodeId)
            {
                throw new InvalidOperationException("Span identity round trip failed.");
            }
            Span<byte> encoded = stackalloc byte[record.EncodedLength];
            record.CopyTo(encoded);
            if (!DHTRecord.Parse(encoded).Key.Equals(record.Key) || typeof(MajDHTNode).Namespace != "MajDHTNetwork")
            {
                throw new InvalidOperationException("Packaged public API mismatch.");
            }
        }
    }
}
