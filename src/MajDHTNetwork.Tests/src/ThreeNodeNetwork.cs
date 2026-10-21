#nullable enable

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using MajDHTNetwork.Protocol;
using Xunit;
using static MajDHTNetwork.Tests.TestSupport;

namespace MajDHTNetwork.Tests
{
    /// <summary>Owns three independent real-socket nodes with an indirectly published file and alias.</summary>
    internal sealed class ThreeNodeNetwork : IAsyncDisposable
    {
        /// <summary>Gets the identity used to sign provider announcements.</summary>
        internal DHTIdentity ProviderIdentity { get; }
        /// <summary>Gets the bootstrap node that forwards traffic but does not retain file content.</summary>
        internal MajDHTNode Bootstrap { get; }
        /// <summary>Gets the node that owns the published file.</summary>
        internal MajDHTNode Provider { get; }
        /// <summary>Gets the indirectly bootstrapped downloader.</summary>
        internal MajDHTNode Downloader { get; }
        /// <summary>Gets the exact bytes of the published multi-block file.</summary>
        internal byte[] Input { get; }
        /// <summary>Gets the original signed file binding.</summary>
        internal DHTRecord Record { get; }
        /// <summary>Gets a second publisher-scoped key for the same content hash.</summary>
        internal DHTRecord Alias { get; }

        /// <summary>Retains the nodes and signed records of an initialized test network.</summary>
        /// <param name="providerIdentity">The provider signing identity.</param>
        /// <param name="bootstrap">The bootstrap and Forwarder node.</param>
        /// <param name="provider">The file provider node.</param>
        /// <param name="downloader">The indirectly joined download node.</param>
        /// <param name="input">The original file bytes.</param>
        /// <param name="record">The original file binding.</param>
        /// <param name="alias">The independent alias binding.</param>
        private ThreeNodeNetwork(DHTIdentity providerIdentity, MajDHTNode bootstrap, MajDHTNode provider,
            MajDHTNode downloader, byte[] input, DHTRecord record, DHTRecord alias)
        {
            ProviderIdentity = providerIdentity;
            Bootstrap = bootstrap;
            Provider = provider;
            Downloader = downloader;
            Input = input;
            Record = record;
            Alias = alias;
        }

        /// <summary>Starts three nodes and publishes a multi-block file before the downloader joins.</summary>
        /// <param name="transport">The single enabled transport.</param>
        /// <param name="token">The caller deadline for initialization.</param>
        /// <returns>The initialized network whose nodes must be asynchronously disposed.</returns>
        /// <exception cref="OperationCanceledException">Initialization was cancelled.</exception>
        internal static async Task<ThreeNodeNetwork> CreateAsync(DHTTransport transport, CancellationToken token)
        {
            var identity = new DHTIdentity();
            var bootstrap = new MajDHTNode(Options(transport, DHTCapabilities.Download | DHTCapabilities.Forwarder));
            var provider = new MajDHTNode(Options(transport, DHTCapabilities.Download | DHTCapabilities.Provide), identity);
            MajDHTNode? downloader = null;
            try
            {
                await Task.WhenAll(bootstrap.StartAsync(token), provider.StartAsync(token));
                await provider.JoinAsync(bootstrap.LocalPeer, token);
                var input = Crypto.Random((16384 * 2) + 79);
                using var source = new MemoryStream(input);
                var record = await provider.PublishAsync("songs/test", source, cancellationToken: token);
                var alias = await provider.PublishAliasAsync("songs/alternate", record, cancellationToken: token);
                // The downloader joins through a configured endpoint rather than a pre-shared contact.
                var downloaderOptions = Options(transport, DHTCapabilities.Download);
                var port = transport == DHTTransport.Tcp ? bootstrap.LocalPeer.TcpPort() : bootstrap.LocalPeer.UdpPort();
                downloaderOptions.BootstrapEndpoints = new List<IPEndPoint> { new IPEndPoint(IPAddress.Loopback, port) };
                downloader = new MajDHTNode(downloaderOptions);
                await downloader.StartAsync(token);
                Assert.Equal(1, await downloader.BootstrapAsync(token));
                return new ThreeNodeNetwork(identity, bootstrap, provider, downloader, input, record, alias);
            }
            catch
            {
                if (downloader != null)
                {
                    await downloader.DisposeAsync();
                }
                await provider.DisposeAsync();
                await bootstrap.DisposeAsync();
                throw;
            }
        }

        /// <summary>Stops all nodes and drains their active socket work.</summary>
        /// <returns>Completion after all nodes have been disposed.</returns>
        public async ValueTask DisposeAsync()
        {
            await Downloader.DisposeAsync();
            await Provider.DisposeAsync();
            await Bootstrap.DisposeAsync();
        }
    }
}
