# MajDHTNetwork

**English** | [简体中文](README.zh-CN.md)

MajDHTNetwork is an independent **.NET Standard 2.1** class library in the
`MajDHTNetwork` namespace. A `MajDHTNode` is a DHT participant, a content
provider and an optional end-to-end encrypted relay at the same time. The
library has no Unity assembly dependency and never opens files or directories
by itself: every stream is supplied by the caller. This is the **MajDHT v1**
protocol, not the BitTorrent DHT.

The wire protocol is specified in [PROTOCOL.md](PROTOCOL.md)
([中文](PROTOCOL.zh-CN.md)).

## Contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Repository layout](#repository-layout)
- [Build](#build)
- [Quick start](#quick-start)
- [Public API](#public-api)
- [Identity, keys and integrity](#identity-keys-and-integrity)
- [Encryption and relays](#encryption-and-relays)
- [Bootstrap and discovery](#bootstrap-and-discovery)
- [TCP, UDP and NAT traversal](#tcp-udp-and-nat-traversal)
- [Storage, quotas and lifecycle](#storage-quotas-and-lifecycle)
- [Logging](#logging)
- [Memory ownership and allocations](#memory-ownership-and-allocations)
- [Security scope](#security-scope)
- [Testing and validation](#testing-and-validation)
- [Packaging and distribution](#packaging-and-distribution)
- [License](#license)

## Highlights

- **Authenticated content.** Keys are scoped to a publisher signing identity;
  every publication, contact and block is signed or proof-verified before use.
- **Encrypted requests.** Every RPC uses fresh ephemeral X25519 agreement,
  HKDF-SHA256 and ChaCha20-Poly1305, with an Ed25519 signature over the envelope
  transcript and plaintext.
- **Two transports.** Length-prefixed TCP and datagram UDP with non-amplifying
  source-address cookies, retries and a bounded replay cache.
- **Relay-assisted traversal.** Peers advertising `Relay` observe real endpoints
  and coordinate TCP/UDP punching; when a direct path is impossible, the same
  relay can forward opaque encrypted envelopes.
- **Pluggable storage.** Blocks live behind `IDHTContentStore`; the default
  `MemoryDHTContentStore` is a bounded LRU cache, and applications can supply a
  persistent store.
- **Host-agnostic.** No Unity types, no `System.IO.File`/`FileStream`, structured
  logging through `Microsoft.Extensions.Logging`.

## Requirements

| Item | Value |
| --- | --- |
| Build SDK | .NET 9, selected by `global.json` (`9.0.100`, `rollForward: latestFeature`) |
| Library target | `netstandard2.1`, `LangVersion` 9.0, nullable enabled |
| Test host | `net9.0`, xUnit v3 |
| Direct dependencies | `BouncyCastle.Cryptography` 2.7.0, `Microsoft.Extensions.Logging.Abstractions` 10.0.13 |
| Dependency pinning | `packages.lock.json` (restore with `--locked-mode`) |

## Repository layout

| Path | Contents |
| --- | --- |
| `MajDHTNetwork.csproj` | Library project, package metadata and the explicit `Compile` glob for `src/MajDHTNetwork/**/*.cs`. |
| `MajDHTNetwork.slnx` | Solution containing the library project only. |
| `src/MajDHTNetwork/` | Production sources: node, discovery, content, NAT, protocol and transport. |
| `src/MajDHTNetwork.Tests/` | .NET 9 xUnit v3 test project with real loopback sockets; excluded from the library project. |
| `PROTOCOL.md`, `PROTOCOL.zh-CN.md` | Wire protocol specification (English / Chinese). |
| `Publish.ps1` | Release script: build, test, pack, loose-DLL archive and consumer validation. |
| `LICENSE` | MIT license. |
| `global.json`, `packages.lock.json` | SDK selection and pinned dependency graph. |

## Build

```powershell
dotnet restore MajDHTNetwork.csproj --locked-mode
dotnet build MajDHTNetwork.csproj --configuration Release --no-restore
```

The output is `bin/Release/netstandard2.1/MajDHTNetwork.dll` together with an
English XML API documentation file. The test project is a separate project and
is never compiled into the library.

```powershell
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release
```

## Quick start

The application owns the cancellation token, the streams and any persistent
identity storage. The following is the body of an async method.

```csharp
using System.IO;
using System.Net;
using System.Text;
using MajDHTNetwork;

#nullable enable

// Bind explicit ports; use 0 for OS-assigned ports, or null to disable a listener.
await using var provider = new MajDHTNode(new DHTNodeOptions
{
    ListenAddress = IPAddress.Loopback,
    TcpPort = 42000,
    UdpPort = 42000,
    Capabilities = DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Relay
});
await provider.StartAsync(cancellationToken);

// This public invitation contains signed endpoints and public keys, never private keys.
var invitation = provider.LocalPeer.ToInvitation();

await using var downloader = new MajDHTNode(new DHTNodeOptions
{
    PreferredTransport = DHTTransport.Udp,
    Capabilities = DHTCapabilities.Download
});
await downloader.StartAsync(cancellationToken);
await downloader.BootstrapAsync(DHTPeer.ParseInvitation(invitation), cancellationToken);

using var source = new MemoryStream(Encoding.UTF8.GetBytes("verified file content"));
var record = await provider.PublishAsync("songs/example", source, cancellationToken: cancellationToken);
var alias = await provider.PublishAliasAsync("songs/another-name", record, cancellationToken: cancellationToken);

// Deliver alias.Key to the receiver through a trusted application channel.
using var destination = new MemoryStream();
await downloader.DownloadAsync(alias.Key, destination, record.FileHash, cancellationToken);
```

Publish locally with `DHTIdentity(seed)` restored through `ExportSeed()` when the
node ID and publisher namespace must survive restarts, and implement
`IDHTContentStore` when blocks must outlive the process.

## Public API

### Node operations

| Member | Purpose |
| --- | --- |
| `MajDHTNode(DHTNodeOptions?, DHTIdentity?, IDHTContentStore?)` | Creates a node; every argument is optional and defaults are created internally. |
| `StartAsync(CancellationToken)` | Binds listeners once; the token is a lifetime token. |
| `StopAsync()`, `DisposeAsync()`, `Dispose()` | Idempotent shutdown; a stopped instance cannot be restarted. |
| `NodeId`, `LocalPeer`, `KnownPeers` | Local identity fingerprint, local signed contact and the current routing contacts. |
| `BootstrapAsync(DHTPeer, CancellationToken)` | Introduces a trusted, unexpired contact. |
| `FindNodesAsync(string routingId, CancellationToken)` | Iterative XOR-distance lookup. |
| `PublishAsync(string, Stream, long revision, CancellationToken)` | Publishes a stream under the local publisher namespace. |
| `PublishAliasAsync(string, DHTRecord, long revision, CancellationToken)` | Publishes a second name for already published content. |
| `AnnounceAsync(DHTRecord, CancellationToken)` | Replicates an existing signature; returns the remote replica count. |
| `ResolveAsync(DHTKey, CancellationToken)` | Looks up a signed publication for a key. |
| `FindProvidersAsync(string fileHash, CancellationToken)` | Finds providers of a complete-file hash, independently of keys. |
| `DownloadAsync(DHTKey, Stream, string? expectedFileHash, CancellationToken)` | Resolves, downloads and verifies the complete file. |
| `DownloadAsync(DHTRecord, Stream, string? expectedFileHash, CancellationToken)` | Downloads a known signed record. |
| `ReadBlockAsync(DHTRecord, DHTPeer, int index, DHTPeer? relay, CancellationToken)` | Verified single-block read for application-managed resume or a specific relay. |
| `RegisterRelayAsync(DHTPeer relay, CancellationToken)` | Registers the node's observed endpoint with a relay. |
| `TryPunchAsync(DHTPeer peer, DHTPeer relay, DHTTransport, CancellationToken)` | Attempts a direct TCP or UDP route through relay coordination. |

### `DHTNodeOptions` defaults

| Option | Default |
| --- | --- |
| `ListenAddress` | `IPAddress.Loopback` |
| `AdvertisedAddress` | `null` (use `ListenAddress`; required for a wildcard listener) |
| `TcpPort`, `UdpPort` | `0` (OS-assigned); `null` disables that listener |
| `PreferredTransport` | `DHTTransport.Tcp` |
| `Capabilities` | `Download \| Provide` |
| `BucketSize` | `8` |
| `LookupParallelism` | `3` |
| `MaxLookupQueries` | `64` |
| `MaxConcurrentRequests` | `32` |
| `MaxRecords` | `1024` |
| `MaxFileSize` | `1 GiB` |
| `BlockSize` | `16384` (1 KiB–32 KiB accepted) |
| `RequestTimeout` | `5 s` |
| `UdpAttempts` | `3` |
| `RecordLifetime` | `24 h` (1 s–7 days accepted) |
| `MaintenanceInterval` | `5 min` |
| `EnableNatTraversal` | `true` |
| `NatTraversalTimeout` | `5 s` |
| `NatPollInterval` | `1 s` |
| `NatRegistrationLifetime` | `30 s` (must cover at least three poll intervals) |
| `MaxNatRegistrations` | `256` |
| `MaxNatRelays` | `4` |
| `Logger` | `NullLogger.Instance` |

### Value types and contracts

| Type | Key members |
| --- | --- |
| `DHTIdentity` | `DHTIdentity()`, `DHTIdentity(ReadOnlySpan<byte> seed)`, `NodeId`, `PublicKey`, `ExportSeed()`, `ExportSeed(Span<byte>)` |
| `DHTPeer` | `NodeId`, `Address`, `TcpPort`, `UdpPort`, `Capabilities`, `ExpiresAt`, `IsExpired`, `ToInvitation()`, `ParseInvitation(string)` |
| `DHTKey` | `DHTKey(string publisherId, string name)`, `Parse(string)`, `IsValid`, `PublisherId`, `Name`, `RoutingId`, equality and hashing |
| `DHTRecord` | `Key`, `FileHash`, `MerkleRoot`, `Length`, `BlockSize`, `BlockCount`, `Revision`, `ExpiresAt`, `IsExpired`, `EncodedLength`, `CopyTo(Span<byte>)`, `ToBytes()`, `Parse(ReadOnlySpan<byte>)` |
| `IDHTContentStore` | `PutAsync(string blockHash, ReadOnlyMemory<byte>, CancellationToken)`, `GetAsync(string blockHash, CancellationToken)` |
| `MemoryDHTContentStore` | `MemoryDHTContentStore(long capacity = 64 MiB, int maxEntries = 65536)` |
| `DHTCapabilities` | `Download = 1`, `Provide = 2`, `Relay = 4` |
| `DHTTransport` | `Tcp`, `Udp` |

## Identity, keys and integrity

A `DHTIdentity` owns a 32-byte secret seed. Construct it from a previously saved
`ExportSeed()` to retain the node ID and publisher namespace across restarts. The
caller must persist this secret securely using the application's storage layer.
Public invitations contain only public material.

A canonical key is `publisher-sha256-fingerprint:case-sensitive-name`. Names are
nonempty, at most 256 strict UTF-8 bytes, and cannot contain control characters.
The fingerprint is SHA-256 of the Ed25519 public key. For example, construct a
lookup key using `new DHTKey(trustedPublisherId, "songs/example")` or restore the
canonical value with `DHTKey.Parse`. The DHT routing identifier is SHA-256 of the
UTF-8 canonical key. Different names or publisher namespaces can bind the same
complete-file SHA-256 hash.

`DHTKey` is an immutable value type. Equality and hashing compare its publisher
and name without allocating a canonical string. The default value has
`IsValid == false`, formats as an empty string, and cannot be used for lookups;
reading its components throws `InvalidOperationException`. Construct or parse a
key before using it.

The publisher fingerprint in a trusted key is the authority for its mapping. A
globally unowned human-readable name would let an attacker replace both a file
hash and its metadata. MajDHT therefore scopes names to a signing identity; the
application authenticates the key or publisher fingerprint out of band.

Each `DHTRecord` signs the key, raw-file SHA-256, domain-separated Merkle root,
file length, block size, positive revision and absolute expiry. Importing a
record verifies the signature and its owner fingerprint. A receiver verifies
every block's exact length and Merkle position before writing it, then verifies
the complete raw-file SHA-256 before completing a download. An optional
`expectedFileHash` pins independently trusted content before any output is
written. Providers recheck their own block store before serving a block.

Higher signed revisions supersede lower revisions; conflicting equal-revision
content is rejected. In-memory revision high-water marks survive record expiry
for seven days plus the envelope skew allowance, bounded to four times
`MaxRecords` distinct keys. This prevents a still-valid older record resurfacing
when a newer short lease expires. Neither the DHT nor a fresh client can prove
that an unreachable publisher has not issued a newer revision. Applications
requiring freshness across process restarts must retain and enforce their last
trusted revisions, or pin a complete-file hash. Publication revisions must
increase and must be persisted by the publisher. New publications have a
one-day lease by default, configurable from one second through seven days;
maintenance reannounces existing signatures without extending their expiry.
Renew by publishing a higher revision, including through `PublishAliasAsync`.

## Encryption and relays

Every request and response uses fresh ephemeral X25519 agreement, HKDF-SHA256
and ChaCha20-Poly1305, with an Ed25519 signature covering the envelope transcript
and plaintext. The recipient's signed contact binds its long-lived agreement
public key to its node identity. The random request ID, operation, recipient,
version and sender are authenticated. Responses must match the expected final
node, operation and 128-bit request ID. Messages allow at most two minutes of
clock skew; synchronize node clocks.

The design encrypts to long-lived recipient keys and **does not provide full
forward secrecy** against later compromise of an identity seed. Fresh ephemeral
sender keys do not change this property. It has not undergone an independent
cryptographic audit.

When direct access fails, a node first asks known peers advertising `Relay` to
introduce a direct TCP or UDP path. If traversal cannot establish a path, it
attempts the existing opaque relay operation. The relay receives a separately
encrypted outer RPC containing the destination ID and an opaque inner envelope.
It forwards the inner envelope unchanged and returns the opaque response. Only
the original downloader and provider can open the file request and block
response; the relay can observe endpoints, packet sizes, timing and the visible
operation number. Corrupt relay responses are rejected and other known relays
can be attempted. A relay only forwards to an already authenticated known peer
and rejects explicit nested relay packets. A malicious participant can still
create multiple separate connections; this is not anonymous routing or
protection against Sybil/eclipse attacks.

Use the low-level verified block API for application-managed resume or a
specific relay:

```csharp
var block = await downloader.ReadBlockAsync(record, provider.LocalPeer, 0,
    relay: relayPeer, cancellationToken: cancellationToken);
```

Provider claims are availability hints; a signed contact alone does not prove
possession. Downloads rotate the initial provider between blocks and retry
another provider after invalid or unavailable blocks.

## Bootstrap and discovery

Every running node exports a bootstrap invitation. There is no privileged
bootstrap role, central directory or built-in hardcoded server. A bootstrap
introduces known contacts and a bounded iterative XOR-distance lookup discovers
more nodes. An offline node can publish locally; `AnnounceAsync` or automatic
maintenance replicates its record after peers become available. Publication
returns a signed record even when no remote replica accepted it; a warning is
reported through the optional logger. `AnnounceAsync` returns the remote replica
count.

Bootstrap invitations expire after one day. Maintenance refreshes the running
node's signed contact; distribute a fresh `LocalPeer.ToInvitation()` when needed.
An invitation is self-authenticating, but its initial source still needs to be
trusted if the application requires a particular bootstrap identity. Peers with
the `Relay` capability also provide authenticated rendezvous assistance.

For LAN or Internet use, choose the listening interface and set
`AdvertisedAddress` to the IP address reachable by other nodes. A wildcard
listener requires an explicit advertised address in the same address family.
IPv4 and IPv6 listeners, arbitrary TCP/UDP ports, equal TCP/UDP port numbers and
separate TCP/UDP port numbers are supported. TCP and UDP listeners can be enabled
independently. Outgoing requests try the preferred advertised transport and then
the alternative.

Host names, external STUN servers, UPnP and router port configuration are outside
this library. Signed contacts keep the configured advertised address; observed
NAT endpoints are retained separately as authenticated direct routes.

## TCP, UDP and NAT traversal

Bootstrapping through a peer advertising `Relay` automatically registers each
common enabled transport. A relay observes the actual source address and port of
an authenticated request. UDP requests retain their cookie validation, and TCP
registrations originate from the listening port. Clients refresh these
short-lived registrations and poll for pending introductions until shutdown. A
node can also register explicitly and request a particular direct transport:

```csharp
await provider.RegisterRelayAsync(relayPeer, cancellationToken);
await downloader.RegisterRelayAsync(relayPeer, cancellationToken);
var connected = await downloader.TryPunchAsync(provider.LocalPeer, relayPeer,
    DHTTransport.Udp, cancellationToken);
```

Use `DHTTransport.Tcp` to request TCP simultaneous open. The relay distributes
both observed endpoints and a random, expiring 128-bit ticket. Each peer probes
from its bound listening port. A valid direct probe must match the ticket, peer
identity, transport and observed endpoint; ordinary requests then use the
authenticated direct route. TCP retains the established connection for further
requests. Successful direct transfers can continue while the relay is offline.
The registration loops and outstanding probes drain during `StopAsync`.

Assisted traversal requires a local listener for the transport being punched,
because the outgoing probe must reuse that listener's port. Set
`EnableNatTraversal = false` to disable client registration and automatic
traversal; a peer advertising `Relay` still serves rendezvous requests subject to
its registry limits. Defaults are a five-second traversal budget, one-second
polling interval, 30-second registration lease, at most four assisting relays per
client and 256 registered identities per relay. Introduction queues are bounded
by `MaxConcurrentRequests`, and active tickets by four times that value.

This is best-effort traversal: endpoint-dependent NAT mappings, blocked UDP, TCP
stacks or firewalls that reject simultaneous open, and router policies can
prevent a direct path. Opaque forwarding remains available when the relay can
reach the destination. It reuses live authenticated registrations, including the
existing TCP session or observed UDP mapping when the signed contact advertises a
private endpoint. If an introduced probe succeeds but the following RPC fails,
the requester still tries that same relay's opaque forwarding path.

## Storage, quotas and lifecycle

`IDHTContentStore` stores raw blocks by their domain-separated Merkle leaf hash.
Implementations must be thread-safe, honor cancellation and retain stable read
snapshots. `PutAsync` must copy input if it retains the data after returning. The
node independently verifies store reads, even for custom stores.

The default `MemoryDHTContentStore` is an LRU cache bounded to 64 MiB and 65,536
entries. It can evict old blocks, so a provider can become a partial provider.
For durable publication or files larger than this cache, supply an
application-owned persistent store. In a MajdataPlay host, implement it with
`MajdataPlay.IO.Storage.FileSystem`. The library uses `System.IO.Stream` and
memory streams only; it never uses `System.IO.File`, `System.IO.Directory` or
`FileStream` for filesystem access. Open application streams through the
existing facade, for example `FileSystem.File.Open(sourceLocation).OpenRead()`,
and pass them to the node. Persisting blocks alone does not restore the in-memory
publication index or Merkle trees: republish the original stream with the
application's retained identity and next revision after a restart.

Other defaults include 256 distance buckets with eight peers each, three parallel
lookup queries, 64 queried peers per lookup, 32 concurrent incoming handlers,
1,024 live records, at most 16 providers per content hash, and 131,072 total
locally indexed Merkle leaves. The configured file limit is at most 1 GiB;
smaller blocks may hit the leaf quota first. All encrypted envelopes are bounded
to 60,000 bytes. The 16 KiB default blocks and 32 KiB maximum leave room for
proofs and nested encryption. UDP datagrams use IP fragmentation for larger
blocks; loss retransmits the complete request. There is no MTU-aware application
fragmentation, congestion control, streaming transport multiplexing or bandwidth
scheduler in v1. Use TCP when datagram fragmentation is unsuitable.

UDP requires a stateless source-address cookie before processing a request. The
fixed 69-byte hello and challenge do not amplify traffic; the cookie binds the
source IP, source port, complete ciphertext and a short server time window.
Requests use bounded retries and the node coalesces duplicate authenticated
request IDs in a bounded two-minute reply cache. This limits reflection and
allocation abuse but does not make a public endpoint immune to traffic floods.

`StartAsync` binds listeners once. Its optional token is a lifetime token.
`StopAsync`, `DisposeAsync` and `Dispose` are idempotent, cancel outgoing socket
work and drain incoming handlers and maintenance. A stopped instance cannot be
restarted. Use asynchronous disposal in an async host. Public operations link
explicit cancellation to the node lifetime. Caller streams and a supplied
identity/store remain caller-owned. A custom store or stream that ignores its
cancellation token can delay shutdown.

Download success means the entire requested file was verified. A failure can
leave partial output and cached blocks; use a staging file through `FileSystem`
and commit it only after the task succeeds. The node performs no atomic file
replacement on behalf of the caller.

## Logging

`DHTNodeOptions.Logger` accepts the standard
`Microsoft.Extensions.Logging.ILogger`; it defaults to `NullLogger.Instance`.
Pass a host-created logger, for example one from
`ILoggerFactory.CreateLogger<MajDHTNode>()`. The host owns the logger and its
providers. Node services emit structured Debug/Information/Warning/Error events
with stable event IDs and a Network context. Cached `LoggerMessage.Define`
delegates avoid formatting and boxing on disabled paths. Logger calls may
originate on background threads. Provider exceptions are isolated from node
cleanup. Diagnostic fields include failure types, without copying private
exception messages, keys, seeds or file paths.

## Memory ownership and allocations

`DHTIdentity(ReadOnlySpan<byte>)`, `DHTIdentity.PublicKey`,
`DHTIdentity.ExportSeed(Span<byte>)`, `DHTRecord.Parse(ReadOnlySpan<byte>)` and
`DHTRecord.CopyTo(Span<byte>)` let synchronous callers use their own buffers.
`EncodedLength` specifies the manifest export capacity. `ExportSeed()` and
`ToBytes()` remain explicit convenience methods that return independent arrays.

Async transfers use `ReadOnlyMemory<byte>` because spans cannot outlive an await.
`ReadBlockAsync` returns a verified read-only block whose managed owner remains
alive as long as the result is retained. The default store copies writes once and
returns stable read-only views; eviction does not invalidate existing views.
Callers must treat returned read-only memory as immutable.

The internal `Packet` is a readonly value type that copies memory views. Borrowed
memory keeps its caller-managed lifetime; decoded packets retain their owned
decrypted arrays. Objects that own mutable state, pooled buffers, identities or
persistent signed metadata remain reference types.

Protocol writers and file-read buffers use cleared pooled arrays; readers slice
existing memory without per-field arrays. Ciphertext is written directly into the
pooled final envelope, and Merkle trees use one contiguous node buffer. Proof
verification uses stack storage. Pooled memory never escapes as public async
results. The legacy array-only cryptographic provider is accessed through array
segments with correct offsets, avoiding buffered signing copies. Small owned
arrays remain where persistence, public defensive copies or provider APIs require
ownership.

Measured warmed managed allocations on the Windows .NET 9 Release test host:

| Workload | Before | After |
| --- | ---: | ---: |
| 32 KiB codec round trip | 98,864 B/op | 96 B/op |
| 32 KiB Merkle leaf | 33,048 B/op | 192 B/op |
| 128-leaf Merkle tree | 46,120 B/op | 8,576 B/op |
| SHA-256 hexadecimal formatting | 1,376 B/op | 152 B/op |
| 32 KiB encrypted packet round trip | 700,807 B/op | about 95,000 B/op |
| Cached 32 KiB block read | — | 0 B/op |
| Disabled logger event | — | 0 B/op |

These measurements use `GC.GetAllocatedBytesForCurrentThread`, warm pools and
providers before measuring, and exclude native allocations and network I/O. They
are allocation regressions rather than throughput or cross-runtime claims.

## Security scope

- Recipient keys are long-lived, so the protocol **does not** provide full
  forward secrecy; compromising an identity seed exposes historical traffic.
- The implementation has **not** been independently audited.
- Relays hide payloads but observe endpoints, sizes, timing and operation numbers.
  This is not anonymous routing and does not resist Sybil or eclipse attacks.
- Provider advertisements are hints; only signed records, Merkle proofs and the
  complete-file hash are authoritative.
- Applications must authenticate keys, publisher fingerprints and bootstrap
  contacts out of band, and must persist identity seeds and revisions securely.
- Freshness beyond a lease is the application's responsibility; pin a complete-file
  hash when content must never change.

## Testing and validation

The test project references the real `netstandard2.1` library and runs real
loopback TCP/UDP sockets; see [its README](src/MajDHTNetwork.Tests/README.md) for
the test inventory and selection filters.

```powershell
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release --filter 'Category=Allocation'
```

Coverage includes protocol vectors and malformed input, authenticated envelopes
and impersonation, Merkle geometry, three-node discovery and downloads, relay
fallback, dual-transport and IPv6 transfers, UDP loss/replay, NAT registration and
punching, quota and lifecycle limits, and warmed allocation budgets.

.NET Standard is an API target, not evidence of successful Unity, Mono, IL2CPP,
Player, mobile, NAT, WAN or hardware integration. Those hosts and network
conditions need their own tests before deployment.

## Packaging and distribution

The package ID, assembly name and public root namespace are all `MajDHTNetwork`;
the current version is `0.1.0`.

```xml
<PackageReference Include="MajDHTNetwork" Version="0.1.0" />
```

```powershell
dotnet pack MajDHTNetwork.csproj --configuration Release --output artifacts/nuget
```

The package contains the netstandard2.1 DLL, the XML documentation file,
`README.md`, `PROTOCOL.md` and `LICENSE`; test sources are excluded. Upload the
`.nupkg` to the chosen feed using that feed's normal release process.

`Publish.ps1` automates the full release flow: locked restore, Release build, the
regression and allocation tests, the NuGet and symbol packages, a loose-DLL ZIP
with runtime dependencies and third-party license notices, and validation of
isolated NuGet and direct-DLL consumers. It produces:

- `artifacts/nuget/MajDHTNetwork.<version>.nupkg`
- `artifacts/nuget/MajDHTNetwork.<version>.snupkg`
- `artifacts/MajDHTNetwork.<version>.dll.zip`
- `artifacts/dll/<version>/`, the uncompressed DLL distribution

For direct DLL consumers, deploy the dependency DLLs included in the ZIP as well
as `MajDHTNetwork.dll`; target frameworks with equivalent built-in assemblies may
resolve those dependencies from their framework. The binary-consumer regression
checks this form of integration on .NET 9.

`Publish.ps1` and `ValidatePackage.ps1` resolve the test project, the runtime
license and the repository root relative to the upstream repository layout
(`Tools/CSharp/MajDHTNetwork` and `Tools/Tests/MajDHTNetwork.Tests`). When running
from a relocated copy, use the `dotnet` commands above or adjust those paths.

## License

MIT. See [LICENSE](LICENSE).

## Protocol

- [PROTOCOL.md](PROTOCOL.md) — MajDHT v1 wire protocol, English.
- [PROTOCOL.zh-CN.md](PROTOCOL.zh-CN.md) — MajDHT v1 线协议，中文。
