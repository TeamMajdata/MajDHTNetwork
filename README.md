# MajDHTNetwork

**English** | [简体中文](README.zh-CN.md)

MajDHTNetwork is an independent **.NET Standard 2.1** class library in the
`MajDHTNetwork` namespace. A `MajDHTNode` is a DHT participant and a content
provider, and can also act as a Traversal node that coordinates direct
connections or as a Forwarder that relays end-to-end encrypted envelopes. The
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
- [Implementing a node with the protocol API](#implementing-a-node-with-the-protocol-api)
- [Identity, keys and integrity](#identity-keys-and-integrity)
- [Encryption and forwarding](#encryption-and-forwarding)
- [Bootstrap and discovery](#bootstrap-and-discovery)
- [TCP, UDP and NAT traversal](#tcp-udp-and-nat-traversal)
- [Custom routing](#custom-routing)
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
- **Observed endpoints only.** No node announces where it listens: a peer's
  endpoint is what the nodes exchanging packets with it observe, and referrals
  carry the referrer's observations alongside the signed contact.
- **Traversal and Forwarder roles.** Peers advertising `Traversal` observe the
  endpoints of registered peers, let them exchange those endpoints and
  coordinate TCP/UDP hole punching; peers advertising `Forwarder` host
  forwarding sessions and relay opaque encrypted envelopes, so two peers that
  cannot connect directly still communicate.
- **Reachability discovery for home networks.** Nodes behind NAT learn their
  external address from independent observers, verify it with an independent
  dial-back and otherwise carry signed hints to Traversal nodes and Forwarders.
- **Dual-stack listeners and endpoint bootstrap.** One node can listen on IPv4 and
  IPv6 at once and join the network through configured bootstrap endpoints.
- **Pluggable storage.** Blocks live behind `IDHTContentStore`; the default
  `MemoryDHTContentStore` is a bounded LRU cache, and applications can supply a
  persistent store.
- **Open protocol API.** The envelope, operation codecs, Merkle, identity-work and
  socket transport types are public, so applications can implement their own node
  and interoperate with `MajDHTNode`.
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
| `IMPLEMENTING.md`, `IMPLEMENTING.zh-CN.md` | Guide to the protocol flows, the public API and building a custom node (English / Chinese). |
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
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using MajDHTNetwork;

#nullable enable

// Bind explicit ports on IPv4 and IPv6; use 0 for OS-assigned ports, or null to disable a listener.
await using var provider = new MajDHTNode(new DHTNodeOptions
{
    ListenAddresses = new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback },
    TcpPort = 42000,
    UdpPort = 42000,
    Capabilities = DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Traversal | DHTCapabilities.Forwarder
});
await provider.StartAsync(cancellationToken);

// Join through a known node's endpoint; the node returns its signed contact itself.
await using var downloader = new MajDHTNode(new DHTNodeOptions
{
    PreferredTransport = DHTTransport.Udp,
    Capabilities = DHTCapabilities.Download,
    BootstrapEndpoints = { new IPEndPoint(IPAddress.Loopback, 42000) }
});
await downloader.StartAsync(cancellationToken);
await downloader.BootstrapAsync(cancellationToken);

using var source = new MemoryStream(Encoding.UTF8.GetBytes("verified file content"));
var record = await provider.PublishAsync("songs/example", source, cancellationToken: cancellationToken);
var alias = await provider.PublishAliasAsync("songs/another-name", record, cancellationToken: cancellationToken);

// Deliver alias.Key to the receiver through a trusted application channel.
using var destination = new MemoryStream();
await downloader.DownloadAsync(alias.Key, destination, record.FileHash, cancellationToken);
```

Create an identity once with `DHTIdentity.Create(options.IdentityWorkBits)`, which
searches for a key meeting the network's identity work and can take seconds, and
restore it with `DHTIdentity(seed)` from `ExportSeed()` so the node ID, publisher
namespace and work survive restarts. A node constructed without an identity
creates one itself. Implement `IDHTContentStore` when blocks must outlive the
process.

## Public API

### Node operations

| Member | Purpose |
| --- | --- |
| `MajDHTNode(DHTNodeOptions?, DHTIdentity?, IDHTContentStore?, IDHTRoutingTable?, IDHTRouteSelector?, IDHTContentFallback?)` | Creates a node; every argument is optional and defaults are created internally. |
| `StartAsync(CancellationToken)` | Binds listeners once and starts a background bootstrap when endpoints are configured; the token is a lifetime token. |
| `StopAsync()`, `DisposeAsync()`, `Dispose()` | Idempotent shutdown; a stopped instance cannot be restarted. |
| `NodeId`, `LocalContact`, `LocalPeer`, `KnownPeers`, `ExternalAddresses` | Local identity fingerprint, local signed contact, that contact paired with the local listener endpoints for out-of-band handover, the current routing peers at their observed endpoints, and the external addresses confirmed by independent observers. |
| `BootstrapAsync(CancellationToken)` | Contacts every configured bootstrap endpoint and returns how many answered. |
| `AddPeerAsync(IPEndPoint, DHTTransport? preferredTransport, CancellationToken)` | Contacts one node at an address and port, trying the given transport first, admits it and returns it at the endpoint that answered. |
| `ExportRoutingTable()` | Exports the identities and observed endpoints of the current routing contacts for persistence; usable at any time. |
| `RestoreRoutingTableAsync(ReadOnlyMemory<byte>, CancellationToken)` | Re-contacts the nodes of an exported routing table, admits those that still answer under their saved identity and returns how many did. |
| `FindNodesAsync(string routingId, CancellationToken)` | Iterative XOR-distance lookup. |
| `PublishAsync(string, Stream, long revision, CancellationToken)` | Publishes a stream under the local publisher namespace. |
| `PublishAsync(string, ReadOnlyMemory<byte> leaves, string fileHash, long length, long revision, CancellationToken)` | Signs and announces a record for blocks already in the content store from their Merkle leaves, whole-file hash and length, without reading them. |
| `PublishAliasAsync(string, DHTRecord, long revision, CancellationToken)` | Publishes a second name for already published content. |
| `AnnounceAsync(DHTRecord, CancellationToken)` | Replicates an existing signature or any withdrawal; returns the remote replica count. |
| `UnpublishAsync(string name, long revision, CancellationToken)` | Signs and replicates a withdrawal of a key in the local publisher namespace; revision 0 picks the next one. |
| `StopProviding(string fileHash)` | Stops serving a file locally without withdrawing any key. |
| `ImportContentAsync(DHTRecord, Stream, CancellationToken)` | Verifies a local copy against an existing signed record, of any publisher, serves it and returns the remote replica count. |
| `ImportContentAsync(DHTRecord, ReadOnlyMemory<byte> leaves, CancellationToken)` | Serves content whose blocks are already in the content store from its Merkle leaves, checked against the signed record, without reading them; returns the remote replica count. |
| `ResolveAsync(DHTKey, CancellationToken)` | Looks up a signed publication for a key. |
| `FindProvidersAsync(string fileHash, CancellationToken)` | Finds providers of a complete-file hash, independently of keys. |
| `DownloadAsync(DHTKey, Stream, string? expectedFileHash, CancellationToken)` | Resolves, downloads and verifies the complete file. |
| `DownloadAsync(DHTRecord, Stream, string? expectedFileHash, CancellationToken)` | Downloads a known signed record. |
| `ReadBlockAsync(DHTRecord, DHTPeer, int index, DHTPeer? forwarder, CancellationToken)` | Verified single-block read for application-managed resume or through a specific Forwarder. |
| `RegisterTraversalAsync(DHTPeer traversal, CancellationToken)` | Registers the node's observed endpoints with a Traversal node and keeps the registration alive. |
| `RegisterForwarderAsync(DHTPeer forwarder, CancellationToken)` | Opens a forwarding session with a Forwarder and keeps it alive, so the Forwarder can deliver traffic to this node. |
| `TryPunchAsync(DHTPeer peer, DHTPeer traversal, DHTTransport, CancellationToken)` | Attempts a direct TCP or UDP route coordinated by a Traversal node. |
| `PeerStatistics`, `GetPeerStatistics(string nodeId)` | Packet-loss statistics per peer and route collected during the node lifetime. |

### `DHTNodeOptions` defaults

| Option | Default |
| --- | --- |
| `ListenAddresses` | `{ IPAddress.Loopback }` (one or two entries, at most one per address family) |
| `PubliclyReachable` | `false` (discover reachability through dial-backs; `true` claims Public reachability at once) |
| `BootstrapEndpoints` | empty (at most sixteen) |
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
| `MaxLocalLeaves` | `131072` total Merkle leaves of served content (1–16,777,216 accepted) |
| `IdentityWorkBits` | `12` (0–20 accepted; must match across the network) |
| `DisjointLookupPaths` | `3` (1–8 accepted) |
| `MaxConcurrentBlockRequests` | `8` (1–64 accepted) |
| `MaxBlockRequestsPerPeer` | `2` (1–16 accepted) |
| `RequestTimeout` | `5 s` |
| `UdpAttempts` | `3` |
| `RecordLifetime` | `24 h` (1 s–7 days accepted) |
| `MaintenanceInterval` | `5 min` |
| `RepublishInterval` | `30 min` (1 s–45 min accepted) |
| `EnableNatTraversal` | `true` (register with Traversal nodes, open forwarding sessions, check reachability, punch) |
| `NatTraversalTimeout` | `5 s` |
| `NatPollInterval` | `1 s` |
| `NatRegistrationLifetime` | `30 s` (must cover at least three poll intervals) |
| `ReachabilityCheckInterval` | `30 min` (1 min–1 day accepted) |
| `MaxNatRegistrations` | `256` (hosted traversal registrations, hosted forwarding sessions and retained direct routes, each) |
| `MaxTraversalNodes` | `4` (1–16 accepted) |
| `MaxForwarders` | `4` (1–16 accepted) |
| `Logger` | `NullLogger.Instance` |

### Value types and contracts

| Type | Key members |
| --- | --- |
| `DHTIdentity` | `DHTIdentity()`, `DHTIdentity(ReadOnlySpan<byte> seed)`, `NodeId`, `PublicKey`, `ExportSeed()`, `ExportSeed(Span<byte>)`, `IdentityWork`, `Create(int workBits, CancellationToken)` |
| `DHTContact` | The signed contact: `NodeId`, `Hints`, `Reachability`, `HasEndpointDependentMapping`, `Capabilities`, `IdentityWork`, `Sequence`, `ExpiresAt`, `IsExpired`, `Encoded`, `Create(...)`, `Parse(ReadOnlyMemory<byte>)`, `SameAdvertisement(DHTContact)` |
| `DHTPeer` | A contact at the endpoints observed for it: `Contact`, `Endpoints`, the contact's members, `DHTPeer(DHTContact, IReadOnlyList<DHTEndpoint>)`, `Observed(DHTContact, DHTTransport, IPEndPoint)`, `Create(DHTIdentity, IPAddress, int tcpPort, int udpPort, DHTCapabilities)`, `WithContact`, `WithEndpoint`, `Merge`, `SameEndpoints`, `WasObservedAt`, `Write`, `Read` |
| `DHTEndpoint` | An observed endpoint: `DHTEndpoint(IPAddress, int tcpPort, int udpPort)`, `Observed(DHTTransport, IPEndPoint)`, `Address`, `TcpPort`, `UdpPort`, `Port(DHTTransport)`, `ToIPEndPoint(DHTTransport)`, `Merge`, `Write`, `Read` |
| `DHTReachability` | `Unknown = 0`, `Public = 1`, `Private = 2` |
| `DHTKey` | `DHTKey(string publisherId, string name)`, `Parse(string)`, `IsValid`, `PublisherId`, `Name`, `RoutingId`, equality and hashing |
| `DHTRecord` | `Key`, `IsWithdrawn`, `FileHash`, `MerkleRoot`, `Length`, `BlockSize`, `BlockCount`, `Revision`, `ExpiresAt`, `IsExpired`, `EncodedLength`, `CopyTo(Span<byte>)`, `ToBytes()`, `Parse(ReadOnlySpan<byte>)`, `Create(...)`, `CreateWithdrawal(...)` |
| `IDHTContentStore` | `PutAsync(string blockHash, ReadOnlyMemory<byte>, CancellationToken)`, `GetAsync(string blockHash, CancellationToken)` |
| `IDHTContentFallback` | `TryAcquireAsync(DHTRecord, CancellationToken)`; makes requested but locally unavailable content available on demand |
| `MemoryDHTContentStore` | `MemoryDHTContentStore(long capacity = 64 MiB, int maxEntries = 65536)` |
| `IDHTRoutingTable` | `Initialize(string localNodeId, int bucketSize)`, `Observe(DHTContact, DHTEndpoint? observed)`, `Remove(string nodeId)`, `Closest(string routingId, int count)` |
| `KademliaDHTRoutingTable` | `KademliaDHTRoutingTable(int maxPerNetworkInBucket = 2, int maxPerNetwork = 10)`; default table of 256 XOR buckets with per-network limits |
| `IDHTRouteSelector` | `SelectDirectRoutes(DHTPeer, DHTRouteContext)`, `SelectAssistedRoutes(DHTPeer, IReadOnlyList<DHTPeer> knownAssistants, DHTRouteContext)` |
| `DefaultDHTRouteSelector` | Default route selection described in [Custom routing](#custom-routing) |
| `DHTRouteContext` | `PreferredTransport`, `AlternateTransport`, `NatTraversalEnabled`, `MaxAssistedAttempts`, `IsRegisteredWith(string)`, `GetPeerStatistics(string)`, `PacketLossRate(string)`, `PacketLossRate(string, DHTDirectRoute)` |
| `DHTPeerStatistics` | `NodeId`, `SentPackets`, `LostPackets`, `PacketLossRate`, `LastUpdated`, `Routes`, `GetRoute(IPEndPoint, DHTTransport)` |
| `DHTRouteStatistics` | `Endpoint`, `Transport`, `SentPackets`, `LostPackets`, `PacketLossRate`, `LastUpdated` |
| `DHTDirectRoute`, `DHTAssistedRoute` | `Endpoint`, `Transport`; `Assistant`, `AttemptPunch` |
| `DHTCapabilities` | `Download = 1`, `Provide = 2`, `Traversal = 4`, `Forwarder = 8` |
| `DHTTransport` | `Tcp`, `Udp` |

## Implementing a node with the protocol API

`MajDHTNode` is one implementation of the MajDHT v1 protocol, not a mandatory
one. Everything it uses to speak the protocol is public, so an application can
write its own participant, whether a minimal client, a specialised index or a
port of the node logic, and interoperate with reference nodes. The wire format
is specified in [PROTOCOL.md](PROTOCOL.md); the types below implement it and
are exactly the ones the reference node uses, so a custom node encodes and
verifies messages the same way. [IMPLEMENTING.md](IMPLEMENTING.md) explains the
protocol flows, what each public type means, how to extend `MajDHTNode` through
its constructor, and how to build an independent node step by step.

| Type (`MajDHTNetwork.Protocol` unless noted) | Purpose |
| --- | --- |
| `Wire` | Canonical encoder over a pooled buffer and zero-copy decoder: `PutByte`/`Byte`, `PutLong`/`Long`, `Put`/`Bytes(limit)`, `PutText`/`Text(limit)`, `PutRaw`, `PutHex`, `Tag`, `End`, `WrittenMemory`, `ToArray`, `MaxPacket`. |
| `Operation` | The operation byte: `Ping`, `Find`, `Store`, `Block`, `Forward`, `Traversal`, `Punch`, `Hello`, `Probe`; responses set bit 7. |
| `Packet` | One request or response: `Packet(sender, requestId, kind, body)`, `Seal(identity, recipient)`, `SealHello(identity)`, `Open(identity, envelope)`, `CheckForward(envelope, destinationId)`, `Sender`, `RequestId`, `Kind`, `Body`, `RequestIdLength`. |
| `ResponseStatus` | The status wrapper of every response body: `WriteSuccess`, `WriteRejection`, `ReadResult`. |
| `FindMessage`, `FindMode`, `FindRequest`, `FindResponse`, `PeerList` | Find request and result codecs with bounded, independently verified peer lists: each entry is a signed contact with the responder's observed endpoints. |
| `StoreMessage`, `BlockMessage`, `BlockRequest` | Store and Block codecs; `BlockMessage.ReadResponse` verifies block length, position and Merkle proof against the requester's own record. |
| `ForwardMessage`, `ForwardAction`, `ForwardRelayRequest` | Forwarding codec: forwarding sessions, relaying an opaque envelope through a Forwarder and delivering it to the destination; `ReadRelayRequest` and `ReadDeliverRequest` enforce the forwarding rules on the inner envelope. |
| `HelloMessage`, `ObservedEndpoint` | Hello result and the observed-endpoint encoding shared with Traversal and Forward sessions. |
| `TraversalMessage`, `TraversalAction`, `TraversalIntroduction`, `TraversalPollResponse`, `DialBackArrangement`, `DialBackDelegation`, `PunchMessage`, `ProbeMessage`, `ProbeRequest` | Registration, introduction, dial-back, punch and probe codecs for Traversal-coordinated direct connections and reachability. |
| `MerkleTree` | Domain-separated leaf and parent hashing: `Leaf`, `AppendLeaf`, `Root`, `Count`, `LeafId`, `WriteProof`, `Proof`, `Verify`, `VerifyLocal`. |
| `Crypto` | `Hash`, `HashPrefixed`, `Hex`, `HexTo`, `ParseHash`, `IsHash`, `AsciiEquals`, `Random`, `Fill`, `Shuffle`, `Verify`, `Hkdf` and the digest, agreement-key, nonce and tag lengths. |
| `IdentityPuzzle` | The Argon2id identity work: `Evaluate`, `Work`, `Remember`, `Search` and its parameters. |
| `ProtocolTags`, `NetworkScope`, `XorDistanceComparer` | Canonical labels, address scope and network-prefix rules, XOR distance ordering. |
| `OwnedMemory`, `OwnedPacket`, `PooledBuffer` | Ownership of the pooled frames that received envelopes borrow. |
| `MajDHTNetwork.Transport.SocketTransport`, `DHTEnvelopeHandler`, `TransmissionCounter` | TCP framing, UDP cookies and retries, listeners and sessions: `SocketTransport(options, handler)`, `Bind`, `Run`, `ExchangeAtAsync`, `PunchAsync`, `TcpPort`, `UdpPort`, `PortFor`, `Stop`, `DisposeAsync`. |
| `DHTContact`, `DHTPeer`, `DHTEndpoint`, `DHTRecord`, `DHTIdentity`, `DHTNodeOptions` (root namespace) | `DHTContact.Create`, `Parse`, `Encoded`, `NodeHash`, `SigningKey`, `AgreementKey`, `SameAdvertisement`; `DHTPeer.Write`, `Read`, `Observed`; `DHTEndpoint.Write`, `Read`; `DHTRecord.Create`, `CreateWithdrawal`, `ParseCached`, `Encoded`, `SameContent`; `DHTIdentity.Sign`, `SignTo`, `AgreementPublicKey`, `NodeHash`, `NextSequence`; `DHTNodeOptions.Snapshot`. |

A node implementation receives envelopes through a `DHTEnvelopeHandler`, opens
them with `Packet.Open`, reads the body with the operation's codec, writes the
result and the `ResponseStatus` wrapper into a `Wire`, and seals the reply to
the authenticated sender. The transport releases the received frame when the
handler's task completes, so anything kept from a request must be copied.
Requests are sent with `Packet.Seal` and `SocketTransport.ExchangeAtAsync`; the
caller authenticates the response sender, operation and request identifier
before reading the result. The identity work, replay cache, routing admission,
quotas and Sybil policies described in this document are node policies, not
codecs: a custom node applies its own.

```csharp
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using MajDHTNetwork;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

// A participant that answers Ping and Hello and serves nothing else.
var identity = new DHTIdentity();
DHTPeer self = null!;
var transport = new SocketTransport(new DHTNodeOptions { UdpPort = null }, (envelope, kind, source, token) =>
{
    var request = Packet.Open(identity, envelope);
    using var result = new Wire();
    using var body = new Wire();
    try
    {
        using var reader = new Wire(request.Body);
        switch ((Operation)request.Kind)
        {
            case Operation.Ping:
                reader.End();
                break;
            case Operation.Hello:
                HelloMessage.ReadRequest(reader);
                HelloMessage.WriteResponse(result, source);
                break;
            default:
                throw new IOException("Unsupported operation.");
        }
        ResponseStatus.WriteSuccess(body, result.WrittenSpan);
    }
    catch (Exception)
    {
        ResponseStatus.WriteRejection(body);
    }
    var reply = new Packet(self, request.RequestId, (byte)(request.Kind | 128), body.WrittenMemory);
    return Task.FromResult<ReadOnlyMemory<byte>>(reply.Seal(identity, request.Sender));
});
transport.Bind();
self = DHTPeer.Create(identity, IPAddress.Loopback, transport.TcpPort, 0, DHTCapabilities.Download);
transport.Run();
```

The test project's `MinimalProtocolNode` is a complete example built only on
this API: it serves a file, indexes announcements, downloads from reference
nodes and is discovered and downloaded from by them.

## Identity, keys and integrity

A `DHTIdentity` owns a 32-byte secret seed. Construct it from a previously saved
`ExportSeed()` to retain the node ID and publisher namespace across restarts. The
caller must persist this secret securely using the application's storage layer.
Signed contacts contain only public material.

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

### Withdrawing a publication

`UnpublishAsync(name)` signs a withdrawal: a record of the same key with a
higher revision, `IsWithdrawn` set and no content. Its revision exceeds every
revision known locally and found in the DHT, and its lease lasts at least as long
as the latest withdrawn publication, so the old signature cannot be reannounced
after the withdrawal expires. The node replicates it near the key and the
withdrawn file hash, and maintenance reannounces it until it expires. Any node
may replicate a withdrawal with `AnnounceAsync`. Honest nodes that receive it
resolve the key as withdrawn (`ResolveAsync` returns the withdrawal and
`DownloadAsync(key)` throws `FileNotFoundException`), drop provider claims and
local content that no other live publication references, and keep refusing older
revisions through the revision floor. Publishing the name again requires a
revision above the withdrawal.

A withdrawal revokes the binding from a key to content, not the content: nodes
that already downloaded the file keep their copies, other keys or publishers can
bind the same file hash, and dishonest nodes can ignore the withdrawal.
`StopProviding(fileHash)` only stops this node from serving a file; other nodes
keep its earlier provider claims until they expire and fail over to other
providers.

### Serving another publisher's content

A node can provide content it did not publish itself. `ImportContentAsync(record,
stream)` reads a local copy, for example a file kept by a replica across restarts,
checks it against the signed length, Merkle root and complete-file hash of an
existing publication, registers it and announces this node as a provider, without
downloading anything. `ImportContentAsync(record, leaves)` registers the same
content from the persisted Merkle leaves of blocks the content store already
holds, without reading them (see [Publishing many files](#publishing-many-files)).
A node constructed with an `IDHTContentFallback` asks it
whenever a peer requests a block of signed content that is not registered locally;
the fallback can import a local copy or download the file, after which the block is
served. A peer can address such a pull-through replica directly with
`ReadBlockAsync(record, replicaPeer, index)`. The request waits only within its own
timeout, so the fallback should bound its wait and let longer work continue in the
background; the peer otherwise fails over to other providers. Implementations must
be thread-safe and should coalesce concurrent requests for the same content, and
must decide which publishers they trust.

## Encryption and forwarding

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

When direct access fails, a node first uses the hints in the destination's
signed contact, then other routed peers advertising `Traversal` or `Forwarder`.
A hinted Traversal node this node is already registered with is asked to
introduce a direct TCP or UDP path; a Forwarder relays the request. The
Forwarder receives a separately encrypted outer RPC containing the destination
ID and an opaque inner envelope, delivers the inner envelope unchanged inside
its own authenticated request to the destination's forwarding session and
returns the opaque response. Only the original downloader and provider can open
the file request and block response; the Forwarder can observe endpoints,
packet sizes, timing and the visible operation number. Corrupt forwarded
responses are rejected and other known Forwarders can be attempted. A Forwarder
only relays to a node holding a live forwarding session with it or to an
already authenticated routed peer, and rejects nested forwards and control
operations. A destination accepts a delivery only from a Forwarder and learns
no endpoint for the origin from it. A malicious participant can still create
multiple separate connections; this is not anonymous routing or protection
against Sybil/eclipse attacks.

Use the low-level verified block API for application-managed resume or a
specific Forwarder:

```csharp
var block = await downloader.ReadBlockAsync(record, providerPeer, 0,
    forwarder: forwarderPeer, cancellationToken: cancellationToken);
```

Provider claims are availability hints; a signed contact alone does not prove
possession. A download requests blocks from several providers at once: at most
`MaxConcurrentBlockRequests` blocks are in flight in total and at most
`MaxBlockRequestsPerPeer` per provider. Each block goes to the provider ranked
best among those with a free slot: the local node first, then lower measured
packet loss, fewer requests in flight and fewer failures. An invalid or
unavailable block returns to the queue for another provider, and the download
fails only after every provider failed that block. Verified blocks are written
to the destination, the digest and the store in order, with a reorder window of
twice `MaxConcurrentBlockRequests` blocks bounding the memory held for blocks
that arrive early. Over TCP one connection carries one request at a time, so
parallelism mainly comes from using several providers.

### Peer statistics

For its whole lifetime a node records, per peer and per route (endpoint and
transport), how many request transmissions it sent and how many received no
response before their attempt timeout. Every UDP retransmission and TCP attempt
counts; hole-punching and dial-back probes do not, and requests relayed
through a Forwarder count towards the Forwarder. `GetPeerStatistics(nodeId)` and
`PeerStatistics` return immutable `DHTPeerStatistics` snapshots whose
`PacketLossRate` is `LostPackets / SentPackets`, with a per-route breakdown in
`Routes` and `GetRoute(endpoint, transport)`. At most 4,096 peers and 16 routes
per peer are retained, evicting the least recently updated entry. Route
selection and download scheduling use these rates.

## Bootstrap and discovery

Any running node can serve as a bootstrap node. There is no privileged bootstrap
role, central directory or built-in hardcoded server. List the endpoints of known
nodes in `DHTNodeOptions.BootstrapEndpoints`; `StartAsync` contacts them in the
background, maintenance retries them while the routing table is empty, and
`BootstrapAsync` contacts them explicitly and returns how many answered. Each
endpoint answers a signed Hello request with its signed contact and the endpoint
it observed for the caller. A bootstrap introduces known contacts and a bounded
iterative XOR-distance lookup discovers more nodes. An offline node can publish
locally; `AnnounceAsync` or automatic maintenance replicates its record after
peers become available. Publication returns a signed record even when no remote
replica accepted it; a warning is reported through the optional logger.
`AnnounceAsync` returns the remote replica count.

`AddPeerAsync(endpoint, preferredTransport)` does the same for one endpoint
learned at run time, for example an address a user typed or one the application
received through its own channel: it sends the Hello through the given transport
first (the node's `PreferredTransport` when null), then through the other
transport at the same port if the first does not answer, admits the node that
answered, registers with it when it is a Traversal node or Forwarder, discovers
neighbors and returns the node at the endpoint that answered. It throws
`IOException` when neither transport answers.

An endpoint does not identify a node: whoever answers at a configured or added
endpoint becomes the first contact. Configure bootstrap endpoints and add peers
only from trusted sources. Peers with the `Traversal` capability coordinate
direct connections and reachability checks; peers with the `Forwarder`
capability relay traffic for the nodes holding a forwarding session with them.

### Persisting the routing table

`ExportRoutingTable()` returns a small snapshot of the identities and observed
endpoints of the current routing contacts, nearest first; it works before the
node starts and after it stopped, and the library never writes it anywhere
itself. After a restart, `RestoreRoutingTableAsync(snapshot)` on a running node
sends a Hello to every saved endpoint, at most sixteen contacts at a time, admits
each node that still answers under its saved identity, registers with the
answering Traversal nodes and Forwarders when NAT traversal is enabled, and then
discovers the current neighbors; it returns how many contacts were admitted.
Endpoints that no longer
answer, or now answer under another identity, are skipped, so an old snapshot
costs a few request timeouts and nothing else. A malformed snapshot throws
`InvalidDataException`. Contact leases last at most a day, which is why the
snapshot keeps endpoints rather than signed contacts. Restoring and bootstrapping
combine freely: a node with a snapshot and bootstrap endpoints contacts both.

### Publishing many files

Publications read, hash and store their streams concurrently; only the moment a
signed record is registered is serialized per node, and a revision that another
publication or withdrawal advanced meanwhile is rejected with
`ArgumentException`. Each replication looks up the nodes near the key and near
the file hash at once and sends its Store requests in parallel. Replications are
admitted one slot at a time so that their requests, together with those of other
work, stay within `MaxConcurrentRequests` outgoing exchanges: the two lookups
run at once only when both fit, and the number of replications in flight is
`MaxConcurrentRequests` divided by that footprint, at least one (one with the
defaults, raise `MaxConcurrentRequests` for more). Maintenance reannounces
records with the same bound, so the maintenance of many publications also runs
in parallel where the budget allows, but it does not take slots from
publications. Each `MaintenanceInterval` the node starts a reannouncement pass,
unless the previous one is still running, over the records that last reached a
replica under their revision at least `RepublishInterval` ago (30 minutes by
default), so a pass during a long bulk publication does not repeat the
announcements it just made. While a publication, import, renewal or withdrawal
waits for or holds a replication slot, and for one second after the last one
ends, the pass yields: it starts no reannouncement. A record stops yielding once
its last accepted announcement is 45 minutes old, because its provider claims
carry this node's contact, whose lease is one hour while reachability is
unverified; the pass handles the records closest to that point first, and a
record that a publication announced meanwhile is skipped. The pass runs apart
from the maintenance loop, which keeps renewing the contact and pruning on time.
A contact change still reannounces every record at once. With 35,000 records,
the default `RepublishInterval` takes about 20 reannouncements per second where
a five-minute one would need about 120. The index of
records, revisions, provider claims and local trees is pruned at most once per
second on the paths that cache or register a record, and at once when a quota
appears full, and the total of local Merkle leaves is kept in step as trees are
registered, replaced and removed, so the leaf quota check never walks every
tree. Publishing or receiving many records therefore costs time linear in their
number.

A publisher with many files need not read them again after a restart. Besides
the blocks themselves, all the node needs to serve a file is its leaves: the
32-byte block digests `MerkleTree.Leaf` computes, concatenated in block order.
An application that keeps its blocks in a persistent `IDHTContentStore` and
persists each file's leaves, whole-file hash and length can resume serving with
`ImportContentAsync(record, leaves)` while the signed record is unexpired, and
sign a fresh revision with `PublishAsync(name, leaves, fileHash, length,
revision)` once it is not; neither call reads the content. Both check the leaves
against the record's block count and Merkle root, or against the length at the
configured block size, and apply the same expiry and leaf-quota checks as their
stream-based counterparts; neither checks that the blocks are present, so a
missing or altered block fails only the requests for that block.

`ListenAddresses` takes one address, or one IPv4 and one IPv6 address for
dual-stack listeners on the same configured ports; wildcard addresses are
allowed. Arbitrary TCP/UDP ports, equal or separate TCP/UDP port numbers, and
independently enabled TCP and UDP listeners are supported. A signed contact
never names the node's own endpoints: every node sends from its listening
ports, so the nodes it talks to observe where it can be reached, keep up to four
observed addresses per contact with their TCP and UDP ports, and pass them on in
referrals. `LocalPeer` pairs the local contact with the listener endpoints for
handing it to another process on the same host. Outgoing requests try the
destination's observed endpoints, most recently observed first, each with the
preferred transport and then the alternative. Host names, external STUN servers
and UPnP are outside this library.

### Sybil resistance

An open DHT cannot stop one party from creating many identities, but MajDHT
makes them costly and limits what they can reach:

- **Identity work.** An identity's `IdentityWork` is the number of leading zero
  bits of a memory-hard Argon2id hash (1 MiB) of its node digest. There is no
  separate nonce: the work belongs to the key, so creating an identity means
  generating keys until one qualifies, and grinding a node ID towards a chosen key
  costs a full puzzle for every candidate. A node's identity must reach
  `IdentityWorkBits` (default 12, a one-time cost of seconds to tens of seconds
  that persists with the seed), and nodes reject requests, responses, referrals,
  assisted routes and introductions below it. Each identity is evaluated once per
  process; at most 128 unknown identities are evaluated per second, so floods of
  fresh identities cannot exhaust the CPU. All nodes of one network must use the
  same value.
- **Verified admission.** A contact enters the routing table only at an endpoint
  this node observed itself: the endpoint that answered a request, or the source
  of an inbound request once the sender answered a Ping at that source, at most
  16 verifications at a time and eight per source network per minute. A known
  node that sends from a new source, such as after a restart on another port,
  is verified there again and learned at its new endpoint. Referred
  endpoints are tried but never admitted on the referrer's word. Peers reachable
  only through Forwarders or punched routes are used but never referred to others.
- **Network diversity.** The routing table keeps at most two contacts per IPv4
  /24 or IPv6 /32 in a bucket and ten in total, and each file keeps at most three
  provider claims per such network, counted by observed source addresses.
  Loopback, private and link-local peers are exempt, so LANs keep working.
- **Randomized selection.** Dial-back helpers are drawn at random, one per
  network; routed Traversal nodes and Forwarders are drawn at random from the
  nearest candidates; download providers start in random order. Identities ground
  near a target cannot predictably capture these roles.
- **Disjoint lookups.** Each lookup follows `DisjointLookupPaths` paths that never
  query the same node and each have their own share of `MaxLookupQueries`, then
  merges them. Sybil referrals can exhaust the paths they capture, but a record or
  provider reached by any honest path is still found.

## TCP, UDP and NAT traversal

Two capabilities assist nodes that cannot reach each other directly, and a node
can advertise either or both:

- A **Traversal** node coordinates direct connections. Registered peers refresh
  their observed TCP and UDP endpoints with it, ask it to introduce them to
  another registrant, and punch holes towards the endpoints it hands out. It also
  arranges the dial-backs that probe whether a node accepts unsolicited packets.
- A **Forwarder** relays traffic. Peers open forwarding sessions with it, so it
  knows the endpoint, or duplex TCP connection, at which to deliver to them, and
  any node can relay an opaque envelope to a session owner through it. Two peers
  that cannot connect directly still communicate through a Forwarder.

Bootstrapping through a peer advertising either capability automatically
registers each common enabled transport with it. The assistant observes the
actual source address and port of each authenticated request; UDP requests
retain their cookie validation, and TCP registrations originate from the
listening port. Clients refresh these short-lived registrations and sessions,
and poll for pending introductions, until shutdown. A node can also register
explicitly and request a particular direct transport:

```csharp
await provider.RegisterTraversalAsync(traversalPeer, cancellationToken);
await downloader.RegisterTraversalAsync(traversalPeer, cancellationToken);
var connected = await downloader.TryPunchAsync(providerPeer, traversalPeer,
    DHTTransport.Udp, cancellationToken);
await provider.RegisterForwarderAsync(forwarderPeer, cancellationToken);
```

Use `DHTTransport.Tcp` to request TCP simultaneous open. The Traversal node
distributes both observed endpoints and a random, expiring 128-bit ticket. Each
peer probes from its bound listening port. A valid direct probe must match the
ticket, peer identity, transport and observed endpoint; ordinary requests then
use the authenticated direct route. TCP retains the established connection for
further requests. Successful direct transfers can continue while the Traversal
node is offline. The session loops and outstanding probes drain during
`StopAsync`.

Assisted traversal requires a local listener for the transport being punched,
because the outgoing probe must reuse that listener's port. Set
`EnableNatTraversal = false` to disable client registration, forwarding sessions
and automatic traversal; a peer advertising `Traversal` or `Forwarder` still
serves requests subject to its registry limits. Defaults are a five-second
traversal budget, one-second polling interval, 30-second lease, at most four
Traversal nodes and four Forwarders per client, and 256 registrations and 256
sessions hosted per node. Introduction queues are bounded by
`MaxConcurrentRequests`, and active tickets by four times that value.

This is best-effort traversal: endpoint-dependent NAT mappings, blocked UDP, TCP
stacks or firewalls that reject simultaneous open, and router policies can
prevent a direct path. Forwarding remains available while a Forwarder holds the
destination's session, including its existing TCP connection or observed UDP
mapping. If an introduced probe through a node that is both a Traversal node and
a Forwarder succeeds but the following RPC fails, the requester still forwards
through that same node.

### Reachability on home networks

A node behind a home router usually has no fixed reachable address. Leave
`PubliclyReachable` off and keep `EnableNatTraversal` enabled; the node then
determines its reachability itself:

1. **External address.** Traversal registrations, forwarding sessions and Hello
   responses report the endpoint each remote node observed. An address reported
   by observers in at least two distinct networks (different IPv4 /24 or IPv6
   /32 prefixes) becomes a confirmed external address, exposed through
   `ExternalAddresses`. When observers report different ports for it, the contact
   sets `HasEndpointDependentMapping` and requesters skip hole punching. A changed
   external address, for example after a PPPoE redial, starts a new epoch that
   discards earlier verification and checks reachability again.
2. **Dial-back.** After each new traversal registration and every
   `ReachabilityCheckInterval`, the node asks its Traversal nodes to arrange a
   dial-back. The Traversal node delegates it to an independent public Traversal
   node in another network, which probes only the address that was observed. An
   accepted probe makes the contact `Public` once that address matches the
   confirmed external address, so one Traversal node cannot make a node claim a
   foreign address.
3. **Private contacts.** When dial-backs through Traversal nodes in two distinct
   networks time out, the contact becomes `Private` as soon as a public Forwarder
   with a live session can be hinted: it embeds up to three public Traversal
   nodes and Forwarders with live sessions, Forwarders first, as `Hints`, each
   with the endpoints the node observed for it. Requesters dial none of its
   endpoints and reach it through a hinted Forwarder, punching first through a
   hinted Traversal node they already hold a registration with.

Private nodes act as DHT clients: they search, download and provide content,
but are never added to routing tables or returned as lookup hops. A contact
change is re-signed immediately and local publications are reannounced five
seconds later so provider indexes hold the new contact. Private and unverified
contacts use a one-hour lease; public contacts use one day. A Traversal node
accepts at most three dial-back requests per requester each minute; a helper
accepts at most ten delegations per delegating node and four dial-backs per
target address each minute, and sends at most five probe rounds per delegation.

## Custom routing

Two routing decisions can be replaced when constructing a node:

```csharp
await using var node = new MajDHTNode(options, identity, store,
    routingTable: new KademliaDHTRoutingTable(), routeSelector: new MyRouteSelector());
```

- **`IDHTRoutingTable`** decides which authenticated contacts are kept as lookup
  hops and which are returned, with their observed endpoints, as nearest to a
  target. The node calls `Initialize` exactly once, so pass a new table to each
  node. It only passes authenticated, non-private contacts to `Observe`, with the
  endpoint at which this node exchanged an authenticated packet with the contact,
  or null when it only refreshes a known contact; it calls `Remove` after
  failures or when a node becomes private, and discards expired, private,
  duplicate and local peers that `Closest` returns. The default
  `KademliaDHTRoutingTable` keeps 256 XOR buckets of `BucketSize` contacts without
  evicting live entries, merges new observations into a contact's endpoints, and
  admits at most two contacts per globally routed network in a bucket and ten in
  the table.
- **`IDHTRouteSelector`** decides how a destination is reached. It returns the
  ordered direct attempts (endpoint and transport) and, after they all fail, the
  ordered assisted attempts: which Traversal nodes and Forwarders to try and
  whether to punch through each first. The `DHTRouteContext` reports the
  preferred transport, whether NAT traversal is enabled and the Traversal nodes
  this node is registered with. A selector may be shared between nodes.

`DefaultDHTRouteSelector` dials a destination's observed endpoints, most recently
observed first, and no endpoint of a private destination. Assisted routes list
the destination's hints, punching only through hinted Traversal nodes this node
is registered with, followed by at most `BucketSize` routed Traversal nodes and
Forwarders; destinations with an endpoint-dependent mapping are never punched,
and an assistant without the `Forwarder` capability is used for punching only.
Within each of these tiers, routes and assistants with a lower measured packet
loss come first; untried routes count as lossless, and equal rates keep the
preferred transport and routing order first. Custom selectors read the same
measurements through `DHTRouteContext.GetPeerStatistics` and
`DHTRouteContext.PacketLossRate`.

Both implementations must be thread-safe, return quickly and perform no network
I/O. Routes are attempts, not trust decisions: every response is authenticated
against the destination's identity whichever route carried it. Authenticated
routes learned through punching, hosted traversal registrations or hosted
forwarding sessions are always tried before the selected direct routes. The node
attempts at most sixteen direct and thirty-two assisted routes and skips
assisted routes through itself, the destination, expired contacts or peers with
neither the `Traversal` nor the `Forwarder` capability.

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
1,024 live records, at most 16 providers per content hash, and 131,072 total (`MaxLocalLeaves`)
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
memory keeps its caller-managed lifetime. Opening an envelope decrypts it **in
place**: the received frame is owned exclusively by the receiver, its ciphertext
region becomes the plaintext, the decoded packet borrows that frame, a consumed
envelope cannot be opened again, and a failed authentication zeroes the region.
No plaintext array is allocated per packet. Objects that own mutable state,
pooled buffers, identities or persistent signed metadata remain reference types.

Received frames are **pooled**. The TCP reader and the UDP receive loop hand
every frame to its consumer as an owned view, and the consumer releases the frame
once it has copied or finished reading whatever it keeps: a downloaded block's
frame is released after the store has copied the block and the destination has
received it, a server-side request frame is released after the handler returns
(a handler abandoned by a timeout keeps its frame until it finishes), and
contacts, records, introduction tickets and nonces parsed from a frame are
copied before the frame goes back to the pool. The public `ReadBlockAsync` copies
a remote block out of its frame before releasing it, so pooled memory never
escapes as a public result.

The library is written for hosts that are sensitive to garbage-collection pauses,
such as Unity gameplay:

- Protocol writers and file-read buffers use cleared pooled arrays; readers slice
  existing memory without per-field arrays. Version labels and identifiers are
  compared as bytes instead of decoded into strings. Ciphertext is written
  directly into the pooled final envelope, the signature is written in place, and
  Merkle trees use one contiguous node buffer. Proof verification uses stack
  storage. Pooled memory never escapes as public async results.
- SHA-256, the prefixed leaf hash and the authenticated cipher are cached per
  thread and reinitialized per use; HKDF-SHA256 runs entirely on the stack and is
  verified against RFC 5869 and the provider's generator; X25519 runs on raw
  scalars with pooled, zeroed secrets; the UDP cookie HMAC is created once per
  transport.
- Verified contacts and records are cached by the digest of their exact bytes,
  bounded and expiry-checked, so the sender of every request and the manifest of
  every block request are signature-checked and allocated once. The replay cache
  is keyed by inline digests rather than strings.
- The replay cache, route copies, TCP frame prefixes, per-block download state
  and statistics keys avoid per-request strings, lists and parsed addresses.
- Received TCP frames are read into pooled buffers, UDP datagrams land in one
  reusable receive buffer per socket and only frames with a consumer are copied
  into pooled buffers, and every frame is released by its consumer, so the third
  32 KiB copy that each downloaded block used to allocate is gone.

The remaining per-block cost is dominated by two owned 32 KiB copies that the
ownership contracts require (the sealed reply retained by the replay cache and
the default store's copy) and by the provider's Ed25519 and X25519 arithmetic:
on the same host one signature allocates about 1.9 KB, one verification about
6.5 KB and each X25519 operation about 1 KB, so a sealed and opened envelope
costs about 11 KB in the provider and about 1 KB in this library.

Measured warmed managed allocations on the Windows .NET 9 Release test host:

| Workload | Original | Previous pass | Now |
| --- | ---: | ---: | ---: |
| 32 KiB codec round trip | 98,864 B/op | 96 B/op | 96 B/op |
| 32 KiB Merkle leaf | 33,048 B/op | 192 B/op | 56 B/op |
| 128-leaf Merkle tree | 46,120 B/op | 8,576 B/op | 8,440 B/op |
| SHA-256 hexadecimal formatting | 1,376 B/op | 152 B/op | 152 B/op |
| 32 KiB encrypted packet round trip | 700,807 B/op | about 95,000 B/op | about 46,000 B/op |
| 64-byte encrypted packet round trip | — | — | about 13,000 B/op |
| 32 KiB block downloaded end to end over TCP (both nodes) | about 253,000 B/block | about 140,000 B/block | about 104,000 B/block |
| 32 KiB block downloaded end to end over UDP (both nodes) | about 256,000 B/block | about 142,000 B/block | about 106,000 B/block |
| Cached 32 KiB block read | — | 0 B/op | 0 B/op |
| Disabled logger event | — | 0 B/op | 0 B/op |

The single-operation rows use `GC.GetAllocatedBytesForCurrentThread`; the
end-to-end rows use `GC.GetTotalAllocatedBytes` around a complete two-node
loopback download of a file the downloader has not seen before, including
request sealing, transport framing, authentication, block verification and
storage on both sides. All warm pools and providers before measuring and exclude
native allocations and network I/O. They are allocation regressions rather than
throughput or cross-runtime claims. In the end-to-end rows, the original column
is the first measurement of that test, the previous pass decrypted in place but
still received every frame into a fresh array, and the current pass releases
pooled frames; its budget of 130,000 B/block fails if the frame copy returns.

## Security scope

- Recipient keys are long-lived, so the protocol **does not** provide full
  forward secrecy; compromising an identity seed exposes historical traffic.
- The implementation has **not** been independently audited.
- Forwarders hide payloads but observe endpoints, sizes, timing and operation
  numbers. This is not anonymous routing and does not resist Sybil or eclipse
  attacks.
- Provider advertisements are hints; only signed records, Merkle proofs and the
  complete-file hash are authoritative.
- Applications must authenticate keys and publisher fingerprints out of band,
  configure bootstrap endpoints only from trusted sources, and persist identity
  seeds and revisions securely. A Hello request is signed but not encrypted.
- Reachability evidence relies on independent observers and helpers. A single
  Traversal node cannot set the external address or make a node claim public
  reachability at a foreign address; nodes colluding across two networks can, and
  colluding Traversal nodes can make a node look private. Referred endpoints are
  the referrer's claim and are only ever tried, never trusted. All of this affects
  reachability, never content integrity.
- Sybil identities are made expensive and contained (see
  [Sybil resistance](#sybil-resistance)) but not prevented: an attacker with
  enough CPU and addresses in many networks can still add identities. Lookups and
  provider claims remain hints; signatures, Merkle proofs and file hashes remain
  authoritative.
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
and impersonation, Merkle geometry, three-node discovery and downloads,
forwarding fallback, dual-transport, IPv6 and dual-stack transfers, endpoint
bootstrap, UDP loss/replay, traversal registration and punching, forwarding
sessions and deliveries, external-address voting, dial-back and hinted private
nodes, packet-loss statistics and loss-ranked routes,
concurrent multi-provider downloads, quota and lifecycle limits, pooled frame
release checked by churning the array pool after a download, and warmed
allocation budgets.

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
`README.md`, `PROTOCOL.md`, `IMPLEMENTING.md` and `LICENSE`; test sources are excluded. Upload the
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
