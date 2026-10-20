# Implementing a MajDHT node

**English** | [简体中文](IMPLEMENTING.zh-CN.md)

This guide explains how the MajDHT v1 protocol behaves, what the library's
public API consists of, and how to build a node of your own: either by
extending the reference `MajDHTNode` through its constructor, or by writing an
independent participant on top of the public protocol types. The exact byte
layouts are specified in [PROTOCOL.md](PROTOCOL.md); the reference node's
application API is described in [README.md](README.md).

## Contents

- [What the public API is](#what-the-public-api-is)
- [Protocol model](#protocol-model)
- [Protocol flows](#protocol-flows)
- [The protocol API in detail](#the-protocol-api-in-detail)
- [Customizing MajDHTNode](#customizing-majdhtnode)
- [Writing an independent node](#writing-an-independent-node)
- [Compatibility checklist](#compatibility-checklist)

## What the public API is

The assembly exposes two layers. Everything that is `public` is supported for
use by applications; everything `internal` is an implementation detail that can
change without notice.

| Layer | Namespace | Purpose |
| --- | --- | --- |
| Application API | `MajDHTNetwork` | Running the reference node: `MajDHTNode`, `DHTNodeOptions`, the value types `DHTIdentity`, `DHTPeer`, `DHTEndpoint`, `DHTKey`, `DHTRecord`, and the extension contracts `IDHTContentStore`, `IDHTRoutingTable`, `IDHTRouteSelector` with their default implementations. |
| Protocol API | `MajDHTNetwork.Protocol`, `MajDHTNetwork.Transport` | Speaking the protocol without `MajDHTNode`: the `Wire` codec, the `Packet` envelope, one codec class per operation, the `MerkleTree`, the identity work, address-scope rules, pooled frame ownership and the `SocketTransport`. The protocol-level members of `DHTPeer`, `DHTRecord`, `DHTIdentity` and `DHTNodeOptions` (creating and parsing signed contacts and records, signing, the node digest, the agreement public key, `Snapshot`) belong to this layer too. |

The protocol API is the same code the reference node runs. `MajDHTNode` has no
private encoder of its own: every request it sends and every response it writes
goes through the public codecs, so a node built on them produces and accepts
exactly the bytes the reference node does.

Three things stay internal on purpose:

- **Secrets.** The X25519 agreement scalar of an identity and the raw signing
  helpers that take provider key objects. A custom node never needs them:
  `Packet.Seal`/`Packet.Open` and `DHTIdentity.Sign`/`SignTo` cover signing and
  encryption.
- **Transport internals.** The UDP cookie exchange, pending-exchange tables and
  TCP session cache live inside `SocketTransport`. Reusing the transport means
  these behave identically in every node; a transport of your own must follow
  the TCP and UDP sections of the protocol document instead.
- **Verification caches.** The caches that make repeated contacts and records
  cheap to verify are reachable through `DHTPeer.Parse` and
  `DHTRecord.ParseCached`, not as types.

Node *policies* are not part of the protocol API. Identity-work thresholds, the
replay cache, routing admission, provider quotas, per-network limits, timeouts
and the Sybil mitigations are decisions a node makes; the codecs only validate
the structure of a message. A custom node applies its own policies, and the
[compatibility checklist](#compatibility-checklist) lists the ones it must not
skip.

## Protocol model

### Participants and roles

Every participant has one identity and advertises capabilities in its signed
contact:

| Capability | Meaning |
| --- | --- |
| `Download` | The node reads blocks from providers. It has no protocol obligations. |
| `Provide` | The node serves `Block` requests for content it holds and may announce content with `Store`. Nodes without this flag have their content announcements rejected. |
| `Relay` | The node forwards opaque envelopes (`Relay`), hosts rendezvous registrations and introductions (`Rendezvous`), and arranges or performs dial-backs. |

Any node, whatever its capabilities, answers `Ping`, `Hello`, `Find` and
`Store`, because every node is part of the index. A node that does not want to
serve an operation rejects it with status 1; a requester treats a rejection as
a peer failure and moves on.

### Objects

| Object | Type | What it is |
| --- | --- | --- |
| Identity | `DHTIdentity` | A 32-byte Ed25519 seed. The node ID is the SHA-256 of the signing public key; the X25519 agreement key is derived from the seed. The identity work is the number of leading zero bits of an Argon2id hash of the node digest, so it is a property of the key and costs one puzzle evaluation per candidate key. |
| Contact | `DHTPeer` | A self-signed advertisement: signing key, agreement key, capabilities, reachability, a strictly increasing sequence, an expiry, an optional confirmed external address, up to four endpoints with `Verified`/`Local`/`Configured` flags and up to three relay hints. Receivers keep the highest sequence. |
| Key | `DHTKey` | `publisherFingerprint:name`. Names are scoped to the signing identity that published them, so nobody else can rebind a name. The routing ID is the SHA-256 of the UTF-8 key. |
| Record | `DHTRecord` | A publisher-signed manifest: key, whole-file SHA-256, domain-separated Merkle root, length, block size, revision and expiry; or a withdrawal with the same key and a higher revision and no content. Higher revisions supersede lower ones; equal revisions with different content are equivocation and rejected. |
| Block | bytes + `MerkleTree` proof | Files are split into `blockSize` blocks, the last one possibly shorter. Leaves are `SHA256(0x00 ‖ block)`, parents `SHA256(0x01 ‖ left ‖ right)`, odd levels duplicate the last node. A block is accepted only with a proof that reaches the signed root at the signed position and length. |

### Messages

Every request and every response is one `Packet`, sealed into an envelope:

1. The header names the version label, the operation byte (bit 7 set for
   responses), the recipient node ID, a fresh ephemeral X25519 public key and a
   12-byte nonce.
2. The plaintext holds the sender's signed contact, a random 16-byte request
   ID, the issue time (±120 s tolerance) and the operation body.
3. The sender signs header and plaintext with Ed25519; the plaintext and
   signature are encrypted with ChaCha20-Poly1305 under a key derived by
   HKDF-SHA256 from the X25519 agreement with the recipient's contact key, with
   the header as additional authenticated data.

`Packet.Seal` produces that envelope; `Packet.Open` authenticates and decrypts
it in place and returns the verified sender contact, request ID, kind and body.
A `Hello` request is the single exception: the sender does not know the
recipient yet, so `Packet.SealHello` sends the signed plaintext with a zero
recipient and key, and the responder seals its answer normally.

A response body always starts with a status byte: `0` followed by the
operation's result, or `1` with an empty result for a generic rejection. The
`ResponseStatus` class writes and reads this wrapper. Requests never carry it.

Envelopes are at most 60,000 bytes. Over TCP each envelope is prefixed by its
32-bit length on a connection that carries requests and responses in both
directions. Over UDP a stateless cookie handshake precedes every request so
that a spoofed source cannot trigger a large response. `SocketTransport`
implements both, including retries and response correlation.

## Protocol flows

The following describes what the reference node does in each situation. A
custom node interoperates as long as it sends and accepts the same operations;
how much of each flow it implements depends on its role.

### Joining

1. The joining node sends `Hello` to a configured endpoint (preferred transport
   first, then the other). The responder answers with its signed contact in the
   envelope and the endpoint it observed for the requester in the body.
2. Having answered at an advertised endpoint, the responder enters the routing
   table. If it advertises `Relay` and NAT traversal is enabled, the joiner
   registers with it (see [relay-assisted traversal](#relay-assisted-traversal)).
3. The joiner looks up its own node ID (`Find` mode `Nodes`) to fill its
   buckets with close contacts, and keeps retrying bootstrap endpoints during
   maintenance while its routing table is empty.

An endpoint does not identify a node: whoever answers becomes the first
contact, so bootstrap endpoints must come from a trusted source.

### Lookups

A lookup takes a routing ID (`Nodes`), a canonical key (`Record`) or a
whole-file hash (`Providers`):

1. Start from the `k` routed contacts nearest to the target, split round robin
   into `DisjointLookupPaths` paths that never query the same node.
2. Each path queries its nearest unvisited contacts with `Find`, `alpha` at a
   time, merges referrals that are closer, drops contacts that failed, and
   stops when its nearest set is exhausted or its share of `MaxLookupQueries`
   is spent.
3. Every returned contact and record is verified independently; contacts whose
   identity work is too low, that are expired or private, or that are the node
   itself are discarded as hops.
4. The paths are merged: the highest valid record revision, the union of
   providers, and the nearest responsive contacts. A record is only accepted
   when it belongs to the exact requested key.

The server side of `Find` returns the record for an exact `Record` target if it
holds one, the routed contacts nearest to the target, and the providers of the
returned record (mode `Record`) or of the target hash (mode `Providers`). Each
contact list has at most 16 entries and a byte budget of 26,000 bytes so the
response stays inside the envelope limit.

### Publishing

1. Read the stream in `blockSize` blocks; for each block compute the leaf
   (`MerkleTree.AppendLeaf`) and store the block under its leaf hash in the
   content store.
2. Build the `MerkleTree`, compute the whole-file SHA-256 and sign the
   `DHTRecord` with the next revision and an expiry of `RecordLifetime`.
3. Find the nodes nearest to the key's routing ID and to the file hash (`Find`
   mode `Nodes` on both) and send `Store` to the union of them.
4. Maintenance reannounces local records until they expire; it never extends a
   publisher-signed expiry. Publishing again with a higher revision renews.
5. `Unpublish` signs a withdrawal whose revision exceeds every revision seen for
   the key and whose expiry covers the withdrawn publications, and replicates it
   the same way. A withdrawal supersedes the binding; it does not delete copies.

The server side of `Store` verifies the record, requires the `Provide`
capability of the authenticated sender for content records, accepts a
withdrawal from anyone, enforces revision monotonicity and equal-revision
consistency, keeps bounded revision floors past expiry, limits records to
`MaxRecords`, keeps at most 16 provider claims per file and at most three from
one globally routed IPv4 /24 or IPv6 /32 by observed source address.

### Downloading

1. Resolve the key with a `Record` lookup, or start from a record obtained out
   of band. An optional trusted file hash is checked against the record before
   anything is written.
2. Find providers with a `Providers` lookup on the file hash; the local node is
   added first when it already holds the content.
3. Request blocks with `Block` (record + index) from several providers at once,
   bounded by `MaxConcurrentBlockRequests` in total and `MaxBlockRequestsPerPeer`
   per provider; providers are ranked by measured packet loss, requests in
   flight and failures.
4. Verify every block against the requester's own record with
   `BlockMessage.ReadResponse` (exact length, position, proof depth and root),
   write it in order, hash it into the running whole-file digest and store it
   locally, so the downloader becomes a provider too.
5. Fail only when every provider failed a block, and finally verify the
   whole-file hash.

The server side of `Block` requires its own `Provide` capability, re-verifies
the stored bytes against the Merkle leaf before serving them, and writes the
block followed by its proof.

### Relaying

When every direct route to a destination fails, the requester keeps the
already sealed inner envelope and wraps it in a `Relay` request to a peer
advertising `Relay`: the destination node ID and the opaque envelope. The relay
checks with `Packet.CheckForward` that the inner header names that destination,
has no response bit and is a `Ping`, `Find`, `Store` or `Block`; it forwards to
a destination it already knows (a routed contact or a live rendezvous
registration, never the requester itself) and returns the opaque response. Only
the requester can open the inner response, and it authenticates it against the
destination exactly as a direct response. Relays see endpoints, sizes, timing
and the operation byte, nothing else.

### Relay-assisted traversal

1. **Registration.** A client sends `Rendezvous` action `Register` to a relay
   over each transport it listens on, from its listening port. The relay records
   the observed source endpoint for that transport and returns it, plus a queued
   introduction if one is pending. Clients refresh every `NatPollInterval`
   within a `NatRegistrationLifetime` lease.
2. **Introduction.** A requester sends action `Introduce` with the target's node
   ID. The relay requires live registrations of both on that transport, creates
   a random 16-byte ticket with a short expiry, queues the requester's
   introduction for the target and returns the target's introduction (contact,
   observed endpoint, ticket, expiry) to the requester.
3. **Punching.** Both peers send `Punch`, whose body is the raw ticket, directly
   to each other's observed endpoint from their listening ports, retrying within
   the ticket lifetime. A receiver accepts a probe only for an active ticket
   whose peer identity, transport and exact source endpoint match, then caches
   the direct route.
4. **Fallback.** If punching fails, or a direct request after punching fails,
   the requester uses opaque forwarding through the same relay.

### Reachability

1. **Observation.** Every `Hello` and `Register` response reports the endpoint
   the responder observed. An address reported by observers in two distinct
   networks becomes the confirmed external address; differing ports mark an
   endpoint-dependent mapping, which disables punching towards that node.
2. **Dial-back.** The client sends action `DialBack` with up to two extra
   candidate ports. The relay picks an independent helper in another network,
   sends it action `DialBackAssist` (client contact, transport, observed
   address, candidate ports, nonce, expiry) and answers the client with the
   arrangement. The helper sends `Probe` (nonce, port index) to each candidate
   port from its own address, at most five rounds. The client accepts a probe
   only for a pending nonce from the expected helper on the expected transport;
   the probed port becomes a `Verified` endpoint while its address matches the
   confirmed external address, and the contact becomes `Public`.
3. **Private contacts.** When dial-backs through relays in two distinct networks
   time out and no `Verified` or `Configured` endpoint exists, the contact
   becomes `Private`: only `Local` endpoints plus up to three public relay
   hints. Private contacts are used as providers but never as routing hops.

Quotas bound every step: three dial-back requests per requester per minute at a
relay, ten delegations per relay and four dial-backs per target address per
minute at a helper.

### Maintenance

Every `MaintenanceInterval` the reference node re-signs its contact before the
lease ends (one day for public contacts, one hour otherwise, and immediately
when the advertisement changes), prunes expired records, claims and
registrations, retries bootstrap endpoints while the table is empty, schedules
reachability checks, looks up its own node ID and reannounces local records.

## The protocol API in detail

### `Wire`: canonical encoding

A `Wire` created without arguments is a writer over a pooled buffer; a `Wire`
over `ReadOnlyMemory<byte>` is a zero-copy reader. Integers are signed 64-bit
big-endian; byte arrays and strings are length-prefixed; strings are strict
UTF-8. Readers take a limit on every variable-length value and throw
`InvalidDataException` on truncated, oversized or negative lengths; `End()`
rejects trailing bytes and every complete-body codec calls it. `WrittenMemory`
and `Bytes(limit)` return borrowed views: a writer's view is valid until the
writer grows or is disposed, a reader's view as long as the input memory lives.
Dispose writers; they return and clear their pooled storage.

### `Packet`: envelopes

`new Packet(sender, requestId, kind, body)` borrows its arguments, so keep them
alive until `Seal` returns the owned envelope bytes. `Packet.Open(identity,
envelope)` decrypts the ciphertext *in place*: the envelope must be exclusively
owned, cannot be opened twice, and the returned `Sender`, `RequestId` and `Body`
borrow it. A failed authentication zeroes the ciphertext region before throwing
`CryptographicException`. `Packet.CheckForward` performs the relay's inner
header check without decrypting.

### Operation codecs

| Class | Request | Successful result |
| --- | --- | --- |
| `Ping` (no class) | empty body; read with `reader.End()` | empty; the response envelope carries the fresh contact |
| `HelloMessage` | empty (`ReadRequest`) | `ObservedEndpoint` (`WriteResponse`/`ReadResponse`) |
| `FindMessage` | `FindMode` + target (`FindRequest`) | record or empty, nearest `ContactList`, provider `ContactList` (`FindResponse`) |
| `StoreMessage` | one signed record | empty |
| `BlockMessage` | record + index (`BlockRequest`) | raw block + proof; `ReadResponse(reader, record, index)` returns the block only after verifying it |
| `RelayMessage` | destination ID + opaque envelope (`RelayRequest`); `ReadRequest` applies `CheckForward` | opaque response envelope |
| `RendezvousMessage` | `ReadAction` then one of `Register`, `Introduce`, `DialBack`, `DialBackAssist` readers | `RendezvousPollResponse`, `RendezvousIntroduction`, `DialBackArrangement` or empty |
| `PunchMessage` | the raw 16-byte ticket | empty |
| `ProbeMessage` | nonce + port index (`ProbeRequest`) | empty |

Writers append to a `Wire` you supply, so one request body or one result can be
assembled in a single pooled buffer and wrapped with `ResponseStatus.WriteSuccess`
or `WriteRejection`. Readers consume a `Wire` positioned at the body (or, for
`RendezvousMessage`, just after the action byte) and return small structs whose
`ReadOnlyMemory<byte>` fields borrow the body. Anything retained beyond the
handler, such as a nonce for a background job, must be copied with `ToArray()`.

### Content integrity

`MerkleTree.AppendLeaf(writer, block)` appends a leaf to a contiguous leaf
buffer and returns the leaf hash used as the content-store key;
`new MerkleTree(leaves)` builds the tree; `Root` is the record's Merkle root;
`WriteProof(writer, index)` writes a proof into a result; `MerkleTree.Verify`
checks a block against a record, position and proof; `VerifyLocal` re-checks a
stored block against an already built tree before serving it. `Crypto.Hash`
and `Crypto.Hex` compute the whole-file hash in its canonical form.

### Identities, contacts and records

`DHTIdentity.Create(workBits)` searches seeds until the identity work is
reached; persist `ExportSeed()` and restore with `new DHTIdentity(seed)`.
`DHTPeer.Create(identity, endpoints, capabilities, reachability,
endpointDependentMapping, externalAddress, relayHints, lifetime)` signs a
contact with the next sequence; the shorter overload signs a one-endpoint
contact with a one-day lease. `DHTPeer.Parse` verifies received contacts and
reuses cached verifications. `DHTRecord.Create` and `CreateWithdrawal` sign
records; `DHTRecord.Parse` and `ParseCached` verify them. `IdentityWork` on
both types evaluates the puzzle with a process-wide cache and a budget of 128
unknown identities per second (`IdentityPuzzle`).

### Transport

`new SocketTransport(options, handler)` validates and copies the options and
creates an unbound transport. `Bind()` opens the TCP and UDP listeners that the
options enable on each listen address; `TcpPort`/`UdpPort` report the bound
ports so the local contact can be signed; `Run()` starts accepting. The
`DHTEnvelopeHandler` receives each envelope with its transport and observed
source and returns the sealed response; a faulted handler drops the request.
`ExchangeAtAsync(transport, endpoint, envelope, token)` sends one envelope to a
pinned endpoint and returns the response frame as an `OwnedMemory` that the
caller disposes after copying what it keeps; it applies the request timeout,
UDP retries and the cookie handshake. `PunchAsync` is the same exchange from the
listening port with short retries for simultaneous open. `TransmissionCounter`
optionally counts sent and unanswered transmissions for loss statistics.
`Stop()` cancels everything and `DisposeAsync()` drains it.

### Helpers

`NetworkScope` classifies addresses (loopback, link-local, private, global),
computes the IPv4 /24 or IPv6 /32 network key used by every per-network quota
and copies addresses defensively. `XorDistanceComparer` orders contacts by XOR
distance to a target. `ProtocolTags` holds the canonical ASCII labels.
`OwnedMemory`, `OwnedPacket` and `PooledBuffer` express who releases a pooled
frame. `KademliaDHTRoutingTable`, `DefaultDHTRouteSelector` and
`MemoryDHTContentStore` are ordinary public classes and can be reused by a
custom node as well.

## Customizing MajDHTNode

If what you need is the reference behavior with different resources or
decisions, extend `MajDHTNode` through its constructor instead of replacing it:

| Extension point | Customizes | Notes |
| --- | --- | --- |
| `DHTNodeOptions` | Listeners, advertised addresses, bootstrap endpoints, capabilities, limits, timeouts, identity work, lookup shape, logger | Validated and copied once at construction; see the defaults table in the README. |
| `DHTIdentity` | The node ID and publisher namespace | Create once with `DHTIdentity.Create`, persist the seed, restore on start. |
| `IDHTContentStore` | Where blocks live | Keyed by Merkle leaf hash; must be thread-safe, honour cancellation and copy retained input. The node re-verifies every read. |
| `IDHTRoutingTable` | Which authenticated contacts are kept as hops and which are returned as nearest | The node calls `Initialize` once, passes only authenticated non-private contacts to `Observe`, and discards unusable results of `Closest`. |
| `IDHTRouteSelector` | The order of direct and relay attempts for a destination | Receives a `DHTRouteContext` with transports, external addresses, registrations and loss statistics; may be shared between nodes. |
| `ILogger` | Diagnostics | Structured, with exception types but never message text, keys or addresses of users. |

Everything that the protocol requires of a node (authentication, verification,
replay protection, quotas) stays in `MajDHTNode` with these extensions, which
is the safest way to run a compatible node. Write an independent node when you
need a different role split, different policies, another transport or another
runtime.

## Writing an independent node

The test project's `MinimalProtocolNode` (`src/MajDHTNetwork.Tests/src/`) is a
complete, compilable example of this section: it serves one file, indexes
announcements, downloads from reference nodes and is discovered and downloaded
from by them, using only public types.

### 1. Identity, options and transport

```csharp
var identity = DHTIdentity.Create(options.IdentityWorkBits);   // persist ExportSeed()
var transport = new SocketTransport(options, HandleAsync);
transport.Bind();
var endpoint = new DHTEndpoint(listenAddress, transport.TcpPort, transport.UdpPort, DHTEndpointFlags.Configured);
var self = DHTPeer.Create(identity, new[] { endpoint }, DHTCapabilities.Download | DHTCapabilities.Provide,
    DHTReachability.Public, false, null, Array.Empty<DHTPeer>(), TimeSpan.FromDays(1));
transport.Run();
```

Use `Configured` for an address the application knows to be reachable,
`Local` for loopback, private or link-local addresses, no flag for an
unverified public address, and `Verified` only after a dial-back. Re-sign the
contact before `ExpiresAt` and whenever endpoints, capabilities or reachability
change; `DHTPeer.Create` issues the strictly increasing sequence for you.

### 2. The request handler

```csharp
private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> envelope, DHTTransport transport, IPEndPoint source,
    CancellationToken cancellationToken)
{
    var packet = Packet.Open(_identity, envelope);                      // authenticates sender, decrypts in place
    if (packet.Kind >= 128 || packet.Sender.NodeId == _identity.NodeId || packet.Sender.IdentityWork < _workBits)
    {
        throw new InvalidDataException("Unexpected response, self request or insufficient identity work.");
    }
    // Recommended: coalesce duplicate (sender, request ID) pairs for two minutes and reject reuse with a different body.
    using var body = new Wire();
    using var result = new Wire();
    try
    {
        using var request = new Wire(packet.Body);
        switch ((Operation)packet.Kind)
        {
            case Operation.Ping:
                request.End();
                break;
            case Operation.Hello:
                HelloMessage.ReadRequest(request);
                HelloMessage.WriteResponse(result, source);
                break;
            case Operation.Find:
                AnswerFind(FindMessage.ReadRequest(request), packet.Sender, result);
                break;
            case Operation.Store:
                Index(StoreMessage.ReadRequest(request), packet.Sender, source.Address);
                break;
            case Operation.Block:
            {
                var block = BlockMessage.ReadRequest(request);
                BlockMessage.WriteResponse(result, LocalBlock(block.Record, block.Index), LocalTree(block.Record), block.Index);
                break;
            }
            default:
                throw new IOException("Unsupported operation.");       // Relay, Rendezvous, Punch, Probe are optional roles
        }
        ResponseStatus.WriteSuccess(body, result.WrittenSpan);
    }
    catch (Exception exception) when (exception is IOException || exception is InvalidDataException)
    {
        ResponseStatus.WriteRejection(body);                             // never leak why
    }
    var reply = new Packet(_self, packet.RequestId, (byte)(packet.Kind | 128), body.WrittenMemory);
    return Task.FromResult<ReadOnlyMemory<byte>>(reply.Seal(_identity, packet.Sender));
}
```

Rules the handler must respect:

- The envelope frame belongs to the transport and is released when the returned
  task completes. Copy anything you keep (contacts and records returned by the
  codecs are already owned objects; raw byte views are not).
- Reject responses (bit 7), requests from your own identity and senders below
  your identity-work threshold before doing any work.
- Echo the request ID and set the response bit; seal to `packet.Sender`, the
  authenticated contact, never to an address.
- A rejection is status 1 with an empty result. Log the failure type for your
  own diagnostics, but do not put details on the wire.
- `Find` answers must come from the routing table and index; `Store` must
  record the authenticated sender, never a provider named in the body; `Block`
  must re-verify stored bytes before serving them.

### 3. Sending requests

```csharp
private async Task<byte[]> RequestAsync(DHTPeer peer, DHTTransport transport, IPEndPoint endpoint, Operation operation,
    ReadOnlyMemory<byte> body, CancellationToken cancellationToken)
{
    var request = new Packet(_self, Crypto.Random(Packet.RequestIdLength), (byte)operation, body);
    using var encoded = await _transport.ExchangeAtAsync(transport, endpoint, request.Seal(_identity, peer), cancellationToken);
    var response = Packet.Open(_identity, encoded.Bytes);
    if (response.Sender.NodeId != peer.NodeId || response.Kind != (request.Kind | 128)
        || !CryptographicOperations.FixedTimeEquals(response.RequestId.Span, request.RequestId.Span)
        || response.Sender.IdentityWork < _workBits)
    {
        throw new CryptographicException("Response sender, operation or correlation mismatch.");
    }
    Observe(response.Sender, endpoint.Address);                           // the peer answered at this endpoint
    return ResponseStatus.ReadResult(response.Body).ToArray();           // copy before the frame is released
}
```

Choose endpoints in the order `Verified`/`Configured`, unverified, `Local`
(the latter only when you share the destination's external address), each
with the preferred and then the other transport, and treat `IOException`,
`InvalidDataException`, `CryptographicException`, `ArgumentException` and
`SocketException` as "try the next route". When all direct routes fail, wrap
the already sealed envelope with `RelayMessage.WriteRequest` and send it to a
relay-capable peer; open the opaque result with `RelayMessage.ReadResponse` and
authenticate it exactly as above. A `Hello` is sent with `SealHello` and its
sender is unknown beforehand, so verify only kind and request ID and then adopt
the sender as the contact of that endpoint.

### 4. State to keep

| State | Why | Reusable types |
| --- | --- | --- |
| Routing table | `Find` answers and lookup seeds; admit a contact only after it answered at an advertised endpoint or sent a request from one; keep at most two contacts per global network in a bucket and ten in total | `KademliaDHTRoutingTable`, `XorDistanceComparer`, `NetworkScope` |
| Record index and revision floors | Serve `Find` mode `Record`; refuse rollbacks; honour withdrawals | `DHTRecord` revisions, `SameContent` |
| Provider claims | Serve `Find` mode `Providers`; drop expired contacts; at most 16 per file, three per global network | `NetworkScope.NetworkKey`, `IsDiversityLimited` |
| Local content | Serve `Block`; verify before serving | `IDHTContentStore`, `MemoryDHTContentStore`, `MerkleTree` |
| Replay cache | Coalesce retransmissions, reject reused request IDs with different content for two minutes | hash of `packet.Body` with `Crypto.Hash` |
| Relay state (optional) | Registrations with observed endpoints per transport, introduction queues, tickets, dial-back quotas | `RendezvousMessage` structs |

### 5. Testing against the reference node

Start a `MajDHTNode` with `BootstrapEndpoints` pointing at your node and check
that `BootstrapAsync` returns 1, that `KnownPeers` contains your node, that
`FindProvidersAsync`/`ResolveAsync` see your record and that `DownloadAsync`
succeeds; then do the reverse through your client code. `CustomNodeTests` in
the test project does exactly this for `MinimalProtocolNode`. Set
`IdentityWorkBits` identically on both sides; the test project sets the
default to 0, production networks use 12.

## Compatibility checklist

A node is compatible with MajDHT v1 reference nodes when it:

- speaks only through `Packet` envelopes with the canonical codecs, keeps
  envelopes within 60,000 bytes and tolerates ±120 s of clock skew;
- answers `Ping`, `Hello`, `Find` and `Store`, rejects everything it does not
  implement with status 1, and never answers a request with a different request
  ID or operation;
- requires the network's identity work on senders, responders and referrals,
  rejects its own identity and responses arriving as requests;
- verifies every contact, record and block it accepts and never trusts
  server-supplied metadata over its own signed record;
- records providers from the authenticated sender of `Store` only, enforces
  revision monotonicity and withdrawals, and bounds every index with quotas;
- admits routing contacts only after they proved an advertised endpoint, never
  refers private contacts, and limits contacts per global network;
- re-signs its contact before expiry with increasing sequences and advertises
  reachability honestly: `Public` only with a `Verified` or `Configured`
  endpoint, `Private` only with relay hints and `Local` endpoints;
- if it advertises `Relay`, forwards only what `Packet.CheckForward` allows to
  destinations it knows, and applies the rendezvous and dial-back quotas.
