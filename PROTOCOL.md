# MajDHT v1 wire protocol

**English** | [简体中文](PROTOCOL.zh-CN.md)

All integers below, except TCP's frame prefix and explicitly stated single
bytes, are **signed 64-bit big-endian**. Every byte array/string is prefixed by
its 64-bit byte length. Strings use strict UTF-8; reject truncated, oversized,
negative-length, noncanonical and trailing values before allocating. Times
are Unix seconds. Identifiers are 64 lowercase hexadecimal characters. There
is no implicit string normalization. Maximum encrypted envelope: 60,000 bytes.
The reference implementation rejects unsupported version strings.

The library exposes this protocol as a public API: the envelope, the operation
codecs, the Merkle tree, the identity work and the socket transport live in the
`MajDHTNetwork.Protocol` and `MajDHTNetwork.Transport` namespaces, so an
independent node implementation can reuse the reference encoders instead of
re-implementing this document. See "Implementing a node with the protocol API"
in [README.md](README.md).

## Identity and contacts

Generate a 32-byte random Ed25519 seed. Node ID is lowercase SHA-256 of its
32-byte signing public key. Derive the separate X25519 private seed using
SHA-256 of the canonical sequence `string("MajDHT/1/identity-agreement"),
bytes(identitySeed)`. X25519 performs its standard scalar clamping.

A signed contact is `bytes(payload), bytes(ed25519Signature(payload))`.
Payload fields, in order:

| Field | Type |
| --- | --- |
| Domain | string `MajDHT/1/contact` |
| Signing key | bytes, exactly 32 |
| Agreement key | bytes, exactly 32 |
| Capabilities | byte flags: Download=1, Provide=2, Traversal=4, Forwarder=8 |
| Reachability | byte: bits 0–1 state (0 Unknown, 1 Public, 2 Private; 3 is rejected), bit 2 endpoint-dependent mapping, other bits zero |
| Sequence | integer, the owner's issue time in Unix **milliseconds**, strictly increasing per identity |
| Expiry | Unix seconds, future and at most two days ahead at validation |
| Hint count | integer 0..3, followed by that many hints |

A contact never carries the owner's own endpoints. **Peers do not announce
where they listen; the endpoint of a peer is whatever the node that exchanges
packets with it observes.** A node learns a peer's endpoint as the socket
source of an authenticated request it received from that peer, or as the
destination that answered one of its own requests. When a node refers a peer to
another node, in a Find response or in a hint, it sends the contact together
with the endpoints it observed, as a **peer**:

```
bytes(contact), integer(endpointCount 0..4), endpointCount × (string(address), integer(tcpPort), integer(udpPort))
```

Each address is a canonical unicast IP string of at most 96 UTF-8 bytes; the
ports are 0..65535 with zero meaning that the peer was not observed over that
transport at that address; at least one port is nonzero and an address appears
at most once. Wildcards, multicast and IPv4 broadcast are rejected. Referred
endpoints are the referrer's claim: a receiver only tries them, and admits the
peer into its routing table only once it observed the peer itself.

The identity work of a contact is the number of leading zero bits of
Argon2id (version 0x13, 1,024 KiB memory, one iteration, parallelism one, 32-byte
output) with the 32-byte node digest as password and the ASCII bytes of
`MajDHT/1/identity-work` as salt. The work is a property of the signing key, so
the contact carries no proof field. Nodes reject requests, responses, lookup
referrals, provider entries, assisted routes, introductions and dial-back
delegations whose identity work is below their configured `IdentityWorkBits`
(default 12); every node of a network must use the same value. A node evaluates
each identity once per process and at most 128 unknown identities per second; an
identity beyond that budget counts as having no work until it is evaluated later.

A **hint** names a Traversal node or Forwarder that the owner holds a live
session with, as a peer: the hinted contact, of at most 1,024 encoded bytes,
followed by the endpoints at which the owner observed it. Each hinted contact
must be valid, unexpired, advertise Traversal or Forwarder with Public
reachability and carry no hints of its own; it has at least one endpoint, and
hints are distinct and differ from the owner. A requester punches through a
hinted Traversal node and forwards through a hinted Forwarder.

The signed payload is at most 2,048 bytes and an encoded contact at most 2,200
bytes. Reachability constraints:

- **Public** means the owner accepts unsolicited packets at its observed
  endpoint, confirmed by an independent dial-back or configured by the
  application; public contacts carry no hints, so they stay usable as hints.
- **Private** requires at least one Forwarder among the hints; the owner's
  observed endpoints are NAT mappings that failed a dial-back and are not dialed.
- **Unknown** permits any hints, including none (a client-only node).

The owner's expiry must not exceed any hint's expiry. Receivers replace a stored
contact only with a higher sequence. The implementation issues one-day leases
for Public contacts and one-hour leases otherwise, re-signing immediately
whenever the advertisement changes.

## Key and signed manifest

A key is `nodeFingerprint:name`; the first 64 characters are the owning signing
key's fingerprint, followed by a colon and the name. The name is nonempty and
at most 256 UTF-8 bytes with no control characters. Routing ID is SHA-256 of
the complete UTF-8 key. Provider lookups route on the complete raw-file hash.

A record is `bytes(payload), bytes(ed25519Signature(payload))` with payload:

| Field | Type |
| --- | --- |
| Domain | string `MajDHT/1/record` |
| Publisher signing key | bytes, exactly 32 |
| Canonical key | string, owner fingerprint must match the signing key |
| Flags | byte: Withdrawn=1, other bits zero |
| File hash | string, SHA-256 of the complete raw file; empty for a withdrawal |
| Merkle root | string, SHA-256 domain-separated tree root; empty for a withdrawal |
| Length | integer 0..1073741824; zero for a withdrawal |
| Block size | integer 1024..32768; zero for a withdrawal |
| Revision | strictly positive integer |
| Expiry | Unix seconds, future and at most seven days ahead |

Maximum accepted serialized record: 2,200 bytes. Block count is
`max(1, ceil(length / blockSize))`. Empty files have one zero-length block.
Only the final block may be shorter than `blockSize`.

A withdrawal is a record with the Withdrawn flag, empty file hash and Merkle root,
and zero length and block size. It has no blocks and supersedes every lower
revision of its key like any higher revision; equal revisions of a withdrawal and
content are equivocation. Its expiry must cover the withdrawn publications, so a
publisher signs it with an expiry no earlier than the latest one it supersedes.

Leaves are `SHA256(0x00 || rawBlock)`. Parents are
`SHA256(0x01 || leftDigest || rightDigest)`. Duplicate the last node at each odd
level. A proof lists sibling digests from the leaf upward; odd indices place
the sibling on the left and even indices place it on the right, dividing the
index by two at every level. Proof depth must equal the depth implied by the
signed block count. Verify exact raw-block length, proof depth and root before
accepting a block. Independently verify complete-file SHA-256 after assembly.

## Encrypted envelope

The outer envelope is `bytes(header), bytes(ciphertextWith16ByteTag)`.
The header is the following canonical sequence:

1. string `MajDHT/1/envelope`.
2. One operation byte: Ping=1, Find=2, Store=3, Block=4, Forward=5, Traversal=6, Punch=7, Hello=8, Probe=9. Set bit 7 for a response.
3. Final recipient node-ID string.
4. Fresh ephemeral X25519 public key, exactly 32 bytes.
5. Fresh random nonce, exactly 12 bytes.

Generate a fresh ephemeral X25519 private key for every envelope, including
responses. Compute X25519 with the final recipient's signed agreement public
key; reject invalid/all-zero shared secrets. HKDF-SHA256 uses the shared
secret as IKM, `SHA256(header)` as salt, ASCII `MajDHT/1/envelope` as info, and
32 output bytes. Encrypt using ChaCha20-Poly1305 with the nonce and complete
canonical header as additional authenticated data.

The encrypted plaintext is `bytes(message), bytes(signature)`. Message fields:

1. Signed sender contact bytes.
2. Random 128-bit request-ID bytes; responses echo the request ID.
3. Issued Unix timestamp, within plus/minus 120 seconds of the receiver clock.
4. Operation body bytes.

The sender's Ed25519 signature covers exactly the canonical sequence
`bytes(header), bytes(message)`. Verify the contact and signature after AEAD
verification. Responses must match the expected final sender, request ID and
operation with response bit set. A response operation body always contains
`byte(status), bytes(result)`, where status 0 means success and 1 is a generic
rejection without private error details. Successful result bytes are described
below. Requests do not include this response status wrapper.

A Hello request (operation 8 without the response bit) is the only exception:
its sender does not yet know the recipient, so the header names 64 `0`
characters as recipient and 32 zero bytes as ephemeral key, and the second outer
field carries `bytes(message), bytes(signature)` in plaintext. The receiver
verifies the signature as usual and seals its Hello response normally to the
sender's contact.

Fresh sender ephemeral keys do not provide full forward secrecy: possession of
a recipient's static identity seed permits deriving its historical agreement
key. Socket connections are disposable; protocol security does not depend on a
long-lived TCP session.

## Operations

| Operation | Request body | Successful result |
| --- | --- | --- |
| Ping (1) | empty | empty; response envelope supplies the fresh contact |
| Find (2) | byte mode, string target | bytes record-or-empty, peer list nearest, peer list providers |
| Store (3) | bytes signed record | empty |
| Block (4) | bytes signed record, integer block index | bytes raw block, integer proof count, proof-count byte arrays |
| Forward (5) | byte action, action-specific fields | see forwarding |
| Traversal (6) | byte action, action-specific fields | see traversal |
| Punch (7) | raw 16-byte introduction ticket | empty |
| Hello (8) | empty | string observed source address, integer observed source port |
| Probe (9) | bytes 16-byte dial-back nonce, integer candidate-port index | empty |

A peer list is an integer count (0..16), followed by that many peers, each a
signed contact followed by the referrer's observed endpoints of it. Each contact
is independently verified. A responder reserves 488 bytes for every peer's
endpoint list and writes at most 26,000 bytes of peers per list, so a Find
response stays below the envelope limit even when contacts carry hints. A node
lists itself in a provider list with its contact and no endpoints, because it
does not know how others observe it; the requester pairs that entry with the
endpoint it reached the responder at. Find mode 0 searches nodes near an
identifier; mode 1 resolves a canonical key; mode 2 finds providers near a
complete-file hash. Find includes a record only for mode 1 and only for the
exact requested key. Mode 1 returns providers for the returned record; mode 2
returns providers for its target hash. Other cases have an empty provider list.

Store records an authenticated sender's provider claim and requires its Provide
flag; it never trusts an unrelated provider supplied in the body. The claim
keeps the sender's observed source endpoint when the request arrived directly,
and no endpoint when a Forwarder delivered it. A withdrawal is accepted from any
authenticated sender and records no provider claim; the receiver then drops
provider claims and local content geometries that no unexpired, non-withdrawn
record references, and Find mode 1 returns the withdrawal with an empty provider
list. Indexes enforce size quotas, expiry, monotonic revisions and
equal-revision content consistency. Receivers retain bounded revision floors
past record expiry. Store success is not proof that the provider owns every
block. For each file, a node keeps at most three provider claims whose
announcements came from one globally routed IPv4 /24 or IPv6 /32, by observed
source address, which is the Forwarder's address for a delivered announcement;
loopback, private and link-local sources are not limited.

Block requires the server's Provide flag and exact local Merkle geometry. The
server reauthenticates stored bytes before responding. A receiver verifies a
proof against its original signed record, not server-supplied replacement
metadata.

Hello lets a node learn the signed contact listening at a configured bootstrap
endpoint. The response also reports the requester's observed source endpoint,
which feeds the external-address vote.

## Forwarding

A **Forwarder** relays encrypted envelopes between two peers that cannot
connect directly. It hosts forwarding sessions, addresses their owners by the
endpoints it observed for them and forwards the traffic; it never opens the
envelopes it carries. Every Forward request starts with an action byte.

Action 0, **Session**, has no further request fields and requires the server's
Forwarder flag. The server records the authenticated sender's observed socket
source for the receiving transport, independently for TCP and UDP, with a lease
of `NatRegistrationLifetime` (default 30 seconds, refreshed every poll interval)
bounded by the sender's contact expiry, and answers with that endpoint (string
canonical address, integer port). Sessions and their bindings are bounded by the
server's registry quota and reclaimed when they expire. A session must arrive
directly from its owner; a Forwarder-delivered Session is rejected.

Action 1, **Relay**, carries `string(destinationNodeId), bytes(envelope)` and
requires the server's Forwarder flag. The destination must hold a live
forwarding session with the Forwarder or be an already authenticated routed
peer, and must differ from the requester. The visible inner header must name the
destination, have no response bit and use Ping, Find, Store or Block; Forward,
Traversal, Punch, Hello and Probe requests cannot be relayed. The Forwarder
delivers the envelope unchanged inside its own authenticated request, action 2,
to the destination's session binding, including its existing duplex TCP
connection, or else to the destination's observed endpoints, and returns the
destination's opaque response envelope as the Relay result.

Action 2, **Deliver**, carries `bytes(envelope)`. The destination accepts it only
when it arrived directly from a sender advertising Forwarder, checks that the
inner header names the destination itself and is a Ping, Find, Store or Block
request, opens the inner envelope and handles it exactly as a request from its
origin, with one difference: the socket source is the Forwarder, so the
destination learns no endpoint for the origin and never admits or verifies it
from this request. The destination's sealed inner response, which only the
origin can open, is the Deliver result. The origin authenticates it against the
destination exactly like a direct response.

If a direct introduction through a node that is both a Traversal node and a
Forwarder succeeds but the subsequent direct RPC fails, the requester still
forwards through that same node.

## Traversal

A **Traversal** node coordinates direct connections: it observes the endpoints
of its registrants, lets two registrants exchange those endpoints and a shared
ticket for TCP or UDP hole punching, and arranges the dial-backs that probe
whether a node accepts unsolicited packets. Every Traversal request starts with
an action byte and requires the server's Traversal flag. Registrations are
separate from forwarding sessions: a node that is both a Traversal node and a
Forwarder keeps the two registries apart.

Clients register and poll with action 0 and no further request fields. The
response contains an endpoint (string canonical IP address, integer port), a
byte indicating whether an introduction follows (0 or 1), and that introduction
when present. The endpoint is observed from the actual authenticated socket,
independently for TCP and UDP; it is never copied from a requester-supplied
address. Clients keep using their listening socket/port for registration and
probing.

Action 1 contains a target node ID. The requester and target must have live
registrations on the receiving transport. The Traversal node queues an
introduction for the target and returns the matching target introduction to the
requester. An introduction contains bytes signed contact, the observed endpoint,
bytes random 16-byte ticket, and integer expiry in Unix **milliseconds**. The
ticket is shared only for this pair and transport. Its expiry is bounded by the
Traversal node's traversal budget and both registration leases. Clients reject
expired tickets, invalid contacts, unsupported transports and mismatched
address families.

Both peers send Punch directly and concurrently from their listening ports.
Punch's body is exactly the raw 16-byte ticket, without an inner length prefix.
The receiver requires an active matching ticket, authenticated sender identity,
transport and exact observed source endpoint before accepting a direct route.
Responses retain the ordinary encrypted status wrapper. A peer whose ticket
arrives later may initially reject a probe; subsequent authenticated retries use
fresh request IDs to avoid replaying that rejection. Registration polling is
lifetime-owned and does not require inbound connectivity from the Traversal node.

The registries, per-transport introduction queues, client session loops, active
tickets and direct route cache all have explicit quotas and expiries. Default
registration leases last 30 seconds and refresh every second. Expired
registrations and completed expired tickets are reclaimed during negotiation.
Direct routes expire after five minutes or the signed peer lease, whichever
comes first. A failed direct route is removed and normal route selection resumes.

## Reachability and dial-back

A node records every endpoint observed for it by an authenticated Traversal,
Forward session or Hello response for ten minutes. An address reported by
observers in at least two distinct networks (IPv4 /24 or IPv6 /32 prefixes;
loopback addresses compare exactly) becomes the confirmed external address of
its family. Different observed ports for that address on one transport set the
endpoint-dependent mapping bit. A change of a confirmed external address starts
a new epoch, which discards that family's dial-back verification and all
recorded dial-back failures.

Traversal action 2 asks the Traversal node for a dial-back; it accepts at most
three such requests per requester per minute:
`byte(2), integer(portCount 0..2), integer(port) × portCount`. The candidate
ports are the observed source port followed by the requested ports, deduplicated,
at most three. The dial-back address is always the observed source address. The
Traversal node selects a helper at random, one per network, among authenticated
routed peers advertising Traversal with Public reachability and an observed
endpoint for the transport and address family whose address is in a network
distinct from the requester and the Traversal node. It generates a random 16-byte
nonce and an expiry no later than its traversal budget, and sends the helper
Traversal action 3:
`byte(3), bytes(requesterContact), byte(transport: 0 TCP, 1 UDP),
string(targetAddress), integer(portCount 1..3), integer(port) × portCount,
bytes(nonce), integer(expiryUnixMilliseconds)`. The Traversal node tries at most
three helpers. Once one accepts, it answers the requester with the observed
endpoint, `string(helperNodeId), bytes(nonce), integer(expiryUnixMilliseconds),
integer(portCount), integer(port) × portCount`; otherwise it rejects.

A helper is itself a Traversal node and accepts action 3 only from a
Traversal-capable sender; it rejects expired or distant expiries, link-local
targets and loopback/private targets outside the scopes of its own listeners,
and allows each delegating node ten delegations and each target address four
dial-backs per minute. It answers immediately and then sends Probe requests,
sealed to the requester's contact, from its own address to each candidate port
until one is accepted, at most five rounds and never longer than its own
traversal budget, because a delegating node can name any target. TCP probes open
new connections; UDP probes use the ordinary cookie exchange.

The requester accepts a Probe only for a pending nonce whose helper identity,
transport and port index match and whose expiry has not passed; an accepted
probe proves that the probed observed endpoint accepts unsolicited packets.
Because the Traversal node chooses both the reported address and the helper, the
contact becomes Public only while the probed address equals the external address
confirmed by observers in two distinct networks. A node configured as publicly
reachable advertises Public at once and skips its own dial-backs.
A dial-back that times out records a failure for the Traversal node's network.
Without a verified or configured public endpoint, failures from two distinct
networks make the contact Private when at least one public Forwarder with a live
session can be listed as a hint. Checks run after each new traversal
registration, after an epoch change and every `ReachabilityCheckInterval`. A
rejection, such as no available helper, is inconclusive and is not a failure.

A requester tries a destination's observed endpoints, most recently observed
first, each with the preferred and then the other transport; it dials no
endpoint of a Private contact. After direct failure it tries each hint: it
punches through a hinted Traversal node only when it already holds a
registration there and the destination's mapping is not endpoint-dependent, and
forwards through a hinted Forwarder. Other routed Traversal nodes and Forwarders
are tried afterwards.

## TCP

Connections retain a stream of framed encrypted requests and responses. Prefix
each envelope with its unsigned 32-bit big-endian byte length. Reject zero
lengths and lengths over 60,000 before allocating the body. Partial reads must
fill the complete frame; EOF before completion is a failure.

A session serializes its outbound requests and complete frame writes, while an
independent reader dispatches incoming requests and delivers response frames.
The visible response bit only selects dispatch; the node still authenticates
the sender, operation and request ID before accepting a result. Both peers can
send requests concurrently, including during TCP simultaneous open. Cached
sessions are bounded by MaxConcurrentRequests and expire after an idle period
of at least 30 seconds or four request timeouts. Request cancellation closes
its session so a delayed response cannot satisfy the next outbound request.

A dual-stack node binds one IPv6-only listener and one IPv4 listener on the same
configured port numbers. The listener and outgoing sockets of an address family
enable endpoint reuse and use the same bound source address and port, so the
source a peer observes is the listening port. Successful punched sessions remain
available for subsequent RPCs and file blocks. Platforms and middleboxes can
reject reuse or simultaneous open; failure permits another transport or an
assisted route.

## UDP

UDP transport frames start with the four bytes `4d 44 55 01` and one kind byte.
These frames wrap encrypted envelopes; the address cookie contains no private
application data. Transport frame bodies below use fixed offsets, without the
64-bit length prefixes used inside encrypted envelopes.

| Kind | Fixed-layout body after the five-byte header |
| --- | --- |
| Hello (0) | 32-byte sealed-request SHA-256, 32 bytes padding; exactly 69 total bytes |
| Challenge (1) | 32-byte cookie, echoed 32-byte request digest; exactly 69 total bytes |
| Request (2) | 32-byte cookie, complete opaque encrypted request |
| Legacy response (3) | complete opaque encrypted response; accepted only when one request is pending for that endpoint |
| Correlated response (4) | 32-byte sealed-request SHA-256, complete opaque encrypted response |

Before sending a request, the client sends Hello and waits for a same-size
Challenge. It checks the echoed request digest, then sends Request and waits
for a correlated Response (4). The shared receive loop pins both the exact
source endpoint and request digest, allowing concurrent RPCs and incoming
requests on the node's bound listener. Unsolicited or mismatched challenges and
replies cannot occupy another request's completion slot. A legacy Response (3)
is accepted only when exactly one request is pending for its pinned endpoint;
otherwise it is discarded as ambiguous. Its decrypted response must still match
the original sender, operation and request ID.

Every retry retains the same bound UDP socket, sealed application request and
request ID. Defaults: three attempts and a five-second timeout per attempt.
Punching uses shorter retries within one request budget. Losing a response
retransmits the cookie-bearing request and receives cached identical encrypted
response bytes. Each address family uses its own UDP socket. Ordinary outbound
UDP can allocate one shared socket per address family without a UDP listener,
but that socket cannot receive incoming requests or support UDP punching.

The stateless cookie is HMAC-SHA256 with a per-running-node random 32-byte secret
over the canonical sequence `bytes(sourceAddress.GetAddressBytes()),
integer(sourcePort), integer(floor(serverUnixSeconds / 60)), bytes(requestDigest)`.
The server accepts the current or immediately previous one-minute window.
It never decrypts or dispatches a Request without verifying this cookie against
the observed source. Invalid frames are silently discarded. This avoids
amplified block responses to spoofed source addresses; Hello/Challenge have equal
sizes. The absolute transport datagram limit is 60,037 bytes.

After envelope authentication, coalesce identical sender-ID/request-ID pairs.
Reusing the same ID with a different operation or body is rejected. A bounded
reply cache holds completed ciphertext responses for up to two minutes, with
early eviction allowed under capacity pressure. Operations are idempotent under
retransmission; Store revision checks remain authoritative after eviction.
UDP sends a whole request again after loss; large blocks rely on IP fragmentation.

## Routing and refresh

Use 256 XOR-distance buckets indexed by the most significant set bit of
`localNodeId XOR remoteNodeId`. Each bucket retains at most k live contacts
(default k=8), ordered by recent authenticated observation, each with the
endpoints the node observed for it. A full live bucket is retained; unsuccessful
queries remove failed peers. A contact is admitted only at an endpoint the node
itself observed: the destination that answered a request sent to one of the
contact's known endpoints, or the source of an inbound request once the sender
answered a direct Ping at that source, at most 16 verifications at a time and
eight per source network per minute. A sender with Unknown reachability that
holds a traversal registration or forwarding session with the node asked for NAT
assistance, so it is not verified until a dial-back makes its contact public.
Responses over punched routes, hosted registrations and sessions or Forwarders
never admit a contact; they refresh a known one. A bucket admits at most two
contacts and the table at most ten whose admission addresses share one globally
routed IPv4 /24 or IPv6 /32. A higher contact sequence replaces the stored
contact; a new observation of a known contact merges into its endpoints, at most
one per address and four in total. Private contacts are never admitted and
remove any earlier contact of the same node, so private nodes never appear as
lookup referrals; they remain eligible as providers.

Iterative lookups split the nearest k routed peers round robin into
`DisjointLookupPaths` paths (default 3). Each path queries its nearest unvisited
k-set with alpha parallelism (default 3), merges closer referrals, removes failed
candidates and terminates when its nearest set is exhausted or its share of the
query budget (default 64 in total) is used. A node queried by one path is never
queried by another, and referrals already claimed by another path are ignored.
The lookup merges the paths: the highest valid record revision, the union of
providers and the nearest responsive peers.
Returned peers, provider sets and candidate counts are bounded. Local
records are replicated near both key routing IDs and file hashes. A node can
serve Find and Store independently of its download, provide, traversal and
forwarding roles, so any node can bootstrap a new participant.

Maintenance refreshes contact signatures, prunes expired index entries, retries
the configured bootstrap endpoints while the routing table is empty, schedules
reachability checks, looks up the local node ID, and reannounces local content
records. A changed advertisement triggers an extra reannouncement after five
seconds. Maintenance does not extend publisher-signed record expiry. This v1
implementation does not perform per-bucket random refresh, live-bucket eviction
probing or persistent routing storage; use multiple independently trusted
bootstrap endpoints when resilience to partitions or hostile peers is required.
