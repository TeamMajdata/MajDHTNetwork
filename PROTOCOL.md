# MajDHT v1 wire protocol

All integers below, except TCP's frame prefix and explicitly stated single
bytes, are **signed 64-bit big-endian**. Every byte array/string is prefixed by
its 64-bit byte length. Strings use strict UTF-8; reject truncated, oversized,
negative-length, noncanonical and trailing values before allocating. Times
are Unix seconds. Identifiers are 64 lowercase hexadecimal characters. There
is no implicit string normalization. Maximum encrypted envelope: 60,000 bytes.
The reference implementation rejects unsupported version strings.

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
| Advertised address | canonical .NET IPAddress string, max 96 UTF-8 bytes |
| TCP port | integer 0..65535; zero disables the listener |
| UDP port | integer 0..65535; at least one listener must be nonzero |
| Capabilities | byte flags: Download=1, Provide=2, Relay=4 |
| Expiry | Unix seconds, future and at most two days ahead at validation |

The implementation issues one-day contacts. Public invitations are the literal
prefix `majdht1:` followed by standard padded base64 of the signed contact.
Wildcards, IPv6 multicast and IPv4 all-ones broadcast are rejected. The declared
address is signed but does not itself prove network ownership.

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
| File hash | string, SHA-256 of the complete raw file |
| Merkle root | string, SHA-256 domain-separated tree root |
| Length | integer 0..1073741824 |
| Block size | integer 1024..32768 |
| Revision | strictly positive integer |
| Expiry | Unix seconds, future and at most seven days ahead |

Maximum accepted serialized record: 2,200 bytes. Block count is
`max(1, ceil(length / blockSize))`. Empty files have one zero-length block.
Only the final block may be shorter than `blockSize`.

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
2. One operation byte: Ping=1, Find=2, Store=3, Block=4, Relay=5. Set bit 7 for a response.
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

Fresh sender ephemeral keys do not provide full forward secrecy: possession of
a recipient's static identity seed permits deriving its historical agreement
key. Socket connections are disposable; protocol security does not depend on a
long-lived TCP session.

## Operations

| Operation | Request body | Successful result |
| --- | --- | --- |
| Ping (1) | empty | empty; response envelope supplies the fresh contact |
| Find (2) | byte mode, string target | bytes record-or-empty, contact list nearest, contact list providers |
| Store (3) | bytes signed record | empty |
| Block (4) | bytes signed record, integer block index | bytes raw block, integer proof count, proof-count byte arrays |
| Relay (5) | string destination node ID, bytes opaque envelope | bytes opaque response envelope |
| Rendezvous (6) | byte action, optional string target node ID | observed endpoint and optional introduction, or target introduction |
| Punch (7) | raw 16-byte introduction ticket | empty |

A contact list is an integer count (0..16), followed by that many signed-contact
byte arrays. Each contact is independently verified. Find mode 0 searches nodes
near an identifier; mode 1 resolves a canonical key; mode 2 finds providers near
a complete-file hash. Find includes a record only for mode 1 and only for the
exact requested key. Mode 1 returns providers for the returned record; mode 2
returns providers for its target hash. Other cases have an empty provider list.

Store records an authenticated sender's provider claim and requires its Provide
flag; it never trusts an unrelated provider supplied in the body. Indexes enforce
size quotas, expiry, monotonic revisions and equal-revision content consistency.
Receivers retain bounded revision floors past record expiry. Store success is
not proof that the provider owns every block.

Block requires the server's Provide flag and exact local Merkle geometry. The
server reauthenticates stored bytes before responding. A receiver verifies a
proof against its original signed record, not server-supplied replacement
metadata.

Relay requires the server's Relay flag and an already authenticated known
destination. It verifies that the visible inner header matches the destination,
has no response bit, and uses Ping, Find, Store or Block. Relay, Rendezvous and
Punch control requests cannot be forwarded. It forwards unchanged
ciphertext without opening the inner envelope. The inner response is opened and
authenticated only by the original requester. A relay can reuse an unexpired
source endpoint from the destination's authenticated rendezvous registration,
including its existing duplex TCP connection, before trying the signed advertised
address. If punching succeeds but the subsequent direct RPC fails, the requester
still attempts opaque forwarding through that same relay.

## Assisted NAT traversal

Rendezvous requires the server's Relay capability. Clients register and poll
with action 0 and no further request fields. The response contains an endpoint
(string canonical IP address, integer port), a byte indicating whether an
introduction follows (0 or 1), and that introduction when present. The endpoint
is observed from the actual authenticated socket, independently for TCP and UDP;
it is never copied from the advertised contact or a requester-supplied address.
Clients keep using their listening socket/port for registration and probing.

Action 1 contains a target node ID. The requester and target must have live
registrations on the receiving transport. The relay queues an introduction for
the target and returns the matching target introduction to the requester. An
introduction contains bytes signed contact, the observed endpoint, bytes random
16-byte ticket, and integer expiry in Unix **milliseconds**. The ticket is shared
only for this pair and transport. Its expiry is bounded by the relay's traversal
budget and both registration leases. Clients reject expired tickets, invalid
contacts, unsupported transports and mismatched address families.

Both peers send Punch directly and concurrently from their listening ports.
Punch's body is exactly the raw 16-byte ticket, without an inner length prefix.
The receiver requires an active matching ticket, authenticated sender identity,
transport and exact observed source endpoint before accepting a direct route.
Responses retain the ordinary encrypted status wrapper. A peer whose ticket
arrives later may initially reject a probe; subsequent authenticated retries use
fresh request IDs to avoid replaying that rejection. Rendezvous polling is
lifetime-owned and does not require inbound connectivity from the relay.

The relay registry, per-transport introduction queues, client relay loops,
active tickets and direct route cache all have explicit quotas and expiries.
Default registration leases last 30 seconds and refresh every second. Expired
registrations and completed expired tickets are reclaimed during negotiation.
Direct routes expire after five minutes or the signed peer lease, whichever
comes first. A failed direct route is removed and normal route selection resumes.

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

The listener and outgoing sockets enable endpoint reuse and use the same bound
source address and port. Successful punched sessions remain available for
subsequent RPCs and file blocks. Platforms and middleboxes can reject reuse or
simultaneous open; failure permits another transport or relay route.

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
response bytes. Ordinary outbound UDP can allocate one shared socket when the
UDP listener is disabled, but that socket cannot receive incoming requests or
support UDP punching.

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
(default k=8), ordered by recent authenticated observation. A full live bucket
is retained; unsuccessful queries remove failed peers. Referrals are verified
but admitted to routing buckets only after an authenticated exchange.

Iterative lookups query the nearest unvisited k-set with alpha parallelism
(default 3). Merge closer referrals, remove failed candidates, and terminate
when the nearest set is exhausted or the query budget (default 64) is reached.
Returned contacts, provider sets and candidate counts are bounded. Local
records are replicated near both key routing IDs and file hashes. A node can
serve Find and Store independently of its download/provide/relay roles, so any
node can bootstrap a new participant.

Maintenance refreshes contact signatures, prunes expired index entries, looks
up the local node ID, and reannounces local content records. It does not extend
publisher-signed record expiry. This v1 implementation does not perform
per-bucket random refresh, live-bucket eviction probing or persistent routing
storage; use multiple independently trusted bootstrap contacts when resilience
to partitions or hostile peers is required.
