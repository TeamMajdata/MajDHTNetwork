# MajDHTNetwork tests

This .NET 9 xUnit v3 project references the production `netstandard2.1` library
in `Tools/CSharp/MajDHTNetwork`. It opens real loopback TCP/UDP sockets and uses
in-memory streams/stores. It does not import or build the Unity project.

```powershell
Push-Location Tools/Tests/MajDHTNetwork.Tests
dotnet restore MajDHTNetwork.Tests.csproj --locked-mode
dotnet test MajDHTNetwork.Tests.csproj --configuration Release --no-restore
Pop-Location
```

Run from this directory so `global.json` selects a stable .NET 9 SDK. The
explicit framework versions are xUnit v3 3.2.2, the Visual Studio/VSTest adapter
3.1.5 and Microsoft.NET.Test.Sdk 17.14.1. `packages.lock.json` pins their complete
restore graph. Every behavior is an independently discovered Fact or Theory;
Merkle file sizes and single-transport scenarios are separate theory rows.
Socket tests have per-case cancellation deadlines of at most 90 seconds;
unsupported IPv6 is reported as a skipped test.

The project compiles only `src/**/*.cs`. The artifact consumer source and any
locally generated consumer projects cannot be compiled into the test assembly.
Build outputs, test results and isolated package-consumer caches live under
ignored `bin/`, `obj/`, `TestResults/` and `.work/` directories.

## Selecting tests

```powershell
dotnet test MajDHTNetwork.Tests.csproj --configuration Release --list-tests
dotnet test MajDHTNetwork.Tests.csproj --configuration Release --filter 'Category=Allocation' --logger 'console;verbosity=detailed'
dotnet test MajDHTNetwork.Tests.csproj --configuration Release --filter 'Category!=Allocation'
dotnet test MajDHTNetwork.Tests.csproj --configuration Release --filter 'Category=NAT|FullyQualifiedName~NatQuotaTests|FullyQualifiedName~NatFallbackTests'
```

Allocation measurements belong to the nonparallel `AllocationCollection`.
xUnit finishes parallel collections before running it exclusively. No live node
or other test shares its measured intervals. Each workload warms providers and
pools before reading `GC.GetAllocatedBytesForCurrentThread`; output and assertions
occur after the interval. All seven original byte budgets remain unchanged:
codec 2,048; Merkle leaf 1,024; 128-leaf tree 16,000; hexadecimal formatting 256;
encrypted packet 150,000; cached block read 64; disabled logger 0 bytes/operation.
Measurements cover managed allocations on the executing thread and exclude
network I/O and native allocations. `ValueTypeTests` joins the same exclusive
collection; its two additional allocation facts require zero total bytes over
10,000 warmed key comparison/hash or Packet construction/copy operations.

## Distribution validation

```powershell
./Tools/CSharp/MajDHTNetwork/Publish.ps1 -Version 0.1.0
./Tools/Tests/MajDHTNetwork.Tests/ValidatePackage.ps1 -Version 0.1.0
```

Run these commands from the repository root. Publication runs the formal test
project before packing and then runs both binary consumers. The standalone
validation command reuses already-created artifacts. The NuGet consumer uses a
new isolated package cache and local feeds, preventing reuse of an older package
with the same version. Both the NuGet and loose-DLL consumers compile only
against distributed binaries and execute a verified two-node transfer and the
public span APIs. Package inspection rejects leaked test sources/build folders
and requires the DLL, XML documentation, README, protocol document and license.

## Project layout

| Files | Responsibility |
| --- | --- |
| `MajDHTNetwork.Tests.csproj`, `global.json`, `packages.lock.json`, `xunit.runner.json` | Test project, stable SDK selection, locked dependencies and runner parallelism. |
| `ValidatePackage.ps1`, `ConsumerSmoke/Program.cs` | Isolated NuGet and loose-DLL consumption of distributed artifacts. |
| `src/ProtocolTests.cs`, `src/UdpCookieTests.cs` | Identity, authenticated envelopes, malformed protocol input and address cookies. |
| `src/ContactTests.cs`, `src/BootstrapTests.cs` | Contact reachability rules, Hello envelopes, address options, endpoint bootstrap and dual-stack listeners. |
| `src/ReachabilityTests.cs` | External-address voting, independent dial-back verification and relay-hinted private nodes over distinct loopback hosts. |
| `src/RoutingCustomizationTests.cs` | Default route ordering, custom routing-table initialization and result filtering, and a custom route selector forcing a relay path. |
| `src/DownloadStatisticsTests.cs` | Per-peer and per-route packet-loss statistics through a lossy UDP proxy, loss-ranked default routes and relays, concurrent two-provider downloads within per-peer limits, and download option validation. |
| `src/AttackSurfaceTests.cs`, `src/ScriptedPeer.cs` | Scripted malicious relays, helpers and clients: colluding address hijack, bounded helper probe traffic, helper scope and quota refusals, relay dial-back quotas, unsolicited probes and named Hello envelopes, copied relay hints, provider failover and malformed contacts. |
| `src/SybilResistanceTests.cs` | Identity proof-of-work enforcement for senders and referrals, verified routing admission with bounded verification of forged endpoints, per-network routing and provider limits, one-helper-per-network dial-back selection, and disjoint lookups that still find a record hidden behind Sybil referrals. |
| `src/TestDefaults.cs` | Module initializer that disables the default identity work for short-lived test nodes; Sybil tests set `IdentityWorkBits` explicitly. |
| `src/IdentityPuzzleTests.cs` | Exclusive check that floods of uncached identities beyond the per-second Argon2id budget are not evaluated. |
| `src/WithdrawalTests.cs` | Signed withdrawals without content, key withdrawal with resolution, download refusal, provider and content pruning, replay refusal and republication, and local `StopProviding`. |
| `src/MemoryTests.cs`, `src/ContentStoreTests.cs` | Span APIs, borrowed/owned memory, owned frame views, immutable snapshots and bounded cache eviction. |
| `src/FrameOwnershipTests.cs` | Pooled receive frames released only after their consumers copied what they keep: stored, written and publicly read blocks survive array-pool churn after TCP and UDP downloads. |
| `src/RoutingTests.cs`, `src/LoggingTests.cs` | Default Kademlia table XOR distance ordering, routing removal and structured logging contracts. |
| `src/MerkleTests.cs`, `src/NetworkTests.cs` | File geometry, signatures, discovery, aliases, relays and malicious-provider recovery. |
| `src/TransportTests.cs`, `src/TransportSessionTests.cs` | Dual listeners, IPv6, fallback/loss/replay, persistent duplex TCP that survives rejected incoming requests, and endpoint-pinned UDP demultiplexing. |
| `src/LeaseTests.cs`, `src/LifecycleTests.cs` | Revision floors, expiry, quotas, capabilities, cancellation and shutdown. |
| `src/NATTests.cs`, `src/NATProtocolPeer.cs`, `src/NatQuotaTests.cs`, `src/NatFallbackTests.cs` | Relay-assisted direct routes, adversarial probes, observed endpoints, registration recovery/quotas and opaque fallback after a successful punch. |
| `src/ValueTypeTests.cs` | Key/Packet defaults, value semantics, input boundaries, ownership and zero-allocation operations. |
| `src/AllocationTests.cs`, `src/AllocationCollection.cs` | Original allocation budgets and exclusive measurement scheduling. |
| `src/SocketFixtures.cs`, `src/ThreeNodeNetwork.cs`, `src/TestSupport.cs`, `src/TestLogger.cs` | Shared real-socket fixtures, cancellation-aware storage, byte checks, first-endpoint contact helpers and diagnostic capture. |

## Preserved coverage

- Public root namespace, span imports/exports, borrowed decoder slices,
  retained owned/decrypted bytes, post-eviction cache snapshots and sparse XOR routing.
- RFC 8032 Ed25519 vectors, nonzero signature offsets, structured logger state,
  severity, private exception redaction, disabled events and provider failures.
- Seven warmed allocation regressions with the original iteration counts/budgets.
- Stable identity restoration, defensive seed exports and signed contact round trips.
- Contact reachability rules: private contacts need relay hints and only local
  endpoints, public contacts need verified or configured endpoints, hints must be
  public relays without nested hints, and leases never outlive hints.
- Signed plaintext Hello envelopes, their tamper detection and forwarding refusal;
  dual-stack, advertised-address and bootstrap-endpoint option validation.
- Background and explicit endpoint bootstrap over TCP and UDP, missing and
  unreachable endpoints, and IPv4-only and IPv6-only clients of one dual-stack node.
- External-address voting by relays on distinct loopback hosts, an independent
  helper's dial-back verifying a public endpoint over TCP and UDP, and failed
  dial-backs producing a private contact that never enters routing tables yet
  serves a verified download through its relay hint.
- Value-type key equality, hashing, dictionary/set use, safe default values,
  canonical publishers, UTF-8 boundaries and malformed text; Packet copy and
  nullable semantics, constructor validation and borrowed/owned memory contracts.
- Authenticated envelope round trips, recipient substitution, sender impersonation,
  ciphertext modification, nested relays and invalid wire lengths.
- Publisher-scoped keys, signed-record modification, empty/exact/partial/odd
  Merkle geometry, changed blocks, wrong positions and modified proof paths.
- Real three-node TCP-only and UDP-only discovery, indirect alias resolution,
  shared content hashes, complete multi-block downloads and trusted hash pins.
- Explicit opaque relay and automatic relay after an unreachable direct contact,
  with only the final provider retaining the content.
- Authenticated malicious-provider responses rejected before healthy-provider retry.
- Dual listeners, TCP-to-UDP fallback, option snapshots and IPv6 transfers.
- A real UDP proxy dropping the first encrypted response, retransmission and
  byte-identical replay-cached encrypted replies.
- A punched TCP connection accepting requests in both directions and retaining
  the original connection for 24 subsequent RPCs after the remote listener closes.
- Concurrent UDP replies delivered in reverse order, digest correlation and
  rejection of an authentic response from an unpinned source endpoint.
- Non-amplifying UDP cookies bound to source port and complete request digest.
- Monotonic revisions and revision floors retained beyond newer-record expiry.
- Bounded cache/record/file quotas, expiry reclamation, alias renewal through
  cleanup, contact renewal and download-only maintenance behavior.
- Malformed TCP frame rejection, capability gates, precancelled operations,
  lifetime cancellation, repeated stop/dispose and outstanding storage-read drainage.
- TCP-only and UDP-only relay registration and direct-route authentication using
  unreachable signed addresses and real observed endpoints. After the relay stops,
  repeated concurrent bidirectional block requests and full downloads still succeed.
- Polling recovery for a common transport whose initial registration failed while
  another transport succeeded.
- Non-relay rejection, absent targets, disabled traversal, maintained-relay quotas,
  invalid timing/size limits, caller cancellation and Stop drainage of polling/probes.
- Authenticated protocol injection of forged tokens, invalid token lengths and a
  correct ticket from a substituted source endpoint; rejected probes cannot enable
  an ordinary transfer after the relay stops, while the same content provider is
  verified via its real address.
- Relay registration quotas, expiry reclamation and source-port observation even
  when the signed advertised port is deliberately unreachable.
- A single opaque relay still succeeds when punching authenticates but ordinary
  direct RPCs are discarded; the relay forwards using the registered observed endpoint.

## Adding regressions

Add a focused `[Fact]` for one behavior or `[Theory]` with `[InlineData]` rows for
transport/input variants. Name the test after its observable contract. Keep
assertions in the discovered test method and reuse `TestSupport` only for
loopback setup/byte comparison. Socket tests should use a local cancellation
deadline and asynchronously dispose every node, transport, proxy and test store.
Use actual protocol serialization and socket exchange for adversarial cases.
Existing opaque-relay regressions use `TestSupport.Options`, which disables NAT
traversal so an automatically learned direct route cannot mask relay coverage.
NAT tests deliberately enable traversal, use bounded short polling intervals
and stop the assisting relay before asserting sustained direct transfers.
New allocation facts must join `AllocationCollection`, stay synchronous during
the measurement and write diagnostics only after measuring. Add a category trait
when a group needs an independent CI filter.

These tests exercise the real .NET Standard library on the current host runtime.
Unity 6000.3.17f1 import, Mono/IL2CPP, Player, Linux/macOS, Android/iOS, physical
NATs/WAN loss/MTU behavior, throughput, mobile suspension, hardware and security
certification require their own integration validation and remain unverified.
