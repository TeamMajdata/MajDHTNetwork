# MajDHTNetwork

[English](README.md) | **简体中文**

MajDHTNetwork 是一个独立的 **.NET Standard 2.1** 类库，命名空间为
`MajDHTNetwork`。一个 `MajDHTNode` 同时是 DHT 参与者与内容提供者，还可以充当协调直连的
Traversal 节点，或中继端到端加密信封的 Forwarder。
本类库不依赖任何 Unity 程序集，也不会自行打开文件或目录：所有流都由调用方提供。
这是 **MajDHT v1** 协议，并非 BitTorrent DHT。

线协议规范见 [PROTOCOL.md](PROTOCOL.md)（[中文](PROTOCOL.zh-CN.md)）。

## 目录

- [亮点](#亮点)
- [环境要求](#环境要求)
- [仓库结构](#仓库结构)
- [构建](#构建)
- [快速开始](#快速开始)
- [公共 API](#公共-api)
- [用协议 API 实现自己的节点](#用协议-api-实现自己的节点)
- [身份、密钥与完整性](#身份密钥与完整性)
- [加密与转发](#加密与转发)
- [引导与发现](#引导与发现)
- [TCP、UDP 与 NAT 穿透](#tcpudp-与-nat-穿透)
- [自定义选路](#自定义选路)
- [存储、配额与生命周期](#存储配额与生命周期)
- [日志](#日志)
- [内存所有权与内存分配](#内存所有权与内存分配)
- [安全范围](#安全范围)
- [测试与验证](#测试与验证)
- [打包与分发](#打包与分发)
- [许可证](#许可证)

## 亮点

- **可认证的内容。** 密钥绑定到发布者签名身份；每条发布记录、联系人和数据块在使用前
  都会被签名或证明校验。
- **加密的请求。** 每个 RPC 都使用全新的临时 X25519 协商、HKDF-SHA256 与
  ChaCha20-Poly1305，并用 Ed25519 签名覆盖信封转录与明文。
- **两种传输层。** 长度前缀的 TCP，以及带非放大源地址 Cookie、重试与有界重放缓存的
  数据报 UDP。
- **只有被观测到的端点。** 没有节点会宣告自己在哪里监听：一个节点的端点以与它交换数据包的
  对端所观测到的为准，推荐时随签名联系人一起携带的是推荐方的观测结果。
- **Traversal 与 Forwarder 两种角色。** 声明 `Traversal` 的节点观测登记节点的端点、让双方交换
  端点并协调 TCP/UDP 打洞；声明 `Forwarder` 的节点托管转发会话并中继不透明的加密信封，
  因此无法直连的两个节点仍然可以通信。
- **面向家宽的可达性发现。** NAT 之后的节点通过独立的观测方得知自己的外部地址，用独立的
  回拨探测验证它；无法验证时在签名联系人中携带指向 Traversal 节点与 Forwarder 的提示。
- **双栈监听与端点引导。** 一个节点可以同时监听 IPv4 与 IPv6，并通过配置的引导端点
  加入网络。
- **可插拔存储。** 数据块由 `IDHTContentStore` 承载；默认的 `MemoryDHTContentStore`
  是有界的 LRU 缓存，应用也可以提供持久化存储。
- **开放的协议 API。** 信封、各操作的编解码器、Merkle、身份工作量与套接字传输层类型
  均为公开类型，应用可以实现自己的节点并与 `MajDHTNode` 互通。
- **与宿主无关。** 不使用 Unity 类型，不调用 `System.IO.File`/`FileStream`，日志走
  `Microsoft.Extensions.Logging` 的结构化接口。

## 环境要求

| 项目 | 取值 |
| --- | --- |
| 构建 SDK | .NET 9，由 `global.json` 选择（`9.0.100`，`rollForward: latestFeature`） |
| 类库目标框架 | `netstandard2.1`，`LangVersion` 9.0，已启用可空引用类型 |
| 测试宿主 | `net9.0`，xUnit v3 |
| 直接依赖 | `BouncyCastle.Cryptography` 2.7.0、`Microsoft.Extensions.Logging.Abstractions` 10.0.13 |
| 依赖锁定 | `packages.lock.json`（用 `--locked-mode` 还原） |

## 仓库结构

| 路径 | 内容 |
| --- | --- |
| `MajDHTNetwork.csproj` | 类库工程、包元数据，以及针对 `src/MajDHTNetwork/**/*.cs` 的显式 `Compile` 通配。 |
| `MajDHTNetwork.slnx` | 仅包含类库工程的解决方案。 |
| `src/MajDHTNetwork/` | 生产代码：节点、发现、内容、NAT、协议与传输。 |
| `src/MajDHTNetwork.Tests/` | .NET 9 xUnit v3 测试工程，使用真实回环套接字；不包含在类库工程中。 |
| `PROTOCOL.md`、`PROTOCOL.zh-CN.md` | 线协议规范（英文 / 中文）。 |
| `IMPLEMENTING.md`、`IMPLEMENTING.zh-CN.md` | 协议流程、公开 API 与自定义节点实现指南（英文 / 中文）。 |
| `Publish.ps1` | 发布脚本：构建、测试、打包、生成松散 DLL 归档并校验消费者。 |
| `LICENSE` | MIT 许可证。 |
| `global.json`、`packages.lock.json` | SDK 选择与锁定的依赖图。 |

## 构建

```powershell
dotnet restore MajDHTNetwork.csproj --locked-mode
dotnet build MajDHTNetwork.csproj --configuration Release --no-restore
```

产物为 `bin/Release/netstandard2.1/MajDHTNetwork.dll`，并附带英文 XML API 文档文件。
测试工程是独立工程，永远不会被编译进类库。

```powershell
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release
```

## 快速开始

取消令牌、流以及任何持久化的身份存储都由应用负责。下面是一段异步方法的方法体。

```csharp
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using MajDHTNetwork;

#nullable enable

// 在 IPv4 与 IPv6 上绑定显式端口；用 0 让操作系统分配端口，用 null 关闭对应监听器。
await using var provider = new MajDHTNode(new DHTNodeOptions
{
    ListenAddresses = new List<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback },
    TcpPort = 42000,
    UdpPort = 42000,
    Capabilities = DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Traversal | DHTCapabilities.Forwarder
});
await provider.StartAsync(cancellationToken);

// 通过已知节点的端点加入网络；该节点会自行返回它的签名联系人。
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

// 通过可信的应用通道把 alias.Key 交给接收方。
using var destination = new MemoryStream();
await downloader.DownloadAsync(alias.Key, destination, record.FileHash, cancellationToken);
```

用 `DHTIdentity.Create(options.IdentityWorkBits)` 创建一次身份（它会搜索满足网络身份工作量的
密钥，可能需要数秒），再用 `DHTIdentity(seed)` 从 `ExportSeed()` 的结果恢复，使节点 ID、发布者
命名空间与工作量跨重启保持。构造节点时若不提供身份，节点会自行创建。当数据块需要比进程活得更久时，
实现 `IDHTContentStore`。

## 公共 API

### 节点操作

| 成员 | 用途 |
| --- | --- |
| `MajDHTNode(DHTNodeOptions?, DHTIdentity?, IDHTContentStore?, IDHTRoutingTable?, IDHTRouteSelector?, IDHTContentFallback?)` | 创建节点；所有参数都可选，缺省时在内部创建默认实现。 |
| `StartAsync(CancellationToken)` | 只绑定一次监听器；配置了引导端点时在后台开始引导；该令牌是生命周期令牌。 |
| `StopAsync()`、`DisposeAsync()`、`Dispose()` | 幂等的关闭流程；已停止的实例不能重启。 |
| `NodeId`、`LocalContact`、`LocalPeer`、`KnownPeers`、`ExternalAddresses` | 本地身份指纹、本地签名联系人、该联系人配上本地监听端点以便带外交接、当前路由中的对等节点及其被观测到的端点，以及由独立观测方确认的外部地址。 |
| `BootstrapAsync(CancellationToken)` | 联系所有配置的引导端点，返回作出应答的端点数量。 |
| `AddPeerAsync(IPEndPoint, DHTTransport? preferredTransport, CancellationToken)` | 按地址与端口联系一个节点，先尝试指定的传输，准入该节点并以作出应答的端点返回它。 |
| `ExportRoutingTable()` | 导出当前路由联系人的身份与被观测到的端点以便持久化；随时可用。 |
| `RestoreRoutingTableAsync(ReadOnlyMemory<byte>, CancellationToken)` | 重新联系导出路由表中的节点，准入仍以保存的身份作出应答的节点，并返回准入数量。 |
| `FindNodesAsync(string routingId, CancellationToken)` | 迭代式 XOR 距离查找。 |
| `PublishAsync(string, Stream, long revision, CancellationToken)` | 在本地发布者命名空间下发布一个流。 |
| `PublishAsync(string, ReadOnlyMemory<byte> leaves, string fileHash, long length, long revision, CancellationToken)` | 用 Merkle 叶子、整文件哈希与长度为内容存储中已有的数据块签名并宣告记录，不读取数据块。 |
| `PublishAliasAsync(string, DHTRecord, long revision, CancellationToken)` | 为已发布内容再发布一个名称。 |
| `AnnounceAsync(DHTRecord, CancellationToken)` | 复制已有签名或任意撤销记录；返回远端副本数量。 |
| `UnpublishAsync(string name, long revision, CancellationToken)` | 签名并复制本地发布者命名空间中某个密钥的撤销记录；修订号为 0 时自动取下一个。 |
| `StopProviding(string fileHash)` | 本节点停止提供某个文件，不撤销任何密钥。 |
| `ImportContentAsync(DHTRecord, Stream, CancellationToken)` | 用已有签名记录（可来自任意发布者）校验本地副本并开始提供，返回接受提供者声明的远端副本数。 |
| `ImportContentAsync(DHTRecord, ReadOnlyMemory<byte> leaves, CancellationToken)` | 用与签名记录核对过的 Merkle 叶子开始提供内容存储中已有的数据块，不读取数据块；返回远端副本数。 |
| `ResolveAsync(DHTKey, CancellationToken)` | 按密钥查找签名发布记录。 |
| `FindProvidersAsync(string fileHash, CancellationToken)` | 按完整文件哈希查找提供者，与密钥无关。 |
| `DownloadAsync(DHTKey, Stream, string? expectedFileHash, CancellationToken)` | 解析、下载并校验完整文件。 |
| `DownloadAsync(DHTRecord, Stream, string? expectedFileHash, CancellationToken)` | 按已知签名记录下载。 |
| `ReadBlockAsync(DHTRecord, DHTPeer, int index, DHTPeer? forwarder, CancellationToken)` | 经过校验的单块读取，用于应用自行管理续传或指定 Forwarder。 |
| `RegisterTraversalAsync(DHTPeer traversal, CancellationToken)` | 向 Traversal 节点登记本节点被观测到的端点并保持登记有效。 |
| `RegisterForwarderAsync(DHTPeer forwarder, CancellationToken)` | 与 Forwarder 建立并保持转发会话，使它能把流量投递给本节点。 |
| `TryPunchAsync(DHTPeer peer, DHTPeer traversal, DHTTransport, CancellationToken)` | 由 Traversal 节点协调，尝试 TCP 或 UDP 直连。 |
| `PeerStatistics`、`GetPeerStatistics(string nodeId)` | 节点生命周期内按节点与路径收集的丢包统计。 |

### `DHTNodeOptions` 默认值

| 选项 | 默认值 |
| --- | --- |
| `ListenAddresses` | `{ IPAddress.Loopback }`（一到两项，每个地址族最多一项） |
| `PubliclyReachable` | `false`（通过回拨探测发现可达性；`true` 则立即声明 Public 可达） |
| `BootstrapEndpoints` | 空（最多十六项） |
| `TcpPort`、`UdpPort` | `0`（由操作系统分配）；`null` 关闭对应监听器 |
| `PreferredTransport` | `DHTTransport.Tcp` |
| `Capabilities` | `Download \| Provide` |
| `BucketSize` | `8` |
| `LookupParallelism` | `3` |
| `MaxLookupQueries` | `64` |
| `MaxConcurrentRequests` | `32` |
| `MaxRecords` | `1024` |
| `MaxFileSize` | `1 GiB` |
| `BlockSize` | `16384`（允许 1 KiB–32 KiB） |
| `MaxLocalLeaves` | 本地提供内容的 Merkle 叶子总数 `131072`（允许 1–16,777,216） |
| `IdentityWorkBits` | `12`（允许 0–20；同一网络必须一致） |
| `DisjointLookupPaths` | `3`（允许 1–8） |
| `MaxConcurrentBlockRequests` | `8`（允许 1–64） |
| `MaxBlockRequestsPerPeer` | `2`（允许 1–16） |
| `RequestTimeout` | `5 秒` |
| `UdpAttempts` | `3` |
| `RecordLifetime` | `24 小时`（允许 1 秒–7 天） |
| `MaintenanceInterval` | `5 分钟` |
| `EnableNatTraversal` | `true`（向 Traversal 节点登记、建立转发会话、检查可达性、打洞） |
| `NatTraversalTimeout` | `5 秒` |
| `NatPollInterval` | `1 秒` |
| `NatRegistrationLifetime` | `30 秒`（至少覆盖三个轮询间隔） |
| `ReachabilityCheckInterval` | `30 分钟`（允许 1 分钟–1 天） |
| `MaxNatRegistrations` | `256`（托管的穿透登记、托管的转发会话与保留的直连路径各自的上限） |
| `MaxTraversalNodes` | `4`（允许 1–16） |
| `MaxForwarders` | `4`（允许 1–16） |
| `Logger` | `NullLogger.Instance` |

### 值类型与契约

| 类型 | 主要成员 |
| --- | --- |
| `DHTIdentity` | `DHTIdentity()`、`DHTIdentity(ReadOnlySpan<byte> seed)`、`NodeId`、`PublicKey`、`ExportSeed()`、`ExportSeed(Span<byte>)`、`IdentityWork`、`Create(int workBits, CancellationToken)` |
| `DHTContact` | 签名联系人：`NodeId`、`Hints`、`Reachability`、`HasEndpointDependentMapping`、`Capabilities`、`IdentityWork`、`Sequence`、`ExpiresAt`、`IsExpired`、`Encoded`、`Create(...)`、`Parse(ReadOnlyMemory<byte>)`、`SameAdvertisement(DHTContact)` |
| `DHTPeer` | 联系人配上为它观测到的端点：`Contact`、`Endpoints`、联系人的各成员、`DHTPeer(DHTContact, IReadOnlyList<DHTEndpoint>)`、`Observed(DHTContact, DHTTransport, IPEndPoint)`、`Create(DHTIdentity, IPAddress, int tcpPort, int udpPort, DHTCapabilities)`、`WithContact`、`WithEndpoint`、`Merge`、`SameEndpoints`、`WasObservedAt`、`Write`、`Read` |
| `DHTEndpoint` | 被观测到的端点：`DHTEndpoint(IPAddress, int tcpPort, int udpPort)`、`Observed(DHTTransport, IPEndPoint)`、`Address`、`TcpPort`、`UdpPort`、`Port(DHTTransport)`、`ToIPEndPoint(DHTTransport)`、`Merge`、`Write`、`Read` |
| `DHTReachability` | `Unknown = 0`、`Public = 1`、`Private = 2` |
| `DHTKey` | `DHTKey(string publisherId, string name)`、`Parse(string)`、`IsValid`、`PublisherId`、`Name`、`RoutingId`、相等比较与哈希 |
| `DHTRecord` | `Key`、`IsWithdrawn`、`FileHash`、`MerkleRoot`、`Length`、`BlockSize`、`BlockCount`、`Revision`、`ExpiresAt`、`IsExpired`、`EncodedLength`、`CopyTo(Span<byte>)`、`ToBytes()`、`Parse(ReadOnlySpan<byte>)`、`Create(...)`、`CreateWithdrawal(...)` |
| `IDHTContentStore` | `PutAsync(string blockHash, ReadOnlyMemory<byte>, CancellationToken)`、`GetAsync(string blockHash, CancellationToken)` |
| `IDHTContentFallback` | `TryAcquireAsync(DHTRecord, CancellationToken)`；在本地尚无被请求内容时按需取得该内容 |
| `MemoryDHTContentStore` | `MemoryDHTContentStore(long capacity = 64 MiB, int maxEntries = 65536)` |
| `IDHTRoutingTable` | `Initialize(string localNodeId, int bucketSize)`、`Observe(DHTContact, DHTEndpoint? observed)`、`Remove(string nodeId)`、`Closest(string routingId, int count)` |
| `KademliaDHTRoutingTable` | `KademliaDHTRoutingTable(int maxPerNetworkInBucket = 2, int maxPerNetwork = 10)`；默认路由表，256 个 XOR 距离桶，带按网络限额 |
| `IDHTRouteSelector` | `SelectDirectRoutes(DHTPeer, DHTRouteContext)`、`SelectAssistedRoutes(DHTPeer, IReadOnlyList<DHTPeer> knownAssistants, DHTRouteContext)` |
| `DefaultDHTRouteSelector` | 默认路径选择，见[自定义选路](#自定义选路) |
| `DHTRouteContext` | `PreferredTransport`、`AlternateTransport`、`NatTraversalEnabled`、`MaxAssistedAttempts`、`IsRegisteredWith(string)`、`GetPeerStatistics(string)`、`PacketLossRate(string)`、`PacketLossRate(string, DHTDirectRoute)` |
| `DHTPeerStatistics` | `NodeId`、`SentPackets`、`LostPackets`、`PacketLossRate`、`LastUpdated`、`Routes`、`GetRoute(IPEndPoint, DHTTransport)` |
| `DHTRouteStatistics` | `Endpoint`、`Transport`、`SentPackets`、`LostPackets`、`PacketLossRate`、`LastUpdated` |
| `DHTDirectRoute`、`DHTAssistedRoute` | `Endpoint`、`Transport`；`Assistant`、`AttemptPunch` |
| `DHTCapabilities` | `Download = 1`、`Provide = 2`、`Traversal = 4`、`Forwarder = 8` |
| `DHTTransport` | `Tcp`、`Udp` |

## 用协议 API 实现自己的节点

`MajDHTNode` 只是 MajDHT v1 协议的一种实现，并非必须使用。它用来参与协议的所有类型
都是公开的，因此应用可以自行编写参与者——无论是最小化的客户端、专用的索引节点，还是
节点逻辑的移植——并与参考节点互通。线格式由 [PROTOCOL.zh-CN.md](PROTOCOL.zh-CN.md)
定义；下表中的类型实现了该格式，并且正是参考节点自身使用的同一份代码，因此自定义节点
对消息的编码与校验方式与参考实现完全一致。[IMPLEMENTING.zh-CN.md](IMPLEMENTING.zh-CN.md)
详细说明了协议的行为与流程、每个公开类型的含义、如何通过构造函数扩展 `MajDHTNode`，
以及如何一步步实现一个独立的节点。

| 类型（除注明外位于 `MajDHTNetwork.Protocol`） | 用途 |
| --- | --- |
| `Wire` | 基于池化缓冲区的规范编码器与零拷贝解码器：`PutByte`/`Byte`、`PutLong`/`Long`、`Put`/`Bytes(limit)`、`PutText`/`Text(limit)`、`PutRaw`、`PutHex`、`Tag`、`End`、`WrittenMemory`、`ToArray`、`MaxPacket`。 |
| `Operation` | 操作字节：`Ping`、`Find`、`Store`、`Block`、`Forward`、`Traversal`、`Punch`、`Hello`、`Probe`；响应置位第 7 位。 |
| `Packet` | 一条请求或响应：`Packet(sender, requestId, kind, body)`、`Seal(identity, recipient)`、`SealHello(identity)`、`Open(identity, envelope)`、`CheckForward(envelope, destinationId)`、`Sender`、`RequestId`、`Kind`、`Body`、`RequestIdLength`。 |
| `ResponseStatus` | 每个响应体的状态包装：`WriteSuccess`、`WriteRejection`、`ReadResult`。 |
| `FindMessage`、`FindMode`、`FindRequest`、`FindResponse`、`PeerList` | Find 请求与结果的编解码，对等节点列表有界且逐个独立校验，每一项都是签名联系人加上应答方观测到的端点。 |
| `StoreMessage`、`BlockMessage`、`BlockRequest` | Store 与 Block 的编解码；`BlockMessage.ReadResponse` 按请求方自己持有的记录校验块长度、位置与 Merkle 证明。 |
| `ForwardMessage`、`ForwardAction`、`ForwardRelayRequest` | 转发编解码：转发会话、经 Forwarder 中继不透明信封以及把它投递给目标；`ReadRelayRequest` 与 `ReadDeliverRequest` 对内层信封强制执行转发规则。 |
| `HelloMessage`、`ObservedEndpoint` | Hello 结果，以及与 Traversal 和 Forward 会话共用的被观测端点编码。 |
| `TraversalMessage`、`TraversalAction`、`TraversalIntroduction`、`TraversalPollResponse`、`DialBackArrangement`、`DialBackDelegation`、`PunchMessage`、`ProbeMessage`、`ProbeRequest` | 登记、引荐、回拨、打洞与探测的编解码，用于由 Traversal 节点协调的直连与可达性。 |
| `MerkleTree` | 带域分隔的叶子与父节点哈希：`Leaf`、`AppendLeaf`、`Root`、`Count`、`LeafId`、`WriteProof`、`Proof`、`Verify`、`VerifyLocal`。 |
| `Crypto` | `Hash`、`HashPrefixed`、`Hex`、`HexTo`、`ParseHash`、`IsHash`、`AsciiEquals`、`Random`、`Fill`、`Shuffle`、`Verify`、`Hkdf`，以及摘要、协商密钥、nonce 与标签长度常量。 |
| `IdentityPuzzle` | Argon2id 身份工作量：`Evaluate`、`Work`、`Remember`、`Search` 及其参数。 |
| `ProtocolTags`、`NetworkScope`、`XorDistanceComparer` | 规范标签、地址作用域与网络前缀规则、XOR 距离排序。 |
| `OwnedMemory`、`OwnedPacket`、`PooledBuffer` | 接收信封所借用的池化帧的所有权。 |
| `MajDHTNetwork.Transport.SocketTransport`、`DHTEnvelopeHandler`、`TransmissionCounter` | TCP 分帧、UDP Cookie 与重试、监听器与会话：`SocketTransport(options, handler)`、`Bind`、`Run`、`ExchangeAtAsync`、`PunchAsync`、`TcpPort`、`UdpPort`、`PortFor`、`Stop`、`DisposeAsync`。 |
| `DHTContact`、`DHTPeer`、`DHTEndpoint`、`DHTRecord`、`DHTIdentity`、`DHTNodeOptions`（根命名空间） | `DHTContact.Create`、`Parse`、`Encoded`、`NodeHash`、`SigningKey`、`AgreementKey`、`SameAdvertisement`；`DHTPeer.Write`、`Read`、`Observed`；`DHTEndpoint.Write`、`Read`；`DHTRecord.Create`、`CreateWithdrawal`、`ParseCached`、`Encoded`、`SameContent`；`DHTIdentity.Sign`、`SignTo`、`AgreementPublicKey`、`NodeHash`、`NextSequence`；`DHTNodeOptions.Snapshot`。 |

节点实现通过 `DHTEnvelopeHandler` 接收信封，用 `Packet.Open` 打开，用对应操作的编解码器
读取请求体，把结果连同 `ResponseStatus` 包装写入一个 `Wire`，再把回复封装给已认证的发送
方。处理器的任务完成后传输层会释放接收帧，因此需要保留的请求内容必须复制。发送请求使用
`Packet.Seal` 与 `SocketTransport.ExchangeAtAsync`；调用方在读取结果前须校验响应的发送方、
操作与请求标识符。本文档描述的身份工作量、重放缓存、路由准入、配额与 Sybil 策略属于节点
策略而非编解码：自定义节点需要自行实施。

```csharp
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using MajDHTNetwork;
using MajDHTNetwork.Protocol;
using MajDHTNetwork.Transport;

#nullable enable

// 一个只应答 Ping 与 Hello、不提供其他服务的参与者。
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

测试工程中的 `MinimalProtocolNode` 是一个仅基于这组 API 的完整示例：它提供一个文件、
索引他人的发布通告、从参考节点下载，也能被参考节点发现并下载。

## 身份、密钥与完整性

`DHTIdentity` 持有一个 32 字节的秘密种子。用先前保存的 `ExportSeed()` 构造它，即可在重启后
保留节点 ID 与发布者命名空间。调用方必须借助应用自身的存储层安全持久化这个秘密。签名联系人
只包含公开材料。

规范化密钥的形式是 `发布者-sha256-指纹:区分大小写的名称`。名称非空、最多 256 个严格 UTF-8
字节，且不能包含控制字符。指纹是 Ed25519 公钥的 SHA-256。例如用
`new DHTKey(trustedPublisherId, "songs/example")` 构造查找密钥，或用 `DHTKey.Parse`
还原规范化字符串。DHT 路由标识符是 UTF-8 规范化密钥的 SHA-256。不同的名称或不同的发布者
命名空间可以绑定同一个完整文件 SHA-256 哈希。

`DHTKey` 是不可变值类型。相等比较与哈希只比较其发布者与名称，不分配规范化字符串。默认值
满足 `IsValid == false`，格式化为空字符串，不能用于查找；读取其组成部分会抛出
`InvalidOperationException`。使用前请构造或解析密钥。

可信密钥中的发布者指纹就是该映射的权威来源。一个全局无主的人类可读名称会让攻击者同时替换
文件哈希与其元数据。因此 MajDHT 把名称限定在某个签名身份之下；应用需在带外认证密钥或
发布者指纹。

每条 `DHTRecord` 都会对密钥、原始文件 SHA-256、域分隔的 Merkle 根、文件长度、块大小、
正整数修订号和绝对过期时间签名。导入记录时会校验签名及其所有者指纹。接收方在写入每个块之前
校验其精确长度与 Merkle 位置，在下载完成前校验完整原始文件的 SHA-256。可选的
`expectedFileHash` 会在写出任何数据之前固定来自独立渠道的可信内容。提供者在提供数据块之前
会再次校验自己的块存储。

更高的签名修订号会取代更低的修订号；同一修订号但内容冲突会被拒绝。内存中的修订高水位会
在记录过期后继续保留七天加上信封时钟偏移容差，不同密钥数量上限定为 `MaxRecords` 的四倍。
这样可避免在新短租约过期后，仍有效的旧记录重新浮现。DHT 与全新客户端都无法证明某个不可达的
发布者没有再发布更高修订号。需要跨进程重启保证新鲜度的应用必须自行保留并强制其最后信任的
修订号，或改为固定完整文件哈希。发布修订号必须递增，而且必须由发布者持久化。新发布的默认
租约为一天，可配置为一秒到七天；维护流程只重新宣告已有签名，不会延长其过期时间。续期的方式
是发布更高的修订号，包括通过 `PublishAliasAsync` 发布。

### 撤销发布

`UnpublishAsync(name)` 会签名一条撤销记录：同一密钥、更高修订号、置位 `IsWithdrawn` 且不含内容。
它的修订号高于本地已知以及在 DHT 中找到的所有修订号，租约至少与被撤销的最新发布一样长，因此撤销
记录过期后旧签名也无法再被宣告。节点会把它复制到密钥附近以及被撤销文件哈希附近，维护流程会持续
重新宣告，直到它过期。任何节点都可以用 `AnnounceAsync` 复制撤销记录。遵守协议的节点收到后会把该
密钥解析为已撤销（`ResolveAsync` 返回撤销记录，`DownloadAsync(key)` 抛出
`FileNotFoundException`），删除不再被其他有效发布引用的提供者声明与本地内容，并借助修订号下限继续
拒绝旧修订号。再次发布该名称需要高于撤销记录的修订号。

撤销针对的是"密钥 → 内容"的绑定，而不是内容本身：已下载文件的节点仍保有副本，其他密钥或发布者
可以绑定同一个文件哈希，不诚实的节点也可以无视撤销。`StopProviding(fileHash)` 只是让本节点停止
提供某个文件；其他节点会保留它之前的提供者声明直到过期，并改由其他提供者获取。

### 提供其他发布者的内容

节点可以提供并非由自己发布的内容。`ImportContentAsync(record, stream)` 读取本地副本（例如
副本节点跨重启保留的文件），按已有发布记录中签名的长度、Merkle 根与完整文件哈希进行校验，
注册后宣告本节点为提供者，整个过程无需下载。`ImportContentAsync(record, leaves)` 则用持久化的
Merkle 叶子登记内容存储中已有数据块的同一内容，不读取数据块（见[批量发布](#批量发布)）。
构造节点时传入 `IDHTContentFallback` 后，每当
对端请求本地尚未注册的已签名内容的数据块时，节点都会询问它；回退实现可以导入本地副本或下载
文件，之后节点即提供该数据块。对端可以用 `ReadBlockAsync(record, replicaPeer, index)` 直接向
这种回源副本请求。请求只在自身超时内等待，因此回退实现应限制等待时间、让较长的工作在后台
继续，否则对端会切换到其他提供者。实现必须线程安全，应合并同一内容的并发请求，并自行决定
信任哪些发布者。

## 加密与转发

每个请求与响应都使用全新的临时 X25519 协商、HKDF-SHA256 与 ChaCha20-Poly1305，并用
Ed25519 签名覆盖信封转录与明文。接收方的签名联系人会把其长期协商公钥绑定到节点身份。随机
请求 ID、操作、接收方、版本与发送方都会参与认证。响应必须匹配预期的最终节点、操作与
128 位请求 ID。消息允许最多两分钟时钟偏移；请同步节点时钟。

本设计面向长期接收方密钥加密，**不提供**针对身份种子日后泄露的完全前向保密。发送方使用
全新的临时密钥也不会改变这一性质。本实现尚未经过独立的密码学审计。

当直连失败时，节点首先使用目标签名联系人中的提示，然后使用路由表中其他声明 `Traversal` 或
`Forwarder` 的节点。对本节点已登记的被提示 Traversal 节点，它请求引入一条 TCP 或 UDP 直连路径；
Forwarder 则为它中继请求。Forwarder 会收到一个单独加密的外层 RPC，其中包含目标 ID 与一个不透明的
内层信封；它把内层信封原样包进自己的已认证请求投递到目标的转发会话，并返回不透明响应。只有最初的
下载方与提供者能打开文件请求与数据块响应；Forwarder 可以观测端点、包大小、时序以及可见的操作编号。
损坏的转发响应会被拒绝，并可尝试其他已知 Forwarder。Forwarder 只会中继给在本节点持有有效转发会话
的节点或已经认证过的路由节点，并拒绝嵌套转发与控制操作。目标只接受来自 Forwarder 的投递，且不会
由此学到来源节点的任何端点。恶意参与者仍然可以建立多个独立连接；这不是匿名路由，也不防御
Sybil/eclipse 攻击。

需要应用自行管理续传或指定 Forwarder 时，请使用底层的、经过校验的数据块 API：

```csharp
var block = await downloader.ReadBlockAsync(record, providerPeer, 0,
    forwarder: forwarderPeer, cancellationToken: cancellationToken);
```

提供者声明只是可用性提示；单独一份签名联系人并不能证明其确实持有数据。一次下载会同时向多个
提供者请求数据块：总共最多有 `MaxConcurrentBlockRequests` 个数据块在途，每个提供者最多
`MaxBlockRequestsPerPeer` 个。每个数据块交给有空闲名额且排名最佳的提供者：本节点优先，其次是
测得丢包率更低、在途请求更少、失败次数更少的提供者。无效或不可用的数据块会回到队列，改由其他
提供者获取；只有所有提供者都无法提供某个数据块时，下载才会失败。经过校验的数据块按顺序写入
目标流、摘要与存储；重排窗口为 `MaxConcurrentBlockRequests` 的两倍，用于限制提前到达的数据块
占用的内存。TCP 的一条连接同一时间只承载一个请求，因此并行主要来自同时使用多个提供者。

### 节点统计

节点在整个生命周期内，按节点以及按路径（端点与传输）记录发出的请求传输次数，以及在单次尝试
超时前没有收到响应的次数。每次 UDP 重传和每次 TCP 尝试都会计入；打洞与回拨探测不计入；经 Forwarder
中继的请求计入该 Forwarder。`GetPeerStatistics(nodeId)` 与 `PeerStatistics` 返回不可变的
`DHTPeerStatistics` 快照，其中 `PacketLossRate` 为 `LostPackets / SentPackets`，按路径的明细见
`Routes` 与 `GetRoute(endpoint, transport)`。最多保留 4,096 个节点、每个节点 16 条路径，超出时
淘汰最久未更新的条目。选路与下载调度都会使用这些丢包率。

## 引导与发现

任何运行中的节点都可以充当引导节点。不存在特权引导角色、中心目录或内置硬编码服务器。把已知
节点的端点列在 `DHTNodeOptions.BootstrapEndpoints` 中：`StartAsync` 会在后台联系它们，
路由表为空时维护流程会重试，`BootstrapAsync` 则显式联系它们并返回作出应答的端点数量。每个
端点对一个签名的 Hello 请求作出应答，返回自己的签名联系人以及它观测到的调用方端点。引导只负责
引入已知联系人，随后由有界的迭代 XOR 距离查找发现更多节点。离线节点可以在本地发布；等有节点
可用后，`AnnounceAsync` 或自动维护会复制其记录。即使没有任何远端副本接受，发布也会返回签名
记录，并通过可选日志上报一条警告。`AnnounceAsync` 返回远端副本数量。

`AddPeerAsync(endpoint, preferredTransport)` 对运行时得到的单个端点做同样的事，例如用户输入的
地址或应用通过自己的渠道收到的地址：先通过指定的传输发送 Hello（为 null 时使用节点的
`PreferredTransport`），若无应答再在同一端口上尝试另一种传输，准入作出应答的节点，若它是 Traversal
节点或 Forwarder 则向其登记，随后发现邻居，并以作出应答的端点返回该节点。两种传输都无应答时抛出
`IOException`。

端点并不标识某个节点：在配置或手动添加的端点上作出应答的任何一方都会成为第一个联系人。请只从
可信来源配置引导端点和添加节点。声明 `Traversal` 能力的节点协调直连与可达性检查；声明 `Forwarder`
能力的节点为与之保持转发会话的节点中继流量。

### 持久化路由表

`ExportRoutingTable()` 返回一份小型快照，包含当前路由联系人的身份与被观测到的端点，按离本节点由近
到远排列；它在节点启动前和停止后都可以调用，本库自身从不把它写到任何地方。重启后，在运行中的节点上
调用 `RestoreRoutingTableAsync(snapshot)`：它向每个保存的端点发送 Hello（同时最多联系十六个
联系人），准入仍以保存的身份作出应答的节点，在启用 NAT 穿透时向作出应答的 Traversal 节点与 Forwarder
登记，然后发现
当前的邻居，并返回准入的联系人数量。不再应答的端点，或者现在以另一身份应答的端点，都会被跳过，
因此一份过期快照只会耗费几次请求超时。格式错误的快照会抛出 `InvalidDataException`。联系人租约
最多一天，所以快照保存的是端点而不是签名联系人。恢复与引导可以同时使用：同时拥有快照和引导
端点的节点会联系两者。

### 批量发布

多个发布会并发地读取、哈希并存储各自的流；每个节点只在登记签名记录的那一刻串行化，若此时有另一个
发布或撤销已经推进了该密钥的修订号，则以 `ArgumentException` 拒绝。每次复制会同时查找密钥附近
与文件哈希附近的节点，并并行发送 Store 请求。复制按槽位准入，使其请求连同其他工作一起不超过
`MaxConcurrentRequests` 个出站交换：只有两次查找合计不超出预算时才会同时进行，同时进行的复制
数量为 `MaxConcurrentRequests` 除以该占用量，至少为一（默认值下为一；需要更多时请调高
`MaxConcurrentRequests`）。维护流程以同样的上限重新宣告记录，因此大量发布的维护也会在预算允许
的范围内并行进行。记录、修订号、提供者声明与本地 Merkle 树的索引在缓存或登记记录的路径上每秒最多
清理一次，配额看似用尽时则立即清理，因此发布或接收大量记录的耗时与记录数成线性关系。

拥有大量文件的发布者在重启后不必再次读取它们。除了数据块本身，节点提供一个文件所需的只有它的
叶子：`MerkleTree.Leaf` 计算出的 32 字节块摘要，按块顺序拼接。把数据块保存在持久化的
`IDHTContentStore` 中，并为每个文件持久化叶子、整文件哈希与长度的应用，可以在签名记录尚未过期时用
`ImportContentAsync(record, leaves)` 恢复提供，在记录过期后用
`PublishAsync(name, leaves, fileHash, length, revision)` 签名新的修订号；两者都不读取内容。两者都会把
叶子与记录的块数和 Merkle 根核对，或与配置块大小下的长度核对，并执行与基于流的同名方法相同的过期与
叶子配额检查；但都不检查数据块是否存在，因此缺失或被改动的数据块只会让针对该块的请求失败。

`ListenAddresses` 接受一个地址，或者一个 IPv4 地址加一个 IPv6 地址，以便在相同的配置端口上
双栈监听；允许使用通配地址。支持任意 TCP/UDP 端口、相同或不同的 TCP/UDP 端口号，TCP 与
UDP 监听器也可以独立启用。签名联系人从不写明节点自己的端点：每个节点都从监听端口发送，因此与它
通信的节点会观测到它能被访问的位置，为每个联系人保留最多四个被观测到的地址及其 TCP 与 UDP 端口，
并在推荐时一并传递。`LocalPeer` 把本地联系人与监听端点配对，用于交给同一主机上的另一个进程。
出站请求按从新到旧的观测顺序尝试目标被观测到的端点，每个端点都先用首选传输，再用另一种传输。
主机名、外部 STUN 服务器与 UPnP 不在本库范围内。

### Sybil 抵御

开放的 DHT 无法阻止一方创建大量身份，但 MajDHT 会提高其成本并限制其影响范围：

- **身份工作量。** 身份的 `IdentityWork` 是对其节点摘要做内存困难的 Argon2id 哈希（1 MiB）后的前导
  零位数。这里没有独立的 nonce：工作量属于密钥本身，因此创建身份就是不断生成密钥直到某个合格；
  想把节点 ID 刷到某个密钥附近，每个候选密钥都要付出一次完整的谜题成本。节点自身的身份必须达到
  `IdentityWorkBits`（默认 12，一次性耗时数秒到数十秒，并随种子持久保存），节点也会拒绝低于该值的
  请求、响应、推荐联系人、辅助路径与引入。每个身份在一个进程内只计算一次；每秒最多计算 128 个未知
  身份，因此大量新身份的洪泛无法耗尽 CPU。同一网络的所有节点必须使用相同的值。
- **经验证的准入。** 联系人只会在本节点自己观测到的端点上进入路由表：应答了请求的那个端点，或者
  入站请求的源——前提是发送方随后应答了发往该源的 Ping，同时最多 16 次验证、每个源网络每分钟最多
  八次。被推荐的端点只会被尝试，绝不凭推荐方的一句话准入。只能经 Forwarder 或打洞路径访问的
  节点可以使用，但不会推荐给其他节点。
- **网络多样性。** 路由表中同一 IPv4 /24 或 IPv6 /32 在每个桶内最多两个联系人、整张表最多十个；
  每个文件按观测到的源地址，同一网络最多保留三个提供者声明。回环、私有与链路本地地址不受限，
  局域网可以照常工作。
- **随机化选择。** 回拨协助者在每个网络中随机抽取一个；路由中的 Traversal 节点与 Forwarder 从最近
  的候选中随机抽取；下载时提供者以随机顺序开始。靠近目标刷出的身份无法稳定地占据这些角色。
- **不相交查找。** 每次查找沿 `DisjointLookupPaths` 条路径进行，各路径从不查询同一节点，并各自
  分得 `MaxLookupQueries` 的一部分，最后合并结果。Sybil 推荐可以耗尽它占据的路径，但只要有一条
  诚实路径找到了记录或提供者，结果就仍能找到。

## TCP、UDP 与 NAT 穿透

两种能力协助无法直接互达的节点，一个节点可以声明其一或两者兼具：

- **Traversal** 节点协调直连。登记的节点向它刷新自己被观测到的 TCP 与 UDP 端点，请求它把自己引荐
  给另一个登记者，并朝它分发的端点打洞。它还安排回拨，用来探测某节点是否能接受未经请求的入站包。
- **Forwarder** 中继流量。节点与它建立转发会话，使它知道要把流量投递到哪个端点（或哪条双工 TCP
  连接）；任何节点都可以经它向会话拥有者中继一个不透明信封。无法直连的两个节点仍可经 Forwarder 通信。

通过声明任一能力的节点进行引导时，会自动为每种共同启用的传输向它登记。协助节点会观测每个已认证
请求的实际源地址与端口；UDP 请求保留其 Cookie 校验，TCP 登记则来自监听端口。客户端会刷新这些
短寿命登记与会话，并持续轮询待处理的引入，直到关闭为止。节点也可以显式登记并请求指定的直连传输：

```csharp
await provider.RegisterTraversalAsync(traversalPeer, cancellationToken);
await downloader.RegisterTraversalAsync(traversalPeer, cancellationToken);
var connected = await downloader.TryPunchAsync(providerPeer, traversalPeer,
    DHTTransport.Udp, cancellationToken);
await provider.RegisterForwarderAsync(forwarderPeer, cancellationToken);
```

用 `DHTTransport.Tcp` 请求 TCP 同时打开。Traversal 节点分发双方观测到的端点以及一个随机、会过期的
128 位票据。每个节点都从自己绑定的监听端口发起探测。有效的直连探测必须匹配票据、节点身份、
传输与观测端点；此后普通请求便走已认证的直连路由。TCP 会保留已建立的连接以服务后续请求。
即使 Traversal 节点离线，已成功的直连传输仍可继续。会话循环与未完成的探测会在 `StopAsync` 期间排空。

辅助穿透要求被穿透的传输存在本地监听器，因为出站探测必须复用该监听器的端口。将
`EnableNatTraversal` 设为 `false` 可关闭客户端登记、转发会话与自动穿透；声明 `Traversal` 或
`Forwarder` 的节点仍会在其登记配额内响应请求。默认值为：五秒穿透预算、一秒轮询间隔、30 秒租约、
每个客户端最多四个 Traversal 节点与四个 Forwarder、每个节点托管最多 256 个登记与 256 个会话。
引入队列以 `MaxConcurrentRequests` 为界，活跃票据数量上限为该值的四倍。

这是尽力而为的穿透：端点相关的 NAT 映射、被阻断的 UDP、拒绝同时打开的 TCP 协议栈或防火墙、
以及路由器策略都可能阻止直连。只要 Forwarder 持有目标的会话（包括现有的 TCP 连接或观测到的
UDP 映射），转发依然可用。如果经同时具备 Traversal 与 Forwarder 能力的节点引入的探测成功但随后的
RPC 失败，请求方仍会经同一节点转发。

### 家宽网络中的可达性

家用路由器之后的节点通常没有固定、可达的地址。此时请不要开启 `PubliclyReachable`，并保持
`EnableNatTraversal` 开启，节点会自行判定可达性：

1. **外部地址。** 穿透登记、转发会话与 Hello 响应会报告每个远端节点观测到的端点。若至少两个处于
   不同网络（IPv4 /24 或 IPv6 /32 前缀不同）的观测方报告同一地址，它就成为已确认的外部地址，可通过
   `ExternalAddresses` 读取。若观测方为该地址观测到不同端口，联系人会置位
   `HasEndpointDependentMapping`，请求方随之跳过打洞。外部地址变化（例如 PPPoE 重拨）会开启
   新纪元，丢弃之前的验证结果并重新检查可达性。
2. **回拨探测。** 每次新建穿透登记以及每隔 `ReachabilityCheckInterval`，节点都会请求其 Traversal
   节点安排一次回拨。Traversal 节点把回拨委托给另一网络中独立的公网 Traversal 节点，协助者只探测
   被观测到的地址。探测被接受且该地址与已确认的外部地址一致后，联系人成为 `Public`，因此单个
   Traversal 节点无法让节点声称外来地址。
3. **私有联系人。** 当经由两个不同网络 Traversal 节点的回拨都超时，只要能提示一个持有有效会话的公网
   Forwarder，联系人就成为 `Private`：它把最多三个持有有效会话的公网 Traversal 节点与 Forwarder
   （Forwarder 优先）嵌入为 `Hints`，并附上本节点为它们观测到的端点。请求方不拨打它的任何端点，
   而是经被提示的 Forwarder 访问它；若请求方已在某个被提示的 Traversal 节点登记，会先经它打洞。

私有节点以 DHT 客户端身份参与网络：它可以查找、下载与提供内容，但不会被加入路由表，也不会
作为查找跳点返回。联系人变化会立即重新签名，本地发布会在五秒后重新宣告，使提供者索引持有新
联系人。私有与未验证联系人的租约为一小时，公网联系人为一天。每个 Traversal 节点每分钟最多接受
同一请求方的三次回拨请求；每个协助者每分钟最多接受同一委托方的十次委托，并最多向同一目标地址
回拨四次，每次委托最多发送五轮探测。

## 自定义选路

构建节点时可以替换两类选路决策：

```csharp
await using var node = new MajDHTNode(options, identity, store,
    routingTable: new KademliaDHTRoutingTable(), routeSelector: new MyRouteSelector());
```

- **`IDHTRoutingTable`** 决定把哪些已认证联系人保留为查找跳点，以及哪些对等节点（连同被观测到的
  端点）作为离目标最近的节点返回。节点只会调用一次 `Initialize`，因此每个节点都要传入新的路由表。
  节点只把已认证且非私有的联系人交给 `Observe`，同时传入本节点与该联系人交换过已认证数据包的端点；
  仅刷新已知联系人时传入 null。节点在请求失败或节点变为私有时调用 `Remove`，并丢弃 `Closest`
  返回的过期、私有、重复以及本节点自身的条目。默认的 `KademliaDHTRoutingTable` 维护 256 个 XOR
  距离桶，每桶最多 `BucketSize` 个联系人，不会淘汰仍然有效的条目，会把新的观测合并进联系人的端点；
  同一公网网络在每个桶中最多两个、整张表最多十个。
- **`IDHTRouteSelector`** 决定如何访问目标节点。它返回按顺序排列的直连尝试（端点与传输），
  以及直连全部失败后按顺序排列的辅助尝试：依次尝试哪些 Traversal 节点与 Forwarder，以及是否先经
  它们打洞。`DHTRouteContext` 提供首选传输、是否启用 NAT 穿透，以及本节点已登记的 Traversal 节点。
  同一个路径选择实现可以在多个节点间共享。

`DefaultDHTRouteSelector` 按从新到旧的观测顺序拨打目标被观测到的端点，私有目标的端点一律不拨打。
辅助路径先列出目标的提示（只对本节点已登记的被提示 Traversal 节点尝试打洞），再列出最多 `BucketSize`
个路由中的 Traversal 节点与 Forwarder；目标映射依赖目的端点时从不打洞，不具备 `Forwarder` 能力的
协助节点只用于打洞。在上述每一层内，测得丢包率更低的路径与协助节点排在前面；未尝试过的路径按无丢包
计算，丢包率相同时保持首选传输与路由顺序在前。自定义的路径选择可以通过
`DHTRouteContext.GetPeerStatistics` 与 `DHTRouteContext.PacketLossRate` 读取同样的测量结果。

两种实现都必须线程安全、快速返回，并且不得进行网络 I/O。路径只是尝试，而非信任决策：无论经由
哪条路径，每个响应都会按目标身份进行认证。经打洞、托管的穿透登记或托管的转发会话得到的已认证路径
总是先于所选的直连路径尝试。节点最多尝试十六条直连路径和三十二条辅助路径，并跳过经由本节点、目标
本身、过期联系人或既无 `Traversal` 也无 `Forwarder` 能力的节点的辅助路径。

## 存储、配额与生命周期

`IDHTContentStore` 以域分隔的 Merkle 叶子哈希为键存放原始数据块。实现必须线程安全、遵守
取消请求，并保持稳定的读取快照。如果实现会在返回后继续持有数据，`PutAsync` 必须复制输入。
即使使用自定义存储，节点也会独立校验从存储读回的数据。

默认的 `MemoryDHTContentStore` 是上限为 64 MiB、65,536 条目的 LRU 缓存。它会淘汰旧块，
因此提供者可能变成部分提供者。若需要持久发布或文件大于该缓存，请提供应用自有的持久化存储。
在 MajdataPlay 宿主中，可用 `MajdataPlay.IO.Storage.FileSystem` 实现它。本库只使用
`System.IO.Stream` 与内存流；从不使用 `System.IO.File`、`System.IO.Directory` 或
`FileStream` 访问文件系统。请通过既有门面打开应用流，例如
`FileSystem.File.Open(sourceLocation).OpenRead()`，再交给节点。仅持久化数据块并不能恢复
内存中的发布索引或 Merkle 树：进程重启后需要用应用保留的身份与下一个修订号重新发布原始流。

其他默认值包括：256 个距离桶、每桶八个节点、三次并行查找查询、每次查找查询 64 个节点、
32 个并发入站处理、1,024 条活跃记录、每个内容哈希最多 16 个提供者、本地索引的 Merkle 叶子
总数 131,072（`MaxLocalLeaves`）。可配置的文件上限为最多 1 GiB；使用较小数据块时可能先触及叶子配额。所有加密
信封上限为 60,000 字节。16 KiB 的默认块与 32 KiB 的最大块为证明与嵌套加密留出余量。较大的
UDP 数据报依赖 IP 分片；丢包会重传整个请求。v1 没有 MTU 感知的应用层分片、拥塞控制、流式
多路复用或带宽调度。数据报分片不适用时请使用 TCP。

UDP 在处理请求前必须先通过无状态源地址 Cookie 校验。固定 69 字节的 hello 与 challenge
不会放大流量；Cookie 绑定源 IP、源端口、完整密文以及一个较短的服务端时间窗口。请求使用有界
重试，节点会在有界的两分钟回复缓存中合并重复的已认证请求 ID。这能限制反射与内存分配滥用，
但无法让公开端点免疫流量洪泛。

`StartAsync` 只绑定一次监听器，其可选令牌是生命周期令牌。`StopAsync`、`DisposeAsync` 与
`Dispose` 是幂等的，会取消出站套接字工作并排空入站处理器与维护流程。已停止的实例不能重启。
在异步宿主中请使用异步释放。公共操作会把显式取消与节点生命周期关联起来。调用方的流以及传入
的身份/存储仍归调用方所有。忽略取消令牌的自定义存储或流可能延迟关闭。

下载成功意味着整个请求的文件都已被校验。失败可能留下部分输出与缓存块；请借助 `FileSystem`
使用暂存文件，只在任务成功后再提交。节点不会代替调用方做原子文件替换。

## 日志

`DHTNodeOptions.Logger` 接受标准的 `Microsoft.Extensions.Logging.ILogger`，默认值为
`NullLogger.Instance`。传入宿主创建的日志器，例如来自
`ILoggerFactory.CreateLogger<MajDHTNode>()` 的实例。日志器及其提供程序归宿主所有。节点各
服务会发出带有稳定事件 ID 与 Network 上下文的结构化 Debug/Information/Warning/Error
事件。缓存的 `LoggerMessage.Define` 委托可在禁用路径上避免格式化与装箱。日志调用可能来自
后台线程。提供程序抛出的异常会被隔离，不影响节点清理。诊断字段包含失败类型，但不会复制私有
的异常消息、密钥、种子或文件路径。

## 内存所有权与内存分配

`DHTIdentity(ReadOnlySpan<byte>)`、`DHTIdentity.PublicKey`、
`DHTIdentity.ExportSeed(Span<byte>)`、`DHTRecord.Parse(ReadOnlySpan<byte>)` 与
`DHTRecord.CopyTo(Span<byte>)` 让同步调用方使用自己的缓冲区。`EncodedLength` 给出清单
导出的容量。`ExportSeed()` 与 `ToBytes()` 仍是显式便利方法，返回独立数组。

异步传输使用 `ReadOnlyMemory<byte>`，因为 span 不能跨越 await 存活。`ReadBlockAsync` 返回
经过校验的只读数据块，只要结果被保留，其托管持有者就保持存活。默认存储写入时只复制一次，并
返回稳定的只读视图；淘汰不会让已有视图失效。调用方必须把返回的只读内存视为不可变。

内部的 `Packet` 是复制内存视图的只读值类型。借用的内存保持调用方管理的生命周期。打开信封时
**就地解密**：接收到的帧由接收方独占，其密文区域直接变为明文，解码后的包借用该帧，已消费的
信封不能再次打开，认证失败时该区域会被清零。每个包不再分配明文数组。持有可变状态、池化缓冲区、
身份或持久签名元数据的对象仍然是引用类型。

接收到的帧是**池化**的。TCP 读取循环与 UDP 接收循环把每一帧作为自有视图交给它的消费者，消费者
在复制或读完需要保留的内容后释放该帧：下载的数据块在存储复制完成、目标流接收完成后才释放其帧；
服务端的请求帧在处理程序返回后释放（因超时而被放弃的处理程序会保留其帧直到自身结束）；从帧中
解析出的联系方式、记录、介绍票据和随机数都会在帧归还池之前被复制。公共的 `ReadBlockAsync`
会在释放帧之前把远程数据块复制出来，因此池化内存绝不会作为公共结果逃逸。

本库面向对垃圾回收停顿敏感的宿主（例如 Unity 的 gameplay 线程）编写：

- 协议写入器与文件读取缓冲区使用清零的池化数组；读取器直接对既有内存切片，不产生逐字段数组。
  版本标签与标识符按字节比较，不再解码为字符串。密文直接写入池化的最终信封，签名就地写入，
  Merkle 树使用一整块连续节点缓冲区。证明校验使用栈空间。池化内存绝不会作为公共异步结果逃逸。
- SHA-256、带前缀的叶子哈希和认证加密器按线程缓存并在每次使用时重新初始化；HKDF-SHA256 完全
  在栈上运行，并已对照 RFC 5869 与提供程序的生成器验证；X25519 直接在原始标量上运行，秘密使用
  池化并清零的缓冲区；UDP cookie 的 HMAC 每个传输只创建一次。
- 已验证的联系方式与记录按其精确字节的摘要缓存，有界且检查过期，因此每个请求的发送方和每个
  数据块请求携带的清单只需验证签名并分配一次。重放缓存以内联摘要为键，不再使用字符串。
- 重放缓存、路由副本、TCP 帧长度前缀、每数据块的下载状态和统计键都避免了逐请求的字符串、
  列表与地址解析。
- 接收到的 TCP 帧直接读入池化缓冲区；UDP 数据报落在每个套接字一份的可复用接收缓冲区中，只有
  有消费者的帧才被复制到池化缓冲区；每一帧都由其消费者释放，因此每个下载数据块原本分配的第三份
  32 KiB 副本不复存在。

剩余的每数据块开销主要来自所有权契约要求的两份 32 KiB 自有副本（重放缓存保留的已封装回复、
默认存储的副本），以及提供程序的 Ed25519 与 X25519 运算：在同一宿主上，一次签名约分配 1.9 KB，
一次验签约 6.5 KB，每次 X25519 运算约 1 KB，因此封装并打开一个信封在提供程序中约耗费 11 KB，
而在本库中约 1 KB。

在 Windows .NET 9 Release 测试宿主上测得的热身托管分配量：

| 工作负载 | 最初 | 上一轮 | 现在 |
| --- | ---: | ---: | ---: |
| 32 KiB 编解码往返 | 98,864 B/op | 96 B/op | 96 B/op |
| 32 KiB Merkle 叶子 | 33,048 B/op | 192 B/op | 56 B/op |
| 128 叶 Merkle 树 | 46,120 B/op | 8,576 B/op | 8,440 B/op |
| SHA-256 十六进制格式化 | 1,376 B/op | 152 B/op | 152 B/op |
| 32 KiB 加密包往返 | 700,807 B/op | 约 95,000 B/op | 约 46,000 B/op |
| 64 字节加密包往返 | — | — | 约 13,000 B/op |
| 经 TCP 端到端下载一个 32 KiB 数据块（两个节点合计） | 约 253,000 B/块 | 约 140,000 B/块 | 约 104,000 B/块 |
| 经 UDP 端到端下载一个 32 KiB 数据块（两个节点合计） | 约 256,000 B/块 | 约 142,000 B/块 | 约 106,000 B/块 |
| 已缓存的 32 KiB 数据块读取 | — | 0 B/op | 0 B/op |
| 被禁用的日志事件 | — | 0 B/op | 0 B/op |

单操作行使用 `GC.GetAllocatedBytesForCurrentThread`；端到端行在两个回环节点之间完整下载一个
下载方未见过的文件，用 `GC.GetTotalAllocatedBytes` 统计，涵盖双方的请求封装、传输分帧、认证、
数据块校验与存储。所有测量都在测量前预热池与提供程序，不含原生分配与网络 I/O。它们是分配
回归基线，而不是吞吐量或跨运行时结论。端到端行中，“最初”列是该测试的首次测量；“上一轮”已经
就地解密，但每一帧仍然接收到一个新分配的数组中；“现在”则释放池化的帧，其 130,000 B/块的预算
会在帧副本重新出现时失败。

## 安全范围

- 接收方密钥是长期密钥，因此本协议**不提供**完全前向保密；身份种子泄露会暴露历史流量。
- 本实现**尚未**经过独立审计。
- Forwarder 会隐藏载荷，但能观测端点、大小、时序与操作编号。这不是匿名路由，也不抵御 Sybil 或
  eclipse 攻击。
- 提供者通告只是提示；只有签名记录、Merkle 证明与完整文件哈希具有权威性。
- 应用必须在带外认证密钥与发布者指纹，只从可信来源配置引导端点，并安全持久化身份种子与
  修订号。Hello 请求有签名但不加密。
- 可达性证据依赖独立的观测方与协助者。单个 Traversal 节点无法设定外部地址，也无法让节点在外来地址上
  声称公开可达；跨两个网络串通的节点可以做到，串通的 Traversal 节点也可以让节点看起来是私有的。被推荐
  的端点只是推荐方的主张，只会被尝试而不会被信任。这些都只影响可达性，不影响内容完整性。
- Sybil 身份的成本被提高、影响被限制（见 [Sybil 抵御](#sybil-抵御)），但无法杜绝：拥有足够
  CPU 且掌握多个网络地址的攻击者仍可加入身份。查找结果与提供者声明仍然只是提示；签名、Merkle
  证明与文件哈希才具有权威性。
- 超出租约的新鲜度由应用负责；当内容必须永不变更时，请固定完整文件哈希。

## 测试与验证

测试工程引用真实的 `netstandard2.1` 类库，并运行真实的回环 TCP/UDP 套接字；测试清单与筛选
方式见[测试工程 README](src/MajDHTNetwork.Tests/README.md)。覆盖范围还包括在下载后搅动数组池、
验证池化帧只在消费者复制完毕后才被释放。

```powershell
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release --filter 'Category=Allocation'
```

覆盖范围包括：协议测试向量与畸形输入、已认证信封与身份冒充、Merkle 几何、三节点发现与下载、
转发回退、双传输、IPv6 与双栈传输、端点引导、UDP 丢包/重放、穿透登记与打洞、转发会话与投递、
外部地址投票、回拨探测与经提示访问的私有节点、丢包统计与按丢包率选路、多提供者并发下载、配额与
生命周期限制，以及热身分配预算。

.NET Standard 只是 API 目标，并不代表已经成功集成 Unity、Mono、IL2CPP、Player、移动端、
NAT、WAN 或硬件。上述宿主与网络条件在部署前需要各自进行验证。

## 打包与分发

包 ID、程序集名称与公共根命名空间均为 `MajDHTNetwork`；当前版本为 `0.1.0`。

```xml
<PackageReference Include="MajDHTNetwork" Version="0.1.0" />
```

```powershell
dotnet pack MajDHTNetwork.csproj --configuration Release --output artifacts/nuget
```

包内包含 netstandard2.1 的 DLL、XML 文档文件、`README.md`、`PROTOCOL.md`、`IMPLEMENTING.md` 与 `LICENSE`；
测试源码不会被打包。请按所选馈送（feed）的常规发布流程上传 `.nupkg`。

`Publish.ps1` 自动化完整的发布流程：锁定还原、Release 构建、回归与分配测试、NuGet 与符号包、
含运行时依赖与第三方许可证声明的松散 DLL ZIP，以及隔离的 NuGet 消费者与直接 DLL 消费者校验。
它产出：

- `artifacts/nuget/MajDHTNetwork.<version>.nupkg`
- `artifacts/nuget/MajDHTNetwork.<version>.snupkg`
- `artifacts/MajDHTNetwork.<version>.dll.zip`
- `artifacts/dll/<version>/`，未压缩的 DLL 分发包

直接使用 DLL 的消费者除 `MajDHTNetwork.dll` 外，还需要部署 ZIP 中包含的依赖 DLL；目标框架若
自带等效程序集，也可以从框架中解析这些依赖。二进制消费者回归测试在 .NET 9 上验证这种集成方式。

`Publish.ps1` 与 `ValidatePackage.ps1` 按上游仓库结构（`Tools/CSharp/MajDHTNetwork` 与
`Tools/Tests/MajDHTNetwork.Tests`）解析测试工程、运行时许可证与仓库根目录。在搬迁后的副本中
运行时，请使用上面的 `dotnet` 命令，或自行调整这些路径。

## 许可证

MIT，见 [LICENSE](LICENSE)。

## 协议

- [PROTOCOL.md](PROTOCOL.md) — MajDHT v1 线协议（英文）。
- [PROTOCOL.zh-CN.md](PROTOCOL.zh-CN.md) — MajDHT v1 线协议（中文）。
