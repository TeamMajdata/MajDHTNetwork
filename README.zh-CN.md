# MajDHTNetwork

[English](README.md) | **简体中文**

MajDHTNetwork 是一个独立的 **.NET Standard 2.1** 类库，命名空间为
`MajDHTNetwork`。一个 `MajDHTNode` 同时是 DHT 参与者、内容提供者和可选的端到端加密中继。
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
- [身份、密钥与完整性](#身份密钥与完整性)
- [加密与中继](#加密与中继)
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
- **中继辅助穿透。** 声明 `Relay` 能力的节点观测真实端点并协调 TCP/UDP 打洞；当直连
  路径不可行时，同一个中继可以转发不透明的加密信封。
- **面向家宽的可达性发现。** NAT 之后的节点通过独立中继得知自己的外部地址，用独立的
  回拨探测验证它；无法验证时改为通告签名的中继提示，而不是地址。
- **双栈监听与端点引导。** 一个节点可以同时监听 IPv4 与 IPv6，并通过配置的引导端点
  加入网络。
- **可插拔存储。** 数据块由 `IDHTContentStore` 承载；默认的 `MemoryDHTContentStore`
  是有界的 LRU 缓存，应用也可以提供持久化存储。
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
    Capabilities = DHTCapabilities.Download | DHTCapabilities.Provide | DHTCapabilities.Relay
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

当节点 ID 与发布者命名空间需要跨重启保持时，用 `DHTIdentity(seed)` 从
`ExportSeed()` 的结果恢复身份；当数据块需要比进程活得更久时，实现
`IDHTContentStore`。

## 公共 API

### 节点操作

| 成员 | 用途 |
| --- | --- |
| `MajDHTNode(DHTNodeOptions?, DHTIdentity?, IDHTContentStore?, IDHTRoutingTable?, IDHTRouteSelector?)` | 创建节点；所有参数都可选，缺省时在内部创建默认实现。 |
| `StartAsync(CancellationToken)` | 只绑定一次监听器；配置了引导端点时在后台开始引导；该令牌是生命周期令牌。 |
| `StopAsync()`、`DisposeAsync()`、`Dispose()` | 幂等的关闭流程；已停止的实例不能重启。 |
| `NodeId`、`LocalPeer`、`KnownPeers` | 本地身份指纹、本地签名联系人与当前路由中的联系人。 |
| `BootstrapAsync(CancellationToken)` | 联系所有配置的引导端点，返回作出应答的端点数量。 |
| `FindNodesAsync(string routingId, CancellationToken)` | 迭代式 XOR 距离查找。 |
| `PublishAsync(string, Stream, long revision, CancellationToken)` | 在本地发布者命名空间下发布一个流。 |
| `PublishAliasAsync(string, DHTRecord, long revision, CancellationToken)` | 为已发布内容再发布一个名称。 |
| `AnnounceAsync(DHTRecord, CancellationToken)` | 复制已有签名；返回远端副本数量。 |
| `ResolveAsync(DHTKey, CancellationToken)` | 按密钥查找签名发布记录。 |
| `FindProvidersAsync(string fileHash, CancellationToken)` | 按完整文件哈希查找提供者，与密钥无关。 |
| `DownloadAsync(DHTKey, Stream, string? expectedFileHash, CancellationToken)` | 解析、下载并校验完整文件。 |
| `DownloadAsync(DHTRecord, Stream, string? expectedFileHash, CancellationToken)` | 按已知签名记录下载。 |
| `ReadBlockAsync(DHTRecord, DHTPeer, int index, DHTPeer? relay, CancellationToken)` | 经过校验的单块读取，用于应用自行管理续传或指定中继。 |
| `RegisterRelayAsync(DHTPeer relay, CancellationToken)` | 向中继登记本节点被观测到的端点。 |
| `TryPunchAsync(DHTPeer peer, DHTPeer relay, DHTTransport, CancellationToken)` | 通过中继协调尝试 TCP 或 UDP 直连。 |

### `DHTNodeOptions` 默认值

| 选项 | 默认值 |
| --- | --- |
| `ListenAddresses` | `{ IPAddress.Loopback }`（一到两项，每个地址族最多一项） |
| `AdvertisedAddresses` | 空（通告具体的监听地址并自动发现可达性；最多四项） |
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
| `RequestTimeout` | `5 秒` |
| `UdpAttempts` | `3` |
| `RecordLifetime` | `24 小时`（允许 1 秒–7 天） |
| `MaintenanceInterval` | `5 分钟` |
| `EnableNatTraversal` | `true` |
| `NatTraversalTimeout` | `5 秒` |
| `NatPollInterval` | `1 秒` |
| `NatRegistrationLifetime` | `30 秒`（至少覆盖三个轮询间隔） |
| `ReachabilityCheckInterval` | `30 分钟`（允许 1 分钟–1 天） |
| `MaxNatRegistrations` | `256` |
| `MaxNatRelays` | `4` |
| `Logger` | `NullLogger.Instance` |

### 值类型与契约

| 类型 | 主要成员 |
| --- | --- |
| `DHTIdentity` | `DHTIdentity()`、`DHTIdentity(ReadOnlySpan<byte> seed)`、`NodeId`、`PublicKey`、`ExportSeed()`、`ExportSeed(Span<byte>)` |
| `DHTPeer` | `NodeId`、`Endpoints`、`RelayHints`、`Reachability`、`HasEndpointDependentMapping`、`ExternalAddress`、`Capabilities`、`Sequence`、`ExpiresAt`、`IsExpired` |
| `DHTEndpoint` | `DHTEndpoint(IPAddress, int tcpPort, int udpPort, DHTEndpointFlags)`、`Address`、`TcpPort`、`UdpPort`、`Flags` |
| `DHTReachability` | `Unknown = 0`、`Public = 1`、`Private = 2` |
| `DHTEndpointFlags` | `None = 0`、`Verified = 1`、`Local = 2`、`Configured = 4` |
| `DHTKey` | `DHTKey(string publisherId, string name)`、`Parse(string)`、`IsValid`、`PublisherId`、`Name`、`RoutingId`、相等比较与哈希 |
| `DHTRecord` | `Key`、`FileHash`、`MerkleRoot`、`Length`、`BlockSize`、`BlockCount`、`Revision`、`ExpiresAt`、`IsExpired`、`EncodedLength`、`CopyTo(Span<byte>)`、`ToBytes()`、`Parse(ReadOnlySpan<byte>)` |
| `IDHTContentStore` | `PutAsync(string blockHash, ReadOnlyMemory<byte>, CancellationToken)`、`GetAsync(string blockHash, CancellationToken)` |
| `MemoryDHTContentStore` | `MemoryDHTContentStore(long capacity = 64 MiB, int maxEntries = 65536)` |
| `IDHTRoutingTable` | `Initialize(string localNodeId, int bucketSize)`、`Observe(DHTPeer)`、`Remove(string nodeId)`、`Closest(string routingId, int count)` |
| `KademliaDHTRoutingTable` | 默认路由表：256 个 XOR 距离桶，每桶 `BucketSize` 个联系人 |
| `IDHTRouteSelector` | `SelectDirectRoutes(DHTPeer, DHTRouteContext)`、`SelectRelayRoutes(DHTPeer, IReadOnlyList<DHTPeer> knownRelays, DHTRouteContext)` |
| `DefaultDHTRouteSelector` | 默认路径选择，见[自定义选路](#自定义选路) |
| `DHTRouteContext` | `PreferredTransport`、`AlternateTransport`、`NatTraversalEnabled`、`ExternalAddresses`、`MaxRelayAttempts`、`IsRegisteredWith(string)`、`SharesExternalAddress(DHTPeer)` |
| `DHTDirectRoute`、`DHTRelayRoute` | `Endpoint`、`Transport`；`Relay`、`AttemptPunch` |
| `DHTCapabilities` | `Download = 1`、`Provide = 2`、`Relay = 4` |
| `DHTTransport` | `Tcp`、`Udp` |

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

## 加密与中继

每个请求与响应都使用全新的临时 X25519 协商、HKDF-SHA256 与 ChaCha20-Poly1305，并用
Ed25519 签名覆盖信封转录与明文。接收方的签名联系人会把其长期协商公钥绑定到节点身份。随机
请求 ID、操作、接收方、版本与发送方都会参与认证。响应必须匹配预期的最终节点、操作与
128 位请求 ID。消息允许最多两分钟时钟偏移；请同步节点时钟。

本设计面向长期接收方密钥加密，**不提供**针对身份种子日后泄露的完全前向保密。发送方使用
全新的临时密钥也不会改变这一性质。本实现尚未经过独立的密码学审计。

当直连失败时，节点首先使用目标签名联系人中的中继提示，然后请求其他已知的、声明 `Relay`
的节点为它引入一条 TCP 或 UDP 直连路径。如果穿透无法建立路径，则尝试既有的不透明中继操作。中继会收到一个单独加密的外层 RPC，其中
包含目标 ID 与一个不透明的内层信封。它原样转发内层信封并返回不透明响应。只有最初的下载方
与提供者能打开文件请求与数据块响应；中继可以观测端点、包大小、时序以及可见的操作编号。损坏
的中继响应会被拒绝，并可尝试其他已知中继。中继只会转发给已经认证过的已知节点，或在本中继
持有有效会合登记的节点，并拒绝显式嵌套的中继包。恶意参与者仍然可以建立多个独立连接；这不是匿名路由，也不防御 Sybil/eclipse
攻击。

需要应用自行管理续传或指定中继时，请使用底层的、经过校验的数据块 API：

```csharp
var block = await downloader.ReadBlockAsync(record, provider.LocalPeer, 0,
    relay: relayPeer, cancellationToken: cancellationToken);
```

提供者声明只是可用性提示；单独一份签名联系人并不能证明其确实持有数据。下载会在不同数据块
之间轮换初始提供者，并在遇到无效或不可用的块之后改试其他提供者。

## 引导与发现

任何运行中的节点都可以充当引导节点。不存在特权引导角色、中心目录或内置硬编码服务器。把已知
节点的端点列在 `DHTNodeOptions.BootstrapEndpoints` 中：`StartAsync` 会在后台联系它们，
路由表为空时维护流程会重试，`BootstrapAsync` 则显式联系它们并返回作出应答的端点数量。每个
端点对一个签名的 Hello 请求作出应答，返回自己的签名联系人以及它观测到的调用方端点。引导只负责
引入已知联系人，随后由有界的迭代 XOR 距离查找发现更多节点。离线节点可以在本地发布；等有节点
可用后，`AnnounceAsync` 或自动维护会复制其记录。即使没有任何远端副本接受，发布也会返回签名
记录，并通过可选日志上报一条警告。`AnnounceAsync` 返回远端副本数量。

端点并不标识某个节点：在配置的端点上作出应答的任何一方都会成为第一个联系人。请只从可信来源
配置引导端点。声明 `Relay` 能力的节点还会提供可认证的会合协助与可达性检查。

`ListenAddresses` 接受一个地址，或者一个 IPv4 地址加一个 IPv6 地址，以便在相同的配置端口上
双栈监听；允许使用通配地址。支持任意 TCP/UDP 端口、相同或不同的 TCP/UDP 端口号，TCP 与
UDP 监听器也可以独立启用。签名联系人最多通告四个端点：

- `AdvertisedAddresses` 中的每一项，标记为 `Configured`，用于固定公网地址或应用配置的
  路由器端口映射；
- 否则为每个具体（非通配）的监听地址，回环、私有、运营商级 NAT 或链路本地地址会标记为
  `Local`；
- 经独立回拨验证后的外部端点，标记为 `Verified`。

出站请求先尝试已配置或已验证的端点，再尝试未验证端点与本地端点；每个端点都先用首选传输，再用
另一种传输。主机名、外部 STUN 服务器与 UPnP 不在本库范围内。

## TCP、UDP 与 NAT 穿透

通过声明 `Relay` 的节点进行引导时，会自动为每种共同启用的传输登记。中继会观测已认证请求的
实际源地址与端口。UDP 请求保留其 Cookie 校验，TCP 登记则来自监听端口。客户端会刷新这些
短寿命登记，并持续轮询待处理的引入，直到关闭为止。节点也可以显式登记并请求指定的直连传输：

```csharp
await provider.RegisterRelayAsync(relayPeer, cancellationToken);
await downloader.RegisterRelayAsync(relayPeer, cancellationToken);
var connected = await downloader.TryPunchAsync(provider.LocalPeer, relayPeer,
    DHTTransport.Udp, cancellationToken);
```

用 `DHTTransport.Tcp` 请求 TCP 同时打开。中继分发双方观测到的端点以及一个随机、会过期的
128 位票据。每个节点都从自己绑定的监听端口发起探测。有效的直连探测必须匹配票据、节点身份、
传输与观测端点；此后普通请求便走已认证的直连路由。TCP 会保留已建立的连接以服务后续请求。
即使中继离线，已成功的直连传输仍可继续。登记循环与未完成的探测会在 `StopAsync` 期间排空。

辅助穿透要求被穿透的传输存在本地监听器，因为出站探测必须复用该监听器的端口。将
`EnableNatTraversal` 设为 `false` 可关闭客户端登记与自动穿透；声明 `Relay` 的节点仍会在
其登记配额内响应会合请求。默认值为：五秒穿透预算、一秒轮询间隔、30 秒登记租约、每个客户端
最多四个辅助中继、每个中继最多 256 个登记身份。引入队列以 `MaxConcurrentRequests` 为界，
活跃票据数量上限为该值的四倍。

这是尽力而为的穿透：端点相关的 NAT 映射、被阻断的 UDP、拒绝同时打开的 TCP 协议栈或防火墙、
以及路由器策略都可能阻止直连。当中继可以到达目标时，不透明转发依然可用。它会复用仍然有效的
已认证登记，包括在签名联系人通告私有端点时复用现有 TCP 会话或观测到的 UDP 映射。如果引入的
探测成功但随后的 RPC 失败，请求方仍会尝试同一中继的不透明转发路径。

### 家宽网络中的可达性

家用路由器之后的节点通常没有固定、可达的地址。此时请保持 `AdvertisedAddresses` 为空，并保持
`EnableNatTraversal` 开启，节点会自行判定可达性：

1. **外部地址。** 中继登记与 Hello 响应会报告每个远端节点观测到的端点。若至少两个处于不同
   网络（IPv4 /24 或 IPv6 /48 前缀不同）的中继报告同一地址，它就成为已确认的
   `ExternalAddress`。若中继为该地址观测到不同端口，联系人会置位
   `HasEndpointDependentMapping`，请求方随之跳过打洞。外部地址变化（例如 PPPoE 重拨）会开启
   新纪元，丢弃之前的验证结果并重新检查可达性。
2. **回拨探测。** 每次新建中继登记以及每隔 `ReachabilityCheckInterval`，节点都会请求其中继
   安排一次回拨。中继把回拨委托给另一网络中的独立公网协助者，协助者只探测中继观测到的地址。
   探测被接受后，联系人会增加一个 `Verified` 端点并成为 `Public`。
3. **私有联系人。** 当经由两个不同网络中继的回拨都超时，联系人成为 `Private`：它去掉不可达
   的端点，并把最多三个持有有效登记的公网中继嵌入为 `RelayHints`。请求方跳过它的端点（只有
   双方外部地址相同时才尝试本地端点），并经提示中继访问它；若请求方已在该中继登记，会先尝试
   打洞。

私有节点以 DHT 客户端身份参与网络：它可以查找、下载与提供内容，但不会被加入路由表，也不会
作为查找跳点返回。联系人变化会立即重新签名，本地发布会在五秒后重新宣告，使提供者索引持有新
联系人。私有与未验证联系人的租约为一小时，公网联系人为一天。每个协助者每分钟最多接受同一中继
的十次委托，并最多向同一目标地址回拨四次。

## 自定义选路

构建节点时可以替换两类选路决策：

```csharp
await using var node = new MajDHTNode(options, identity, store,
    routingTable: new KademliaDHTRoutingTable(), routeSelector: new MyRouteSelector());
```

- **`IDHTRoutingTable`** 决定把哪些已认证联系人保留为查找跳点，以及哪些联系人作为离目标最近的
  节点返回。节点只会调用一次 `Initialize`，因此每个节点都要传入新的路由表。节点只把已校验且
  非私有的联系人交给 `Observe`，在请求失败或节点变为私有时调用 `Remove`，并丢弃 `Closest`
  返回的过期、私有、重复以及本节点自身的联系人。默认的 `KademliaDHTRoutingTable` 维护 256 个
  XOR 距离桶，每桶最多 `BucketSize` 个联系人，不会淘汰仍然有效的条目。
- **`IDHTRouteSelector`** 决定如何访问目标节点。它返回按顺序排列的直连尝试（端点与传输），
  以及直连全部失败后按顺序排列的中继尝试，并指明是否先经该中继打洞。`DHTRouteContext` 提供
  首选传输、是否启用 NAT 穿透、已确认的外部地址，以及本节点已登记的中继。同一个路径选择实现
  可以在多个节点间共享。

`DefaultDHTRouteSelector` 先尝试已配置或已验证的端点，再尝试未验证端点，最后尝试本地端点，
每个端点都先用首选传输；只有双方外部地址相同时，才会使用私有目标的本地端点。中继路径先列出
目标的中继提示（只对本节点已登记的提示中继尝试打洞），再列出最多 `BucketSize` 个路由中的中继；
目标映射依赖目的端点时从不打洞。

两种实现都必须线程安全、快速返回，并且不得进行网络 I/O。路径只是尝试，而非信任决策：无论经由
哪条路径，每个响应都会按目标身份进行认证。经打洞或会合登记得到的已认证路径总是先于所选的直连
路径尝试。节点最多尝试十六条直连路径和三十二条中继路径，并跳过经由本节点、目标本身、过期联系人
或不具备 `Relay` 能力的节点的中继路径。

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
总数 131,072。可配置的文件上限为最多 1 GiB；使用较小数据块时可能先触及叶子配额。所有加密
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

内部的 `Packet` 是复制内存视图的只读值类型。借用的内存保持调用方管理的生命周期；解码后的
包保留其自有的解密数组。持有可变状态、池化缓冲区、身份或持久签名元数据的对象仍然是引用类型。

协议写入器与文件读取缓冲区使用清零的池化数组；读取器直接对既有内存切片，不产生逐字段数组。
密文直接写入池化的最终信封，Merkle 树使用一整块连续节点缓冲区。证明校验使用栈空间。池化内存
绝不会作为公共异步结果逃逸。旧的仅数组式加密提供程序通过带正确偏移的数组段访问，避免产生
缓冲签名副本。只有在持久化、公共防御性复制或提供程序 API 要求所有权时，才保留小的自有数组。

在 Windows .NET 9 Release 测试宿主上测得的热身托管分配量：

| 工作负载 | 优化前 | 优化后 |
| --- | ---: | ---: |
| 32 KiB 编解码往返 | 98,864 B/op | 96 B/op |
| 32 KiB Merkle 叶子 | 33,048 B/op | 192 B/op |
| 128 叶 Merkle 树 | 46,120 B/op | 8,576 B/op |
| SHA-256 十六进制格式化 | 1,376 B/op | 152 B/op |
| 32 KiB 加密包往返 | 700,807 B/op | 约 95,000 B/op |
| 已缓存的 32 KiB 数据块读取 | — | 0 B/op |
| 被禁用的日志事件 | — | 0 B/op |

这些测量使用 `GC.GetAllocatedBytesForCurrentThread`，并在测量前预热线程池与提供程序，不含
原生分配与网络 I/O。它们是分配回归基线，而不是吞吐量或跨运行时结论。

## 安全范围

- 接收方密钥是长期密钥，因此本协议**不提供**完全前向保密；身份种子泄露会暴露历史流量。
- 本实现**尚未**经过独立审计。
- 中继会隐藏载荷，但能观测端点、大小、时序与操作编号。这不是匿名路由，也不抵御 Sybil 或
  eclipse 攻击。
- 提供者通告只是提示；只有签名记录、Merkle 证明与完整文件哈希具有权威性。
- 应用必须在带外认证密钥与发布者指纹，只从可信来源配置引导端点，并安全持久化身份种子与
  修订号。Hello 请求有签名但不加密。
- 可达性证据依赖独立的中继与协助者；串通的中继可以让节点看起来是私有的，这会降低效率，但
  不影响完整性。
- 超出租约的新鲜度由应用负责；当内容必须永不变更时，请固定完整文件哈希。

## 测试与验证

测试工程引用真实的 `netstandard2.1` 类库，并运行真实的回环 TCP/UDP 套接字；测试清单与筛选
方式见[测试工程 README](src/MajDHTNetwork.Tests/README.md)。

```powershell
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release
dotnet test src/MajDHTNetwork.Tests/MajDHTNetwork.Tests.csproj --configuration Release --filter 'Category=Allocation'
```

覆盖范围包括：协议测试向量与畸形输入、已认证信封与身份冒充、Merkle 几何、三节点发现与下载、
中继回退、双传输、IPv6 与双栈传输、端点引导、UDP 丢包/重放、NAT 登记与打洞、外部地址投票、
回拨探测与经中继提示访问的私有节点、配额与生命周期限制，以及热身分配预算。

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

包内包含 netstandard2.1 的 DLL、XML 文档文件、`README.md`、`PROTOCOL.md` 与 `LICENSE`；
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
