# 实现一个 MajDHT 节点

[English](IMPLEMENTING.md) | **简体中文**

本指南说明 MajDHT v1 协议的行为方式、协议库公开 API 的构成，以及如何构建自己的节点：
既可以通过构造函数扩展参考实现 `MajDHTNode`，也可以基于公开的协议类型编写一个独立的
参与者。精确的字节布局见 [PROTOCOL.zh-CN.md](PROTOCOL.zh-CN.md)；参考节点的应用层 API
见 [README.zh-CN.md](README.zh-CN.md)。

## 目录

- [公开 API 指什么](#公开-api-指什么)
- [协议模型](#协议模型)
- [协议流程](#协议流程)
- [协议 API 详解](#协议-api-详解)
- [自定义 MajDHTNode](#自定义-majdhtnode)
- [编写独立的节点](#编写独立的节点)
- [兼容性清单](#兼容性清单)

## 公开 API 指什么

程序集暴露两个层次。所有 `public` 成员都受支持、可供应用使用；所有 `internal` 成员都是
实现细节，可能随时变更。

| 层次 | 命名空间 | 用途 |
| --- | --- | --- |
| 应用 API | `MajDHTNetwork` | 运行参考节点：`MajDHTNode`、`DHTNodeOptions`，值类型 `DHTIdentity`、`DHTContact`、`DHTPeer`、`DHTEndpoint`、`DHTKey`、`DHTRecord`，以及扩展契约 `IDHTContentStore`、`IDHTRoutingTable`、`IDHTRouteSelector` 与它们的默认实现。 |
| 协议 API | `MajDHTNetwork.Protocol`、`MajDHTNetwork.Transport` | 不借助 `MajDHTNode` 直接参与协议：`Wire` 编解码器、`Packet` 信封、每个操作一个编解码类、`MerkleTree`、身份工作量、地址作用域规则、池化帧所有权以及 `SocketTransport`。`DHTContact`、`DHTPeer`、`DHTEndpoint`、`DHTRecord`、`DHTIdentity` 与 `DHTNodeOptions` 中与协议相关的成员（创建与解析签名联系人和记录、编码带观测端点的对等节点、签名、节点摘要、协商公钥、`Snapshot`）也属于这一层。 |

协议 API 就是参考节点运行的那份代码。`MajDHTNode` 没有任何私有编码器：它发送的每个请求、
写出的每个响应都经过这些公开编解码器，因此基于它们构建的节点产生并接受的字节与参考节点
完全一致。

有三类内容刻意保持 internal：

- **机密。** 身份的 X25519 协商标量，以及接受加密提供方密钥对象的原始签名辅助方法。自定义
  节点不需要它们：`Packet.Seal`/`Packet.Open` 与 `DHTIdentity.Sign`/`SignTo` 已覆盖签名与加密。
- **传输层内部。** UDP Cookie 交换、待决交换表与 TCP 会话缓存位于 `SocketTransport` 内部。复用
  该传输层意味着这些行为在所有节点中一致；若自行实现传输层，则必须遵循协议文档的 TCP 与
  UDP 章节。
- **校验缓存。** 让重复出现的联系人与记录可以廉价校验的缓存通过 `DHTContact.Parse` 与
  `DHTRecord.ParseCached` 使用，而不作为类型暴露。

节点*策略*不属于协议 API。身份工作量阈值、重放缓存、路由准入、提供者配额、按网络限额、超时
以及 Sybil 缓解措施都是节点自己的决定；编解码器只校验消息的结构。自定义节点需要实施自己的
策略，[兼容性清单](#兼容性清单)列出了其中不可省略的部分。

## 协议模型

### 参与者与角色

每个参与者拥有一个身份，并在签名联系人中声明能力：

| 能力 | 含义 |
| --- | --- |
| `Download` | 节点从提供者读取数据块。没有协议义务。 |
| `Provide` | 节点为自己持有的内容应答 `Block` 请求，并可以用 `Store` 通告内容。没有该标志的节点，其内容通告会被拒绝。 |
| `Traversal` | 节点协调直连：托管带观测端点的穿透登记，为进行 TCP/UDP 打洞的双方互相引荐（`Traversal`），并安排或执行探测直连可达性的回拨。 |
| `Forwarder` | 节点在两个对等节点之间中继流量：托管转发会话，按观测端点寻址会话拥有者，中继不透明信封并把它们投递给目标（`Forward`），因此无法直连的双方仍能通信。 |

无论能力如何，任何节点都应答 `Ping`、`Hello`、`Find` 与 `Store`，因为每个节点都是索引的一部分。
不愿提供某项操作的节点以状态 1 拒绝；请求方把拒绝视为对端失败并继续尝试其他节点。

### 对象

| 对象 | 类型 | 说明 |
| --- | --- | --- |
| 身份 | `DHTIdentity` | 32 字节 Ed25519 种子。节点 ID 是签名公钥的 SHA-256；X25519 协商密钥由种子派生。身份工作量是节点摘要的 Argon2id 哈希的前导零位数，因此它是密钥本身的属性，每个候选密钥都要花费一次谜题求值。 |
| 联系人 | `DHTContact` | 自签名的通告：签名密钥、协商密钥、能力、可达性、严格递增的序号、过期时间，以及最多三个提示，每个提示是拥有者与之保持有效会话的 Traversal 节点或 Forwarder，附带拥有者为其观测到的端点。联系人从不写明拥有者自己的端点。接收方保留序号最高的那份。 |
| 对等节点 | `DHTPeer` | 联系人配上本节点（或推荐它的节点）观测到它的端点：最多四个地址及各自的 TCP 与 UDP 端口。一个节点的端点以对端从实际数据包中观测到的为准；`DHTEndpoint.Observed` 从套接字源构造一个端点。 |
| 密钥 | `DHTKey` | `publisherFingerprint:name`。名称限定在发布它的签名身份之下，其他人无法重新绑定。路由 ID 是密钥 UTF-8 字节的 SHA-256。 |
| 记录 | `DHTRecord` | 发布者签名的清单：密钥、整文件 SHA-256、带域分隔的 Merkle 根、长度、块大小、修订号与过期时间；或者是同一密钥、更高修订号、无内容的撤销记录。高修订号取代低修订号；相同修订号但内容不同视为背叛并被拒绝。 |
| 数据块 | 字节 + `MerkleTree` 证明 | 文件按 `blockSize` 切块，最后一块可能更短。叶子为 `SHA256(0x00 ‖ block)`，父节点为 `SHA256(0x01 ‖ left ‖ right)`，奇数层复制最后一个节点。只有证明能在签名的位置与长度上到达签名根时，数据块才被接受。 |

### 消息

每个请求与响应都是一个 `Packet`，封装为一个信封：

1. 头部包含版本标签、操作字节（响应置位第 7 位）、接收方节点 ID、全新的临时 X25519 公钥与
   12 字节 nonce。
2. 明文包含发送方的签名联系人、随机 16 字节请求 ID、签发时间（容差 ±120 秒）与操作体。
3. 发送方用 Ed25519 对头部与明文签名；明文与签名用 ChaCha20-Poly1305 加密，密钥由与接收方
   联系人密钥做 X25519 协商后经 HKDF-SHA256 派生，头部作为附加认证数据。

`Packet.Seal` 生成该信封；`Packet.Open` 就地认证并解密，返回已校验的发送方联系人、请求 ID、
类型与请求体。`Hello` 请求是唯一的例外：发送方尚不知道接收方，因此 `Packet.SealHello` 以零
接收方与零密钥发送签名明文，而应答方正常封装其响应。

响应体总是以一个状态字节开头：`0` 后接操作结果，或 `1` 加空结果表示笼统拒绝。`ResponseStatus`
类负责写入与读取这一包装。请求不带该包装。

信封最大 60,000 字节。TCP 上每个信封带 32 位长度前缀，连接双向承载请求与响应。UDP 上每个
请求之前有一次无状态 Cookie 握手，避免伪造源地址触发大响应。`SocketTransport` 实现了两者，
包括重试与响应关联。

## 协议流程

下文描述参考节点在各种情形下的行为。自定义节点只要发送并接受相同的操作即可互通；各流程
实现到什么程度取决于它的角色。

### 加入网络

1. 加入的节点向配置的端点发送 `Hello`（先用首选传输，再用另一种）。应答方在信封中返回其签名
   联系人，在请求体中返回它为请求方观测到的端点。
2. 应答方在该端点作出了应答，因此以加入方观测到的端点进入路由表。若它声明 `Traversal` 或
   `Forwarder` 且启用了 NAT 穿透，加入方向它登记或与它建立转发会话（见[穿透协调](#穿透协调)与
   [转发](#转发)）。
3. 加入方查找自己的节点 ID（`Find` 模式 `Nodes`）以填充邻近联系人，并在路由表为空期间于
   维护中反复重试引导端点。

端点不能标识节点：谁在该端点应答谁就成为第一个联系人，因此引导端点必须来自可信来源。

### 查找

一次查找以路由 ID（`Nodes`）、规范密钥（`Record`）或整文件哈希（`Providers`）为目标：

1. 从距目标最近的 `k` 个路由联系人出发，轮转分配到 `DisjointLookupPaths` 条从不查询同一节点的
   路径上。
2. 每条路径以 `alpha` 并发向最近的未访问联系人发送 `Find`，合并更近的引荐，丢弃失败的联系人，
   并在最近集合耗尽或用完自己那份 `MaxLookupQueries` 时结束。
3. 返回的每个联系人与记录都独立校验；身份工作量不足、已过期、私有或就是本节点的联系人不会
   作为跳点。
4. 合并各路径：最高的有效记录修订号、提供者的并集，以及最近的可应答联系人。只有属于所请求
   密钥的记录才会被接受。

`Find` 的服务端：对精确的 `Record` 目标返回它持有的记录，返回距目标最近的路由联系人，并返回
所返回记录（模式 `Record`）或目标哈希（模式 `Providers`）的提供者。每个对等节点列表最多 16 项、
字节预算 26,000，使响应保持在信封上限内；每一项都带有应答方自己为该节点观测到的端点，而应答方
列出自己时不带端点，因为请求方已经知道它在哪里应答。

### 发布

1. 按 `blockSize` 读取流；对每块计算叶子（`MerkleTree.AppendLeaf`），并以叶子哈希为键把块存入
   内容存储。
2. 构建 `MerkleTree`，计算整文件 SHA-256，用下一个修订号和 `RecordLifetime` 的过期时间签名
   `DHTRecord`。
3. 分别查找距密钥路由 ID 与文件哈希最近的节点（两次 `Find` 模式 `Nodes`），向两者的并集发送
   `Store`。
4. 维护会在本地记录过期前反复重新通告，但永不延长发布者签名的过期时间。用更高修订号再次
   发布即为续期。
5. `Unpublish` 签名一条撤销记录，其修订号高于该密钥见过的所有修订号、过期时间覆盖被撤销的
   发布，并以同样方式复制。撤销取代的是绑定，不会删除副本。
6. 把每个文件的叶子、整文件哈希与长度和持久化内容存储一起保存的发布者，重启后无需读取文件即可
   恢复：`ImportContentAsync(record, leaves)` 重新登记未过期的记录，
   `PublishAsync(name, leaves, fileHash, length, revision)` 签名新记录。

`Store` 的服务端校验记录，内容记录要求已认证发送方具有 `Provide` 能力，撤销记录接受任何
发送方，强制修订号单调与相同修订号内容一致，在过期后仍保留有界的修订下限，记录数不超过
`MaxRecords`，每个文件最多保留 16 条提供者声明，且按观测源地址计，每个全球可路由的 IPv4 /24
或 IPv6 /32 网络最多三条。

### 下载

1. 用 `Record` 查找解析密钥，或从带外获得的记录开始。可选的受信文件哈希在写入任何内容之前
   与记录比对。
2. 用 `Providers` 查找文件哈希的提供者；本地已持有内容时把自己排在最前。
3. 同时向多个提供者发送 `Block`（记录 + 索引），总并发不超过 `MaxConcurrentBlockRequests`、每个
   提供者不超过 `MaxBlockRequestsPerPeer`；按测得丢包率、在途请求数与失败次数给提供者排序。
4. 用 `BlockMessage.ReadResponse` 按请求方自己的记录校验每个块（精确长度、位置、证明深度与
   根），按序写出、滚动计算整文件摘要并存入本地，于是下载方也成为提供者。
5. 只有在每个提供者都对某块失败时才失败，最后校验整文件哈希。

`Block` 的服务端要求自己具有 `Provide` 能力，在提供之前把存储的字节重新与 Merkle 叶子核对，
并写出块与它的证明。

### 转发

Forwarder 在无法直连的对等节点之间中继加密信封。

1. **会话。** 希望经 Forwarder 被访问的节点，从监听端口在每个它监听的传输上向 Forwarder 发送
   `Forward` 动作 `Session`。Forwarder 记录该传输上观测到的源端点、保留其 TCP 连接并返回该端点。
   会话在 `NatRegistrationLifetime` 租约内每隔 `NatPollInterval` 刷新。
2. **中继。** 当到某目标的所有直连路径都失败时，请求方保留已封装好的内层信封，把它包进动作
   `Relay`：目标节点 ID 与不透明信封。Forwarder 用 `Packet.CheckForward` 检查内层头部确实指向该
   目标、没有响应位、且是 `Ping`、`Find`、`Store` 或 `Block`，并且只中继给自己已知的目标（有效的
   转发会话或路由中的对等节点，绝不是请求方自己）。
3. **投递。** Forwarder 把内层信封包进自己的已认证动作 `Deliver`，发送到目标的会话绑定，包括现有
   的双工 TCP 连接。目标只接受来自 Forwarder 的投递，把内层请求当作其来源节点自己的请求处理而
   不学到来源的任何端点，并返回封装好的内层响应，Forwarder 再把它返回给请求方。只有请求方能
   打开它，并像直连响应一样按目标身份认证它。Forwarder 只能看到端点、大小、时序与操作字节。

### 穿透协调

Traversal 节点协调直连。即使节点同时具备两种能力，它的穿透登记也与转发会话相互独立。

1. **登记。** 客户端从监听端口在每个它监听的传输上向 Traversal 节点发送 `Traversal` 动作
   `Register`。该节点记录该传输上观测到的源端点并返回，若有排队的引荐也一并返回。客户端在
   `NatRegistrationLifetime` 租约内每隔 `NatPollInterval` 刷新。
2. **引荐。** 请求方发送动作 `Introduce` 与目标节点 ID。Traversal 节点要求双方在该传输上都有有效
   登记，生成随机 16 字节、短期有效的票据，把请求方的引荐排入目标队列，并把目标的引荐（联系人、
   观测端点、票据、过期时间）返回给请求方。
3. **打洞。** 双方从监听端口直接向对方的观测端点发送 `Punch`，请求体就是原始票据，在票据有效期
   内重试。接收方只接受票据有效、对端身份、传输与精确源端点都匹配的探测，随后缓存直连路径。路径
   有效期间，只要它空闲约 `NatKeepAliveInterval`，双方都会经它发送 `Ping`，使 NAT 映射与 TCP 会话保持
   打开；报文已发出的保活连续失败两次后，该路径即被丢弃。
4. **回退。** 若打洞失败，或打洞后的直连请求失败，请求方改经 Forwarder 转发；若该节点同时声明
   两种能力，Forwarder 就是同一个节点。

### 可达性

1. **观测。** 每个 `Hello`、`Register` 与 `Session` 响应都报告应答方观测到的端点。被两个不同网络
   的观测者报告的地址成为已确认外部地址；端口不一致则标记端点相关映射，并禁止向该节点打洞。
2. **回拨。** 客户端发送动作 `DialBack` 以及最多两个额外候选端口。Traversal 节点在另一网络中挑选
   独立的公网 Traversal 节点作为助手，向其发送动作 `DialBackAssist`（客户端联系人、传输、观测
   地址、候选端口、nonce、过期时间），并把安排结果返回客户端。助手从自己的地址向每个候选端口
   发送 `Probe`（nonce、端口索引），最多五轮。客户端只接受来自预期助手、预期传输、对应待决
   nonce 的探测；在被探测的地址与已确认外部地址一致期间，联系人变为 `Public`。配置为
   `PubliclyReachable` 的节点无需回拨即声明 `Public`。
3. **私有联系人。** 当经两个不同网络 Traversal 节点发起的回拨都超时、且没有验证或配置过公开
   可达性时，只要能提示一个持有有效会话的公网 Forwarder，联系人就变为 `Private`：它携带最多三个
   提示，Forwarder 优先，每个都附带拥有者观测到的端点。私有联系人可作为提供者使用，但从不作为
   路由跳点，也不会拨打它们的任何观测端点。

每一步都有配额约束：Traversal 节点对每个请求方每分钟最多三次回拨请求；助手对每个委托节点每分钟
最多十次委托、对每个目标地址每分钟最多四次回拨。

### 维护

每隔 `MaintenanceInterval`，参考节点在租约结束前重新签名联系人（公共联系人一天，其余一小时，
通告变化时立即重签），清理过期的记录、声明与登记，在路由表为空时重试引导端点，安排可达性
检查，查找自己的节点 ID，并重新通告本地记录。

## 协议 API 详解

### `Wire`：规范编码

无参构造的 `Wire` 是基于池化缓冲区的写入器；基于 `ReadOnlyMemory<byte>` 构造的 `Wire` 是零拷贝
读取器。整数为有符号 64 位大端；字节数组与字符串带长度前缀；字符串为严格 UTF-8。读取器对
每个变长值都接受一个上限，并在截断、超长或负长度时抛出 `InvalidDataException`；`End()` 拒绝
尾随字节，每个完整请求体/结果的编解码器都会调用它。`WrittenMemory` 与 `Bytes(limit)` 返回借用
的视图：写入器的视图在写入器增长或释放前有效，读取器的视图与输入内存同寿。请释放写入器，
它会归还并清零池化存储。

### `Packet`：信封

`new Packet(sender, requestId, kind, body)` 借用其参数，因此在 `Seal` 返回自有的信封字节之前要
保持它们有效。`Packet.Open(identity, envelope)` *就地*解密密文：信封必须独占持有、不能打开两次，
返回的 `Sender`、`RequestId` 与 `Body` 都借用它。认证失败会在抛出 `CryptographicException` 之前把
密文区域清零。`Packet.CheckForward` 在不解密的情况下执行 Forwarder 与投递目标所需的内层头部检查。

### 操作编解码器

| 类 | 请求 | 成功结果 |
| --- | --- | --- |
| `Ping`（无类） | 空请求体；用 `reader.End()` 读取 | 空；响应信封携带新鲜联系人 |
| `HelloMessage` | 空（`ReadRequest`） | `ObservedEndpoint`（`WriteResponse`/`ReadResponse`） |
| `FindMessage` | `FindMode` + 目标（`FindRequest`） | 记录或空、最近的 `PeerList`、提供者 `PeerList`（`FindResponse`）；每个对等节点都带有应答方观测到的端点 |
| `StoreMessage` | 一条签名记录 | 空 |
| `BlockMessage` | 记录 + 索引（`BlockRequest`） | 原始块 + 证明；`ReadResponse(reader, record, index)` 校验后才返回块 |
| `ForwardMessage` | 先 `ReadAction`，再用 `Session`（空）、`Relay`（目标 ID + 不透明信封，`ForwardRelayRequest`）或 `Deliver`（不透明信封）的读取器；后两者执行 `CheckForward` | 会话返回 `ObservedEndpoint`，其余返回不透明的响应信封 |
| `TraversalMessage` | 先 `ReadAction`，再用 `Register`、`Introduce`、`DialBack`、`DialBackAssist` 之一的读取器 | `TraversalPollResponse`、`TraversalIntroduction`、`DialBackArrangement` 或空 |
| `PunchMessage` | 原始 16 字节票据 | 空 |
| `ProbeMessage` | nonce + 端口索引（`ProbeRequest`） | 空 |

写入器把内容追加到你提供的 `Wire` 中，因此一个请求体或一个结果可以在同一个池化缓冲区内组装，
再用 `ResponseStatus.WriteSuccess` 或 `WriteRejection` 包装。读取器消费定位在请求体起点（对
`ForwardMessage` 与 `TraversalMessage` 则是动作字节之后）的 `Wire`，返回小型结构体，其中的 `ReadOnlyMemory<byte>`
字段借用请求体。任何需要在处理器之外保留的内容（例如后台任务要用的 nonce）都必须用
`ToArray()` 复制。

### 内容完整性

`MerkleTree.AppendLeaf(writer, block)` 把一个叶子追加到连续的叶子缓冲区并返回用作内容存储键的
叶子哈希；`new MerkleTree(leaves)` 构建树；`Root` 即记录的 Merkle 根；`WriteProof(writer, index)`
把证明写入结果；`MerkleTree.Verify` 按记录、位置与证明校验块；`VerifyLocal` 在提供之前把存储的
块与已构建的树重新核对。`Crypto.Hash` 与 `Crypto.Hex` 以规范形式计算整文件哈希。连续的叶子
缓冲区也是 `ImportContentAsync` 与 `PublishAsync` 可以代替流接受的输入，因此应用可以持久化它，
并在不读取内容的情况下重新登记内容。

### 身份、联系人与记录

`DHTIdentity.Create(workBits)` 搜索种子直到达到身份工作量；用 `ExportSeed()` 持久化并用
`new DHTIdentity(seed)` 恢复。`DHTContact.Create(identity, capabilities, reachability,
endpointDependentMapping, hints, lifetime)` 以下一个序号签名联系人；较短的重载签名一个无提示、
可达性未知、一天租约的联系人。`DHTContact.Parse` 校验收到的联系人并复用缓存的校验结果。联系人
从不携带拥有者自己的端点：`DHTPeer.Observed(contact, transport, source)` 把发送方与其请求到来的
套接字源配对，`new DHTPeer(contact, endpoints)` 把它与从别处得知的端点配对，`DHTPeer.Write`/`Read`
把对等节点编码为联系人后接其观测端点，用于推荐与提示。`DHTRecord.Create` 与 `CreateWithdrawal`
签名记录；`DHTRecord.Parse` 与 `ParseCached` 校验记录。联系人与记录上的 `IdentityWork` 借助进程级
缓存求解谜题，并限制每秒最多求值 128 个未知身份（`IdentityPuzzle`）。

### 传输层

`new SocketTransport(options, handler)` 校验并复制选项，创建未绑定的传输层。`Bind()` 在每个监听
地址上打开选项启用的 TCP 与 UDP 监听器；`TcpPort`/`UdpPort` 报告绑定的端口，用于签名本地联系人；
`Run()` 开始接受请求。`DHTEnvelopeHandler` 收到每个信封及其传输与观测源，并返回封装好的响应；
处理器出错则丢弃该请求。`ExchangeAtAsync(transport, endpoint, envelope, token)` 向固定端点发送一个
信封并以 `OwnedMemory` 返回响应帧，调用方复制所需内容后释放它；它负责请求超时、UDP 重试与
Cookie 握手。`PunchAsync` 是从监听端口发出、带短间隔重试以实现同时打开的同类交换。
`TransmissionCounter` 可选地统计已发送与未应答的传输次数，用于丢包统计。`Stop()` 取消一切，
`DisposeAsync()` 等待排空。

### 辅助类型

`NetworkScope` 对地址分类（回环、链路本地、私有、全球），计算每个按网络配额所用的 IPv4 /24 或
IPv6 /32 网络键，并防御性地复制地址。`XorDistanceComparer` 按到目标的 XOR 距离排序联系人。
`ProtocolTags` 保存规范 ASCII 标签。`OwnedMemory`、`OwnedPacket` 与 `PooledBuffer` 表达谁负责释放
池化帧。`KademliaDHTRoutingTable`、`DefaultDHTRouteSelector` 与 `MemoryDHTContentStore` 是普通的
公开类，自定义节点同样可以复用。

## 自定义 MajDHTNode

如果你需要的只是参考行为配上不同的资源或决策，请通过构造函数扩展 `MajDHTNode`，而不是替换它：

| 扩展点 | 定制内容 | 说明 |
| --- | --- | --- |
| `DHTNodeOptions` | 监听器、公开可达性、引导端点、能力、限额、超时、身份工作量、查找形态、日志 | 构造时校验并复制一次；默认值见 README 的表格。 |
| `DHTIdentity` | 节点 ID 与发布者命名空间 | 用 `DHTIdentity.Create` 创建一次，持久化种子，启动时恢复。 |
| `IDHTContentStore` | 数据块存放位置 | 以 Merkle 叶子哈希为键；必须线程安全、响应取消并复制保留的输入。节点会重新校验每次读取。 |
| `IDHTRoutingTable` | 哪些已认证联系人作为跳点保留、保留在哪些观测端点上、哪些作为最近节点返回 | 节点只调用一次 `Initialize`，只把已认证的非私有联系人连同与之交换过数据包的端点传给 `Observe`，并丢弃 `Closest` 返回的不可用结果。 |
| `IDHTRouteSelector` | 到某目标的直连与辅助尝试顺序 | 收到包含传输、穿透登记与丢包统计的 `DHTRouteContext`；可在节点间共享。 |
| `ILogger` | 诊断 | 结构化日志，包含异常类型，但绝不包含消息正文、密钥或用户地址。 |

在这些扩展之下，协议对节点的全部要求（认证、校验、重放保护、配额）仍留在 `MajDHTNode` 内，
这是运行兼容节点最稳妥的方式。只有在需要不同的角色划分、不同的策略、另一种传输层或另一个
运行时时，才编写独立的节点。

## 编写独立的节点

测试工程中的 `MinimalProtocolNode`（`src/MajDHTNetwork.Tests/src/`）是本节的完整可编译示例：它仅
使用公开类型，提供一个文件、索引他人的通告、从参考节点下载，也能被参考节点发现并下载。

### 1. 身份、选项与传输层

```csharp
var identity = DHTIdentity.Create(options.IdentityWorkBits);   // 持久化 ExportSeed()
var transport = new SocketTransport(options, HandleAsync);
transport.Bind();
var self = DHTContact.Create(identity, DHTCapabilities.Download | DHTCapabilities.Provide,
    DHTReachability.Public, false, Array.Empty<DHTPeer>(), TimeSpan.FromDays(1));
transport.Run();
```

联系人不写明你自己的任何端点：与你通信的节点会观测你的数据包来自哪里，而你从监听端口发送，
使它们观测到的位置可达。只有在确知未经请求的数据包能到达监听器时才声明 `Public`，不能到达时
声明 `Private` 并附上 Forwarder 提示，其余情况声明 `Unknown`。在 `ExpiresAt` 之前以及能力、
可达性或提示变化时重新签名联系人；`DHTContact.Create` 会自动签发严格递增的序号。

### 2. 请求处理器

```csharp
private Task<ReadOnlyMemory<byte>> HandleAsync(ReadOnlyMemory<byte> envelope, DHTTransport transport, IPEndPoint source,
    CancellationToken cancellationToken)
{
    var packet = Packet.Open(_identity, envelope);                      // 认证发送方，就地解密
    if (packet.Kind >= 128 || packet.Sender.NodeId == _identity.NodeId || packet.Sender.IdentityWork < _workBits)
    {
        throw new InvalidDataException("Unexpected response, self request or insufficient identity work.");
    }
    // 建议：在两分钟内合并相同的（发送方, 请求 ID），并拒绝请求体不同的重复 ID。
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
                Index(StoreMessage.ReadRequest(request), DHTPeer.Observed(packet.Sender, transport, source));
                break;
            case Operation.Block:
            {
                var block = BlockMessage.ReadRequest(request);
                BlockMessage.WriteResponse(result, LocalBlock(block.Record, block.Index), LocalTree(block.Record), block.Index);
                break;
            }
            default:
                throw new IOException("Unsupported operation.");       // Forward、Traversal、Punch、Probe 是可选角色
        }
        ResponseStatus.WriteSuccess(body, result.WrittenSpan);
    }
    catch (Exception exception) when (exception is IOException || exception is InvalidDataException)
    {
        ResponseStatus.WriteRejection(body);                             // 绝不泄露原因
    }
    var reply = new Packet(_self, packet.RequestId, (byte)(packet.Kind | 128), body.WrittenMemory);
    return Task.FromResult<ReadOnlyMemory<byte>>(reply.Seal(_identity, packet.Sender));
}
```

处理器必须遵守的规则：

- 信封帧属于传输层，返回的任务完成后即被释放。需要保留的内容必须复制（编解码器返回的联系人
  与记录已是自有对象；原始字节视图不是）。
- 在做任何工作之前，先拒绝响应（第 7 位）、来自自己身份的请求以及身份工作量低于阈值的发送方。
- 回显请求 ID 并置响应位；封装给已认证的联系人 `packet.Sender`，而不是某个地址。
- 拒绝就是状态 1 加空结果。可以为自己的诊断记录失败类型，但不要把细节放到线上。
- `Find` 的应答必须来自路由表与索引，每个对等节点带上你为它观测到的端点；`Store` 必须把已认证
  的发送方记录在其请求到来的源端点上，而不是请求体里声称的提供者；`Block` 在提供之前必须重新
  校验存储的字节。

### 3. 发送请求

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
    Observe(DHTPeer.Observed(response.Sender, transport, endpoint));      // 对端在该端点作出了应答
    return ResponseStatus.ReadResult(response.Body).ToArray();           // 在帧释放前复制
}
```

按从新到旧的观测顺序拨打对等节点的观测端点，每个端点先用首选传输再用另一种，跳过 `Private`
联系人的端点，并把 `IOException`、`InvalidDataException`、`CryptographicException`、
`ArgumentException` 与 `SocketException` 视为“尝试下一条路径”。所有直连路径都失败后，用
`ForwardMessage.WriteRelayRequest` 包装已封装好的信封，发送给目标提示的某个 Forwarder 或其他具备
Forwarder 能力的节点；用 `ForwardMessage.ReadEnvelopeResponse` 取出不透明结果，并完全按上述方式
认证。要让自己能经 Forwarder 被访问，需与它保持刷新的 `Session` 并接受它的 `Deliver` 请求，把内层
信封当作其来源的请求处理而不学到来源的端点。`Hello` 用 `SealHello` 发送，事先不知道发送方，因此
只校验类型与请求 ID，然后把发送方当作在该端点观测到的联系人。

### 4. 需要维护的状态

| 状态 | 原因 | 可复用的类型 |
| --- | --- | --- |
| 路由表 | 应答 `Find` 与作为查找种子；只在你自己观测到的端点上准入联系人：应答了你的那个端点，或其请求的源端点（前提是它随后应答了发往该处的 Ping）；每个桶中每个全球网络最多两个联系人，整表最多十个 | `KademliaDHTRoutingTable`、`XorDistanceComparer`、`NetworkScope` |
| 记录索引与修订下限 | 应答 `Find` 模式 `Record`；拒绝回滚；尊重撤销 | `DHTRecord` 的修订号、`SameContent` |
| 提供者声明 | 应答 `Find` 模式 `Providers`；丢弃过期联系人；每个文件最多 16 条、每个全球网络最多三条 | `NetworkScope.NetworkKey`、`IsDiversityLimited` |
| 本地内容 | 应答 `Block`；提供前校验 | `IDHTContentStore`、`MemoryDHTContentStore`、`MerkleTree` |
| 重放缓存 | 合并重传，两分钟内拒绝内容不同的重复请求 ID | 用 `Crypto.Hash` 计算 `packet.Body` 的摘要 |
| 穿透与转发状态（可选） | 每个传输的登记与转发会话及其观测端点、引荐队列、票据、回拨配额 | `TraversalMessage` 与 `ForwardMessage` 的结构体 |

### 5. 与参考节点互测

启动一个 `MajDHTNode`，把 `BootstrapEndpoints` 指向你的节点，检查 `BootstrapAsync` 返回 1、
`KnownPeers` 包含你的节点、`FindProvidersAsync`/`ResolveAsync` 能看到你的记录、`DownloadAsync`
成功；然后反过来用你的客户端代码测试。测试工程中的 `CustomNodeTests` 正是对 `MinimalProtocolNode`
做这件事。两边的 `IdentityWorkBits` 必须一致；测试工程把默认值设为 0，生产网络使用 12。

## 兼容性清单

满足以下条件的节点与 MajDHT v1 参考节点兼容：

- 只通过 `Packet` 信封与规范编解码器通信，信封不超过 60,000 字节，容忍 ±120 秒时钟偏差；
- 应答 `Ping`、`Hello`、`Find` 与 `Store`，对未实现的操作以状态 1 拒绝，绝不以不同的请求 ID 或
  操作回应请求；
- 要求发送方、应答方与引荐都达到网络的身份工作量，拒绝自己的身份以及以请求形式到达的响应；
- 校验它接受的每个联系人、记录与数据块，绝不让服务端提供的元数据凌驾于自己签名的记录之上；
- 只从 `Store` 的已认证发送方记录提供者，强制修订号单调与撤销，并为每个索引设置配额；
- 绝不宣告自己的端点，只在自己观测到的端点上把联系人纳入路由，以自己观测到的端点推荐对等节点，
  绝不推荐私有联系人，并限制每个全球网络的联系人数；
- 在过期前以递增序号重新签名联系人，并如实声明可达性：仅在能于观测端点接受未经请求的数据包时
  为 `Public`，仅在至少有一个 Forwarder 提示时为 `Private`；
- 若声明 `Forwarder`，只把 `Packet.CheckForward` 允许的内容中继到它已知的目标，并在自己的已认证
  请求内投递；若声明 `Traversal`，执行登记与回拨配额；并且只接受来自 Forwarder 的投递，不从中学
  到任何端点。
