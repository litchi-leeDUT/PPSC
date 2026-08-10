# 密态智能合约与动态混合协议设计

> 状态：协议草案 v0.1。本文定义链上事实、链下秘密、存储定位、执行和动态委员会交接边界。

## 1. 安全目标与基本假设

系统需要同时保证：

1. 合约状态、用户输入和同态私钥不以明文出现在链上。
2. 任一少于阈值的委员会成员集合不能恢复秘密。
3. 链上能够确定当前程序、输入、旧状态、委员会和最终结果属于同一次执行。
4. 委员会更换时不重构明文，不允许旧、新委员会通过重放回滚状态。
5. 密文或份额丢失能够被发现，达到可用性阈值前不得开始执行。
6. 下一轮委员会不能由当前委员会单方面选择。

本设计仍需明确威胁模型：每轮最多允许多少恶意节点、旧委员会与新委员会是否可能串谋、节点是否允许自适应腐化。未明确这些参数前不能确定安全阈值。

## 2. 用户发布的密态合约

用户发布的不是任意 EVM 字节码，而是一个版本化的 `ConfidentialContractPackage`：

```text
manifest
├── contract_id
├── owner / upgrade_policy
├── runtime_id + runtime_hash
├── ABI hash
├── functions[]
│   ├── selector
│   ├── program_id
│   ├── code_hash
│   ├── operators[]: MPC | FHE
│   ├── conversions[]: C2S | S2C
│   ├── input_schema_hash
│   ├── state_schema_hash
│   └── resource_limits
└── initial_state_root
```

链上 `ProgramRegistry` 保存 manifest hash、程序 hash、运行时 hash、ABI hash 和位置。程序体有两种部署方式：

- 小程序：按固定大小分块直接存链上，委员会从链上重组并校验 `code_hash`。
- 大程序：链上存内容寻址 URI/CID 和 `code_hash`，委员会从多个镜像下载并校验哈希。

“从链上获取函数”在协议上表示：链上记录是函数身份和完整性的唯一事实来源。无论程序体来自哪里，哈希不匹配都必须终止。

程序必须运行在确定性沙箱中（建议受限 WASM/专用 IR），禁止系统时钟、网络、随机系统调用和未计量资源。随机数只能由执行上下文显式提供。

## 3. 密文数据描述

每份链下数据拥有稳定 `data_id`，链上登记：

```text
DataDescriptor {
  data_id,
  contract_id,
  owner_commitment,
  representation,             // SS | FHE，只有两种持久化表示
  payload_commitment,
  schema_hash,
  encryption_scheme_id,
  key_epoch,
  version,
  storage_set_root,
  availability_threshold,
  expiry,
}
```

链上绝不保存秘密份额、HE 私钥份额、明文或可解密备份。`storage_set_root` 是存储节点记录的 Merkle root；需要查询单个节点时提交 Merkle proof，避免为每份数据保存大数组。

### 3.1 秘密分享数据

- 客户端按委员会阈值参数生成有认证的份额。
- 每个份额经目标节点的传输公钥再次加密。
- 每个节点只持有自己的份额。
- `payload_commitment` 绑定原值、schema、版本、contract 和 data ID。
- 节点返回 possession receipt；达到 `availability_threshold` 后链上数据才可转为 `Available`。

### 3.2 同态密文与密钥份额

- 同一密文可复制到多个存储节点；链上登记密文内容哈希和副本集合 root。
- 评估公钥/evaluation key 可以公开，但必须版本化并绑定 `key_epoch`。
- HE 私钥份额有独立 `dataId` 和 SS `DataReference`，由当前 active committee 持有。
- active committee 同时负责 FHE/MPC operator、C2S/S2C、密钥份额和授权 Pick；系统不设置独立长期 KMS committee。
- “无 KMS”不表示没有密钥管理：DKG、份额认证、存储、handoff、Pick 和安全删除都必须实现。
- FHE ciphertext 可复制；密钥份额不可复制成足以跨节点恢复的集中记录。
- 一个 FHE ciphertext reference 必须显式绑定 `fhe_key_reference`。同一 key 下所有 ciphertext 共享该 key owner 的释放策略。

论文没有给出完整 DKG，因此原型阶段可以把 DKG 定义为外部密码插件，但不得用单节点生成完整私钥后直接分片替代生产协议。

## 4. 链下存储逻辑

### 4.1 数据面

每个存储节点本地保存：

```text
FragmentRecord {
  data_id,
  version,
  mode,
  key_epoch,
  fragment_index,
  payload,              // 本节点份额或完整 HE 密文
  payload_hash,
  descriptor_hash,
  created_at,
  expires_at,
}
```

- PostgreSQL 保存公开元数据、任务状态、链游标、receipt 和幂等记录。
- RocksDB/对象存储保存大密文和本节点秘密份额。
- 秘密份额必须使用节点本地 KEK 静态加密；KEK 来自 KMS/HSM，不与数据同库。
- 以 `(data_id, version, fragment_index)` 为幂等键，只允许版本单调增加。
- 读取必须同时检查链上 descriptor、payload hash、版本和授权执行 ID。

### 4.2 控制面

链上 `DataRegistry` 记录：

- descriptor hash 和状态：`Pending → Available → Locked → Superseded/Expired`
- storage set root、可用阈值、receipt root
- 当前数据版本和 key epoch
- 正在占用它的 execution ID（若要求串行写）

链上记录存储节点会泄露节点拓扑，这是可用性与隐私之间的权衡。默认保存集合 root，仅在挑战、取数或审计时揭示成员证明。

### 4.3 可用性证明

单纯登记节点地址不代表数据真的存在。最小版本使用节点签名 receipt：

```text
Sign_storage_node(
  chain_id, registry, data_id, version,
  payload_hash, expiry, challenge_epoch
)
```

生产版本应加入周期性随机 possession challenge、押金与 slash；否则节点可签名后删除数据。

## 5. 链上合约划分

```text
ConfidentialContractRegistry  合约包、函数、runtime、升级策略
DataRegistry                  数据描述符、位置 root、版本、可用性
NodeRegistry                  节点身份、角色、能力、抵押、VRF key
CommitteeManager              epoch、sortition、成员 root、阈值
ExecutionManager              执行状态机、输入/状态锁、轮次
ResultVerifier                VRF/签名/ZK/状态转换证明验证
```

`ExecutionManager` 的公开执行记录：

```text
Execution {
  execution_id,
  contract_id,
  function_selector,
  program_id,
  program_hash,
  input_root,
  old_state_root,
  current_state_root,
  operator_sequence_hash,
  protocol_round,
  committee_epoch,
  current_committee_id,
  next_committee_id,
  deadline,
  status,
}
```

Hybrid 是 operator sequence 的属性，不是 execution 或数据的第三种表示。每个 operator 明确标记为 `MPC` 或 `FHE`，每条跨域边明确标记 `C2S` 或 `S2C`，并绑定所使用的 FHE key reference。

链上调用不是同步执行私密函数，而是创建异步 execution。只有验证结果后，链上才原子更新状态 root 并触发回调。

### 5.1 Address Registry

论文给出的最小公开引用为：

```text
Ref_x = (dataId_x, PKSet_x, threshold_x, repr_x, owner_x)
repr_x ∈ {SS, FHE}
```

工程实现额外保存 `commitment/version/fheKeyRef`，但这些字段必须被同一 descriptor hash 覆盖：

- SS：`threshold=t` 表示最多 `t` 份额不泄密，打开至少需要 `t+1` 份；`PKSet` 是持有本地份额的 active committee。
- FHE：`threshold=0`，`PKSet` 是 ciphertext 存储/计算节点；真正门限属于 `fheKeyRef` 指向的 SS key reference。
- owner：仅用于授权 Pick，不意味着 owner 可以绕过协议读取其他人的值。

### 5.2 Deploy / Upload / Invoke / Pick

```text
Deploy(contractPackage) -> contractAddr
Upload(protected value) -> local receipts
Register(DataReference) -> dataId available
Invoke(contractAddr, selector, input dataIds, nonce) -> executionId
RegisterOutput(executionId, output Ref, transcript) -> Completed
Pick(dataId, recipient, nonce, expiry, owner signature) -> protected shares
```

- Deploy 不产生以后调用的 input data ID。
- Invoke 只携带公开 ID，不携带 plaintext、share 或 FHE secret key。
- 只有协议检查全部成功后才登记输出；失败时 `outputId = ⊥`。
- Pick 签名必须域分离并绑定 `chainId、registry address、tag、dataId、recipient、nonce、expiry`，防止跨链、跨合约和换收件人重放。
- SS Pick 返回足够的 result shares；FHE Pick 针对 key reference 返回足够的 key shares，owner 在本地重构 key 并解密 ciphertext。
- FHE key 一经 Pick，owner 能解密该 key 下所有 ciphertext，因此 key 粒度和 release policy 必须匹配，不能让不同 owner 或不同授权域复用同一 key。

## 6. Cryptographic sortition

### 6.1 候选集合快照

每轮选择使用已最终确认的 `NodeRegistry` 快照，过滤：

- 角色和算法能力匹配；
- 抵押、在线期、地理/运营者去中心化约束满足；
- 没有被惩罚或参与冲突任务；
- 支持指定 runtime、Sharing/HE 参数。

### 6.2 不可预测随机种子

推荐种子：

```text
seed_e = H(
  finalized_chain_randomness,
  execution_id,
  next_epoch,
  registry_snapshot_root,
  previous_transcript_hash
)
```

不得只使用 `block.timestamp`、可被 proposer 操纵的单个 block hash，或当前委员会提供的随机数。目标链没有安全随机信标时，应接入可验证随机信标/VRF 服务并定义不可用降级规则。

### 6.3 节点自选与链上确定

候选节点计算：

```text
(y, proof) = VRF_sk(seed_e || role || algorithm_id)
selected iff y < threshold(weight, target_size, total_weight)
```

节点提交 VRF proof，合约验证身份 key、快照权重和阈值。若入选人数过多，按 `H(y, node_id)` 排序截取；不足则使用独立派生的 retry seed 进入下一 selection attempt。最终成员列表形成 `member_root`。

为了抵御选择性不响应，候选节点先提交 selection proof，再在截止期前提交 acceptance 和临时会话公钥。未响应节点可处罚，但 retry seed 不能由其决定。

### 6.4 重叠与串谋约束

动态切换时应限制旧、新委员会重叠比例，并按运营者而非节点 key 去重。若安全假设要求每轮恶意节点少于 `t`，必须分析跨轮腐化；仅“每轮随机”并不自动提供 proactive security。

## 7. 动态混合执行状态机

```text
Requested
  → InputsAvailable
  → CommitteeSelecting
  → CommitteeFinalized
  → ProgramLoaded
  → Evaluating(round r)
  ├→ RoundCompleted
  │    ├→ Evaluating(round r+1)            同一委员会
  │    └→ NextCommitteeSelecting
  │          → HandoffPreparing
  │          → HandoffAccepted
  │          → Evaluating(round r+1)       新委员会
  └→ ResultPending
       → Verified
       → Finalized
```

每轮链上或可验证 transcript 承诺：

```text
transcript_r = H(
  execution_id,
  program_hash,
  round,
  mode,
  input_commitments,
  old_state_root,
  output_commitments,
  current_committee_id,
  committee_epoch
)
```

当前和下一委员会均从链上读取同一 `ProgramDescriptor`、execution 和数据 descriptor，等待最终性后才行动。

## 8. 跨委员会交接

论文定义每个 epoch 必须整体迁移的状态：

```text
State_epoch = (
  Key,   // FHE secret-key shares
  Live,  // live authenticated contract-value shares
  MAC,   // MAC-key and MAC-tag shares
  Prep   // unused conversion masks and degree-reduction pairs
)
```

这四类状态必须由同一 handoff transcript 覆盖。只迁移值份额而漏掉 MAC/preprocessing 会破坏连续性；重复迁移或重复消费 preprocessing 会破坏隐私。

### 8.1 秘密分享状态

使用 verifiable/proactive resharing：

1. 新委员会发布经链上确认的成员 root 和会话加密公钥。
2. 旧成员把自己的旧份额转换成发给每个新成员的子份额，并附一致性证明。
3. 新成员收集至少旧阈值的有效包，组合为新份额。
4. 新委员会提交 `share_commitment` 和达到新阈值的 handoff acknowledgement。
5. 链上把 active committee 原子切换到新委员会。
6. 旧委员会在挑战窗口后安全删除旧份额。

全过程不得恢复原秘密。新阈值、成员数量和字段参数必须被 handoff transcript 绑定。

### 8.2 门限 HE 密钥

按照论文模型，FHE key domain 和公钥在 handoff 前后保持不变，只把同一 secret key 的份额刷新给新 active committee。`dataId`、owner 和复制的 ciphertext 均保持不变；完成后更新 SS/key references 的 `PKSet`。

这要求所选门限 FHE 与 fluid sharing 协议能够安全迁移对应 ring/module 中的 key share。论文明确说明具体 malicious-secure handoff 仍未完成，因此在得到协议和证明前，该能力只能标为实验性，不能作为生产安全声明。

### 8.3 混合协议转换

允许的转换必须注册为明确 gateway：

```text
Sharing → HE：委员会共同生成密文并证明与分享承诺一致
HE → Sharing：门限解密到秘密份额，而不是公开明文
HE_A → HE_B：threshold key switching
Sharing_A → Sharing_B：proactive resharing
```

每个 gateway 输出 commitment/proof，并进入 transcript。禁止把 `decrypt()` 作为通用转换捷径。

论文当前真正定义的主路径是：

**C2S（FHE → authenticated SS）**

1. 固定转换层 `Q = q_c`、FHE scale `Δ_c`、逻辑 scale `S`、layout 和范围 `B`。
2. 委员会以 key shares 计算 raw-decryption polynomial 的份额。
3. raw polynomial 和 FHE noise 均不得打开。
4. 在 MPC 内完成 decode、round、range check 和 wrap-around check。
5. 输出带 MAC 的逻辑值 sharing，并以新 `dataId` 登记 SS reference。

**S2C（authenticated SS → FHE）**

1. preprocessing 生成同一随机 `r` 的 authenticated polynomial sharing 与 ciphertext。
2. 校验源 sharing 的 MAC 和范围。
3. 只打开经过 MAC 检查的 `d = m - r mod Q`。
4. 计算 `ct_m = ct_r + d` 并以新 `dataId` 登记 FHE reference。
5. correlated mask 必须原子消费且永不复用；复用会暴露两个源值的差。

`Q = q_c` 只对齐 coefficient residues，不等价于逻辑数据域，也不消除 encode/decode、scale、rounding 和 wrap-around 检查。

## 9. 失败、超时和回滚

- sortition 不足：更换 retry seed，最多固定次数，之后任务失败并退款。
- 程序不可用/哈希错误：标记程序镜像故障，不执行。
- 输入可用性不足：任务保持等待或超时取消，不得用部分输入继续。
- handoff 不足阈值：旧委员会仍为 active；不可出现两个 active committee。
- 评估超时：选择新委员会，从最后一个已确认 checkpoint 恢复。
- 链重组：只处理 finalized 事件；所有消息绑定 block hash 和 execution version。
- 结果冲突：冻结 execution，提交 transcript 作为惩罚/仲裁证据。

## 10. 第一版建议收敛范围

1. 受限 WASM/IR，不接受任意 EVM 字节码。
2. 程序 hash 在链上，程序体走内容寻址存储。
3. 数据位置用 Merkle root，存储节点签名 receipt。
4. 首先实现秘密分享动态 resharing。
5. active committee 持有 FHE key shares；动态迁移在完成 malicious-secure handoff 前标记为实验性。
6. sortition 使用链上可验证随机源 + 节点 VRF。
7. 每轮产生 transcript commitment，只有 checkpoint 确认后才能切换委员会。
8. 第一版结果用门限签名，后续升级到状态转换证明。

## 11. 必须先定下来的参数

- [ ] 恶意模型：半诚实/恶意、静态/自适应腐化、跨轮串谋。
- [ ] 每类委员会规模、阈值和最大重叠比例。
- [ ] 链上随机源、最终性和 selection timeout。
- [ ] 程序运行时、指令集、gas/resource metering。
- [ ] 秘密分享协议及可验证 resharing 库。
- [ ] HE 方案、参数、threshold/key-switching 能力。
- [ ] 数据副本数、availability threshold、挑战和 slash。
- [ ] 哪些轮次允许从 Sharing/HE 切换，以及相应证明。
- [ ] C2S 的 secure decoding、rounding、wrap correction 和 malformed ciphertext 检查。
- [ ] S2C correlated mask 的一致性生成、持久化和 exactly-once 消费。
- [ ] FHE key、live values、MAC 和 Prep 的组合式 malicious-secure handoff 证明。

## 12. 论文覆盖范围与工程边界

本文档依据 `main.pdf` 补充了两种持久表示、Address Registry、operator sequence、Pick、C2S/S2C、authenticated MPC、PRSS preprocessing 和四元组 handoff 状态。

论文没有完成以下内容，工程实现不得声称已经由论文证明：

- malicious-secure C2S/S2C 的完整协议和组合证明；
- malicious-secure fluid handoff 的具体协议；
- malformed ciphertext、inconsistent key view 和跨 epoch 自适应腐化的完整处理；
- 性能数据和 Hybrid 相对 all-FHE/static-Hybrid 的收益阈值；
- cryptographic sortition 的具体 VRF/随机信标构造。

本文第 6 节的 VRF sortition 是项目工程补充，不是论文已经给出的具体协议，必须单独审计。
