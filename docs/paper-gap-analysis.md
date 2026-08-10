# `main.pdf` 与工程设计对照

> 审阅基线：`main.pdf`，生成时间 2026-08-05，共 10 页。

## 已进入工程接口

| 论文概念 | 工程落点 | 状态 |
|---|---|---|
| 两种持久私密表示 SS/FHE | `DataRepresentation` | 已定义 |
| `Ref=(dataId, PKSet, threshold, repr, owner)` | `ppsc-chain::DataReference` | 已定义并增加 commitment/version/key ref |
| 合约定义 operator domain 和显式转换 | `ContractOperator`、`OperatorStep` | 已定义 |
| Invoke 只传公开 data ID | `InvocationRequest` | 已定义 |
| owner 签名 Pick | `PickRequest` | 已定义并补充防重放域 |
| C2S 转换参数与内部 decode/range/wrap 检查 | `ConversionParameters`、`ciphertext_to_authenticated_sharing` | 接口已定义 |
| S2C 一次性相关 mask | `CorrelatedConversionMask`、`authenticated_sharing_to_ciphertext` | 接口已定义 |
| epoch 状态 `(Key, Live, MAC, Prep)` | `EpochStateManifest` | 已定义 |
| 本地 SS/key/MAC/preprocessing 记录 | `FragmentKind`、`FragmentRepository` | 已定义 |
| sortition 和 handoff 动作 | `ProtocolAction`、`CryptoProvider` | 框架已定义 |

## 论文内容对现有设计的修正

1. 删除第三种持久 `Hybrid` representation；Hybrid 只表示 operator sequence 同时使用 FHE 和 MPC。
2. active committee 持有 FHE key shares，不设置独立长期 KMS committee。
3. handoff 必须原子覆盖 FHE key、live value、MAC 和未消费 preprocessing。
4. FHE ciphertext 与其 key reference 分开寻址；Pick key 后会释放该 key 下所有 ciphertext 的解密能力。
5. `Q=q_c` 只对齐系数剩余类，不代表逻辑域相同，也不能省略 scale/round/wrap 检查。

## 工程补充，不是论文结论

- VRF sortition 的 seed、资格快照、权重和重试规则。
- 存储节点 Merkle root、receipt、availability challenge 和 slash。
- Pick 的 `chainId/registry/recipient/nonce/expiry` 域分离。
- 程序体的内容寻址存储、Runtime hash 和资源计量。
- 链最终性、重组恢复和输出登记幂等语义。

这些补充需要单独安全审计，不能引用论文作为已证明依据。

## 阻塞生产实现的论文缺口

- [ ] C2S 的 malicious-secure raw-decryption、decode、round 和 malformed-ciphertext 检查。
- [ ] S2C correlated mask 的恶意安全生成及一致性证明。
- [ ] FHE key/live value/MAC/Prep 的组合式 fluid handoff 协议与证明。
- [ ] authenticated opening 的一致广播和完整 soundness 参数。
- [ ] DKG、threshold FHE 具体方案和 key-share refresh 实例化。
- [ ] 自适应跨 epoch 腐化与可靠安全删除假设。
- [ ] all-FHE、static hybrid、dynamic hybrid 的同算子基准测试。

## PDF 草稿问题

- 存在未解析引用 `?` 和 `Section ??`。
- Discussion/Conclusion 出现重复章节编号。
- 部分 protocol box 给出代数轮廓，但未给出完整恶意安全子协议。
- 摘要和正文已经明确声明 conversion、handoff 及性能评估尚未完成。

因此当前工程目标应是“可插拔原型与验证平台”，而不是宣称已经得到端到端 malicious security。
