# Rust 节点架构

## 范围

本 workspace 只负责链下 Rust 节点。Solidity 合约和 TypeScript SDK 是独立工程，通过 `ppsc-chain` 和公开数据结构接入。

## 依赖规则

```text
                         +-------------+
                         |  ppsc-node  |
                         +------+------+
                 +--------------+--------------+
                 v              v              v
          ppsc-chain      ppsc-network    ppsc-storage
                 \              |              /
                  +-------------v-------------+
                           ppsc-protocol
                                 |
                           ppsc-crypto
                                 |
                            ppsc-core
```

- `core` 不依赖其他业务 crate。
- `crypto` 只表达密码能力，不感知 gRPC、数据库或合约。
- `protocol` 只使用抽象端口，不直接创建网络连接或数据库连接。
- `network` 只做消息传输与认证，不解释密码协议。
- `node` 是唯一允许组合具体实现的地方；禁止全局单例。

## 横切规则

- 每个公开接口都有明确错误类型。
- 密钥、秘密份额、明文及可推导秘密的信息不得实现 `Display`/`Debug`。
- 日志只允许任务 ID、节点 ID、阶段、公开链高度和脱敏错误码。
- 所有外部输入在适配器边界验证大小、版本、身份和重放条件。
- 状态写入应具备幂等键；链事件按 `(chain_id, block_hash, log_index)` 去重。
- 接口的内存实现与生产实现必须通过同一组契约测试。

## 关键流程

1. `ChainGateway` 监听任务登记和委员会变更事件。
2. `NodeRuntime` 将事件转为 `ProtocolTask` 并持久化。
3. `ProtocolEngine` 产生待发送的协议消息或待计算动作。
4. `PeerTransport` 传递公开协议信封，载荷由协议层定义。
5. 密码动作只通过 `CryptoProvider` 执行。
6. 完成后存储状态承诺，并由 `ChainGateway` 提交结果/证明。

密态合约发布、数据存储、cryptographic sortition、动态委员会和混合协议的完整设计见
[密态智能合约与动态混合协议](confidential-contract-protocol.md)。

## 未决架构决策

- 共识链及最终性判定规则。
- 委员会选择、门限和成员身份密钥体系。
- 隐私计算协议与经审计库。
- 结果证明类型（门限签名、ZK 证明或其他）。
- PostgreSQL 与 RocksDB 的职责划分。
