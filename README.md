# Privacy-Preserving Smart Contract Node

这是 `project.md` 所描述系统的 Rust 链下节点框架。当前阶段只定义模块边界、核心领域类型和接口，不包含具体密码学原语、链合约或网络实现。

## Workspace

| crate | 职责 |
|---|---|
| `ppsc-core` | 跨模块领域类型、状态和公共错误 |
| `ppsc-crypto` | 加密、秘密分享、同态计算的能力接口 |
| `ppsc-protocol` | 与传输无关的任务协议和状态机 |
| `ppsc-network` | 节点间消息和 gRPC 传输抽象 |
| `ppsc-storage` | 密态数据、任务状态和协议消息持久化 |
| `ppsc-chain` | Solidity 合约事件监听和交易提交 |
| `ppsc-node` | 组合各端口、执行节点主循环 |

依赖方向见 [架构文档](docs/architecture.md)，各模块的可修改约定在 `docs/modules/`。

## 后续实现顺序

1. 确认 `docs/modules/` 中的决策和待确认项。
2. 固化 Solidity ABI 与 gRPC protobuf。
3. 为各接口增加内存实现和契约测试。
4. 选型并封装经过审计的密码学库。
5. 实现 PostgreSQL/RocksDB、链适配器及节点进程。

## 验证

```sh
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
```

