# Privacy-Preserving Smart Contract Node


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
密态执行细节见 [动态混合协议设计](docs/confidential-contract-protocol.md)，论文采用情况和未完成项见
[论文—工程对照](docs/paper-gap-analysis.md)。

链上 Solidity MVP、测试和 Sepolia 部署说明见
[链上控制面 MVP](docs/onchain-mvp.md)。
编写用户隐私合约时参阅
[隐私保护智能合约编写接口](docs/privacy-contract-authoring-api.md)。
公开 ERC-20 与密态余额的双向兑换见
[密态代币兑换合约](docs/confidential-token-swap.md)。
Rust 执行状态机、MPC/FHE 端口和明文开发后端见
[Runtime 接口与明文开发后端](docs/runtime.md)。
SS/FHE 上传、节点选择、handoff、计算和链上位置更新见
[存储与 Handoff 流程](docs/storage-handoff-workflow.md)。

从零开始运行同一条本地链上的完整演示（密态条件转账、明文代币存款、密态余额查询和提款），见
[PPSC 完整端到端演示](docs/README-complete-confidential-demo.md)。

一键验证该完整流程：

```sh
./scripts/test-handoff-workflow.sh
```

一键运行本地 Solidity 测试、Anvil 部署和链上回读：

```sh
./scripts/test-local.sh
```

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
