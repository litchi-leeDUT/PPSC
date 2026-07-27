# Project Goal

构建一个支持隐私交易和隐私智能合约的区块链系统。

# Core Architecture

- 链上：任务登记、委员会管理、状态承诺、结果验证
- 链下：密态数据存储、秘密分享计算、同态计算
- 客户端：数据加密、交易构造、结果解密
- 节点：任务监听、协议执行、结果提交

# Technology Stack

- Smart Contract: Solidity
- Off-chain Node: Rust
- Client SDK: TypeScript
- Communication: gRPC
- Storage: PostgreSQL / RocksDB
- Testing: Foundry + Rust tests

# Engineering Rules

- 核心模块禁止使用全局变量
- 密码协议与网络通信分离
- 所有接口必须有错误类型
- 每个功能必须有单元测试
- 密码学实现禁止自行发明原语
- 不允许在日志中输出秘密份额和密钥