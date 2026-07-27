# Storage 模块约定

> 状态：草案，可直接修改。对应 crate：`ppsc-storage`

## 职责

- 持久化任务状态、协议消息、checkpoint 和密态/敏感数据。
- 为 PostgreSQL、RocksDB 或组合方案提供统一端口。
- 保存本节点被分配的秘密份额或 HE 密文副本，并生成可用性 receipt。

详细协议见 [密态智能合约与动态混合协议](../confidential-contract-protocol.md)。

## 必须遵守

- 状态迁移使用 compare-and-set，拒绝丢失更新。
- 消息以 `MessageId` 幂等写入。
- 敏感数据静态加密，密钥不得与数据存于同一后端。
- 数据库错误不得包含参数中的秘密内容。
- 明确备份、恢复、保留和安全删除策略。

## 建议分工

- PostgreSQL：任务元数据、状态、链游标、幂等记录。
- RocksDB：大体积密文、checkpoint、短生命周期协议数据。
- 该分工是草案，应由访问模式和运维要求确认。

## 测试清单

- 所有实现共享仓储契约测试。
- 并发状态迁移、事务回滚和幂等写入。
- 崩溃恢复、数据损坏检测、迁移升级/回滚。
- 日志和错误输出泄密扫描。

## 待确认

- [ ] PostgreSQL/RocksDB 的最终职责。
- [ ] checkpoint 和密文的保留期限。
- [ ] 静态加密与密钥管理系统。
- [ ] 链重组时的事务回滚模型。
- [ ] storage set root、receipt root 和 possession challenge 格式。
