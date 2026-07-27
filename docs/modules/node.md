# Node 模块约定

> 状态：草案，可直接修改。对应 crate：`ppsc-node`

## 职责

- 通过构造函数注入并组合 chain、crypto、protocol、network、storage。
- 管理进程生命周期、事件循环、并发、健康检查和优雅停机。
- 将协议动作转换为可观测、可重试的副作用。

## 必须遵守

- 禁止全局可变状态和隐藏单例。
- 配置在启动时完成校验；敏感配置使用专用 secret 类型。
- 每个任务有并发上限和取消机制，整体必须支持背压。
- 日志仅包含公开标识、阶段和脱敏错误码。
- 停机前停止接收新任务、持久化 checkpoint、等待有界时间。

## 建议配置

```text
node.identity
chain.rpc_url / chain.contract / chain.finality
network.listen / network.tls
storage.postgres / storage.rocksdb
runtime.max_tasks / runtime.shutdown_timeout
```

真实 secret 不写入配置文件，字段改为环境变量或 secret manager 引用。

## 测试清单

- 使用全部 fake adapter 的任务完整生命周期。
- 依赖故障注入、退避、重试耗尽和恢复。
- SIGTERM 优雅停机和 checkpoint 恢复。
- 日志泄密测试与资源上限测试。

## 待确认

- [ ] 配置格式和 secret manager。
- [ ] 任务并发/队列上限及资源隔离。
- [ ] 健康检查、指标和 tracing 后端。
- [ ] 部署形态（systemd、容器或 Kubernetes）。

