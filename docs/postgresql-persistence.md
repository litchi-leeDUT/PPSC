# PostgreSQL 持久化

`PostgresBalanceRuntime` 是内存版 `BalanceRuntime` 的持久化实现，并继续实现同一个
`BalanceRuntimeApi`。上层调用充值、提现、余额查询时不需要改变命令结构。

## 一致性模型

每次状态转换在一个 PostgreSQL 事务内完成：

1. `SELECT ... FOR UPDATE` 锁定 `ppsc_runtime_meta` 的唯一状态根；
2. 比较调用者提交的 `expected_old_state_root`；
3. 检查 deposit ID 或 withdrawal nullifier 是否已使用；
4. 锁定并更新账户的密文余额；
5. 写入重放保护标记和完整状态转换审计记录；
6. 更新全局状态根并提交。

因此多个 Runtime 进程连接同一数据库时，只有持有当前状态根的请求能够提交。失败事务会自动回滚，
不会出现余额已更新但 nullifier 未记录的中间状态。

表结构位于 `crates/runtime/migrations/0001_runtime.sql`。金额以 16 字节大端序 `BYTEA`
保存，完整覆盖 Rust `u128`；余额字段只保存 MPC/FHE backend 产生的密文，不保存解密后的余额。
当前 `PlaintextBackend` 仍仅用于开发测试，生产部署必须注入真实 MPC/FHE backend。

## 本地运行

如果已安装 Docker：

```bash
docker compose -f docker-compose.postgres.yml up -d
export DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc'
cargo run -p ppsc-runtime --bin postgres_migrate
```

运行真实数据库集成测试：

```bash
export TEST_DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc'
./scripts/test-postgres-runtime.sh
```

测试使用唯一账户、资产、deposit ID 和 nullifier，不会清空已有表。未设置
`TEST_DATABASE_URL` 时，普通 `cargo test` 会明确跳过数据库联调。

## 接入 Runtime

```rust
use ppsc_runtime::{postgres::PostgresBalanceRuntime, PlaintextBackend};

let runtime = PostgresBalanceRuntime::connect(
    &std::env::var("DATABASE_URL")?,
    PlaintextBackend,
)?;
```

`connect` 会幂等执行 migration。生产环境建议使用受限数据库角色、TLS 连接、备份与迁移锁，
并将数据库 URL 放入密钥管理系统。
