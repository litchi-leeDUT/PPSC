# 可演示流程脚本

所有脚本都从项目根目录运行。第一次运行 Cargo 或 Foundry 时可能需要下载依赖。

## 一键演示

```bash
./scripts/demo-all.sh
```

默认依次演示：

1. Runtime 密态余额充值、查询和提现；
2. SS/FHE 数据发布、sortition、committee handoff 和计算；
3. 在临时 Anvil 链部署用户隐私合约并发布密态函数；
4. 明文代币与密文代币双向兑换。

同时演示 PostgreSQL：

```bash
WITH_POSTGRES=1 ./scripts/demo-all.sh
```

## 单独运行

```bash
./scripts/demo/01-runtime-balance.sh
./scripts/demo/02-storage-handoff.sh
./scripts/demo/03-local-chain-contract.sh
./scripts/demo/04-token-swap.sh
./scripts/demo/05-postgres-persistence.sh
```

PostgreSQL 脚本会优先使用已有的 `TEST_DATABASE_URL`。未提供时，它会通过
`docker-compose.postgres.yml` 启动开发数据库。演示结束后数据库保持运行，便于检查审计记录：

```bash
docker compose -f docker-compose.postgres.yml exec postgres \
  psql -U ppsc -d ppsc -c \
  'SELECT sequence, operation_kind, version FROM ppsc_state_transitions ORDER BY sequence;'
```

停止数据库但保留数据卷：

```bash
docker compose -f docker-compose.postgres.yml down
```

删除数据卷属于破坏性操作，需要时手动执行 `docker compose ... down -v`。
