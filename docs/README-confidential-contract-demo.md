# 用户发布并调用密态合约：真实链上/链下演示

本演示逐条运行命令，不使用测试用例或封装 Shell 脚本。完整数据路径是：

```text
PrivateBalanceApp 发起 execution
  -> ControlPlane 记录任务并选择 committee
  -> private_balance_worker 从 PostgreSQL 读取密文
  -> Runtime 执行 C2S -> MPC 条件转账 -> S2C
  -> committee 对结果签名
  -> ControlPlane 验签、登记输出并更新密态变量引用
  -> Runtime 从新引用执行授权余额 opening
```

密态函数语义：仅当 `senderBalance > minimumBalance` 时，从 sender 向 receiver 转
`amount`。初始值 sender=100、receiver=20、minimum=50、amount=30，因此预期结果是
sender=70、receiver=50。

> 当前 MPC/FHE adapter 使用开发明文 backend，但输入、输出仍以 ciphertext 对象存储在
> PostgreSQL，链上仅保存 data ID、commitment、slot、存储节点和状态根。生产部署时替换
> backend，不改变 App 与 ControlPlane 的接口。

## 1. 初始化 PostgreSQL

`private_balance_worker` 不会猜测数据库地址，启动前必须在**当前终端**设置
`DATABASE_URL`。`.env` 文件也不会被 Cargo 自动加载。

### 1.1 使用本机 Homebrew PostgreSQL（推荐）

确认安装位置并把客户端加入当前终端的 `PATH`：

```bash
brew --prefix postgresql@16
export PATH="$(brew --prefix postgresql@16)/bin:$PATH"
psql --version
```

如果你安装的是其他版本，把命令中的 `postgresql@16` 换成实际 formula 名称。启动服务：

```bash
brew services start postgresql@16
pg_isready -h 127.0.0.1 -p 5432
```

预期：

```text
127.0.0.1:5432 - accepting connections
```

首次运行时创建演示用户和数据库。下面两组命令可以重复执行；已经存在时会跳过创建：

```bash
psql postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='ppsc'" \
  | grep -q 1 \
  || psql postgres -c "CREATE ROLE ppsc LOGIN PASSWORD 'ppsc_dev_only';"

psql postgres -tAc "SELECT 1 FROM pg_database WHERE datname='ppsc'" \
  | grep -q 1 \
  || psql postgres -c "CREATE DATABASE ppsc OWNER ppsc;"
```

为当前终端设置连接字符串并验证登录：

```bash
export DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc'

psql "$DATABASE_URL" -c \
  'SELECT current_database(), current_user, version();'
```

预期 `current_database` 为 `ppsc`，`current_user` 为 `ppsc`。

### 1.2 使用 Docker（可选）

如果不使用本机 PostgreSQL，可以改用仓库中的 Compose 配置：

```bash
cd /Users/esion/Desktop/ppsc
docker compose -f docker-compose.postgres.yml up -d
docker compose -f docker-compose.postgres.yml ps

export DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc'
```

不要同时启动 Homebrew 和 Docker 的 PostgreSQL，否则两者会争用 `5432` 端口。

### 1.3 检查 Runtime 所需环境变量

每次打开新终端，都需要重新执行 `export DATABASE_URL=...`。在运行 worker 前检查：

```bash
test -n "$DATABASE_URL" && echo "DATABASE_URL=$DATABASE_URL"
```

如果没有输出，立即执行：

```bash
export DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc'
```

worker 第一次连接时会自动、幂等创建演示所需的
`ppsc_demo_ciphertext_slots` 和 `ppsc_demo_variable_bindings`，不需要手工导入 SQL。

## 2. 启动 Anvil 并设置演示环境

终端 A：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"
anvil --host 127.0.0.1 --port 8545
```

终端 B 设置环境：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

export RPC_URL=http://127.0.0.1:8545
# 新终端不会继承第 1 步的 export，所以这里再次设置。
export DATABASE_URL=postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc

export USER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export RUNTIME_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
export DEMO_USER=$(cast wallet address --private-key "$USER_KEY")
export RUNTIME_ADDRESS=$(cast wallet address --private-key "$RUNTIME_KEY")

export MEMBER_KEY_1=0x0000000000000000000000000000000000000000000000000000000000000b0b
export MEMBER_KEY_2=0x000000000000000000000000000000000000000000000000000000000000d00d
export MEMBER_KEY_3=0x000000000000000000000000000000000000000000000000000000000000cafe
export NODE_1=$(cast wallet address --private-key "$MEMBER_KEY_1")
export NODE_2=$(cast wallet address --private-key "$MEMBER_KEY_2")
export NODE_3=$(cast wallet address --private-key "$MEMBER_KEY_3")
export RECEIVER="$NODE_3"
```

确认 Anvil 可连接：

```bash
cast block-number --rpc-url "$RPC_URL" --no-proxy
```

如果仍出现 `HTTP error 502 with empty body`，说明代理变量没有被清除；重新执行上述六个
`unset` 项，而不只是添加 `--no-proxy`。

在继续部署前，同时检查两个本地服务和关键环境变量：

```bash
pg_isready -h 127.0.0.1 -p 5432
psql "$DATABASE_URL" -Atc 'SELECT 1'
cast block-number --rpc-url "$RPC_URL" --no-proxy
printenv DATABASE_URL RPC_URL
```

预期 PostgreSQL 显示 `accepting connections`，SQL 返回 `1`，Anvil 返回区块高度，最后两行
显示完整连接地址。

## 3. 部署 verifier 和 ControlPlane

```bash
export VERIFIER=$(forge create \
  contracts/script/DeployInteractiveSwap.s.sol:InteractiveAcceptAllSortition \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --no-proxy \
  --broadcast --json | jq -r .deployedTo)

export CONTROL=$(forge create contracts/src/PpscControlPlane.sol:PpscControlPlane \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --no-proxy \
  --broadcast --json \
  --constructor-args "$DEMO_USER" "$RUNTIME_ADDRESS" "$VERIFIER" | jq -r .deployedTo)

printf 'verifier=%s\ncontrol=%s\n' "$VERIFIER" "$CONTROL"
```

`PpscControlPlane` 构造函数现在严格只有 3 个参数：`owner`、`runtime`、`verifier`。不要把
committee 参数传给构造函数，否则会出现 `expected 3 but got 10`。

## 4. sortition 确定 committee

本地 verifier 接受开发 evidence；生产版应替换为 VRF/质押权重证明。

```bash
export COMMITTEE_ID=$(cast keccak 'private-transfer-committee-epoch-1')
export COMMITTEE_SEED=$(cast keccak 'vrf-seed-epoch-1')

cast send "$CONTROL" \
  'finalizeCommittee(bytes32,bytes32,uint64,address[],uint16,bytes)' \
  "$COMMITTEE_ID" "$COMMITTEE_SEED" 1 \
  "[$NODE_1,$NODE_2,$NODE_3]" 2 0x01 \
  --private-key "$RUNTIME_KEY" --rpc-url "$RPC_URL" --quiet

cast call "$CONTROL" 'committeeMembers(bytes32)(address[])' \
  "$COMMITTEE_ID" --rpc-url "$RPC_URL"
```

预期返回三个节点地址。threshold 为 2。

## 5. 用户部署 PrivateBalanceApp

```bash
export INITIAL_STATE_ROOT=$(cast keccak 'encrypted-balances-v1')
export DEPLOYMENT_SALT=$(cast keccak 'alice-private-balance-contract')
export MANIFEST_HASH=$(cast keccak 'private-balance-manifest-v1')
export RUNTIME_HASH=$(cast keccak 'ppsc-runtime-mpc-fhe-v1')

export APP=$(forge create contracts/src/examples/PrivateBalanceApp.sol:PrivateBalanceApp \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --no-proxy \
  --broadcast --json \
  --constructor-args "$CONTROL" "$DEMO_USER" "$DEPLOYMENT_SALT" \
  "$MANIFEST_HASH" "$RUNTIME_HASH" "$INITIAL_STATE_ROOT" | jq -r .deployedTo)

export CONTRACT_ID=$(cast call "$APP" \
  'confidentialContractId()(bytes32)' --rpc-url "$RPC_URL")

printf 'app=%s\ncontractId=%s\n' "$APP" "$CONTRACT_ID"
```

App 构造函数原子发布固定程序定义。用户不需要、也不能为每次调用重新发布计算函数：

```bash
cast call "$APP" 'privateTransferPublished()(bool)' --rpc-url "$RPC_URL"
```

预期：

```text
true
```

## 6. Runtime 初始化并持久化密态变量

`bootstrap` 会完成以下真实操作：

- 用开发 backend 加密 100、20、50、30；
- 把 ciphertext 写入 PostgreSQL 的 `ppsc_demo_ciphertext_slots`；
- 把稳定变量地址到 `(dataId, slot)` 的映射写入
  `ppsc_demo_variable_bindings`；
- 由 Runtime 在 ControlPlane 登记 data、存储节点并声明状态变量。

```bash
if [[ -z "$DATABASE_URL" ]]; then
  echo 'DATABASE_URL 未设置，请先执行第 1.3 节的 export 命令'
else
  cargo run -p ppsc-runtime --bin private_balance_worker -- bootstrap
fi
```

预期：

```text
Runtime bootstrap completed: encrypted balances and policy variables persisted
```

检查链上 sender 变量引用：

```bash
export SENDER_VAR=$(cast call "$APP" \
  'balanceVariable(address)(bytes32)' "$DEMO_USER" --rpc-url "$RPC_URL")

cast call "$CONTROL" \
  'stateVariableReference(bytes32)((bytes32,bytes32,uint8,uint32,uint64,bool))' \
  "$SENDER_VAR" --rpc-url "$RPC_URL"
```

最后一个字段应为 `true`。链上返回的是 data ID、表示法、slot 和版本，不包含余额。

## 7. 计算前查询余额

这里的 `query` 模拟用户已获授权后的 opening。它先核对链上变量引用与 PostgreSQL binding
一致，再读取对应 ciphertext 并通过 backend 解密；不是写死的打印内容。

```bash
cargo run -p ppsc-runtime --bin private_balance_worker -- query sender
cargo run -p ppsc-runtime --bin private_balance_worker -- query receiver
```

预期：

```text
authorized balance opening: account=0xf39F... balance=100 dataId=0xa1a1... slot=0
authorized balance opening: account=0xBa53... balance=20 dataId=0xa2a2... slot=0
```

## 8. 用户调用密态条件转账

先通过 `eth_call` 得到 execution ID，再发送真实交易：

```bash
export INVOCATION_NONCE=1
export DEADLINE=4102444800

export EXECUTION_ID=$(cast call "$APP" \
  'conditionalTransfer(address,uint64,uint64)(bytes32)' \
  "$RECEIVER" "$INVOCATION_NONCE" "$DEADLINE" \
  --from "$DEMO_USER" --rpc-url "$RPC_URL")

cast send "$APP" 'conditionalTransfer(address,uint64,uint64)' \
  "$RECEIVER" "$INVOCATION_NONCE" "$DEADLINE" \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

printf 'executionId=%s\n' "$EXECUTION_ID"
cast call "$CONTROL" 'executionStatus(bytes32)(uint8)' \
  "$EXECUTION_ID" --rpc-url "$RPC_URL"
```

此时状态应为 `1 (Requested)`。调用参数只有 receiver、nonce、deadline；四个密态变量地址
由 App 按规则确定，并在调用时解析到 ControlPlane 当前 data ID，用户不能替换余额变量。

## 9. Runtime/committee 处理链上 execution

```bash
cargo run -p ppsc-runtime --bin private_balance_worker -- \
  process "$EXECUTION_ID"
```

预期：

```text
execution processed and committed: 0x...
```

该命令不是自包含 demo。它会：

1. 在链上分配 committee，并把 execution 标记为 Running；
2. 按变量 binding 从 PostgreSQL 加载四个 ciphertext；
3. 执行 `C2S -> MPC(gt, conditional sub/add) -> S2C`；
4. 生成输出 ciphertext、commitment、新状态根和 transcript root；
5. 收集 2-of-3 committee 签名并调用 `submitResult`；
6. 登记新输出的存储节点；
7. committee 再签名，将 sender/receiver 变量更新到新 data ID 的 slot 0/1；
8. 事务性地持久化新 ciphertext 和本地 binding。

## 10. 计算后查询余额并核对链上状态

```bash
cargo run -p ppsc-runtime --bin private_balance_worker -- query sender
cargo run -p ppsc-runtime --bin private_balance_worker -- query receiver
```

预期：

```text
authorized balance opening: account=0xf39F... balance=70 dataId=0x... slot=0
authorized balance opening: account=0xBa53... balance=50 dataId=0x... slot=1
```

两条记录现在引用相同的新输出 data ID，但分别使用 slot 0 和 slot 1。这证明输出不是再次运行
一个固定打印的 demo，而是由本次 execution 产生、写入 PostgreSQL，并同步回链上变量引用。

检查 execution：

```bash
cast call "$CONTROL" 'executionStatus(bytes32)(uint8)' \
  "$EXECUTION_ID" --rpc-url "$RPC_URL"
```

预期：

```text
6
```

`6` 表示 Completed。也可直接查询两个变量的新链上引用：

```bash
export RECEIVER_VAR=$(cast call "$APP" \
  'balanceVariable(address)(bytes32)' "$RECEIVER" --rpc-url "$RPC_URL")

cast call "$CONTROL" \
  'stateVariableReference(bytes32)((bytes32,bytes32,uint8,uint32,uint64,bool))' \
  "$SENDER_VAR" --rpc-url "$RPC_URL"
cast call "$CONTROL" \
  'stateVariableReference(bytes32)((bytes32,bytes32,uint8,uint32,uint64,bool))' \
  "$RECEIVER_VAR" --rpc-url "$RPC_URL"
```

两个返回值的 data ID 应相同，slot 分别为 0 和 1，version 都已增加。

## 11. 当前边界

这条链路已经真实连接 Anvil、ControlPlane、Rust Runtime 和 PostgreSQL，但仍属于开发实现：

- worker 当前使用显式 `process <executionId>`，尚未做常驻事件监听循环；
- MPC/FHE backend 当前内部用明文算法模拟，接口和 C2S/S2C 边界已保留；
- committee 私钥仅用于本地演示，生产环境必须由独立节点分别持有；
- `query` 使用开发授权 opening，生产环境应校验链上 opening request，并把结果加密给用户公钥。

因此，目前能演示和验证的是完整控制流、持久化、签名与变量版本更新；它还不是可在生产环境保护
真实资产的密码学实现。
