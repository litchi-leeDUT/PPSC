# PPSC 总演示：明文存款 → 密态转账 → 密态提款

这份文档演示一条连续的余额生命周期：

```text
sender 明文 mUSD=1000
  → sender 存入明文 100
  → Runtime 创建 sender 密态余额 100
  → sender 密态转账 30 给 receiver
  → sender 密态余额 70，receiver 密态余额 30
  → receiver 提取密态 20
  → receiver 密态余额 10，并收到明文 19.8
```


> 当前密码 backend 内部仍以明文算法模拟 MPC/FHE，但数据库持久化、状态根、防重放、
> committee 签名和链上 ERC-20 付款都是真实执行的开发实现。

## 1. 业务流程

### 1.1 明文存款

1. sender 调用 ERC-20 `approve`；
2. sender 调用 Swap `deposit`，100 mUSD 进入合约托管；
3. Swap 创建 Pending 存款并发出 `DepositRequested`；
4. Runtime 监听事件，在密态账户中执行 `0 + 100`；
5. Runtime 持久化 ciphertext、data ID、版本和状态根；
6. committee 签署 `DepositSettlement`；
7. `finalizeDeposit` 更新链上状态根和密态总负债。

### 1.2 密态转账

1. sender 调用 `requestConfidentialTransfer`；
2. Swap 创建 Pending 转账并发出 `ConfidentialTransferRequested`；
3. Runtime 从同一余额表加载 sender=100，receiver 不存在时按密态零处理；
4. Runtime 在 MPC 接口内验证 `sender >= 30`；
5. Runtime 原子计算并持久化 sender=70、receiver=30；
6. committee 签署两个新余额 data ID、新状态根和 transcript；
7. `finalizeConfidentialTransfer` 验签并更新 Swap 密态状态根，总负债仍为 100。

### 1.3 密态提款

1. receiver 调用 `requestWithdrawal` 请求取出 20；
2. Runtime 从转账后的同一余额记录读取 receiver=30；
3. Runtime 密态验证 `30 >= 20`，并计算 `30 - 20 = 10`；
4. committee 签署 `WithdrawalSettlement`；
5. `finalizeWithdrawal` 更新状态根、减少密态总负债并消费 nullifier；
6. Swap 收取 1% 手续费，向 receiver 支付 19.8 个明文 mUSD。

## 2. 初始化 PostgreSQL

```bash
cd /Users/esion/Desktop/ppsc
export PATH="$(brew --prefix postgresql@16)/bin:$PATH"
brew services start postgresql@16

psql postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='ppsc'" \
  | grep -q 1 \
  || psql postgres -c "CREATE ROLE ppsc LOGIN PASSWORD 'ppsc_dev_only';"

# 每次演示创建唯一数据库，不能复用上一次的密态余额。
export DEMO_DB="ppsc_complete_$(date +%Y%m%d_%H%M%S)"
createdb -O ppsc "$DEMO_DB"

export DATABASE_URL="postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/$DEMO_DB"
psql "$DATABASE_URL" -Atc 'SELECT current_database(),current_user'
```

记住终端输出的 `$DEMO_DB`。后续所有命令必须继续使用这个终端中的 `DATABASE_URL`，不要重新写回
固定的 `ppsc_complete_demo`，也不要复用上一次演示数据库。

## 3. 启动 Anvil 和设置账户

终端 A：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"
anvil --host 127.0.0.1 --port 8545
```

终端 B：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

export RPC_URL=http://127.0.0.1:8545
# 沿用第 2 节生成的值，不要在这里改成旧数据库。
test -n "$DATABASE_URL" && echo "$DATABASE_URL"

export SENDER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export RECEIVER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
export SENDER=$(cast wallet address --private-key "$SENDER_KEY")
export RECEIVER=$(cast wallet address --private-key "$RECEIVER_KEY")

export MEMBER_KEY_1=0x0000000000000000000000000000000000000000000000000000000000000b0b
export MEMBER_KEY_2=0x000000000000000000000000000000000000000000000000000000000000d00d
export MEMBER_KEY_3=0x000000000000000000000000000000000000000000000000000000000000cafe
export NODE_1=$(cast wallet address --private-key "$MEMBER_KEY_1")
export NODE_2=$(cast wallet address --private-key "$MEMBER_KEY_2")
export NODE_3=$(cast wallet address --private-key "$MEMBER_KEY_3")

# Runtime 用 committee 节点自己的 EOA 提交 finalize，绝不使用 sender 私钥。
export NODE_TX_KEY="$MEMBER_KEY_1"
export NODE_TX_ADDRESS="$NODE_1"

# 仅本地 Anvil：给节点设置首次提交所需的周转余额。生产节点应自备少量周转金，
# 后续每个成功任务由用户预存在合约的 taskGasEscrow 补偿。
cast rpc anvil_setBalance "$NODE_TX_ADDRESS" 0x8AC7230489E80000 \
  --rpc-url "$RPC_URL"

cast block-number --rpc-url "$RPC_URL" --no-proxy
psql "$DATABASE_URL" -Atc 'SELECT 1'
printf 'sender=%s\nreceiver=%s\n' "$SENDER" "$RECEIVER"
printf 'runtime tx sender=%s\n' "$NODE_TX_ADDRESS"
```

## 4. 部署 ControlPlane、committee、mUSD 和原 Swap

```bash
export VERIFIER=$(forge create \
  contracts/test/ConfidentialTokenSwap.t.sol:AcceptAllSortitionVerifier \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  | jq -r .deployedTo)

export CONTROL=$(forge create contracts/src/PpscControlPlane.sol:PpscControlPlane \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  --constructor-args "$SENDER" "$SENDER" "$VERIFIER" \
  | jq -r .deployedTo)

export COMMITTEE_ID=$(cast keccak 'unified-balance-committee-epoch-1')
cast send "$CONTROL" \
  'finalizeCommittee(bytes32,bytes32,uint64,address[],uint16,bytes)' \
  "$COMMITTEE_ID" "$(cast keccak 'unified-sortition-seed')" 1 \
  "[$NODE_1,$NODE_2,$NODE_3]" 2 0x01 \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet

export TOKEN=$(forge create contracts/test/mocks/MockERC20.sol:MockERC20 \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  | jq -r .deployedTo)

export SWAP=$(forge create \
  contracts/src/ConfidentialTokenSwap.sol:ConfidentialTokenSwap \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  --constructor-args "$SENDER" "$CONTROL" "$COMMITTEE_ID" 86400 \
  | jq -r .deployedTo)

cast send "$SWAP" 'configureToken(address,bool,uint128,uint16)' \
  "$TOKEN" true 1000000000000000000 100 \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet

cast send "$TOKEN" 'mint(address,uint256)' \
  "$SENDER" 1000000000000000000000 \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet

printf 'control=%s\ntoken=%s\nswap=%s\n' "$CONTROL" "$TOKEN" "$SWAP"
```

这里部署的就是原 `ConfidentialTokenSwap`，现在它同时提供存款、密态转账和提款请求接口。

## 5. 建立两个密态账户 commitment

```bash
export SENDER_PRIVATE_ACCOUNT=$(cast keccak "private-account:$SENDER:$TOKEN")
export RECEIVER_PRIVATE_ACCOUNT=$(cast keccak "private-account:$RECEIVER:$TOKEN")

printf 'senderPrivate=%s\nreceiverPrivate=%s\n' \
  "$SENDER_PRIVATE_ACCOUNT" "$RECEIVER_PRIVATE_ACCOUNT"

# receiver 亲自把 commitment 绑定到自己的地址，之后只有 receiver 能请求 opening/提款。
cast send "$SWAP" 'registerConfidentialAccount(bytes32)' "$RECEIVER_PRIVATE_ACCOUNT" \
  --private-key "$RECEIVER_KEY" --rpc-url "$RPC_URL" --quiet
```

commitment 用于定位链下密态账户；链上地址不是数据库中的余额主键。

## 6. 查询初始余额

```bash
export SENDER_PUBLIC=$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$SENDER" --rpc-url "$RPC_URL" | awk '{print $1}')
export RECEIVER_PUBLIC=$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$RECEIVER" --rpc-url "$RPC_URL" | awk '{print $1}')

printf 'sender明文=%s\n' "$(cast from-wei "$SENDER_PUBLIC" ether)"
printf 'receiver明文=%s\n' "$(cast from-wei "$RECEIVER_PUBLIC" ether)"
```

预期 sender=1000，receiver=0。尚未存款时两个密态账户都不存在，不需要也不应该直接调用
Runtime 查询。

## 7. 启动无人值守 Runtime committee daemon

先在**终端 B**生成只供本地演示使用的 Runtime 环境文件。此时终端 B 已经拥有实际部署得到的
`SWAP/TOKEN` 和第 2 节生成的唯一 `DATABASE_URL`：

```bash
export RUNTIME_ENV_FILE=/private/tmp/ppsc-complete-runtime.env
umask 077
printf 'export DATABASE_URL=%q\nexport RPC_URL=%q\nexport SWAP=%q\nexport TOKEN=%q\nexport NODE_TX_KEY=%q\nexport NO_PROXY=%q\nexport no_proxy=%q\n' \
  "$DATABASE_URL" "$RPC_URL" "$SWAP" "$TOKEN" "$NODE_TX_KEY" \
  '127.0.0.1,localhost' '127.0.0.1,localhost' \
  > "$RUNTIME_ENV_FILE"
chmod 600 "$RUNTIME_ENV_FILE"
echo "Runtime 环境已保存到 $RUNTIME_ENV_FILE"
```

然后在**终端 C**直接执行以下完整命令，不需要逐个重新填写变量：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
source /private/tmp/ppsc-complete-runtime.env

printenv DATABASE_URL RPC_URL SWAP TOKEN
printf 'runtime node tx address=%s\n' \
  "$(cast wallet address --private-key "$NODE_TX_KEY")"
cast block-number --rpc-url "$RPC_URL" --no-proxy
psql "$DATABASE_URL" -Atc 'SELECT 1'

export POLL_INTERVAL_SECONDS=2
cargo run -p ppsc-runtime --bin confidential_swap_worker
```

检查输出中的 Runtime 交易地址必须是 `$NODE_1`，不能是 sender 地址。`cast block-number` 应返回
区块高度，PostgreSQL 检查应返回 `1`。

预期：

```text
committee daemon started: swap=0x... poll=2s
```

此后不要再手工调用 worker 的 `deposit <id>`、`transfer <id>` 或 `withdraw <id>`。保持终端 C
运行即可。daemon 自动读取链上任务队列、执行 Runtime 计算、收集开发 committee 签名并发送
finalize 交易；处理成功时输出 `processed 1 on-chain task(s)`。

演示结束后删除临时环境文件：

```bash
rm /private/tmp/ppsc-complete-runtime.env
```

生产环境不能把节点私钥写入普通文件，应使用节点密钥库、HSM 或 secret manager。

## 8. sender 存入 100 个明文 mUSD

```bash
export DEPOSIT_AMOUNT=$(cast to-wei 100 ether)

cast send "$TOKEN" 'approve(address,uint256)' "$SWAP" "$DEPOSIT_AMOUNT" \
  --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet

export DEPOSIT_ID=$(cast call "$SWAP" \
  'deposit(address,uint256,bytes32,uint64)(bytes32)' \
  "$TOKEN" "$DEPOSIT_AMOUNT" "$SENDER_PRIVATE_ACCOUNT" 1 \
  --from "$SENDER" --rpc-url "$RPC_URL")

cast send "$SWAP" 'deposit(address,uint256,bytes32,uint64)' \
  "$TOKEN" "$DEPOSIT_AMOUNT" "$SENDER_PRIVATE_ACCOUNT" 1 \
  --value 0.002ether --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet
```

此时 sender 明文余额变为 900，Swap 托管 100，但密态余额尚未增加，Deposit 为 Pending。

## 9. daemon 自动完成存款，用户查询 sender 密态余额

等待终端 C 输出：

```text
deposit finalized: amount=100000000000000000000 ... version=1
processed 1 on-chain task(s)
```

用户通过链上 opening 请求查询，不能直接调用 Runtime：

```bash
export OPENING_KEY=$(cast keccak 'sender-demo-opening-public-key')
export SENDER_OPENING_1=$(cast call "$SWAP" \
  'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)(bytes32)' \
  "$TOKEN" "$SENDER_PRIVATE_ACCOUNT" "$OPENING_KEY" 1 4102444800 \
  --from "$SENDER" --rpc-url "$RPC_URL")
cast send "$SWAP" \
  'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)' \
  "$TOKEN" "$SENDER_PRIVATE_ACCOUNT" "$OPENING_KEY" 1 4102444800 \
  --value 0.001ether --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet
```

等待 daemon 输出 `balance opening fulfilled`，然后用户客户端读取加密结果。本地开发编码可用
`cast to-dec` 查看；生产结果必须先用用户 opening 私钥解密：

```bash
export ENCRYPTED_BALANCE=$(cast call "$SWAP" \
  'balanceOpeningResults(bytes32)(bytes)' "$SENDER_OPENING_1" --rpc-url "$RPC_URL")
cast to-dec "$ENCRYPTED_BALANCE"
```

预期：

```text
deposit finalized: amount=100000000000000000000 ... version=1
authorized confidential balance: amount=100000000000000000000 ... version=1
```

## 10. sender 发起密态转账 30 给 receiver

```bash
export TRANSFER_AMOUNT=$(cast to-wei 30 ether)
export TRANSFER_EXPIRY=4102444800

export TRANSFER_ID=$(cast call "$SWAP" \
  'requestConfidentialTransfer(address,bytes32,bytes32,uint256,uint64,uint64)(bytes32)' \
  "$TOKEN" "$SENDER_PRIVATE_ACCOUNT" "$RECEIVER_PRIVATE_ACCOUNT" \
  "$TRANSFER_AMOUNT" 1 "$TRANSFER_EXPIRY" \
  --from "$SENDER" --rpc-url "$RPC_URL")

cast send "$SWAP" \
  'requestConfidentialTransfer(address,bytes32,bytes32,uint256,uint64,uint64)' \
  "$TOKEN" "$SENDER_PRIVATE_ACCOUNT" "$RECEIVER_PRIVATE_ACCOUNT" \
  "$TRANSFER_AMOUNT" 1 "$TRANSFER_EXPIRY" \
  --value 0.002ether --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet

printf 'transferId=%s\n' "$TRANSFER_ID"
```

这一步只创建 Pending 任务。`ConfidentialTransferRequested` 事件唤起 Runtime。

## 11. daemon 自动执行密态转账

等待终端 C 输出：

```text
confidential transfer finalized: amount=30000000000000000000 ...
processed 1 on-chain task(s)
```

Runtime 在同一个 PostgreSQL 事务中：

```text
加载 sender ciphertext(100)
创建 receiver 密态零值
验证 sender >= 30
计算 sender=70、receiver=30
更新两个 ppsc_balance_records
写入 ppsc_processed_transfers 防止重放
更新全局密态状态根
committee 签名
finalizeConfidentialTransfer
```

密态转账不改变 Swap 托管资产和 `privateLiabilities`，总负债仍为 100。

## 12. 查询转账后的两个密态余额

分别由 sender 和 receiver 发起链上 opening 请求，nonce 对每个用户独立递增：

```bash
export SENDER_OPENING_2=$(cast call "$SWAP" \
  'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)(bytes32)' \
  "$TOKEN" "$SENDER_PRIVATE_ACCOUNT" "$OPENING_KEY" 2 4102444800 \
  --from "$SENDER" --rpc-url "$RPC_URL")
cast send "$SWAP" 'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)' \
  "$TOKEN" "$SENDER_PRIVATE_ACCOUNT" "$OPENING_KEY" 2 4102444800 \
  --value 0.001ether --private-key "$SENDER_KEY" --rpc-url "$RPC_URL" --quiet

export RECEIVER_OPENING_KEY=$(cast keccak 'receiver-demo-opening-public-key')
export RECEIVER_OPENING_1=$(cast call "$SWAP" \
  'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)(bytes32)' \
  "$TOKEN" "$RECEIVER_PRIVATE_ACCOUNT" "$RECEIVER_OPENING_KEY" 1 4102444800 \
  --from "$RECEIVER" --rpc-url "$RPC_URL")
cast send "$SWAP" 'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)' \
  "$TOKEN" "$RECEIVER_PRIVATE_ACCOUNT" "$RECEIVER_OPENING_KEY" 1 4102444800 \
  --value 0.001ether --private-key "$RECEIVER_KEY" --rpc-url "$RPC_URL" --quiet
```

等待 daemon fulfill 后读取：

```bash
cast to-dec "$(cast call "$SWAP" 'balanceOpeningResults(bytes32)(bytes)' \
  "$SENDER_OPENING_2" --rpc-url "$RPC_URL")"
cast to-dec "$(cast call "$SWAP" 'balanceOpeningResults(bytes32)(bytes)' \
  "$RECEIVER_OPENING_1" --rpc-url "$RPC_URL")"
```

预期：

```text
sender:   amount=70000000000000000000 version=2
receiver: amount=30000000000000000000 version=1
```

也就是 sender=70、receiver=30。

## 13. receiver 请求提取 20 个密态 mUSD

```bash
export WITHDRAW_AMOUNT=$(cast to-wei 20 ether)
export WITHDRAW_EXPIRY=4102444800

export WITHDRAWAL_ID=$(cast call "$SWAP" \
  'requestWithdrawal(address,uint256,bytes32,address,uint64,uint64)(bytes32)' \
  "$TOKEN" "$WITHDRAW_AMOUNT" "$RECEIVER_PRIVATE_ACCOUNT" "$RECEIVER" \
  1 "$WITHDRAW_EXPIRY" --from "$RECEIVER" --rpc-url "$RPC_URL")

cast send "$SWAP" \
  'requestWithdrawal(address,uint256,bytes32,address,uint64,uint64)' \
  "$TOKEN" "$WITHDRAW_AMOUNT" "$RECEIVER_PRIVATE_ACCOUNT" "$RECEIVER" \
  1 "$WITHDRAW_EXPIRY" \
  --value 0.002ether --private-key "$RECEIVER_KEY" --rpc-url "$RPC_URL" --quiet
```

此时 receiver 尚未收到明文代币，密态余额仍为 30。

## 14. daemon 自动验证并完成 receiver 提款

等待终端 C 输出：

```text
withdrawal finalized: grossAmount=20000000000000000000 ... version=2
processed 1 on-chain task(s)
```

Runtime 从转账后的 receiver 余额 30 中扣除 20。`finalizeWithdrawal` 验证 committee 后，
Swap 向 receiver 支付 19.8，记录 0.2 手续费。

## 15. 查询最终结果

```bash
export RECEIVER_OPENING_2=$(cast call "$SWAP" \
  'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)(bytes32)' \
  "$TOKEN" "$RECEIVER_PRIVATE_ACCOUNT" "$RECEIVER_OPENING_KEY" 2 4102444800 \
  --from "$RECEIVER" --rpc-url "$RPC_URL")
cast send "$SWAP" 'requestBalanceOpening(address,bytes32,bytes32,uint64,uint64)' \
  "$TOKEN" "$RECEIVER_PRIVATE_ACCOUNT" "$RECEIVER_OPENING_KEY" 2 4102444800 \
  --value 0.001ether --private-key "$RECEIVER_KEY" --rpc-url "$RPC_URL" --quiet

# daemon fulfill 后：
cast to-dec "$(cast call "$SWAP" 'balanceOpeningResults(bytes32)(bytes)' \
  "$RECEIVER_OPENING_2" --rpc-url "$RPC_URL")"

export SENDER_PUBLIC=$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$SENDER" --rpc-url "$RPC_URL" | awk '{print $1}')
export RECEIVER_PUBLIC=$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$RECEIVER" --rpc-url "$RPC_URL" | awk '{print $1}')
export RESERVE=$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$SWAP" --rpc-url "$RPC_URL" | awk '{print $1}')
export LIABILITY=$(cast call "$SWAP" 'privateLiabilities(address)(uint256)' \
  "$TOKEN" --rpc-url "$RPC_URL" | awk '{print $1}')
export FEES=$(cast call "$SWAP" 'accruedFees(address)(uint256)' \
  "$TOKEN" --rpc-url "$RPC_URL" | awk '{print $1}')

printf 'sender明文=%s\n' "$(cast from-wei "$SENDER_PUBLIC" ether)"
printf 'receiver明文=%s\n' "$(cast from-wei "$RECEIVER_PUBLIC" ether)"
printf 'Swap托管=%s\n' "$(cast from-wei "$RESERVE" ether)"
printf '密态总负债=%s\n' "$(cast from-wei "$LIABILITY" ether)"
printf '手续费=%s\n' "$(cast from-wei "$FEES" ether)"
cast call "$SWAP" 'reserveIsSolvent(address)(bool)' "$TOKEN" --rpc-url "$RPC_URL"
```

预期：

```text
sender密态余额=70
receiver密态余额=10
sender明文=900
receiver明文=19.8
Swap托管=80.2
密态总负债=80
手续费=0.2
true
```

资产守恒：

```text
Swap托管 80.2 = 密态负债 80 + 累计手续费 0.2
```

## 16. 常见错误

环境变量检查：

```bash
printenv DATABASE_URL RPC_URL SWAP TOKEN NODE_TX_KEY
```

502：清除代理变量。`stale state root`：数据库和链上 Swap 不是同一次演示，应使用新的空数据库
和空 Anvil 链。`insufficient balance`：Runtime 不会生成 settlement，Swap 不会支付资产。

## 17. 当前安全边界

- Runtime 当前使用开发明文 backend，生产环境必须替换为真实 MPC/FHE；
- committee 私钥固定且公开，只能用于本地演示；
- worker 当前按 ID 显式处理，生产服务应监听三个 Requested 事件；
- 查询使用开发 authorization，生产 opening 必须验证用户授权并加密给用户公钥；
- 转账金额当前是公开的，若金额也需隐藏，需要把 amount 改为密态输入引用；
- 合约与密码协议未经过生产安全审计。

## 18. committee 轮换与 handoff

daemon 游标保存在 `ppsc_swap_listener_cursors`，进程重启后继续处理；operation ID/nullifier
提供第二层防重放。

### 定时轮换

先通过 ControlPlane 的 sortition 流程登记下一个 active committee，然后设置：

```bash
export COMMITTEE_ROTATION_SECONDS=3600
export NEXT_COMMITTEE_ID=0x...
export NEXT_COMMITTEE_NODES='0xNodeA,0xNodeB,0xNodeC'
export NEXT_MEMBER_KEY_1=0x...
export NEXT_MEMBER_KEY_2=0x...
export NEXT_NODE_DATABASE_URLS='postgres://...nodeA;postgres://...nodeB;postgres://...nodeC'

cargo run -p ppsc-runtime --bin confidential_swap_worker -- watch
```

到期后 daemon 会把当前所有 balance ciphertext 复制/重分享到新节点记录
`ppsc_balance_handoff_fragments`，并把完整余额快照和状态根分别安装到三个独立 PostgreSQL
数据库。只有所有目标数据库提交成功后才生成 handoff root，并调用：

```text
beginCommitteeHandoff
→ 旧 committee 对交出状态签名
→ 新 committee 对收到状态签名
→ finalizeCommitteeHandoff
→ activeCommitteeId 切换
```

只有旧、新 committee 的 threshold 签名都通过后才会切换。当前余额 backend 是开发 FHE
复制语义；真实 SS backend 必须把该步骤替换为 proactive resharing，真实 FHE backend 需要移交
密钥份额而不能复制秘密密钥。

### 用户预付 committee 提交 gas

三个 Requested 交易都通过 `--value 0.002ether` 给对应 task 的 `taskGasEscrow` 充值。committee
提交节点仍需先垫付 EVM gas；只有有效 threshold settlement 成功后，合约才把该 task 的预存
ETH 计入 `gasRefundCredits[msg.sender]`。提交节点领取：

```bash
cast send "$SWAP" 'claimGasRefund(address)' "$NODE_TX_ADDRESS" \
  --private-key "$NODE_TX_KEY" --rpc-url "$RPC_URL"
```

无有效 committee 签名无法获得补偿；取消 Pending 存款或提款时，未使用的 task gas credit
退回原用户。EVM 合约不能在交易发生前主动支付 gas；需要完全免垫付时应接入 ERC-4337 Paymaster。
