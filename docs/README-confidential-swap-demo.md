# 明文 ERC-20 与密态余额：存款、查询、取款演示

本演示不使用测试函数，也不伪造 Runtime 输出。用户把 100 mUSD 存入 Swap，Runtime 将其
记入 PostgreSQL 中的密文账户；用户授权查询后看到密态余额 100；随后请求取出 40 mUSD，
Runtime 验证并扣除密态余额，committee 签名后 Swap 向用户支付 39.6 mUSD（1% 手续费）。

最终状态：

| 阶段 | 用户明文余额 | Swap 托管 | 用户密态余额 | 手续费 |
|---|---:|---:|---:|---:|
| 初始 | 1000 | 0 | 不存在 | 0 |
| 存入并完成密态入账 | 900 | 100 | 100 | 0 |
| 取出 40 | 939.6 | 60.4 | 60 | 0.4 |

> 当前 `PlaintextBackend` 只用于开发，但余额通过 Runtime 接口作为 ciphertext 写入
> PostgreSQL。链上只记录总负债、密态状态根、data ID 和 committee 证明，不保存用户密态余额。

## 0. 先理解完整业务流程

本节先说明每一步由谁执行、输入是什么、输出是什么。后面的命令只是这些步骤在本地环境中的具体操作。

### 0.1 参与者和状态

演示中有四类参与者：

| 参与者 | 作用 |
|---|---|
| 用户 | 持有明文 ERC-20，并控制一个链下密态账户 |
| Swap 合约 | 托管明文 ERC-20，记录存取款请求、状态根和总负债 |
| Runtime | 监听合约事件，读取并更新 PostgreSQL 中的密文余额 |
| Committee | 对 Runtime 计算结果进行阈值签名，授权合约更新状态或付款 |

用户密态账户由 `privateAccountCommitment` 标识。这个 commitment 不是余额，也不是链上
`address`，而是对链下账户标识、资产、随机数和版本等信息的承诺。

演示开始时：

```text
用户明文余额               = 1000 mUSD
Swap 托管余额              = 0 mUSD
用户密态余额               = 不存在
Swap 记录的密态总负债      = 0 mUSD
privateStateRoot            = 0x00...00
```

### 0.2 存款：明文 100 mUSD 转为密态 100 mUSD

#### 步骤 A：用户授权明文代币

用户调用 ERC-20 的：

```solidity
token.approve(swap, 100 ether);
```

这一步只授予 Swap 转账额度，不会立即移动资金，也不会改变密态余额。

#### 步骤 B：用户创建存款请求

用户调用：

```solidity
deposit(token, 100 ether, privateAccountCommitment, nonce)
```

Swap 执行以下检查和状态变化：

1. token 已启用，金额达到最小存款要求；
2. nonce 没有被该用户使用过；
3. 从用户地址转入 100 mUSD；
4. 创建状态为 `Pending` 的 `Deposit`；
5. 发出 `DepositRequested` 事件。

此时状态为：

```text
用户明文余额               = 900
Swap 托管余额              = 100
用户密态余额               = 仍不存在
Swap 记录的密态总负债      = 0
Deposit.status              = Pending
```

也就是说，明文资产已经安全锁定，但在 Runtime 完成计算前不能认为用户已经得到密态资产。

#### 步骤 C：Runtime 监听 DepositRequested

Runtime 从事件中取得：

```text
depositId
token
depositor
amount = 100
privateAccountCommitment
```

然后使用 `privateAccountCommitment + token` 定位 PostgreSQL 中的密态余额。如果账户第一次
存款，Runtime 创建零余额；否则读取当前 ciphertext。

Runtime 执行的密态逻辑为：

```text
oldCiphertext
  → C2S/FHE-to-MPC
  → secretAdd(oldBalance, 100)
  → S2C/MPC-to-FHE
  → newCiphertext
```

Runtime 将以下内容原子写入 PostgreSQL：

```text
newCiphertext
encryptedBalanceDataId
newStateRoot
transcriptRoot
version = oldVersion + 1
processed depositId
```

`processed depositId` 用来阻止同一笔链上存款被重复记入密态余额。

#### 步骤 D：Committee 确认密态入账

Committee 对下面的 settlement 进行阈值签名：

```solidity
DepositSettlement {
    expectedOldStateRoot,
    newStateRoot,
    encryptedBalanceDataId,
    transcriptRoot
}
```

Runtime 或 relayer 调用：

```solidity
finalizeDeposit(depositId, settlement, committeeSignatures)
```

Swap 验证旧状态根和 committee 签名后：

```text
Deposit.status              = Finalized
privateStateRoot            = newStateRoot
privateLiabilities          = 100
用户密态余额               = 100（仅 Runtime 可读取密文）
```

如果 Runtime 长时间没有完成，用户只能在退款等待期结束后调用 `cancelDeposit` 取回处于
Pending 状态的 100 mUSD；已 Finalized 的存款不能再次退款。

### 0.3 查询：用户查看自己的密态余额

链上没有 `privateBalanceOf(address)`，因为这种接口会破坏余额隐私。查询过程应为：

1. 用户证明自己有权打开 `privateAccountCommitment` 对应的账户；
2. Runtime 根据账户 commitment 和 token 查询当前 `encryptedBalanceDataId`；
3. 存储节点读取对应 ciphertext；
4. committee 执行门限 opening，或者把结果加密给用户查询公钥；
5. 用户解密得到余额，链上和其他用户看不到结果。

本地开发 worker 使用测试 opening authorization，所以终端会显示：

```text
authorized confidential balance: amount=100000000000000000000 ... version=1
```

这里的金额使用 mUSD 的 18 位最小单位，即密态余额为 100 mUSD。

### 0.4 提款：密态 40 mUSD 转为明文 39.6 mUSD

#### 步骤 A：用户创建提款请求

用户调用：

```solidity
requestWithdrawal(
    token,
    40 ether,
    privateAccountCommitment,
    recipient,
    nonce,
    expiry
)
```

Swap 创建状态为 `Pending` 的 `WithdrawalRequest` 并发出 `WithdrawalRequested`。此时：

```text
用户密态余额               = 100
用户明文余额               = 900
Swap 托管余额              = 100
Withdrawal.status           = Pending
```

创建请求不会立即扣除密态余额，也不会立即发送明文代币。

#### 步骤 B：Runtime 验证提款授权和密态余额

Runtime 从 `WithdrawalRequested` 中取得 withdrawal ID、请求人、密态账户 commitment、
公开金额、recipient 和 expiry，然后检查：

1. 请求尚未过期；
2. 用户提供了密态账户 owner authorization；
3. 账户资产类型与 token 匹配；
4. 当前密态余额 `>= 40`；
5. withdrawal/nullifier 没有处理过。

Runtime 执行：

```text
encryptedBalance(100)
  → C2S/FHE-to-MPC
  → secretGreaterOrEqual(100, 40)
  → secretSub(100, 40)
  → S2C/MPC-to-FHE
  → encryptedBalance(60)
```

余额不足时流程在这里终止：不会产生有效 committee settlement，Swap 也不会发送明文代币。

#### 步骤 C：Runtime 持久化扣款并生成证明

Runtime 把新 ciphertext、data ID、状态根、transcript 和 nullifier 原子写入 PostgreSQL，
然后构造：

```solidity
WithdrawalSettlement {
    nullifier,
    expectedOldStateRoot,
    newStateRoot,
    encryptedBalanceDataId,
    transcriptRoot
}
```

Committee 的签名摘要还会绑定 withdrawal ID、请求人、recipient、金额、账户 commitment、
chain ID、Swap 地址和当前 committee，因此不能篡改收款人或复用到另一条链。

#### 步骤 D：Swap 验签后支付明文代币

Runtime 或 relayer 调用：

```solidity
finalizeWithdrawal(withdrawalId, settlement, committeeSignatures)
```

Swap 按以下顺序处理：

1. 检查请求为 Pending 且未过期；
2. 检查旧状态根、nullifier 和密态总负债；
3. 验证 committee threshold 签名；
4. 将请求标记为 Finalized，并消费 nullifier；
5. 更新密态状态根和总负债；
6. 计算 1% 手续费；
7. 向请求中绑定的 recipient 转账 39.6 mUSD。

最终状态：

```text
用户明文余额               = 939.6
Swap 托管余额              = 60.4
用户密态余额               = 60
Swap 记录的密态总负债      = 60
累计手续费                 = 0.4
Withdrawal.status           = Finalized
nullifier                   = spent
```

### 0.5 为什么合约不能直接调用 Runtime

Runtime 是链下服务，EVM 无法像调用另一个 Solidity 合约那样同步调用它。因此这里的“唤起”
是可验证的异步流程：

```text
用户交易
  → Swap 记录 Pending 状态
  → Swap 发出事件
  → Runtime 监听事件并计算
  → Committee 签名计算结果
  → Runtime/relayer 提交 finalize 交易
  → Swap 验证后完成状态转换
```

链上 Pending 记录防止任务丢失，事件用于通知，committee 签名用于让合约验证链下计算结果。

## 1. 初始化独立的演示数据库

```bash
cd /Users/esion/Desktop/ppsc
export PATH="$(brew --prefix postgresql@16)/bin:$PATH"
brew services start postgresql@16

psql postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='ppsc'" \
  | grep -q 1 \
  || psql postgres -c "CREATE ROLE ppsc LOGIN PASSWORD 'ppsc_dev_only';"

psql postgres -tAc "SELECT 1 FROM pg_database WHERE datname='ppsc_swap_demo'" \
  | grep -q 1 \
  || psql postgres -c "CREATE DATABASE ppsc_swap_demo OWNER ppsc;"

export DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc_swap_demo'
psql "$DATABASE_URL" -Atc 'SELECT current_database(), current_user'
```

第一次完整演示应使用空数据库。如果这个数据库以前运行过本演示，请创建一个新数据库，例如
`ppsc_swap_demo_2`，并同步修改 `DATABASE_URL`。不要把其他演示正在使用的数据库清空。

## 2. 启动一条空的 Anvil 链

终端 A：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"
anvil --host 127.0.0.1 --port 8545
```

后续命令在终端 B 执行：

```bash
cd /Users/esion/Desktop/ppsc
source "$HOME/.zshenv"

unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost

export RPC_URL='http://127.0.0.1:8545'
export DATABASE_URL='postgres://ppsc:ppsc_dev_only@127.0.0.1:5432/ppsc_swap_demo'
export USER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export RELAYER_KEY="$USER_KEY"
export DEMO_USER=$(cast wallet address --private-key "$USER_KEY")

cast block-number --rpc-url "$RPC_URL" --no-proxy
psql "$DATABASE_URL" -Atc 'SELECT 1'
```

预期都返回 `0` 或 `1`，不能出现 502 或 connection refused。

## 3. 直接部署原来的 ConfidentialTokenSwap

这里不再使用 `DeployInteractiveSwap`。`InteractiveSwap` 之前只是把本地基础设施部署打包在一起的
辅助脚本，并不是另一份业务合约；但这个名字容易造成混淆。本节直接部署项目原有的
`PpscControlPlane`、`MockERC20` 和 `ConfidentialTokenSwap`。

### 3.1 检查部署账户

```bash
# 清除可能来自旧终端或 .env 的字面量占位符。
unset DEPLOYER_PRIVATE_KEY
export USER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# 必须输出 0x 开头的 64 位十六进制私钥，而不是 $USER_KEY 或 $DEPLOYER_PRIVATE_KEY。
printf 'USER_KEY=%s\n' "$USER_KEY"
cast wallet address --private-key "$USER_KEY"
```

正确的检查输出类似：

```text
USER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

如果第一行显示 `USER_KEY=$DEPLOYER_PRIVATE_KEY`，说明之前用了单引号，例如
`export USER_KEY='$DEPLOYER_PRIVATE_KEY'`。单引号不会展开变量，重新执行上面的固定测试私钥命令。

### 3.2 部署本地 sortition verifier 和 ControlPlane

本地演示 verifier 接受开发 selection evidence。生产环境必须换成真实可验证 sortition。

```bash
export VERIFIER=$(forge create \
  contracts/test/ConfidentialTokenSwap.t.sol:AcceptAllSortitionVerifier \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  | jq -r .deployedTo)

export CONTROL=$(forge create contracts/src/PpscControlPlane.sol:PpscControlPlane \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  --constructor-args "$DEMO_USER" "$DEMO_USER" "$VERIFIER" \
  | jq -r .deployedTo)

printf 'verifier=%s\ncontrol=%s\n' "$VERIFIER" "$CONTROL"
```

### 3.3 登记开发 committee

```bash
export MEMBER_KEY_1=0x0000000000000000000000000000000000000000000000000000000000000b0b
export MEMBER_KEY_2=0x000000000000000000000000000000000000000000000000000000000000d00d
export MEMBER_KEY_3=0x000000000000000000000000000000000000000000000000000000000000cafe
export NODE_1=$(cast wallet address --private-key "$MEMBER_KEY_1")
export NODE_2=$(cast wallet address --private-key "$MEMBER_KEY_2")
export NODE_3=$(cast wallet address --private-key "$MEMBER_KEY_3")
export COMMITTEE_ID=$(cast keccak 'confidential-swap-committee-epoch-1')

cast send "$CONTROL" \
  'finalizeCommittee(bytes32,bytes32,uint64,address[],uint16,bytes)' \
  "$COMMITTEE_ID" "$(cast keccak 'swap-sortition-seed-1')" 1 \
  "[$NODE_1,$NODE_2,$NODE_3]" 2 0x01 \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet
```

这三个地址已按数值升序排列，阈值为 2。开发 worker 使用前两个成员签名。

### 3.4 部署原来的 Mock mUSD 和 ConfidentialTokenSwap

```bash
export TOKEN=$(forge create contracts/test/mocks/MockERC20.sol:MockERC20 \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  | jq -r .deployedTo)

export SWAP=$(forge create \
  contracts/src/ConfidentialTokenSwap.sol:ConfidentialTokenSwap \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --broadcast --json \
  --constructor-args "$DEMO_USER" "$CONTROL" "$COMMITTEE_ID" 86400 \
  | jq -r .deployedTo)

# 启用 mUSD：最小存款 1 token，提款手续费 100 bps = 1%。
cast send "$SWAP" 'configureToken(address,bool,uint128,uint16)' \
  "$TOKEN" true 1000000000000000000 100 \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

# 给演示用户铸造 1000 个明文 mUSD。
cast send "$TOKEN" 'mint(address,uint256)' \
  "$DEMO_USER" 1000000000000000000000 \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

printf 'token=%s\nswap=%s\n' "$TOKEN" "$SWAP"
```

这里部署的就是原合约：

```text
contracts/src/ConfidentialTokenSwap.sol:ConfidentialTokenSwap
```

确认地址确实有代码：

```bash
cast code "$CONTROL" --rpc-url "$RPC_URL" | cut -c1-20
cast code "$TOKEN" --rpc-url "$RPC_URL" | cut -c1-20
cast code "$SWAP" --rpc-url "$RPC_URL" | cut -c1-20
```

三条都必须返回非空的 `0x...` 字节码。

## 4. 查询初始明文与密态状态

```bash
export USER_PUBLIC_BEFORE=$(cast call "$TOKEN" \
  'balanceOf(address)(uint256)' "$DEMO_USER" --rpc-url "$RPC_URL" | awk '{print $1}')

cast from-wei "$USER_PUBLIC_BEFORE" ether
cast call "$TOKEN" 'balanceOf(address)(uint256)' "$SWAP" --rpc-url "$RPC_URL"
cast call "$SWAP" 'privateLiabilities(address)(uint256)' "$TOKEN" --rpc-url "$RPC_URL"
cast call "$SWAP" 'privateStateRoots(address)(bytes32)' "$TOKEN" --rpc-url "$RPC_URL"
```

预期用户明文余额是 `1000`，Swap 托管和密态总负债都是 `0`，状态根是全零。

此时查询用户密态余额会失败，因为账户尚不存在。这是正确行为：

```bash
export PRIVATE_ACCOUNT=$(cast keccak "swap-demo-private-account:$DEMO_USER")
cargo run -p ppsc-runtime --bin confidential_swap_worker -- \
  query "$PRIVATE_ACCOUNT"
```

预期错误包含 `balance not found`。

## 5. 用户把 100 个明文 mUSD 存入 Swap

```bash
export DEPOSIT_AMOUNT=$(cast to-wei 100 ether)
export DEPOSIT_NONCE=1

cast send "$TOKEN" 'approve(address,uint256)' "$SWAP" "$DEPOSIT_AMOUNT" \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

export DEPOSIT_ID=$(cast call "$SWAP" \
  'deposit(address,uint256,bytes32,uint64)(bytes32)' \
  "$TOKEN" "$DEPOSIT_AMOUNT" "$PRIVATE_ACCOUNT" "$DEPOSIT_NONCE" \
  --from "$DEMO_USER" --rpc-url "$RPC_URL")

cast send "$SWAP" 'deposit(address,uint256,bytes32,uint64)' \
  "$TOKEN" "$DEPOSIT_AMOUNT" "$PRIVATE_ACCOUNT" "$DEPOSIT_NONCE" \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

printf 'depositId=%s\n' "$DEPOSIT_ID"
```

这笔交易完成后，明文代币已经托管，但密态余额还没有增加：

```bash
cast from-wei "$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$DEMO_USER" --rpc-url "$RPC_URL" | awk '{print $1}')" ether
cast from-wei "$(cast call "$TOKEN" 'balanceOf(address)(uint256)' \
  "$SWAP" --rpc-url "$RPC_URL" | awk '{print $1}')" ether
cast call "$SWAP" 'privateLiabilities(address)(uint256)' "$TOKEN" --rpc-url "$RPC_URL"
```

预期依次为 `900`、`100`、`0`。`DepositRequested` 事件就是 Runtime 的任务入口。

## 6. Runtime 增加用户密文余额并完成存款

```bash
cargo run -p ppsc-runtime --bin confidential_swap_worker -- \
  deposit "$DEPOSIT_ID" "$DEPOSIT_AMOUNT" "$PRIVATE_ACCOUNT"
```

预期：

```text
deposit finalized: amount=100000000000000000000 encryptedBalanceDataId=0x... version=1
```

worker 实际执行：

1. 从链上读取当前 `privateStateRoot`；
2. 在 PostgreSQL 中创建/读取用户 ciphertext；
3. 执行密态加法 `oldBalance + 100`；
4. 原子写入 ciphertext、data ID、状态转换和 deposit 防重放记录；
5. 生成 `DepositSettlement` 和 2-of-3 committee 签名；
6. 调用 `finalizeDeposit`，使链上 `privateLiabilities` 增加 100。

## 7. 用户授权查询密态余额

```bash
cargo run -p ppsc-runtime --bin confidential_swap_worker -- \
  query "$PRIVATE_ACCOUNT"
```

预期：

```text
authorized confidential balance: amount=100000000000000000000 dataId=0x... version=1
```

金额以 ERC-20 最小单位显示，即 `100 × 10^18`。开发 backend 使用测试授权 opening；生产版
必须验证用户签名或链上 opening request，并将结果加密给用户公钥。

链上只能看到总负债，不能查询这个用户的余额：

```bash
cast from-wei "$(cast call "$SWAP" 'privateLiabilities(address)(uint256)' \
  "$TOKEN" --rpc-url "$RPC_URL" | awk '{print $1}')" ether
```

预期为 `100`。

## 8. 用户请求从密态余额取出 40 mUSD

```bash
export WITHDRAW_AMOUNT=$(cast to-wei 40 ether)
export WITHDRAW_NONCE=1
export WITHDRAW_EXPIRY=4102444800

export WITHDRAWAL_ID=$(cast call "$SWAP" \
  'requestWithdrawal(address,uint256,bytes32,address,uint64,uint64)(bytes32)' \
  "$TOKEN" "$WITHDRAW_AMOUNT" "$PRIVATE_ACCOUNT" "$DEMO_USER" \
  "$WITHDRAW_NONCE" "$WITHDRAW_EXPIRY" \
  --from "$DEMO_USER" --rpc-url "$RPC_URL")

cast send "$SWAP" \
  'requestWithdrawal(address,uint256,bytes32,address,uint64,uint64)' \
  "$TOKEN" "$WITHDRAW_AMOUNT" "$PRIVATE_ACCOUNT" "$DEMO_USER" \
  "$WITHDRAW_NONCE" "$WITHDRAW_EXPIRY" \
  --private-key "$USER_KEY" --rpc-url "$RPC_URL" --quiet

printf 'withdrawalId=%s\n' "$WITHDRAWAL_ID"
```

此时只创建了 Pending 任务，用户尚未收到明文代币，密态余额也尚未提交变化。
`WithdrawalRequested` 事件唤起 Runtime。

## 9. Runtime 验证并扣除密态余额，Swap 支付明文代币

```bash
cargo run -p ppsc-runtime --bin confidential_swap_worker -- \
  withdraw "$WITHDRAWAL_ID" "$WITHDRAW_AMOUNT" "$PRIVATE_ACCOUNT"
```

预期：

```text
withdrawal finalized: grossAmount=40000000000000000000 encryptedBalanceDataId=0x... version=2
```

worker 从 PostgreSQL 加载密文余额，执行 `balance >= 40` 和 `balance - 40`。余额不足时不会
生成 settlement，Swap 也不会付款。成功时 committee 签名绑定原请求和新密文 data ID，
`finalizeWithdrawal` 验签、消费 nullifier、更新状态根后才转出 ERC-20。

## 10. 查询取款后的密态余额和明文余额

查询密态余额：

```bash
cargo run -p ppsc-runtime --bin confidential_swap_worker -- \
  query "$PRIVATE_ACCOUNT"
```

预期：

```text
authorized confidential balance: amount=60000000000000000000 dataId=0x... version=2
```

查询链上明文状态：

```bash
export USER_PUBLIC_AFTER=$(cast call "$TOKEN" \
  'balanceOf(address)(uint256)' "$DEMO_USER" --rpc-url "$RPC_URL" | awk '{print $1}')
export SWAP_RESERVE=$(cast call "$TOKEN" \
  'balanceOf(address)(uint256)' "$SWAP" --rpc-url "$RPC_URL" | awk '{print $1}')
export PRIVATE_LIABILITY=$(cast call "$SWAP" \
  'privateLiabilities(address)(uint256)' "$TOKEN" --rpc-url "$RPC_URL" | awk '{print $1}')
export FEES=$(cast call "$SWAP" \
  'accruedFees(address)(uint256)' "$TOKEN" --rpc-url "$RPC_URL" | awk '{print $1}')

printf '用户明文余额=%s\n' "$(cast from-wei "$USER_PUBLIC_AFTER" ether)"
printf 'Swap 托管=%s\n' "$(cast from-wei "$SWAP_RESERVE" ether)"
printf '密态总负债=%s\n' "$(cast from-wei "$PRIVATE_LIABILITY" ether)"
printf '累计手续费=%s\n' "$(cast from-wei "$FEES" ether)"
cast call "$SWAP" 'reserveIsSolvent(address)(bool)' "$TOKEN" --rpc-url "$RPC_URL"
```

预期：

```text
用户明文余额=939.600000000000000000
Swap 托管=60.400000000000000000
密态总负债=60.000000000000000000
累计手续费=0.400000000000000000
true
```

## 11. 常见错误

`missing environment variable ...`：所有 `export` 必须和 `cargo run` 在同一个终端执行：

```bash
printenv DATABASE_URL RPC_URL SWAP TOKEN RELAYER_KEY
```

`HTTP error 502 with empty body`：清除代理变量，然后重试：

```bash
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
export no_proxy=127.0.0.1,localhost
```

`stale state root`：链上 Swap 与当前 PostgreSQL 数据库不是同一次演示。应同时使用新的空 Anvil
链和新的空演示数据库。

`insufficient balance`：用户密态余额不足，Runtime 不会签署结算，合约不会支付明文资产。

## 12. 安全边界

- 本地演示的 committee 私钥固定且公开，不能用于生产；
- 当前 backend 内部以明文算法模拟 MPC/FHE，但持久化和接口按 ciphertext 处理；
- worker 由命令显式处理 ID，生产服务应常驻监听 `DepositRequested` 和
  `WithdrawalRequested`；
- 生产余额 opening 必须具备用户授权、接收公钥、过期时间和防重放 nonce；
- 金额、token、存款人、明文收款人和时间在本方案中是公开的。
