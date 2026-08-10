# 明文代币与密态代币兑换合约

> 实现：[`ConfidentialTokenSwap.sol`](../contracts/src/ConfidentialTokenSwap.sol)  
> 状态：MVP，已通过本地 Foundry 测试；生产部署前需要安全审计。

## 1. 定义

这里的“明文代币”是标准 ERC-20。它的持有人、转账金额和余额在链上公开。

“密态代币”不是另一个链上 ERC-20 合约，也不能通过 `balanceOf(address)` 查询。它是 PPSC 链下隐私账本中的 FHE/SS 余额，链上只保存：

```text
privateStateRoot
privateLiability
deposit/withdraw public record
nullifier
committee attestation
```

兑换比例为 `1:1`，提款时可以收取公开手续费。

## 2. 资产流

### 明文 → 密态

```text
用户 approve ERC-20
  → deposit(token, amount, privateAccountCommitment, nonce)
  → Swap 锁定公开 ERC-20
  → DepositRequested
  → 委员会给隐私账户增加密态余额
  → 委员会签署新 privateStateRoot
  → finalizeDeposit
  → privateLiability 增加
```

若委员会没有在退款等待期内完成铸造，用户可调用 `cancelDeposit` 取回公开代币。已经 finalized 的存款不能退款，因为密态余额已经产生。

### 密态 → 明文

```text
用户调用 requestWithdrawal
  → 合约记录 Pending 请求并发出 WithdrawalRequested
  → Runtime/committee 监听链上事件
  → 委员会验证密态余额和 owner authorization
  → Runtime 从用户密文余额扣除 grossAmount
  → 产生唯一 nullifier 和新 privateStateRoot
  → 委员会对 WithdrawalSettlement 签名
  → Runtime/relayer 调用 finalizeWithdrawal
  → Swap 验签、标记 nullifier、更新状态根
  → 向公开 recipient 支付 grossAmount - fee
```

链上 calldata 不包含私密账户 ID，但 token、提款金额、公开 recipient、时间和 nullifier 是公开的。

## 3. 核心安全不变量

对每种公开 token：

```text
actual ERC20 balance >= accountedBalances
actual ERC20 balance >= privateLiabilities
```

- `accountedBalances`：合约接收且尚未退款、提款或提取手续费的实际代币；
- `privateLiabilities`：已经成功铸造到密态账本、尚未销毁的总额；
- `accruedFees`：密态提款已销毁但仍留在合约的手续费。

每次密态状态转换必须满足：

```text
expectedOldStateRoot == currentPrivateStateRoot
committee threshold signatures valid
newStateRoot != 0
nullifier has not been spent
```

## 4. 部署

部署前要求：

1. `PpscControlPlane` 已部署；
2. active committee 已通过 `finalizeCommittee` 登记；
3. 准备要托管的标准 ERC-20 地址。

环境变量：

```sh
export DEPLOYER_PRIVATE_KEY=0xTEST_KEY
export CONTROL_PLANE_ADDRESS=0xControlPlane
export PUBLIC_TOKEN_ADDRESS=0xToken
export ACTIVE_COMMITTEE_ID=0xCommitteeId

# 按 token 最小单位填写，例如 18 decimals 的 1 token。
export MINIMUM_DEPOSIT=1000000000000000000

# 100 = 1%，最大 1000 = 10%。
export WITHDRAWAL_FEE_BPS=100

export REFUND_DELAY_SECONDS=86400
```

部署：

```sh
forge script \
  contracts/script/DeployConfidentialTokenSwap.s.sol:DeployConfidentialTokenSwap \
  --rpc-url "$RPC_URL" \
  --broadcast -vvv
```

## 5. 管理接口

### configureToken

```solidity
function configureToken(
    address token,
    bool enabled,
    uint128 minimumDeposit,
    uint16 withdrawalFeeBps
) external onlyAdmin;
```

- 禁用 token 只阻止新存款和提款，不移动已有准备金；
- 最大手续费为 1,000 bps，即 10%；
- MVP 拒绝 fee-on-transfer/rebasing 等到账金额不等于参数的 token。

### setActiveCommittee

```solidity
function setActiveCommittee(bytes32 nextCommitteeId) external onlyAdmin;
```

目标委员会必须在 `PpscControlPlane` 中处于 active。切换前必须完成链下密态状态、key、MAC 和 preprocessing handoff。

### pause

```solidity
function setPaused(bool nextPaused) external onlyAdmin;
```

暂停会阻止存款 finalize 和提款，但不会阻止用户在退款期结束后取消尚未 finalize 的存款。

## 6. 用户存款

### approve

```solidity
IERC20(token).approve(address(swap), amount);
```

### deposit

```solidity
bytes32 depositId = swap.deposit(
    token,
    amount,
    privateAccountCommitment,
    nonce
);
```

`privateAccountCommitment` 应绑定：

```text
private account public key
asset/token address
chainId
swap address
randomness
account schema/version
```

不要直接使用 `keccak256(userAddress)`，否则会暴露公开地址和隐私账户的关联。

委员会监听：

```solidity
event DepositRequested(
    bytes32 indexed depositId,
    address indexed token,
    address indexed depositor,
    uint256 amount,
    bytes32 privateAccountCommitment
);
```

## 7. 委员会完成密态铸造

```solidity
struct DepositSettlement {
    bytes32 expectedOldStateRoot;
    bytes32 newStateRoot;
    bytes32 encryptedBalanceDataId;
    bytes32 transcriptRoot;
}
```

委员会完成密态状态更新后，获取签名摘要：

```solidity
bytes32 digest = swap.depositDigest(depositId, settlement);
```

委员会成员对该 digest 签名。签名数组必须按 signer 地址升序、不能重复，并达到委员会阈值：

```solidity
swap.finalizeDeposit(depositId, settlement, sortedSignatures);
```

`transcriptRoot` 必须覆盖 operator sequence、输入承诺、旧/新状态根、committee epoch 和输出 data ID。

## 8. 超时退款

```solidity
swap.cancelDeposit(depositId);
```

条件：

- 调用者是原 depositor；
- deposit 仍为 `Pending`；
- 已经过 `refundDelay`。

## 9. 用户请求密态提款

用户在链上创建提款任务：

```solidity
bytes32 withdrawalId = swap.requestWithdrawal(
    token,
    grossAmount,
    privateAccountCommitment,
    recipient,
    nonce,
    expiry
);
```

`token`、`grossAmount`、`recipient` 和 `expiry` 是公开信息。`privateAccountCommitment`
用于让 Runtime 定位并验证链下密态账户，但不应泄露账户原像或余额。

合约发出以下事件来唤起 Runtime：

```solidity
event WithdrawalRequested(
    bytes32 indexed withdrawalId,
    address indexed token,
    address indexed requester,
    address recipient,
    uint256 grossAmount,
    bytes32 privateAccountCommitment,
    uint64 expiry
);
```

相同用户的 `nonce` 只能使用一次。过期且尚未处理的请求可以由原请求人调用
`cancelWithdrawal(withdrawalId)` 标记为 Cancelled；创建请求本身不会从合约释放任何资产。

## 10. Runtime 验证、扣款并完成明文提款

```solidity
struct WithdrawalSettlement {
    bytes32 nullifier;
    bytes32 expectedOldStateRoot;
    bytes32 newStateRoot;
    bytes32 encryptedBalanceDataId;
    bytes32 transcriptRoot;
}
```

Runtime/committee 监听 `WithdrawalRequested` 后必须在链下验证：

- requester 提供了对 `privateAccountCommitment` 对应账户的有效 owner authorization；
- 密态余额至少为 `grossAmount`；
- 资产类型匹配；
- 使用 MPC/FHE 完成密态比较和扣款，且不足时不产生 settlement；
- nullifier 从授权 secret、账户/Note 和 nonce 安全派生；
- `encryptedBalanceDataId` 指向扣款后的新密文余额；
- 新状态根与扣款结果一致。

签名并提交：

```solidity
bytes32 digest = swap.withdrawalSettlementDigest(withdrawalId, settlement);
swap.finalizeWithdrawal(withdrawalId, settlement, sortedCommitteeSignatures);
```

签名摘要同时绑定链 ID、Swap 地址、active committee、withdrawal ID、请求人、收款人、
公开金额、密态账户 commitment、过期时间和完整 settlement，不能把一个请求的证明挪给另一个请求。

`finalizeWithdrawal` 按 Checks-Effects-Interactions 顺序执行：检查 Pending/expiry/旧状态根/
nullifier/负债，验证 threshold 签名，先标记请求和 nullifier 并更新状态，再转 ERC-20。

计算：

```text
fee    = grossAmount × feeBps / 10_000
payout = grossAmount - fee
```

任意 relayer 都可提交已签名 settlement；资产只会发送到原始请求绑定的 `recipient`。

旧的单阶段 `withdraw(Withdrawal, signatures)` 暂时保留用于兼容已有调用方；新集成应使用
`requestWithdrawal/finalizeWithdrawal` 两阶段接口。

## 11. 查询

```solidity
swap.privateStateRoots(token);
swap.privateLiabilities(token);
swap.accountedBalances(token);
swap.accruedFees(token);
swap.spentNullifiers(nullifier);
swap.reserveIsSolvent(token);
swap.deposits(depositId);
swap.withdrawalRequests(withdrawalId);
```

## 12. 测试

仅运行 Swap 测试：

```sh
forge test --match-contract ConfidentialTokenSwapTest -vvv
```

运行所有合约测试：

```sh
./scripts/test-local.sh
```

测试覆盖：

- 明文代币存入和托管；
- 委员会确认密态铸造；
- 密态销毁并提款明文代币；
- 手续费和准备金核算；
- nullifier 重放拒绝；
- 存款超时退款；
- 委员会签名不足拒绝。

项目提供以下可执行脚本：

```sh
# 所有 Swap 测试
./scripts/swap/test-all.sh

# 正向：公开存款 → 密态铸造 → 密态销毁 → 公开提款
./scripts/swap/test-deposit-withdraw.sh

# Pending 存款超时退款
./scripts/swap/test-refund.sh

# 委员会签名不足等安全负向测试
./scripts/swap/test-security.sh

# 启动临时 Anvil 并真实广播完整兑换流程
./scripts/swap/demo-local.sh
```

## 13. 当前限制

- 没有实现实际 FHE/MPC 铸造与销毁；合约验证的是委员会阈值签名；
- `EcdsaSortitionVerifier` 仍是测试网 authority verifier；
- 明文侧金额、token、depositor/recipient 和时间公开；
- 不支持 fee-on-transfer、rebasing、ERC-777 hook 等非标准 token 行为；
- 没有处理 token 黑名单、暂停或升级导致的托管冻结；
- committee 切换由 admin 发起，生产版应与验证完成的 handoff 原子绑定；
- 合约没有经过第三方安全审计。

生产上线前应增加完整密码证明、withdraw authorization policy、紧急治理、多签 admin、资产上限、速率限制和独立审计。

Rust 侧的存款入账、提款扣款、余额查询和明文开发后端已经实现在
[`ppsc-runtime`](../crates/runtime/src/lib.rs)，具体接口见
[Runtime 文档](runtime.md)。
