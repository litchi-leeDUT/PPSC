# PPSC Runtime 接口与明文开发后端

> 实现：[`ppsc-runtime`](../crates/runtime/src/lib.rs)  
> 当前用途：本地功能联调。`PlaintextBackend` 绝不能用于公开测试网或生产环境。

## 1. 模块边界

```text
BalanceRuntime
├── BalanceRuntimeApi              业务状态机
├── MpcBackend                     MPC 算术端口
├── FheBackend                     FHE 加密/owner 解密端口
├── HybridConversionBackend        C2S/S2C 端口
└── CommitmentBackend              状态/data/transcript 承诺端口
```

Runtime 不检查后端类型。将 `PlaintextBackend` 替换成真实实现时，存款、提款、版本、状态根和防重放状态机不需要改写。

## 2. MPC 接口

```rust
pub trait MpcBackend: Send + Sync {
    fn share_amount(&self, amount: u128) -> Result<MpcAmount, BackendError>;
    fn checked_add(
        &self,
        left: &MpcAmount,
        right: &MpcAmount,
    ) -> Result<MpcAmount, BackendError>;
    fn checked_sub(
        &self,
        left: &MpcAmount,
        right: &MpcAmount,
    ) -> Result<MpcAmount, BackendError>;
    fn greater_than_or_equal(
        &self,
        left: &MpcAmount,
        right: &MpcAmount,
    ) -> Result<bool, BackendError>;
}
```

生产实现应返回 authenticated sharing，并在比较、打开和状态转换时执行 MAC 检查。

## 3. FHE 接口

```rust
pub trait FheBackend: Send + Sync {
    fn encrypt_amount(
        &self,
        amount: u128,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<FheAmount, BackendError>;

    fn decrypt_for_owner(
        &self,
        ciphertext: &FheAmount,
        account: PrivateAccountId,
        authorization: &[u8],
    ) -> Result<u128, BackendError>;
}
```

生产实现的 `decrypt_for_owner` 应执行 threshold key switching 或门限解密授权，不能把系统完整 FHE 私钥交给调用者。

## 4. 混合转换接口

```rust
pub trait HybridConversionBackend: Send + Sync {
    fn fhe_to_mpc(&self, ciphertext: &FheAmount)
        -> Result<MpcAmount, BackendError>;

    fn mpc_to_fhe(
        &self,
        value: &MpcAmount,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<FheAmount, BackendError>;
}
```

真实 C2S 必须在 MPC 内完成 decode、round、range 和 wrap 检查。真实 S2C 必须使用一次性 correlated mask。

## 5. Runtime API

```rust
pub trait BalanceRuntimeApi {
    fn credit_deposit(&self, command: DepositCommand)
        -> Result<StateTransition, RuntimeError>;

    fn debit_withdrawal(&self, command: WithdrawalCommand)
        -> Result<StateTransition, RuntimeError>;

    fn encrypted_balance(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
    ) -> Result<EncryptedBalanceView, RuntimeError>;

    fn open_balance_for_owner(
        &self,
        account: PrivateAccountId,
        asset: AssetId,
        authorization: &[u8],
    ) -> Result<u128, RuntimeError>;
}
```

### 存款入账

```rust
let transition = runtime.credit_deposit(DepositCommand {
    deposit_id,
    account,
    asset,
    amount: 100,
    expected_old_state_root,
})?;
```

第一次入账调用 `encrypt_amount`。已有余额时执行：

```text
FHE balance
→ fhe_to_mpc
→ checked_add
→ mpc_to_fhe
→ new data ID/state root/transcript root
```

链适配器使用 `StateTransition` 构造 Swap 的 `DepositSettlement`，再收集委员会签名并调用 `finalizeDeposit`。

### 提款扣款

```rust
let transition = runtime.debit_withdrawal(WithdrawalCommand {
    nullifier,
    account,
    asset,
    gross_amount: 40,
    expected_old_state_root,
})?;
```

执行：

```text
FHE balance
→ fhe_to_mpc
→ greater_than_or_equal
→ checked_sub
→ mpc_to_fhe
→ mark nullifier
→ new state root/transcript root
```

### 查询密文余额

```rust
let view = runtime.encrypted_balance(account, asset)?;
```

返回：

- `data_id`；
- ciphertext bytes；
- 当前 state root；
- balance version。

开发环境解密：

```rust
let balance = runtime.open_balance_for_owner(
    account,
    asset,
    PlaintextBackend::authorization_for_tests(),
)?;
```

明文开发后端只接受固定的 `dev-authorized`。这是防误用标记，不是真实身份认证。

## 6. 状态一致性

Runtime 使用 Mutex 保证单进程原子更新，并检查：

- `expected_old_state_root`；
- deposit ID 未处理；
- nullifier 未消费；
- amount 非零；
- 余额充足；
- u128 加减法不溢出；
- version 单调递增。

当前状态在内存中，进程退出后消失。生产实现必须把 balance record、processed deposit、spent nullifier 和 root 原子写入 PostgreSQL/RocksDB。

## 7. 明文后端行为

`PlaintextBackend`：

- MPC share 实际为 16 字节大端 `u128`；
- FHE ciphertext 实际为开发前缀加 16 字节 `u128`；
- commitment 使用确定性、非密码学开发摘要；
- C2S/S2C 直接转换明文；
- 不输出秘密 Debug/Display。

这套编码仅用于验证接口和业务状态机。它没有任何密码学安全性。

## 8. 运行

```sh
./scripts/test-runtime.sh
```

或：

```sh
cargo test -p ppsc-runtime
cargo run -p ppsc-runtime
```

示例输出：

```text
development runtime completed version 2
development plaintext balance: 60
```

## 9. 下一步接链

仍需实现以下适配层：

1. `DepositRequested` Ethereum event listener；
2. private account commitment 到 Runtime account ID 的授权解析；
3. committee 消息广播和阈值签名收集；
4. `finalizeDeposit`/`withdraw` 交易提交；
5. PostgreSQL/RocksDB repository；
6. gRPC `QueryEncryptedBalance` 和 `OpenBalanceForOwner`；
7. 真实 MPC/FHE backend；
8. committee handoff 和 checkpoint 恢复。

SS/FHE 数据发布、存储节点网络、sortition、handoff 和位置更新的开发版工作流见
[存储与 Handoff 流程](storage-handoff-workflow.md)。
