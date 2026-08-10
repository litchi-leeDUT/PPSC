# SS/FHE 发布、Sortition、Handoff 与计算流程

> 当前实现是可运行的内存开发版。真实链 RPC、Shamir/FHE、VRF、数据库和委员会网络仍通过接口替换。

## 1. 端到端流程

```text
Client
  ├─ SS：为每个 storage node 生成并上传一个 share
  └─ FHE：加密后复制到 storage nodes
       ↓
PpscControlPlane.registerData
PpscControlPlane.registerDataLocations
       ↓
Runtime 监听 DataPublished / ExecutionRequested
       ↓
SortitionBackend.select(seed, eligible nodes, committee size)
       ↓
StorageNetwork.handoff(dataId, selected committee)
       ↓
新委员会读取输入并执行 operator
       ↓
委员会签署 DataHandoff
       ↓
PpscControlPlane.updateDataLocationsAfterHandoff
       ↓
链上更新 storage nodes/root、PK-set root、epoch、version
       ↓
保存输出并提交计算结果
```

## 2. 链上位置接口

数据 owner 先调用 `registerData`，其中 `storageSetRoot` 必须为排序节点地址数组的：

```solidity
keccak256(abi.encode(storageNodes))
```

再公开节点列表：

```solidity
control.registerDataLocations(dataId, storageNodes);
```

要求：

- 节点非零、严格升序且不重复；
- 调用者是 data owner；
- 节点列表的 hash 等于已登记 `storageSetRoot`。

查询：

```solidity
address[] memory nodes = control.dataStorageNodes(dataId);
```

## 3. Handoff 后更新

Runtime 完成实际数据传输后收集当前计算委员会的阈值签名，再调用：

```solidity
control.updateDataLocationsAfterHandoff(
    dataId,
    executionId,
    newStorageNodes,
    newPublicKeySetRoot,
    sortedCommitteeSignatures
);
```

签名摘要通过以下接口取得：

```solidity
control.dataHandoffDigest(
    dataId,
    executionId,
    newStorageSetRoot,
    newPublicKeySetRoot,
    newEpoch,
    newVersion
);
```

合约验证：

- execution 处于 `Running`；
- selected committee active；
- 每个新 storage node 都是当前委员会成员；
- 地址严格升序；
- 签名达到阈值、来自委员会且无重复；
- 摘要绑定旧/新 storage root、旧/新 PK-set root、epoch 和 version。

成功后原子更新：

```text
storage node list
storageSetRoot
publicKeySetRoot
epoch
version = version + 1
```

## 4. Rust 存储网络

实现：[`workflow.rs`](../crates/runtime/src/workflow.rs)

```rust
pub struct InMemoryStorageNetwork;
```

支持：

- `upload_secret_shares`：每节点一份 SS fragment；
- `upload_fhe_ciphertext`：FHE ciphertext 多节点复制；
- `locations`：查询当前持有数据的节点；
- `handoff`：把 SS/FHE 数据迁移到 selected committee；
- 版本单调递增；
- representation/version 一致性检查。

## 5. 事件监听接口

```rust
pub trait ChainEventSource {
    fn next_event(&self) -> Result<Option<RuntimeChainEvent>, WorkflowError>;
}
```

开发版 `InMemoryChain` 提供事件队列。生产 Ethereum adapter 应把以下合约事件解码为 `RuntimeChainEvent`：

- `DataRegistered`；
- `DataLocationsRegistered`；
- `ExecutionRequested`；
- `CommitteeFinalized`；
- `HandoffFinalized`。

## 6. Sortition 接口

```rust
pub trait SortitionBackend {
    fn select(
        &self,
        seed: &[u8; 32],
        eligible: &[NodeId],
        committee_size: usize,
    ) -> Result<Vec<NodeId>, WorkflowError>;
}
```

`DeterministicDevSortition` 使用非密码学确定性排名，仅供测试。生产实现必须验证链上随机源、registry snapshot、VRF proof、权重和 selection deadline。

## 7. 明文开发后端

`PlaintextWorkflowCrypto` 的行为：

- SS fragment 实际包含相同明文及不同 fragment index；
- FHE ciphertext 实际为开发前缀加明文 u128；
- handoff 会读取明文并重新编码；
- 计算当前只实现 `SumU128`。

它只用于跑通控制流，没有任何秘密分享或同态安全性。

## 8. 已跑通的测试

Rust 测试：

```text
SS value  = 40，存储于 nodes 1/2/3
FHE value = 60，存储于 nodes 4/5
eligible  = nodes 6/7/8/9
sortition = 选择其中 3 个
handoff   = 两份输入迁移到新委员会
compute   = 40 + 60
output    = FHE(100)，保存到新委员会
chain     = 记录 2 次 handoff + 1 次 result update
```

运行：

```sh
./scripts/test-handoff-workflow.sh
```

Solidity 测试同时验证显式地址登记、委员会 handoff 和链上地址/version 更新。

## 9. 生产化缺口

- [ ] Alloy/Ethereum WebSocket event adapter；
- [ ] PostgreSQL/RocksDB storage network；
- [ ] 节点间 mTLS gRPC 上传和 handoff；
- [ ] authenticated Shamir/PRSS；
- [ ] threshold FHE ciphertext/key-share storage；
- [ ] malicious-secure resharing/key handoff；
- [ ] VRF sortition verifier；
- [ ] committee threshold signature collector；
- [ ] 交易 nonce、重试、finality 和链重组恢复；
- [ ] possession receipt、availability challenge 和 slash。
