# PPSC 隐私保护智能合约编写接口

> 版本：0.1（MVP）  
> Solidity：`^0.8.24`  
> 状态：当前 ABI 已实现并通过本地 Anvil 测试；标记为“建议”的语法尚未实现编译器支持。

## 1. 编程模型

PPSC 合约由两个部分组成：

```text
公开 Solidity 外壳
├── owner、访问控制和公开业务状态
├── confidentialContractId
├── 私密状态承诺 stateRoot
└── 调用 PpscControlPlane

链下隐私程序
├── SS/FHE 类型和输入 Schema
├── operator sequence
├── C2S/S2C 转换点
├── 确定性计算程序
└── 输出及新状态承诺
```

Solidity 合约不得保存明文隐私变量。例如余额不能声明为：

```solidity
mapping(address => uint256) public balanceOf; // 禁止用于隐私余额
```

应声明或查询私密状态根：

```solidity
function privateStateRoot() external view returns (bytes32) {
    return controlPlane.contractStateRoot(confidentialContractId);
}
```

实际余额在链下持久化为以下两种表示之一：

- `SecretSharing`：带认证的秘密分享；
- `Fhe`：门限 FHE 密文。

“Hybrid”只表示一个函数同时包含 MPC/FHE operator，不是第三种数据表示。

## 2. 开发者接口

用户应用合约至少应公开：

```solidity
interface IConfidentialApplication {
    function controlPlane() external view returns (PpscControlPlane);
    function owner() external view returns (address);
    function confidentialContractId() external view returns (bytes32);
    function privateStateRoot() external view returns (bytes32);
}
```

当前参考实现为：

```solidity
contract PrivateBalanceApp {
    PpscControlPlane public immutable controlPlane;
    address public immutable owner;
    bytes32 public immutable confidentialContractId;

    constructor(
        PpscControlPlane controlPlane_,
        address owner_,
        bytes32 deploymentSalt,
        bytes32 manifestHash,
        bytes32 runtimeHash,
        bytes32 initialPrivateStateRoot
    ) {
        controlPlane = controlPlane_;
        owner = owner_;
        confidentialContractId = controlPlane_.publishContract(
            deploymentSalt,
            manifestHash,
            runtimeHash,
            initialPrivateStateRoot
        );
    }
}
```

注意：`publishContract` 的调用者是用户应用合约，因此控制面记录的 contract owner 是应用合约地址；应用合约自身再负责验证最终用户 owner。

## 3. 合约 Manifest

Manifest 是链下规范文件，其规范化编码的哈希登记在链上。推荐 JSON 结构：

```json
{
  "format": "ppsc-manifest-v1",
  "name": "PrivateBalance",
  "version": "1.0.0",
  "runtime": {
    "id": "ppsc-wasm-v1",
    "hash": "0x..."
  },
  "privateState": [
    {
      "name": "balances",
      "schema": "map<accountId,u128>",
      "representation": "FHE",
      "keyPolicy": "per-application-v1"
    }
  ],
  "functions": [
    {
      "signature": "privateTransfer(bytes32,bytes32)",
      "programHash": "0x...",
      "operatorSequenceHash": "0x...",
      "abiHash": "0x...",
      "codeLocation": "ipfs://...",
      "maxSteps": 250000
    }
  ]
}
```

Manifest 规范化规则必须固定，例如 RFC 8785 JCS；不能直接对任意缩进的 JSON 文本计算哈希。

### 必须绑定的字段

- Manifest 格式及版本；
- Runtime ID/hash；
- 私密状态名称、类型、范围、shape 和表示；
- 每个函数的 ABI、程序和 operator sequence；
- FHE 参数集及 key policy；
- MPC field、阈值和认证方案；
- 资源上限；
- 升级和授权策略。

## 4. 私密类型

建议的源语言类型如下；当前 Solidity 编译器不会直接识别这些类型，应由 SDK/IR 描述：

| 类型 | 含义 | 持久表示 |
|---|---|---|
| `SInt<N>` | 带认证秘密分享整数 | SS |
| `SBool` | 带认证秘密分享布尔值 | SS |
| `FheInt<N>` | FHE 定点/整数密文 | FHE |
| `FheBool` | FHE 布尔密文 | FHE |
| `PrivateAccountId` | 不透明隐私账户标识 | SS/FHE |
| `DataId<T>` | 链上公开句柄，不包含值 | public bytes32 |

每个数值类型必须声明：

```text
bit width
signedness
logical range
fixed-point scale
shape / slot layout
overflow policy
```

不得只写一个无范围的 `uint256`，否则 C2S 的 range 和 wrap-around 检查无法确定。

## 5. Operator Sequence

每个隐私函数都必须发布确定的 operator sequence。推荐 IR：

```yaml
format: ppsc-operator-sequence-v1
function: privateTransfer(bytes32,bytes32)

inputs:
  - id: encrypted_balances
    type: FheMap<AccountId,u128>
  - id: encrypted_transfer
    type: FheTuple<AccountId,AccountId,u128>

operators:
  - id: op_0
    domain: FHE
    opcode: load
    inputs: [encrypted_balances, encrypted_transfer]

  - id: op_1
    domain: C2S
    opcode: convert
    inputs: [op_0]
    parameters: conversion_u128_v1

  - id: op_2
    domain: MPC
    opcode: ge
    inputs: [sender_balance, amount]

  - id: op_3
    domain: MPC
    opcode: checked_sub
    inputs: [sender_balance, amount]

  - id: op_4
    domain: MPC
    opcode: checked_add
    inputs: [receiver_balance, amount]

  - id: op_5
    domain: S2C
    opcode: convert
    inputs: [op_3, op_4]
    parameters: conversion_u128_v1

outputs:
  privateState: op_5
  public: []
```

链上登记：

```solidity
controlPlane.publishFunction(
    confidentialContractId,
    bytes4(keccak256("privateTransfer(bytes32,bytes32)")),
    programHash,
    operatorSequenceHash,
    abiHash,
    "ipfs://bafy-private-transfer-program",
    250_000
);
```

### Operator 规则

- 每个 operator 只能属于 `MPC` 或 `FHE`；
- 跨域必须显式使用 `C2S` 或 `S2C`；
- 不得由 Runtime 根据负载临时改变 operator domain；
- FHE operator 必须引用确定的 key policy/parameter set；
- Sequence 必须是确定性 DAG，禁止隐式网络、系统时间和未计量随机数；
- 私密分支必须转换成 data-oblivious select/circuit，不能泄露控制流。

## 6. 数据上传和登记接口

### 6.1 数据引用

```solidity
struct DataReference {
    address owner;
    bytes32 commitment;
    bytes32 publicKeySetRoot;
    bytes32 storageSetRoot;
    bytes32 fheKeyId;
    Representation representation;
    DataStatus status;
    uint16 threshold;
    uint64 version;
    uint64 epoch;
}
```

### 6.2 注册 SS 数据

```solidity
controlPlane.registerData(
    dataId,
    valueCommitment,
    committeePublicKeySetRoot,
    shareStorageSetRoot,
    bytes32(0),
    PpscControlPlane.Representation.SecretSharing,
    privacyThreshold,
    version,
    epoch
);
```

约束：

- `threshold > 0`；
- `fheKeyId == 0`；
- 每个节点只能收到自己的份额；
- 链上登记前应获得足够的存储 receipt。

### 6.3 注册 FHE 密文

```solidity
controlPlane.registerData(
    ciphertextDataId,
    ciphertextCommitment,
    fhePublicKeySetRoot,
    ciphertextStorageSetRoot,
    fheKeyDataId,
    PpscControlPlane.Representation.Fhe,
    0,
    version,
    epoch
);
```

约束：

- `threshold == 0`；
- `fheKeyDataId` 必须指向同 owner 的 Available SS key reference；
- 密文可以复制，但链上不得出现 FHE 私钥份额；
- `commitment` 必须覆盖 ciphertext bytes、参数集、key ID 和版本。

## 7. 调用接口

隐私函数是异步执行，用户调用控制面：

```solidity
bytes32 executionId = controlPlane.invoke(
    confidentialContractId,
    PRIVATE_TRANSFER_SELECTOR,
    inputDataIds,
    nonce,
    deadline
);
```

调用成功只表示任务已登记，状态为 `Requested`，不表示隐私程序已经执行完成。

```text
Requested
→ CommitteeAssigned
→ Running
→ Handoff（可选）
→ Running
→ Completed | Failed | Cancelled
```

Runtime 监听：

```solidity
event ExecutionRequested(
    bytes32 indexed executionId,
    bytes32 indexed contractId,
    bytes4 indexed selector,
    address requester,
    bytes32 inputRoot
);
```

### 调用方约束

- 所有 `inputDataIds` 必须处于 `Available`；
- `(requester, nonce)` 不能重复；
- `deadline` 必须晚于当前区块时间；
- 输入顺序必须与 ABI/Manifest 完全一致；
- 不得在 calldata 中包含明文或份额。

## 8. 结果与状态更新

Runtime 只能在 active committee 产生足够的有序阈值签名后调用 `submitResult`：

```solidity
struct ResultSubmission {
    bytes32 outputId;
    bytes32 outputCommitment;
    bytes32 outputPublicKeySetRoot;
    bytes32 outputStorageSetRoot;
    bytes32 outputFheKeyId;
    Representation outputRepresentation;
    uint16 outputThreshold;
    uint64 outputVersion;
    bytes32 newStateRoot;
    bytes32 transcriptRoot;
}
```

控制面执行 compare-and-set：只有当前合约 state root 仍等于 execution 的 `oldStateRoot` 才能更新。这会阻止两个并发任务覆盖同一个旧私密状态。

应用合约不应自行接受未经控制面验证的结果，也不应提供 owner 可直接修改 `privateStateRoot` 的后门。

## 9. Pick/open 接口

数据 owner 请求取回结果：

```solidity
bytes32 requestId = controlPlane.requestPick(
    dataId,
    recipientEncryptionKeyHash,
    nonce,
    expiry
);
```

Runtime/committee 监听 `PickRequested` 并在链下返回：

- SS 结果：至少满足打开阈值的结果份额；
- FHE 结果：对应 FHE key reference 的足够 key shares。

FHE key 一旦被 owner 重构，该 owner 可以解密同一 key 下的所有 ciphertext。因此不得在不同 owner 或不同释放策略间复用 FHE key。

当前 ABI 要求 owner 地址直接发送 `requestPick`。Relay 代发和 EIP-712 owner signature 属于下一版本接口。

## 10. 权限模型

| 操作 | 调用者 |
|---|---|
| 发布合约 | 用户应用合约 |
| 发布函数 | 控制面记录的合约 owner，当前即用户应用合约 |
| 注册输入数据 | 数据 owner |
| Invoke | 用户或上层应用合约 |
| Finalize committee | Runtime |
| Assign/mark running | Runtime |
| Submit result | Runtime + committee threshold signatures |
| Handoff | Runtime + incoming committee threshold signatures |
| Pick | 数据 owner |
| 更换 Runtime/verifier | Control-plane admin |

用户应用合约应至少实现：

- owner 检查；
- 单次函数发布保护；
- 禁止任意状态根写入；
- 必要时的暂停和升级治理；
- 不在事件和 revert data 中泄露秘密。

## 11. Solidity 错误

控制面公开错误：

| 错误 | 含义 |
|---|---|
| `Unauthorized` | 调用者没有权限 |
| `AlreadyExists` | ID、函数、委员会或输出重复 |
| `NotFound` | 合约、函数、数据或委员会不存在 |
| `InvalidArgument` | 零值、无效位置或引用关系错误 |
| `InvalidState` | 状态迁移或旧 state root 不匹配 |
| `InvalidThreshold` | SS/FHE/委员会阈值不合法 |
| `InvalidSelection` | sortition evidence 验证失败 |
| `InvalidSignature` | 委员会签名无效、重复或未排序 |
| `DeadlineExpired` | Invoke/结果已经过期 |
| `NonceAlreadyUsed` | Invoke 或 Pick 重放 |

调用方不得依靠 revert 字符串携带上下文秘密，应在本地将 selector 映射为公开错误码。

## 12. 完整示例

参考实现：

- [`PrivateBalanceApp.sol`](../contracts/src/examples/PrivateBalanceApp.sol)
- [`PrivateBalanceApp.t.sol`](../contracts/test/PrivateBalanceApp.t.sol)
- [`DemoLocalPrivacyApp.s.sol`](../contracts/script/DemoLocalPrivacyApp.s.sol)

运行：

```sh
./scripts/test-local.sh
```

## 13. 上线前检查清单

- [ ] Manifest 使用确定性规范化编码并验证哈希。
- [ ] 程序体下载后验证 `programHash` 和 `runtimeHash`。
- [ ] 每个私密整数声明范围、符号和 scale。
- [ ] 每个 FHE/MPC 跨域位置显式声明转换。
- [ ] C2S 检查 decode、round、range 和 wrap-around。
- [ ] S2C correlated mask 保证一次性消费。
- [ ] 所有 FHE ciphertext 显式绑定 key reference。
- [ ] SS 份额和 key share 不进入链、日志或错误。
- [ ] Invoke nonce、deadline 和输入顺序经过验证。
- [ ] 状态更新使用 old/new root compare-and-set。
- [ ] 委员会签名按地址升序、去重并达到阈值。
- [ ] Handoff 覆盖 Key、Live、MAC 和 Prep。
- [ ] Pick 的 key 粒度与 owner release policy 一致。
- [ ] 测试正常、恶意输入、重放、并发和换届恢复。

## 14. 当前 MVP 限制

- 没有 Solidity 隐私类型编译器，operator sequence 由开发者/SDK 生成；
- `EcdsaSortitionVerifier` 是测试网 authority verifier，不是生产 VRF；
- Pick 暂不支持 relayer/EIP-712；
- 数据 availability receipt/challenge 尚未在合约中强制验证；
- malicious-secure C2S/S2C 和 fluid handoff 仍需具体密码协议及证明；
- 当前用户应用示例只负责发布，没有封装 `invoke` 的业务级 wrapper。

