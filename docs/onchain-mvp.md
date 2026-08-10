# 链上控制面 MVP

## 合约

- `PpscControlPlane`：合约/函数、数据引用、委员会、执行、handoff、结果和 Pick。
- `EcdsaSortitionVerifier`：测试网临时验证器，由 authority 对链下 sortition 结果签名。
- `ISortitionVerifier`：生产 VRF/random-beacon verifier 的替换接口。
- `PrivateBalanceApp`：用户部署隐私余额合约的示例，只公开 manifest、程序哈希和状态根。

链上只保存公开程序、位置、data ID、commitment、集合 root、状态和签名证据。禁止提交明文、秘密份额、FHE secret-key share、MAC share 或 preprocessing secret。

## 状态流

```text
publishContract → publishFunction
registerData(SS key) → registerData(FHE ciphertext)
finalizeCommittee
invoke → assignCommittee → markRunning
  ├─ beginHandoff → finalizeHandoff → markRunning
  └─ submitResult → register output → update state root
requestPick → committee returns protected shares off chain
```

`submitResult` 和 `finalizeHandoff` 要求委员会阈值签名，签名者必须按地址升序排列并且不能重复。

## 本地测试

推荐直接运行一键脚本：

```sh
./scripts/test-local.sh
```

脚本会自动启动和关闭临时 Anvil，并完成格式检查、编译、全部测试、用户隐私合约广播部署及链上状态回读。

也可以分步执行：

```sh
source "$HOME/.zshenv"
forge fmt --check
forge test -vvv
```

## Sepolia 部署

创建 `.env`，设置 `SEPOLIA_RPC_URL` 和仅用于测试网的 `DEPLOYER_PRIVATE_KEY`，部署账户需要少量 Sepolia ETH：

```sh
set -a
source .env
set +a
forge script contracts/script/DeploySepolia.s.sol:DeploySepolia \
  --rpc-url "$SEPOLIA_RPC_URL" \
  --broadcast
```

广播记录位于 `broadcast/`。部署后应通过 `cast code`、`cast call` 和一次完整的测试 invocation 验证。

## 安全边界

当前 `EcdsaSortitionVerifier` 只适合测试网，它证明 authority 批准了委员会，不是去中心化 VRF。生产部署前必须替换 verifier，并完成论文列出的 malicious-secure conversion/handoff。

## 用户部署隐私合约

`PrivateBalanceApp` 构造时调用 `publishContract`，获得稳定 `confidentialContractId`。随后 owner 调用 `publishPrivateTransfer` 登记：

```text
programHash
operatorSequenceHash
ABI hash
程序内容寻址位置
最大执行步数
```

用户余额不以 `mapping(address => uint256)` 保存。链上只能查询 `privateStateRoot`；实际余额保持为链下 SS/FHE 数据，并通过 `dataId` 参与调用。

在已启动的 Anvil 上执行完整用户部署演示：

```sh
export DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
forge script contracts/script/DemoLocalPrivacyApp.s.sol:DemoLocalPrivacyApp \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast -vvv
```

该私钥是 Anvil 公开测试私钥，只能用于本地链。
