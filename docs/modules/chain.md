# Chain 模块约定

> 状态：草案，可直接修改。对应 crate：`ppsc-chain`

## 职责

- 监听任务登记、委员会更新、任务取消等合约事件。
- 提交状态承诺、公开结果和证明。
- 隔离节点逻辑与具体 EVM RPC/ABI 库。
- 管理合约包、程序描述符、数据位置 root、sortition 结果和动态执行状态。

详细协议见 [密态智能合约与动态混合协议](../confidential-contract-protocol.md)。

## 必须遵守

- 事件使用 `(chain_id, block_hash, log_index)` 唯一标识。
- 仅在达到配置的最终性后启动不可逆的协议步骤。
- 提交交易必须幂等，并处理 nonce、替换交易和链重组。
- ABI 地址、chain ID 和部署区块必须来自显式配置。
- 不在交易 calldata 或错误日志中放入任何秘密。

## 接口契约

- `events_after` 返回稳定排序且可安全重放的事件。
- `is_finalized` 的规则必须按链类型配置。
- `submit_result` 重复调用不得产生逻辑上的重复结果。

## 测试清单

- Foundry 合约测试与 Rust ABI 编解码交叉测试。
- 链重组、RPC 切换、重复日志和漏块回补。
- revert 原因映射、gas 估算失败和 nonce 冲突。
- 本地链端到端任务登记/结果提交。

## 待确认

- [ ] 目标链、chain ID、最终性深度和 RPC 服务。
- [ ] 合约 ABI、地址和升级模式。
- [ ] 结果提交者的授权和 gas 支付策略。
- [ ] 链重组后已执行协议任务的处置规则。
- [ ] 程序体链上分块或内容寻址存储的大小分界线。
- [ ] VRF/random beacon 的合约验证方式。
