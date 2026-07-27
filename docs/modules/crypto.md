# Crypto 模块约定

> 状态：草案，可直接修改。对应 crate：`ppsc-crypto`

## 职责

- 为加密/解密、秘密分享、份额恢复、密态计算、承诺和证明提供统一能力端口。
- 隔离上层协议与具体密码库。
- 提供 VRF sortition、proactive resharing 和受支持的门限 HE key switching 能力。

详细协议见 [密态智能合约与动态混合协议](../confidential-contract-protocol.md)。

## 必须遵守

- 禁止自行设计密码原语；具体实现必须记录库名、版本、审计状态和参数来源。
- 随机数必须来自操作系统 CSPRNG 或所选库认可的安全源。
- 密钥、份额、明文不得进入日志、错误文本、指标标签或 panic。
- 所有密文必须绑定任务 ID、协议版本和上下文作为 associated data。
- 密钥材料应清零，并优先使用锁页内存/硬件密钥能力。

## 接口契约

- `split_secret` 校验 `1 <= threshold <= participants`。
- `combine_shares` 拒绝跨任务、重复成员和不足阈值的份额。
- `verify` 失败只返回公开错误码，不回显证明内部数据。
- `evaluate` 的程序格式、资源上限和确定性必须被版本化。

## 测试清单

- 已知答案测试与上游库测试向量。
- 篡改密文、proof、associated data 后必须失败。
- 阈值边界、重复份额、错误委员会测试。
- 模糊测试和跨版本兼容测试。

## 待确认

- [ ] MPC/秘密分享协议及审计库。
- [ ] 同态方案、参数集和允许的程序模型。
- [ ] 承诺及结果证明方案。
- [ ] 长期身份密钥与每任务临时密钥生命周期。
- [ ] 是否支持恶意安全的 verifiable resharing。
- [ ] HE 库是否原生支持 threshold key refresh/key switching。
