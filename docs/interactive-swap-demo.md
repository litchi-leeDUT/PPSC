# 交互式 Swap 演示

运行：

```bash
./scripts/interactive-swap-demo.sh
```

脚本会启动一条临时 Anvil 链，部署 `PpscControlPlane`、Mock mUSD 和
`ConfidentialTokenSwap`，初始给演示用户发放 1000 mUSD。随后可以反复选择：

- 查询明文余额、托管余额、密态负债、手续费、状态根和储备金状态；
- 将明文 mUSD 存入 Swap，并模拟 committee 阈值签名确认密态铸造；
- 销毁密态余额并提现明文 mUSD。

建议演示路径：先选择 `1`，再选择 `2` 存入 100，最后选择 `3` 提现 40。预期结果：

| 阶段 | 用户明文余额 | Swap 托管 | 密态余额 | 手续费 |
|---|---:|---:|---:|---:|
| 初始 | 1000 | 0 | 0 | 0 |
| deposit 尚未确认 | 900 | 100 | 0 | 0 |
| committee 确认 | 900 | 100 | 100 | 0 |
| 提现 40 | 939.6 | 60.4 | 60 | 0.4 |

生产系统不会公开单个用户的密态余额。演示只有一个私密账户，因此用链上
`privateLiabilities` 总负债作为可观察的密态余额；真实余额内容仍应由链下 MPC/FHE Runtime
授权解密后返回。脚本中的固定私钥和开发 committee 只能用于本地 Anvil。
