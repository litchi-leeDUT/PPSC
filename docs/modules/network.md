# Network 模块约定

> 状态：草案，可直接修改。对应 crate：`ppsc-network`

## 职责

- 提供节点间传输端口及 gRPC 适配器。
- 负责连接认证、限流、大小限制、超时和传输级重试。

## 必须遵守

- 传输层不得解析或推进密码协议状态。
- 生产连接必须双向认证，节点身份必须映射到委员会成员。
- envelope 必须包含版本、发送者、接收者、任务 ID 和防重放消息 ID。
- 禁止记录 payload；指标只能记录大小、延迟和公开错误码。

## gRPC 草案

```proto
service CommitteeTransport {
  rpc Send(Envelope) returns (Acknowledgement);
}
```

protobuf 字段号在第一次发布后只可保留或追加，不可复用。正式 `.proto` 在确定载荷版本策略后添加。

## 测试清单

- mTLS 身份正确/错误/过期。
- 最大消息限制、超时、背压和断线重连。
- 重复消息与跨任务重放。
- protobuf 向前/向后兼容。

## 待确认

- [ ] 服务发现方式与证书签发/轮换。
- [ ] 单消息大小、并发和速率上限。
- [ ] unary、streaming 或二者组合。
- [ ] acknowledgement 是否表示接收、持久化或处理完成。

