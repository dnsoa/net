# HTTP/2 协议层审计报告

**审计日期**: 2026-04-01
**审计范围**: `github.com/dnsoa/net/httpx/protocol/http2/` (http2.go, stream.go, session.go)
**对照基准**: RFC 7540 + Zig 生产实现 (`/workspace/Codes/zig/httpx.zig/`)

---

## 1. DATA 帧 PADDED 标志未处理

**状态**: 待修复
**优先级**: P2
**RFC**: §6.1 — PADDED flag (0x08) 置位时，payload 第一字节为 Pad Length，末尾为 padding

**问题**: `session.go:handleDataFrame` 不检查 PADDED 标志，直接将 `frame.Payload` 发给 `dataCh`。padding 字节混入应用层 body 数据。

**Zig 对照**: `server.zig:684-689` 和 `client.zig:861-866` 均正确处理。

**修复方向**: 在 `handleDataFrame` 中增加 PADDED 剥离逻辑：

```go
func (s *Session) handleDataFrame(frame Frame) {
    // ...
    payload := frame.Payload
    if frame.Header.Flags&FlagPadded != 0 {
        if len(payload) == 0 {
            // protocol error
            return
        }
        padLen := int(payload[0])
        payload = payload[1:]
        if padLen > len(payload) {
            // protocol error
            return
        }
        payload = payload[:len(payload)-padLen]
    }
    data := append([]byte(nil), payload...)
    // ... send to dataCh
}
```

**注意**: RFC 7540 §6.1 规定 padding 计入 flow control 窗口，所以 WINDOW_UPDATE 逻辑不需要改动。

---

## 2. WINDOW_UPDATE 零增量静默忽略

**状态**: 待修复
**优先级**: P2
**RFC**: §6.9 — "A receiver MUST treat the receipt of a WINDOW_UPDATE frame with a flow-control window increment of 0 as a stream error of type PROTOCOL_ERROR"

**问题**: `session.go:handleWindowUpdateFrame` 对 `increment <= 0` 静默 return，未发送任何错误帧。

```go
// session.go:524
if increment <= 0 {
    return  // 应发送 PROTOCOL_ERROR
}
```

**补充**: `stream.go:ApplyReceivedFrame` 中有正确验证（返回 error），但 session.go 的 `handleWindowUpdateFrame` 不经过 `ApplyReceivedFrame`，直接处理。所以 `stream.go` 的验证是死代码。

**Zig 对照**: Zig `stream.zig:394` 在协议层返回 `error.ProtocolError`，但 Zig server (`server.zig:703`) 对 WINDOW_UPDATE 也是静默消费。两者 server 行为一致，都违反 RFC。

**修复方向**:

```go
if increment <= 0 {
    if frame.Header.StreamID == 0 {
        // connection error
        s.readLoopErr = errors.New("http2: connection window update with zero increment")
        s.broadcastError(s.readLoopErr)
    } else {
        // stream error
        s.writeMu.Lock()
        s.writeRSTStream(frame.Header.StreamID, ErrProtocolError)
        s.writeMu.Unlock()
    }
    return
}
```

---

## 3. maxReadFrameSize 初始化方向错误

**状态**: 待修复
**优先级**: P3
**RFC**: §6.5.2 — "SETTINGS_MAX_FRAME_SIZE indicates the size of the largest frame payload that the sender is willing to receive"

**问题**: `maxReadFrameSize` 用于限制接收帧大小，应使用我方宣告的限制，而非对端的。

- `conn.Settings.MaxFrameSize` = 我方限制 → 约束对端发给我们的帧（正确用于读取）
- `conn.PeerSettings.MaxFrameSize` = 对端限制 → 约束我们发给对端的帧（正确用于发送）

当前代码：
```go
// session.go:327 — newSession
maxReadFrameSize: int(conn.PeerSettings.MaxFrameSize),  // 应为 conn.Settings.MaxFrameSize

// session.go:855-857 — applyRemoteSettings
if size := int(s.conn.PeerSettings.MaxFrameSize); size > 0 {
    s.maxReadFrameSize = size  // 不应更新：对端值约束发送，不约束接收
}
```

**Zig 对照**: Zig client 用本地配置 `self.config.max_response_size` 限制读取，正确。

**实际影响**: 极低。默认值均为 16384，且正常对端会遵守我方 SETTINGS 不会超发。仅对端发送非默认 MaxFrameSize 且不遵守我方限制时才暴露。

**修复方向**:
```go
// newSession
maxReadFrameSize: int(conn.Settings.MaxFrameSize),

// applyRemoteSettings 中删除 maxReadFrameSize 更新
// 对端 MaxFrameSize 仅用于发送路径（streamWriter 已正确使用 PeerSettings）
```

---

## 4. SETTINGS 参数范围验证缺失

**状态**: 待修复
**优先级**: P3
**RFC**: §6.5.2 规定以下范围约束

| 参数 | 有效范围 | 违反时错误类型 |
|------|----------|---------------|
| SETTINGS_MAX_FRAME_SIZE | 16384 ~ 16777215 | PROTOCOL_ERROR (connection) |
| SETTINGS_INITIAL_WINDOW_SIZE | 0 ~ 2^31-1 | FLOW_CONTROL_ERROR (connection) |
| SETTINGS_ENABLE_PUSH (server→client) | 仅允许 0 | PROTOCOL_ERROR (connection) |

**问题**: `http2.go:ApplySettingsPayload` 直接赋值，无范围检查。

**Zig 对照**: Zig 同样缺失范围验证。

**修复方向**: 在 `ApplySettingsPayload` 中增加验证：

```go
case SettingMaxFrameSize:
    if value < 16384 || value > 16777215 {
        return errors.New("http2: SETTINGS_MAX_FRAME_SIZE out of range")
    }
    settings.MaxFrameSize = value
case SettingInitialWindowSize:
    if value > 2147483647 {
        return errors.New("http2: SETTINGS_INITIAL_WINDOW_SIZE out of range")
    }
    settings.InitialWindowSize = value
```

---

## 5. ApplyReceivedFrame 调用顺序瑕疵

**状态**: 不修
**优先级**: 无

**问题**: `stream.go:ReceiveHeaderBlockFrame` 先调用 `ApplyReceivedFrame`（触发状态转换），再验证 PADDED/PRIORITY。如果验证失败，流状态已被修改。

**Zig 对照**: Zig 先验证 PADDED/PRIORITY，再返回结果给调用者做状态转换。顺序更合理。

**不修原因**: 验证失败触发 `broadcastError` 导致连接关闭，残留状态无实际影响。

---

## 6. 双重流状态机

**状态**: 记录
**优先级**: 不修（当前无问题）

**现状**:
- `stream.go` `StreamManager.Streams` — HPACK 编解码、帧构建
- `session.go` `activeStreams` — 运行时流控、DATA 路由

**潜在风险**: `WriteResponse` 非流式路径调用 `BuildDataFrames`，检查 StreamManager 的 `stream.State`。如果两套状态不同步，可能出错。

**当前安全**: edge-cdn 的 HTTP2Server 使用 streaming 路径（`WriteResponseHead` + `streamWriter`），不经过 `BuildDataFrames`。

**Zig 对照**: Zig 只有一套 `StreamManager`，HPACK 上下文嵌入其中。更简洁。

---

## Go 优于 Zig 的地方

| 特性 | Go | Zig server |
|------|-----|------------|
| 应用对端 SETTINGS | 完整应用 | 仅发 ACK，不应用 |
| SETTINGS 帧内容 | 发送全部 6 个参数 | 发空帧（无参数） |
| InitialWindowSize 增量传播 | 正确传播到活跃流 | 未实现 |
| 流式多路复用 | 完整支持 | 单请求/连接 |
| GOAWAY 处理 | 设标志继续处理现有流 | 直接返回 |
| PING echo | 正确 | 正确 |
| HEADERS PADDED/PRIORITY | 正确 | 正确 |
| CONTINUATION 聚合 | 正确 | 正确 |
| Server/Client preface | 正确 | 正确 |
