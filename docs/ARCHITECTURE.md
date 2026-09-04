# 实现架构与阶段

## 进程边界

```text
door ── VLAN/bridge ── physical Pad
          │
          └─ AF_PACKET Agent ── HTTP 控制面 (REST + SSE) ── Backend(s)
                            └─ RTSP 数据面 (RTP/JPEG + PCMU)
```

Agent 是唯一允许构造 `PENGUIN0` 控制包的组件。Backend 只能发起带 `command_id`
的 claim / unlock / hangup 请求，Agent 负责状态校验和幂等：claim 只在振铃中且
Pad 未接听时成功；unlock 只在远程已接听时允许，默认 1 秒冷却；命令重放返回缓存
结果。Backend 拿不到原始包，也不能指定 opcode 或目标。

## 接口分层

代码按接口拆开：

- `agent_api`：`AgentControl`（状态、带序号可续传的事件、幂等命令）和
  `AgentMedia`（视频/音频 broadcast、快照、预录缓冲、对讲）两个 trait，以及
  `EventLog`（事件环）、`CommandCache`（幂等缓存）、`MediaRing`（按时间和字节
  双上限的预录缓冲）。
- `replay_agent`：进程内的 pcap 回放实现，走生产状态机和编码器，只是不注入。
- `door_station`：可交互的软件门口机。用保存的抓包帧/音频当门口摄像头和麦克风（呼叫
  期间按 `loop_fps` 循环），从 stdin 控制台 ring/hangup，claim/unlock/hangup 走可配置
  shell 回调（默认日志+noop，回调里接“真正开门”），收到的对讲音频用播放器
  （默认 ffplay）放出来。与 `replay_agent` 一样实现同一组 trait，对后端不可区分。
- `agent_server`：把任意实现暴露成 HTTP 控制面的适配器，手写 HTTP/1.1，不引入
  HTTP 库。
- 真实抓包 Agent（`agent::run_live_agent` + `bridge`）目前仍走旧的 PAG1
  WebSocket，下一步接到同一组 trait 上。

standalone 部署时 Backend 直接调用 trait（函数调用和 channel，无序列化）；分离
部署时经 HTTP。两种部署的失败模型一致：事件有 seq 并可续订，命令有 command_id，
慢消费者丢事件后从 snapshot 重建。

## 控制面

见 `docs/openapi.yaml`（内嵌在二进制里，`/openapi.yaml` 可取）：

- REST 上行：`POST /v1/call/{claim,unlock,hangup}`，body 带 `command_id`；
  `GET /v1/state`；`GET /v1/media`；`GET /v1/snapshot.jpg`（带
  `X-Frame-Age-Ms`）；过渡的 `POST /v1/talk`（PCM S16LE 8 kHz chunked，同一
  时刻只接受一路，第二路 409 `talk_busy`）。
- SSE 下行：`GET /v1/events`，每条事件带 `seq`，服务端 5-10 分钟随机断开，客户端
  带 `Last-Event-ID` 重连补发；超出事件环则先发 `snapshot`。事件是广播，多个
  订阅互不影响，各自独立处理 Lagged。
- 协商强制：请求必须带 `Accept`，有 body 必须带 `Content-Type`，否则 406/415 并
  列出支持的类型；媒体类型带编码版本参数（`application/json; v=1`），换编码只
  需增加候选。
- 鉴权：`Authorization: Bearer <token>`；空 token 关闭鉴权，仅开发用。
- `/swagger` 由开关控制，页面从 CDN 加载 Swagger UI 读取本机 `/openapi.yaml`。

## 数据面（设计已定，待实现）

RTSP，视频用 RFC 2435 RTP/JPEG，音频 PCMU/L16，RTP 时间戳加 RTCP SR 做音画同步，
对讲用 ONVIF backchannel。已用 `testdata/pad.cap` 验证门口机 JPEG 满足 RTP/JPEG
约束（baseline、4:2:0、标准 Huffman 表、无 restart marker），且 `-c:v copy` 打包
后能被 ffmpeg 收端解码，全程不重编码。Agent 侧按“零重组 + iovec 发送”实现：
一个 PENGUIN0 分片对应一个 RTP 包。TCP interleaved 为首选传输，UDP 保留。

预录缓冲：`media.history_secs` 秒（`history_max_kib` 兜底），开流时可从几秒前
起播，事件录像有前置片段；`GET /v1/media` 报告配置窗口和当前持有的跨度。

## PAG1 Agent 协议（旧，待下线）

每个 WebSocket binary message 恰好是一帧：

| Offset | Size | 编码 |
|---:|---:|---|
| 0 | 4 | `PAG1` |
| 4 | 1 | version = 1 |
| 5 | 1 | kind: event/command/result/jpeg/PCM |
| 6 | 2 | flags, big-endian |
| 8 | 8 | session ID, big-endian |
| 16 | 4 | sequence, big-endian |
| 20 | 8 | monotonic timestamp µs, big-endian |
| 28 | 4 | payload length, big-endian |
| 32 | N | CBOR control or raw media |

视频帧为完整 JPEG；门口音频为原始 PCM S16LE/8 kHz/mono。慢消费者通过有界广播
队列丢视频，不阻塞门禁收包。

## MediaEngine

- `lite`：不解码来自门口机的 JPEG；只计数并返回内置黑色 JPEG/配置的静态图。
  这是 MT7628 standalone 的安全降级模式。
- `ffmpeg`：持久 `image2pipe` 进程，把 MJPEG 缩放、限帧并编码 H.264 baseline。
  FFmpeg 是否静态或动态链接对 Rust 接口不可见，可由 OpenWrt 包策略决定。

## 共存与 first-answer 静默

振铃靠门口机→Pad 的 `00b7/01` session setup 和持续媒体维持；结束靠发往 Pad 的
`00b7/1e`（抓包里门口机重复 3 次）。据此：

- **振铃阶段不下任何规则**，门口机→Pad 正常，物理 Pad 和所有订阅后端一起响、都能
  看画面。Agent 靠 AF_PACKET 在 RX 侧旁路嗅探，nft forward drop 不影响它继续把媒体
  转给后端。
- **远端 claim 成功即接管物理 Pad**（`firewall::pad_silence_rules`）：下发 bridge 表
  同时丢弃 **门口机→Pad** 和 **Pad→门口机** 的 UDP 10000，前者停铃停画面，后者防止
  物理 Pad 事后抢接；并注入一个**伪装成门口机、发往 Pad 的 `00b7/1e`**
  （`inject_pad_reset`），让 Pad 立刻认为通话结束而停铃，不必等它自身超时。远端作为
  owner 的控制和音频由 Agent 以 Pad→门口机注入，源自主机而非 pad_interface 入口，不被
  规则命中。
- **物理 Pad 先接**：Agent 在桥上观察到 Pad→门口机的 `00b7/05`，状态机标记 owner=Pad，
  不下任何静默规则，远端 claim 被拒。残余竞态只有一个包处理时延。
- **挂断或程序退出**：删表 fail-open，物理 Pad 恢复；启动时也先清一次残留表。

以上 first-answer 静默是 Linux live Agent（bridge + AF_PACKET + `nft`）的行为，规则和
reset 包的构造已单测，但 Pad 是否认中途注入的门口机 hangup 需授权实机验证。

- `manual`（旧的保守回退）：nftables 始终丢弃 Pad→门口机的 UDP 10000/10008，物理 Pad
  完全无法控制，只有远端能操作。
- `automatic`：规则送入带 `bypass` 的 NFQUEUE 做逐包仲裁；该 verdict loop 尚未启用，
  上面基于静态规则的静默是更简单、无需逐包 fail-open 的替代路径。

## 当前实现边界

已有：协议解析、pcap 等时回放、PAG1 WebSocket Agent、真实 AF_PACKET 捕获、控制
包注入、手动 nft 规则、first-answer 状态机、媒体抽象、接口层、HTTP 控制面、
预录缓冲。

待做（按顺序）：RTSP 数据面；远程 Agent 客户端（HTTP + RTSP 实现同一组 trait）；
真实 Agent 接到 trait 和 HTTP 服务上并下线 PAG1；Matter / HomeKit 后端（当前
在仓库外的 `wip/` 中，等 Agent 接口稳定后回迁）。
