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
- `socket_agent`：用户态 Pad 端 Agent，绑 UDP 控制口扮演 Pad，接住 `emit-door`
  合成门口机的寻呼/引导/会话握手，把门口视频/音频经同一 HTTP 控制面 fan-out；
  后端的接听/开门/对讲以 Pad 身份回发给门口机。纯 tokio UDP、跨平台（不需
  AF_PACKET），因此 `emit-door` ↔ `socket_agent` ↔ 浏览器 Pad 可在一台
  笔记本上闭环，无需硬件和桥。
- `emitter`：从协议合成的软件门口机模拟器。按配置的门口机/房间身份，按实机验证的
  呼叫顺序发包：`005d/01` 寻呼 ×10（振铃触发）→ `0098/01` bootstrap → `00b7/01`
  ring ×3 → `00b7/0a` 视频 + keepalive；**音频在收到 Pad 的 `00b7/05` answer 后才发**
  （振铃期发音频会抑制 Pad 本地铃声）；结束发 hangup。全部从协议合成、不重放抓包。
  画面来自 JPEG 文件目录（假摄像头），音频来自 PCM 文件或静音；`--door-ip` 缺省时从
  connect 到 Pad 后的本机出口地址自动取，写进包体供 Pad 回包。发出后监听 Pad 的回包
  （capability/answer/unlock/voice/hangup）并报告、播放。`session_request`、`jpeg_packets`、
  `page_request`、`bootstrap_request` 有“合成==抓包”单测自证。UDP 10008 的设备 ID→IP 查询（类 ARP：广播 `01+room_id`，Pad 从自身地址回
  `02+room_id`，取应答源 IP）由 `resolve_pad` 实现，`resolve` 子命令使用，也已内建进
  `emit-door`：省略目标即按 `--room-id` 自动发现 Pad IP 后再呼叫。用途：
  在门口机与 Pad 相距很远时，验证我们分析的协议、以及 Agent/后端的正确性。
- `door_station`：可交互的软件门口机。用保存的抓包帧/音频当门口摄像头和麦克风（呼叫
  期间按 `loop_fps` 循环），从 stdin 控制台 ring/hangup，claim/unlock/hangup 走可配置
  shell 回调（默认日志+noop，回调里接“真正开门”）。收到的对讲音频默认写文件
  （raw S16LE 8 kHz mono），`--play` 才用 ffplay、`--player` 用自定义命令播放；
  同一套 `AudioSink` 也用于 `emit-door` 收 Pad 语音。与 `replay_agent` 一样实现
  同一组 trait，对后端不可区分。
- `agent_server`：把任意实现暴露成 HTTP 控制面的适配器，手写 HTTP/1.1，不引入
  HTTP 库。
- `agent::LiveAgent`（`run_live_agent` + `bridge`，仅 Linux）：AF_PACKET 抓桥、
  驱动通话状态机、广播门口视频/音频，并在收到后端命令时注入 claim/unlock/hangup、
  对讲音频注入 Pad→门口机方向。它实现同一组 trait，由 `agent_server` 用与 replay
  完全相同的方式对外服务。控制面只有 HTTP + SSE，没有别的后端传输。

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
- 内置网页 Pad（`/`、`/pad`）由 `agent.web_ui` 开关控制，默认开：不部署任何
  Matter/HAP 后端时也有一个跨平台可用的界面；headless 部署可关。它只是控制面的
  一个普通客户端，没有任何特权通道。

## 数据面（设计已定，待实现）

RTSP，视频用 RFC 2435 RTP/JPEG，音频 PCMU/L16，RTP 时间戳加 RTCP SR 做音画同步，
对讲用 ONVIF backchannel。已用 `testdata/pad.cap` 验证门口机 JPEG 满足 RTP/JPEG
约束（baseline、4:2:0、标准 Huffman 表、无 restart marker），且 `-c:v copy` 打包
后能被 ffmpeg 收端解码，全程不重编码。Agent 侧按“零重组 + iovec 发送”实现：
一个 PENGUIN0 分片对应一个 RTP 包。TCP interleaved 为首选传输，UDP 保留。

预录缓冲：`media.history_secs` 秒（`history_max_kib` 兜底），开流时可从几秒前
起播，事件录像有前置片段；`GET /v1/media` 报告配置窗口和当前持有的跨度。

门口视频为完整 JPEG，门口音频为原始 PCM S16LE/8 kHz/mono，都经有界广播队列
fan-out，慢消费者丢帧、不阻塞抓包。

## MediaEngine

- `lite`：不解码来自门口机的 JPEG；只计数并返回内置黑色 JPEG/配置的静态图。
  这是 MT7628 standalone 的安全降级模式。
- `ffmpeg`：持久 `image2pipe` 进程，把 MJPEG 缩放、限帧并编码 H.264 baseline。
  FFmpeg 是否静态或动态链接对 Rust 接口不可见，可由 OpenWrt 包策略决定。

## 共存与 first-answer 静默

振铃由门口机→Pad 的 `005d/01` 寻呼触发，靠 `00b7/01` session setup 建立的会话和
持续媒体维持；结束靠发往 Pad 的 `00b7/1e`（抓包里门口机重复 3 次）。据此：

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

已有：协议解析、pcap 等时回放（`ReplayAgent`）、真实 AF_PACKET 捕获 Agent
（`LiveAgent`，Linux）、控制包注入、手动 nft 规则、first-answer 状态机、媒体抽象、
接口层、唯一的 HTTP 控制面（REST + SSE）、预录缓冲。回放与实机走同一组 trait 和
同一个 `agent_server`，对后端不可区分。

待做（按顺序）：RTSP 数据面；远程 Agent 客户端（HTTP + RTSP 实现同一组 trait）供
分离部署；Matter / HomeKit 后端（当前在仓库外的 `wip/` 中，等 Agent 接口稳定后回迁）。
