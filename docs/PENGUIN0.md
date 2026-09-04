# PENGUIN0 室内门禁协议技术说明

本文档只描述 `pad.cap` 中可以直接验证的事实。名称是便于实现而取的中性名称，
并非厂商公开名称。标为“推测”的字段需要更多抓包确认。

## 1. 捕获对象与传输

| 角色 | Station ID | IPv4 |
|---|---|---|
| 门口机 | `M00000000000` | `192.168.124.2` |
| 室内 Pad | `S00000000000` | `192.168.124.61` |

- UDP 10008：房间发现，载荷没有 `PENGUIN0` 公共头。
- UDP 10000：bootstrap、通话控制、JPEG、PCM 和通话后快照。
- 除嵌入的 IPv4 地址使用网络字节序外，多字节整数均为 little-endian。
- pcap 在 Linux bridge 上抓取，包含 UDP GRO 合并记录；真实 socket 通常仍一次收到
  一个 UDP datagram。解析器必须能按逻辑长度和下一个 magic 拆分。

## 2. 公共头

所有 PENGUIN 消息以前 32 字节开头：

| Offset | Size | 类型 | 说明 |
|---:|---:|---|---|
| 0 | 8 | bytes | ASCII `PENGUIN0` |
| 8 | 2 | u16le | family |
| 10 | 4 | u32le | opcode |
| 14 | 4 | u32le | declared length 或 status；部分门口机消息为 0 |
| 18 | 14 | bytes | 当前捕获中全 0 |
| 32 | ... | bytes | family-specific body |

已观察的形状：

| Family/opcode | 方向 | Wire/declared | 次数 | 含义 |
|---|---|---:|---:|---|
| `005d/01` | 门口机→Pad | 36/36 | 10 | 周期状态；body 为 `1e0000`，语义未知 |
| `0098/01` | 门口机→Pad | 32/20 | 1 | bootstrap request；declared 小于公共头，厂商异常 |
| `0098/02` | Pad→门口机 | 898/898 | 1 | bootstrap reply |
| `009b/02` | 双向 | 32/32、134/134 | 2 | 快照名称协商 |
| `009b/04` | Pad→门口机 | 134/134 | 1 | 快照名称结束/确认（推测） |
| `00b4/01..05` | 双向 | 40..1238 | 34 | 通话后 JPEG 文件传输 |
| `00b7/01` | 门口机→Pad | 254/254 | 3 | session setup/request |
| `00b7/03` | Pad→门口机 | 96/96 | 1 | session capability reply |
| `00b7/05` | Pad→门口机 | 80/80 | 1 | answer |
| `00b7/06` | Pad→门口机 | 80/80 | 1 | unlock |
| `00b7/0a` | 双向 | 602/0 或 602；1290/0 | 1941 | audio/JPEG media |
| `00b7/0c` | 双向 | 80/0 或 80 | 98 | keepalive |
| `00b7/1e` | 双向 | 80/80 | 4 | hangup |

## 3. 发现与 bootstrap

### UDP 10008

- Request：byte 0 为 `01`，后接 NUL 结尾/填充的房间 Station ID。
- Reply：byte 0 为 `02`，后接固定 34 字节、NUL 填充的房间 Station ID。

### `0098/02` bootstrap reply

Body：

| Offset（body） | Size | 说明 |
|---:|---:|---|
| 0 | 2 | `01 00` |
| 2 | 20 | Pad Station ID，NUL 填充 |
| 22 | 4 | Pad IPv4 |
| 26 | 840 | 当前捕获中全 0 |

总长 898。门口机 request 的 declared length 为 20、实际只有 32 字节；实现按实际 UDP
边界接收，不按该 declared length 截断公共头。

## 4. Session family `0x00b7`

Session body 前 48 字节是两个 endpoint：

| 绝对 offset | Size | 说明 |
|---:|---:|---|
| 32 | 20 | 门口机 Station ID |
| 52 | 4 | 门口机 IPv4 |
| 56 | 20 | Pad Station ID |
| 76 | 4 | Pad IPv4 |

Pad 发出的 answer、unlock、keepalive、hangup 都是相同的 80 字节 envelope，只改变
opcode。捕获中用户称按了两次开锁，但只出现一个有效 `00b7/06`；实现因此对一次上层
Unlock 只发一个 datagram，并做一秒防抖。

### setup capability

门口机 `00b7/01` 在 endpoint 后携带 `VIDEOA` 及一组能力值。Pad 的 96 字节 reply 为：

```text
endpoint block (48)
"VIDEOA\0\0" (8)
u16le: 50, 9, 9, 255
```

这些数值的厂商含义尚未证实；兼容实现逐字节复用。

## 5. Media `00b7/0a`

Media header 位于绝对 offset 80，共 10 字节：

| Offset | Size | 类型 | 说明 |
|---:|---:|---|---|
| 80 | 2 | u16le | media type |
| 82 | 2 | u16le | frame/packet sequence |
| 84 | 2 | u16le | fragment count |
| 86 | 2 | u16le | 1-based fragment index |
| 88 | 2 | u16le | 本 slot 有效字节数 |
| 90 | ... | bytes | media payload |

### JPEG（type 1）

- UDP 逻辑长度固定 1290：80-byte envelope + 10-byte media header + 1200-byte slot。
- 一帧通常分 7 片；最后一片只取 `valid_length`，不得拼接 padding。
- 按 sequence 聚合，可容忍乱序；所有 1..N 片存在后拼接。
- 完整帧以 `ffd8` 开始、`ffd9` 结束。
- 捕获得到 230 帧，640×480 JFIF，45.061173s 至 54.129880s，约 25 FPS。

### Audio（type 3）

- 逻辑长度固定 602：80 + 10 + 512。
- PCM 为 mono、8 kHz、signed 16-bit little-endian。
- 每包 256 samples，即 32 ms。
- 门口机→Pad 的 declared length 为 0；Pad→门口机为 602。
- 双向音频从 50.924707s 开始，Pad 接听后约 0.99 秒出现。

## 6. 捕获时序

| 时间 | Frame | 事件 |
|---:|---:|---|
| 42.150088 | 2 | 房间 discovery |
| 43.162706 | 14 | bootstrap request |
| 43.164778 | 15 | bootstrap reply |
| 43.179387 | 18 | 首次 session request |
| 43.326102 | 21 | Pad capability reply |
| 45.061173 | 43 | 首个完整 JPEG |
| 49.933180 | 919 | Pad answer |
| 50.924707 | 1111 | 双向 audio 开始 |
| 51.559897 | 1296 | unlock |
| 54.090359 | 1985 | Pad hangup |
| 54.091538 | 1986-1988 | 门口机重复 hangup |
| 54.097089 | 1992 | post-call snapshot 开始 |

状态机：

```text
Idle --00b7/01--> Ringing --00b7/05--> Connected
  ^                   |                    |
  +------1e-----------+---------1e---------+
                                           +--06--> Connected
```

门口机没有对 `05` 单独回复；它通过继续媒体并随后开始双向音频体现接听状态。因此物理
Pad 与远端客户端的 first-answer-wins 必须在桥上集中观察/仲裁，不能靠两个独立客户端
自行判断。

## 7. 快照 family `0x009b` / `0x00b4`

捕获中的文件信息包含：

- path：`/bffs1`
- filename：`cap0904004745.jpeg`
- station：`M00000000000`

`00b4/04` 使用约 1200 字节数据 slot，共 26 个数据消息。`00b4/01` 为文件请求，
`02` 返回长度/分片信息，`03` 开始，`04` 数据，`05` 为接收确认（具体字段语义仍需
更多样本验证）。该传输不参与实时画面，首版只解析、记录，不主动发起。

## 8. 安全与实现约束

- 只接受配置的 station ID、IP 和 MAC；任何值均不得仅依赖 UDP 源地址认证。
- 未处于远端已接听且 owner 为 remote 时，不得发送真实 unlock。
- 一个上层 command ID 只能执行一次，重连重试返回缓存结果。
- bridge/NFQUEUE 故障必须 fail-open，保证原 Pad 在程序退出后恢复。
- 文档与实现仅用于用户获授权的自有门禁网络。

