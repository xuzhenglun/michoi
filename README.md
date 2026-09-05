# michoi

`michoi` is a clean-room Rust implementation of the `PENGUIN0` LAN
intercom seen in `testdata/pad.cap`: the **Agent** that captures the door
station traffic, arbitrates who owns a call, injects the answer / unlock /
hangup packets, and exposes all of that to smart-home backends over standard
protocols. It targets macOS for replay/development and Linux / OpenWrt
`ramips/mt76x8` for packet capture and control injection.

The decoded installation is room station `S00000000000` (`192.168.124.61`) and door station `M00000000000` (`192.168.124.2`). UDP 10008
is discovery; UDP 10000 carries call control, fragmented JPEG and PCM audio.
The complete evidence-backed wire description is in
[`docs/PENGUIN0.md`](docs/PENGUIN0.md); component boundaries are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the Agent's public API is
[`docs/openapi.yaml`](docs/openapi.yaml).

## Implementation status

| Area | Status |
|---|---|
| Capture parser, GRO split, JPEG reconstruction, PCM extraction | implemented and tested against `testdata/pad.cap` |
| Exact answer/unlock/hangup encoders | implemented |
| First-answer state machine, unlock authorization, cooldown, idempotency | implemented |
| pcap replay Agent with capture timing (`tools fake-agent`) | implemented |
| Agent interface (`AgentControl` / `AgentMedia` traits) | implemented; used by the replay Agent, both Agent wire modes, the door station, and the HTTP server |
| HTTP control plane: REST + SSE, negotiation, bearer auth, Swagger UI | the only backend transport; verified end to end against the replay Agent |
| Proactive camera monitor (`00b8`) + elevator call (`0106`) over HTTP | implemented (`GET /v1/cameras`, `POST /v1/monitor`, `POST /v1/elevator`); protocol byte-exact, agent path tested against a fake door |
| Pre-roll media buffer (configurable seconds / bytes) | implemented |
| RTSP data plane (RTP/JPEG + PCMU, no re-encoding) | designed and validated with the captured frames; **not implemented yet** |
| Agent `tap` mode: Linux AF_PACKET bridge capture + raw control injection over HTTP | implemented; needs authorized on-device validation |
| Manual Pad blocking rule generator | implemented |
| Automatic NFQUEUE first-answer arbitration | **not complete; do not deploy automatic mode** |

Smart-home backends (Matter, Apple HomeKit) are developed separately and are
not part of this tree yet.

## Build and verify on macOS

Rust 1.87 or newer is required.

```sh
cargo test
cargo build --release
python3 -m unittest discover -v     # legacy Python analyzer tests
```

Analyze the capture:

```sh
cargo run -- tools analyze testdata/pad.cap
```

## Agent control plane (HTTP)

The Agent's public interface is plain HTTP/1.1, described in
[`docs/openapi.yaml`](docs/openapi.yaml) (OpenAPI 3.1, embedded in the binary
and served at `/openapi.yaml`).

- **Control plane**: REST for commands (`POST /v1/call/{claim,unlock,hangup}`
  with a client-chosen `command_id`, replayed idempotently), `GET /v1/state`,
  and a Server-Sent Events feed at `GET /v1/events` whose messages carry a
  sequence number. Streams are closed after a random 5–10 minutes; clients
  reconnect with `Last-Event-ID` and get the events they missed, or a
  `snapshot` event when the gap is no longer buffered. Events are broadcast:
  every subscriber receives every event.
- **Negotiation is mandatory**: every request needs `Accept`, every request
  with a body needs `Content-Type`; otherwise `406` / `415` with the supported
  list. Media types carry a codec version (`application/json; v=1`).
- **Authentication**: `Authorization: Bearer <token>` (`agent.token`);
  an empty token disables it for development.
- **Agent-side validation**: the Agent never forwards a command blindly.
  `claim` needs a ringing call the Pad has not answered, `hangup` needs an
  active call, `unlock` is rate limited by the cooldown and, like on the
  physical Pad, allowed at any time: idle, ringing without answering, or in
  a call (`security.unlock_requires_answer = true` restores the strict
  remote-owner-only rule). Rejections come back as `409` / `429` with a
  `CallError`.
- **Data plane**: RTSP (RTP/JPEG + PCMU, no re-encoding) is reported by
  `GET /v1/media`; until it lands, `GET /v1/snapshot.jpg` (with
  `X-Frame-Age-Ms`) and the transitional `POST /v1/talk` (PCM S16LE 8 kHz,
  chunked, one upload at a time) are available.
- **Pre-roll buffer**: the Agent keeps the last `media.history_secs` seconds
  of door video and audio in memory (capped by `media.history_max_kib`) so a
  late joiner can start a few seconds back and event clips have context.
  `GET /v1/media` reports `history_ms` (configured) and `buffered_ms`
  (currently held); `history_secs = 0` disables it.

The Rust side is split by interface: `agent_api` (the traits every backend
uses), `replay_agent` (in-process pcap replay), `agent` (the real Agent with
its two wire modes, `wire_udp` for `pad` and `wire_tap` for `tap`), and
`agent_server` (the HTTP adapter over any implementation, no HTTP crate needed).
Standalone builds call the traits directly; distributed builds go through HTTP.
The HTTP control plane is the only backend transport.

Run the replay Agent (a debugging tool) with the control plane and Swagger UI:

```sh
cargo run -- tools fake-agent --repeat-after 4 --http 127.0.0.1:8080 --token secret --swagger
curl -H 'Authorization: Bearer secret' -H 'Accept: application/json' http://127.0.0.1:8080/v1/state
curl -N -H 'Authorization: Bearer secret' -H 'Accept: text/event-stream' http://127.0.0.1:8080/v1/events
curl -X POST -H 'Authorization: Bearer secret' -H 'Accept: application/json' -H 'Content-Type: application/json' \
     -d '{"command_id":"c1"}' http://127.0.0.1:8080/v1/call/claim
open http://127.0.0.1:8080/swagger
```

### Software door station

`tools fake-agent` replays the capture on a fixed timeline (a locked demo). The
`door` subcommand is the interactive counterpart: a software door station you
operate, so a person can sit on the door side while the browser Pad or a
backend acts as the room. It serves the same HTTP control plane.

```sh
cargo run -- door testdata/pad.cap --http 127.0.0.1:8080 --token secret \
  --on-unlock 'echo opened; curl -s http://relay/open'
```

- Camera and microphone are the saved capture, looped at `--loop-fps` while a
  call is up (so the room sees a plausible door feed and hears door audio).
- The console reads `ring` (start a call), `hangup`, `quit` from stdin.
- `claim`, `unlock` and `hangup` invoke a callback: the shell command from
  `--on-answer` / `--on-unlock` / `--on-hangup` (with `DOOR_EVENT` and
  `DOOR_SESSION` in the environment), or, when none is set, a log line and
  noop. This is where "open the real door" is wired.
- The visitor's talk-back audio is written to a file by default
  (`visitor-talk.s16le`, raw S16LE 8 kHz mono; override with `--audio-out`).
  Pass `--play` to hear it through ffplay, or `--player <cmd>` for a custom
  player.

Point the browser Pad or `scripts/agent-http-test.py` at it as usual; type
`ring` in the door console to raise a call.

To pretend to be the door station and ring a **real** room Pad (or another
Agent), `tools emit-door` synthesizes the call from the protocol — it does not
replay the capture. Every datagram (`00b7/01` ring, `00b7/0a` video and
audio, keepalive, hangup) is built by our code from a configured door/room
identity, so a real Pad's response tells you whether the protocol analysis is
right. The camera is a directory of JPEG files (a fake camera device); audio
is a raw-PCM file or silence.

```sh
cargo run -- tools emit-door 192.168.104.108
# room IP defaults to the target; set the Pad's own station id if it checks it:
cargo run -- tools emit-door 192.168.104.108 --room-id S00XXXXXXXXX --frames testdata/frames
```

It binds the control port, sends the ring, streams video/audio and keepalives,
and listens for the Pad's replies, reporting and tallying the capability reply
(`00b7/03`), answer (`00b7/05`), **unlock** (`00b7/06`) and **voice**
(`00b7/0a` audio). The Pad's voice is written to a file by default
(`pad-voice.s16le`, raw S16LE 8 kHz mono; override with `--audio-out`); pass
`--play` to hear it through ffplay, or `--player <cmd>` for a custom player.
Answer on the Pad and watch the round-trip summary. `--door-id` / `--door-ip`
set the door's own identity; `--seconds` bounds the run.

The Pad's IP can be resolved from its room Station ID over the private UDP
10008 discovery protocol (an ARP-like "who has this room?" broadcast; the Pad
answers from its own address):

```sh
cargo run -- tools resolve S00000000000 --broadcast 192.168.124.255
# S00000000000 -> 192.168.124.61
cargo run -- tools emit-door --room-id S00000000000 --broadcast 192.168.124.255
```

Discovery is built into `tools emit-door`: omit the target and it resolves the Pad
IP from `--room-id` over UDP 10008 (`--broadcast` sets where to ask, default
`255.255.255.255`), then rings it. Pass an explicit `ip` / `ip:port` target to
skip discovery. `scripts/fake-pad-discovery.py` answers a discovery query for
testing.

The reconstruction is checked in unit tests: `session_request` reproduces the
captured ring byte for byte, and `jpeg_packets` reproduces the captured
fragmentation and round-trips a frame. `scripts/fake-pad.py` answers, unlocks
and sends a voice packet so the emulator can be tested end to end without
hardware. This is the harness for validating the Agent and, later, the
HAP/Matter backends when the real door and Pad are far apart.

### Full loop on one machine: `agent --mode pad`

In `pad` mode the Agent *is* the Pad on a plain UDP socket, so the whole chain
runs on a laptop with no hardware and no bridge: `tools emit-door` (the
synthesized door) rings it, it answers the paging / bootstrap / session
handshake and fans the door's video and audio out over the same HTTP control
plane, and the browser Pad drives it. Answer / unlock / talk from the browser
are sent back to the door as Pad-originated packets. Unlike the live Agent it
needs no AF_PACKET, so it runs on macOS too.

```sh
# terminal 1: the Agent as the Pad + HTTP control plane (+ browser Pad at /)
cargo run -- agent --mode pad --device-id S00000000000 --http 127.0.0.1:8080

# terminal 2: ring it as a synthesized door station
cargo run -- tools emit-door 127.0.0.1 --frames testdata/frames
```

Then open `http://127.0.0.1:8080/`: the page rings, shows the door picture,
and its answer / unlock / talk buttons drive `emit-door` (which prints the
`00b7/05` answer, `00b7/06` unlock and voice it receives back). `emit-door`
binds an ephemeral port automatically when the Agent already holds the
control port. `pad` mode answers UDP 10008 discovery, so `tools emit-door
--discover` can find it too.

### Browser Pad

The Agent serves (optionally: on by default, off with `web_ui = false` in the
config or `--no-web-ui` on the demo subcommands) a self-contained page at
`/pad` (also `/`) that behaves
like the physical room station: ring alert with a Web Audio ringtone, live
door picture and sound, answer, unlock (at any time, no need to answer
first), hang up, and hold-to-talk. It has no external assets and no build
step; the token is stored in the browser and appended as `?token=` where
headers are impossible (`EventSource`, `<img>`, WebSocket).

```sh
cargo run -- tools fake-agent --repeat-after 4 --http 127.0.0.1:8080 --token secret
open http://127.0.0.1:8080/pad      # enter "secret" in the settings dialog
```

Browser transports, all served by the same HTTP server:

| Direction | Endpoint | Format |
|---|---|---|
| picture | `GET /v1/stream.mjpeg` | `multipart/x-mixed-replace`, latest frame first, `X-Pts-Us` per part |
| sound | `GET /v1/audio.pcm` | `audio/L16; rate=8000; channels=1`, chunked, played through Web Audio |
| talk-back | `GET /v1/talk.ws` (WebSocket) | binary PCM S16LE 8 kHz; same one-at-a-time rule as `POST /v1/talk` |
| state | `GET /v1/events` | SSE, the browser resumes with `Last-Event-ID` by itself |

WebSocket exists only because browsers cannot stream an HTTP/1.1 request
body; every other path is plain HTTP. The microphone needs a secure context,
so hold-to-talk works on `localhost` or behind HTTPS, not on a plain
`http://192.168.x.x` page.

`scripts/agent-http-test.py --browser` additionally checks the page, the
MJPEG and PCM streams and the WebSocket talk-back with a raw RFC 6455
client.

`scripts/agent-http-test.py` (standard library only) runs the whole contract
against a running Agent: negotiation and authentication errors, the call
command flow with idempotent replay and cooldown, snapshot age, exclusive
talk-back, and SSE delivery plus `Last-Event-ID` resume:

```sh
python3 scripts/agent-http-test.py http://127.0.0.1:8080 --token secret
```

`--repeat-after` makes the replayed call ring again every few seconds; the
call rings for about 7 s before the captured Pad answers, so commands that
need a ringing call must land inside that window (the test script waits for
the `call_started` event).

## OpenWrt copy mode

Copy and edit [`config.example.toml`](config.example.toml). Determine MACs and
port direction first:

```sh
tcpdump -eni br-lan 'udp port 10000 or udp port 10008'
swconfig dev switch0 show
```

Build with an OpenWrt 24.10.4 SDK matching `ramips/mt76x8`:

```sh
rustup toolchain install nightly --component rust-src
./scripts/build-openwrt.sh /path/to/openwrt-sdk
```

The script rebuilds static musl `std` for Rust's Tier-3
`mipsel-unknown-linux-musl` target, uses the SDK linker, enables AF_PACKET, and
fails if the stripped executable exceeds 8 MiB. The exact MIPS binary cannot be
produced without that matching SDK/sysroot.

Install the binary, config, and procd init script, but initially leave the
physical Pad unblocked. Validate passive capture logs. Then print and review the
manual rule:

```sh
/usr/sbin/michoi tools check-config /etc/michoi/config.toml
/usr/sbin/michoi tools nft-rules /etc/michoi/config.toml
/usr/sbin/michoi agent /etc/michoi/config.toml
```

Apply the printed rule only during a supervised test. It matches the physical
Pad bridge ingress interface rather than merely its MAC, so locally injected
replacement packets are not dropped. Removing table `bridge michoi`
restores the Pad path:

```sh
nft delete table bridge michoi
```

AF_PACKET requires root or `CAP_NET_RAW`. Keep UDP 10000/10008 private and do
not expose an unauthenticated control plane outside a trusted LAN/VPN. The live
Agent accepts packets only when configured source MAC, IP, station IDs and
endpoint IPs all match. A real unlock is rejected unless the remote owner won
the current call.

## Debug logging

`RUST_LOG` sets verbosity (via `tracing`/`EnvFilter`). At `trace` every
control packet is logged as hex on send and receive, across the tools and
both Agent wires; the data plane (media, opcode `0x0a`) is excluded so the
trace stays readable. Discovery (UDP 10008) is included.

```sh
RUST_LOG=trace michoi tools elevator M00000000000 --broadcast 192.168.124.255
RUST_LOG=michoi=trace michoi agent config.toml   # crate-scoped
```

## Legacy Python tools

The original dependency-free analyzer remains under `pad_intercom/`:

```sh
python3 -m pad_intercom.analyze testdata/pad.cap
python3 -m unittest discover -v
```

It is not used by the OpenWrt Rust binary.
