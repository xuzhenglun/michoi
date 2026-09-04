//! Agent building blocks: the pcap replay timeline and the live AF_PACKET
//! capture Agent.
//!
//! Both feed the same HTTP control plane (`agent_server`) through the
//! `AgentControl` / `AgentMedia` traits: `ReplayAgent` (in `replay_agent`)
//! replays `pad.cap`, and `LiveAgent` (here, Linux only) captures the real
//! bridge and injects control/audio. HTTP + SSE is the only backend transport.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{Context, Result};

use crate::pcap::read_udp;
use crate::protocol::{
    split_coalesced, Endpoints, JpegReassembler, Message, FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER,
    OP_HANGUP, OP_MEDIA, OP_REQUEST, OP_UNLOCK,
};
use crate::transport::{AgentEvent, FrameKind, WireFrame};

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use std::sync::{Arc, Mutex};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use std::time::{Duration, Instant};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use futures_util::{future::BoxFuture, FutureExt};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use tokio::sync::broadcast;
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::agent_api::{
    now_ms, AgentControl, AgentMedia, AudioChunk, AudioInfo, CallAction, CallError, CallState,
    CommandCache, CommandResult, Event, EventKind, EventLog, MediaHistory, MediaInfo, MediaRing,
    Owner, VideoFrame, VideoInfo,
};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::agent_server::ServerConfig;
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::protocol::{audio_packet, session_control};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::state::{CallMachine, CallPhase};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::bridge::PacketSocket;
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::config::IntercomConfig;
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::ethernet::{build_udp_ipv4, EthernetUdp, MacAddress};

#[derive(Debug, Clone)]
pub struct TimedFrame {
    pub offset_micros: u64,
    pub frame: WireFrame,
}

pub fn replay_timeline(path: impl AsRef<Path>) -> Result<Vec<TimedFrame>> {
    let records = read_udp(path)?;
    let first_session = records
        .iter()
        .flat_map(|record| {
            split_coalesced(&record.payload)
                .into_iter()
                .map(move |raw| (record, raw))
        })
        .find_map(|(record, raw)| {
            let msg = Message::parse(raw).ok()?;
            (msg.family == FAMILY_SESSION && msg.opcode == OP_REQUEST)
                .then_some(record.timestamp_micros)
        })
        .context("pcap has no PENGUIN0 session request")?;
    let mut jpeg = JpegReassembler::default();
    let mut out = Vec::new();
    let mut sequence = 0_u32;
    let mut session_id = 0_u64;
    let mut started = false;
    let mut ended = false;

    for record in &records {
        if record.timestamp_micros < first_session {
            continue;
        }
        for raw in split_coalesced(&record.payload) {
            let Ok(msg) = Message::parse(raw) else {
                continue;
            };
            if msg.family != FAMILY_SESSION {
                continue;
            }
            let offset = record.timestamp_micros - first_session;
            if msg.opcode == OP_REQUEST && !started {
                started = true;
                session_id = first_session.max(1);
                let endpoints = msg.endpoints().unwrap_or_else(Endpoints::captured);
                let event = AgentEvent::CallStarted {
                    door_id: endpoints.door.id,
                    room_id: endpoints.room.id,
                };
                out.push(TimedFrame {
                    offset_micros: offset,
                    frame: WireFrame::cbor(FrameKind::Event, session_id, sequence, offset, &event)?,
                });
                sequence += 1;
            }
            if msg.opcode == OP_ANSWER || msg.opcode == OP_UNLOCK {
                let event = AgentEvent::PadActionObserved { opcode: msg.opcode };
                out.push(TimedFrame {
                    offset_micros: offset,
                    frame: WireFrame::cbor(FrameKind::Event, session_id, sequence, offset, &event)?,
                });
                sequence += 1;
            }
            if msg.opcode == OP_HANGUP && !ended {
                ended = true;
                let event = AgentEvent::CallEnded {
                    reason: "captured_hangup".into(),
                };
                out.push(TimedFrame {
                    offset_micros: offset,
                    frame: WireFrame::cbor(FrameKind::Event, session_id, sequence, offset, &event)?,
                });
                sequence += 1;
            }
            if msg.opcode != OP_MEDIA || record.source_ip != Ipv4Addr::new(192, 168, 124, 2) {
                continue;
            }
            let Some(media) = msg.media() else { continue };
            if media.media_type == MEDIA_AUDIO {
                out.push(TimedFrame {
                    offset_micros: offset,
                    frame: WireFrame {
                        kind: FrameKind::DoorPcm,
                        flags: 0,
                        session_id,
                        sequence,
                        timestamp_micros: offset,
                        payload: media.data.to_vec(),
                    },
                });
                sequence += 1;
            } else if let Some(frame) = jpeg.push(&media) {
                out.push(TimedFrame {
                    offset_micros: offset,
                    frame: WireFrame {
                        kind: FrameKind::Jpeg,
                        flags: 0,
                        session_id,
                        sequence,
                        timestamp_micros: offset,
                        payload: frame,
                    },
                });
                sequence += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
pub struct LivePolicy {
    pub cooldown: Duration,
    pub unlock_requires_answer: bool,
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
const LIVE_AGENT_ID: &str = "openwrt-live";

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
struct LiveCall {
    machine: CallMachine,
    door_id: Option<String>,
    room_id: Option<String>,
    since_ms: Option<u64>,
}

/// The live capture Agent: it observes the bridge, tracks call state, fans out
/// door media, and injects claim/unlock/hangup/talk on the wire. It implements
/// the same traits as `ReplayAgent`, so `agent_server` serves it identically.
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
pub struct LiveAgent {
    call: Mutex<LiveCall>,
    events: EventLog,
    commands: CommandCache,
    video: broadcast::Sender<VideoFrame>,
    audio: broadcast::Sender<AudioChunk>,
    latest: Mutex<Option<VideoFrame>>,
    history: MediaRing,
    started: Instant,
    socket: Arc<PacketSocket>,
    config: IntercomConfig,
    inject_seq: AtomicU32,
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
impl LiveAgent {
    fn new(
        socket: Arc<PacketSocket>,
        config: IntercomConfig,
        policy: LivePolicy,
        history: Duration,
        history_max_bytes: usize,
        started: Instant,
    ) -> Arc<Self> {
        let (video, _) = broadcast::channel(32);
        let (audio, _) = broadcast::channel(128);
        Arc::new(Self {
            call: Mutex::new(LiveCall {
                machine: CallMachine::with_policy(policy.cooldown, policy.unlock_requires_answer),
                door_id: None,
                room_id: None,
                since_ms: None,
            }),
            events: EventLog::new(256, 64),
            commands: CommandCache::new(256),
            video,
            audio,
            latest: Mutex::new(None),
            history: MediaRing::new(history, history_max_bytes),
            started,
            socket,
            config,
            inject_seq: AtomicU32::new(1),
        })
    }

    fn next_seq(&self) -> u32 {
        self.inject_seq.fetch_add(1, Ordering::Relaxed)
    }

    fn session_string(&self) -> String {
        self.call.lock().unwrap().machine.state().session_id.to_string()
    }

    // --- capture side: called by capture_loop as wire events arrive ---

    fn on_call_started(&self, session_id: u64, door_id: String, room_id: String) {
        {
            let mut call = self.call.lock().unwrap();
            call.machine.start_call(session_id);
            call.door_id = Some(door_id.clone());
            call.room_id = Some(room_id.clone());
            call.since_ms = Some(now_ms());
        }
        self.events.push(EventKind::CallStarted {
            session_id: session_id.to_string(),
            door_id,
            room_id,
        });
    }

    fn on_pad_answer(&self) {
        let (accepted, id) = {
            let mut call = self.call.lock().unwrap();
            let id = call.machine.state().session_id;
            let accepted = call.machine.pad_answer().is_ok();
            if accepted {
                call.since_ms = Some(now_ms());
            }
            (accepted, id)
        };
        if accepted {
            self.events.push(EventKind::PadAnswered {
                session_id: id.to_string(),
            });
        }
    }

    fn on_pad_unlock(&self) {
        let (pad_owns, id) = {
            let call = self.call.lock().unwrap();
            let state = call.machine.state();
            (state.owner == Owner::Pad, state.session_id)
        };
        if pad_owns {
            self.events.push(EventKind::Unlocked {
                session_id: id.to_string(),
                by: Owner::Pad,
            });
        }
    }

    fn on_wire_hangup(&self) {
        let (active, id) = {
            let mut call = self.call.lock().unwrap();
            let id = call.machine.state().session_id;
            let active = call.machine.state().phase != CallPhase::Idle;
            call.machine.hangup();
            call.since_ms = Some(now_ms());
            (active, id)
        };
        if active {
            // A real hangup ends any takeover: restore the physical Pad path.
            restore_physical_pad();
            self.events.push(EventKind::CallEnded {
                session_id: id.to_string(),
                reason: "wire_hangup".into(),
            });
        }
    }

    fn push_video(&self, frame: VideoFrame) {
        *self.latest.lock().unwrap() = Some(frame.clone());
        self.history.push_video(&frame);
        let _ = self.video.send(frame);
    }

    fn push_audio(&self, chunk: AudioChunk) {
        self.history.push_audio(&chunk);
        let _ = self.audio.send(chunk);
    }

    // --- backend side: idempotent commands, injected on the wire ---

    fn execute(&self, action: CallAction, command_id: &str) -> CommandResult {
        if let Some(replayed) = self.commands.get(command_id) {
            return replayed;
        }
        let opcode = match action {
            CallAction::Claim => OP_ANSWER,
            CallAction::Unlock => OP_UNLOCK,
            CallAction::Hangup => OP_HANGUP,
        };
        let session = self.session_string();
        let outcome: Result<EventKind, CallError> = {
            let mut call = self.call.lock().unwrap();
            match action {
                CallAction::Claim => call
                    .machine
                    .remote_answer()
                    .map(|()| {
                        call.since_ms = Some(now_ms());
                        EventKind::RemoteAnswered {
                            session_id: session.clone(),
                        }
                    })
                    .map_err(CallError::from),
                CallAction::Unlock => call
                    .machine
                    .unlock(Instant::now())
                    .map(|()| EventKind::Unlocked {
                        session_id: session.clone(),
                        by: Owner::Remote,
                    })
                    .map_err(CallError::from),
                CallAction::Hangup => {
                    if call.machine.state().phase == CallPhase::Idle {
                        Err(CallError::NoCall)
                    } else {
                        call.machine.hangup();
                        call.since_ms = Some(now_ms());
                        Ok(EventKind::CallEnded {
                            session_id: session.clone(),
                            reason: "remote_hangup".into(),
                        })
                    }
                }
            }
        };
        let result = match outcome {
            Ok(event) => {
                // The state machine accepted it; now inject the packet.
                if let Err(error) = inject_control(&self.socket, &self.config, opcode, self.next_seq())
                {
                    tracing::warn!(%error, ?action, "control injection failed");
                    CommandResult::rejected(command_id, CallError::AgentOffline)
                } else {
                    // First-answer takeover: a remote claim silences and locks
                    // out the physical Pad; a remote hangup restores it. Both
                    // are fail-open inside their helpers.
                    if opcode == OP_ANSWER {
                        silence_physical_pad(&self.socket, &self.config, self.next_seq());
                    }
                    if opcode == OP_HANGUP {
                        restore_physical_pad();
                    }
                    self.events.push(event);
                    CommandResult::ok(command_id)
                }
            }
            Err(error) => CommandResult::rejected(command_id, error),
        };
        self.commands.store(&result);
        tracing::info!(?action, command_id, ok = result.ok, error = ?result.error, "command");
        result
    }
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
impl AgentControl for LiveAgent {
    fn agent_id(&self) -> String {
        LIVE_AGENT_ID.into()
    }

    fn state(&self) -> CallState {
        let call = self.call.lock().unwrap();
        let state = call.machine.state();
        CallState {
            phase: state.phase,
            owner: state.owner,
            session_id: (state.phase != CallPhase::Idle).then(|| state.session_id.to_string()),
            door_id: call.door_id.clone(),
            room_id: call.room_id.clone(),
            since_ms: call.since_ms,
            agent_id: LIVE_AGENT_ID.into(),
            connected: true,
            uptime_ms: self.started.elapsed().as_millis() as u64,
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn recent(&self, after_seq: u64) -> Option<Vec<Event>> {
        self.events.recent(after_seq)
    }

    fn command(&self, action: CallAction, command_id: &str) -> BoxFuture<'_, CommandResult> {
        let result = self.execute(action, command_id);
        async move { result }.boxed()
    }
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
impl AgentMedia for LiveAgent {
    fn clock_us(&self) -> u64 {
        self.started.elapsed().as_micros() as u64
    }

    fn video(&self) -> broadcast::Receiver<VideoFrame> {
        self.video.subscribe()
    }

    fn audio(&self) -> broadcast::Receiver<AudioChunk> {
        self.audio.subscribe()
    }

    fn snapshot(&self) -> Option<VideoFrame> {
        self.latest.lock().unwrap().clone()
    }

    fn history(&self, since_us: u64) -> MediaHistory {
        self.history.history(since_us)
    }

    fn media_info(&self) -> MediaInfo {
        let allowed = {
            let call = self.call.lock().unwrap();
            let state = call.machine.state();
            call.machine.remote_media_allowed(state.session_id)
        };
        MediaInfo {
            rtsp_url: None,
            video: VideoInfo {
                codec: "jpeg".into(),
                width: 640,
                height: 480,
            },
            audio: AudioInfo {
                codec: "pcm_s16le".into(),
                sample_rate: 8000,
                channels: 1,
            },
            talk: allowed,
            history_ms: self.history.window().as_millis() as u64,
            buffered_ms: self.history.buffered().as_millis() as u64,
        }
    }

    fn talk(&self, chunk: AudioChunk) -> BoxFuture<'_, Result<(), CallError>> {
        let allowed = {
            let call = self.call.lock().unwrap();
            let state = call.machine.state();
            call.machine.remote_media_allowed(state.session_id)
        };
        let result = if allowed {
            inject_audio(&self.socket, &self.config, 0, &chunk.pcm, self.next_seq())
                .map(|_| ())
                .map_err(|_| CallError::AgentOffline)
        } else {
            Err(CallError::UnlockNotAllowed)
        };
        async move { result }.boxed()
    }
}

/// Open the bridge, start the blocking capture, and serve the live Agent over
/// the HTTP control plane (REST + SSE). Linux only.
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
pub async fn run_live_agent(
    server: ServerConfig,
    intercom: IntercomConfig,
    policy: LivePolicy,
    history: Duration,
    history_max_bytes: usize,
) -> Result<()> {
    MacAddress::parse(
        intercom
            .pad_mac
            .as_deref()
            .context("intercom.pad_mac is required in copy mode")?,
    )?;
    MacAddress::parse(
        intercom
            .door_mac
            .as_deref()
            .context("intercom.door_mac is required in copy mode")?,
    )?;
    anyhow::ensure!(
        intercom.bridge_interface != "CONFIGURE_ME",
        "bridge_interface is not configured"
    );
    let socket = Arc::new(PacketSocket::open(&intercom.bridge_interface)?);
    // Clear any silence table left over from a previous run (fail-open).
    restore_physical_pad();
    let started = Instant::now();
    let agent = LiveAgent::new(socket, intercom, policy, history, history_max_bytes, started);

    let capture = agent.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = capture_loop(&capture, started) {
            tracing::error!(%error, "live packet capture stopped");
        }
    });

    tracing::info!(
        listen = %server.listen,
        interface = agent.socket.interface(),
        "live Agent serving HTTP control plane"
    );
    crate::agent_server::serve(server, agent).await
}

/// Blocking bridge capture: filter door<->Pad control traffic, drive the call
/// state machine, and fan out door media into the `LiveAgent`.
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn capture_loop(agent: &LiveAgent, started: Instant) -> Result<()> {
    let config = &agent.config;
    let socket = &agent.socket;
    let door_mac = MacAddress::parse(config.door_mac.as_deref().context("door_mac missing")?)?;
    let pad_mac = MacAddress::parse(config.pad_mac.as_deref().context("pad_mac missing")?)?;
    let mut buffer = vec![0_u8; 65_536];
    let mut jpeg = JpegReassembler::default();
    let mut next_session = 1_u64;
    loop {
        let size = socket.receive(&mut buffer)?;
        let Ok(udp) = EthernetUdp::parse(&buffer[..size]) else {
            continue;
        };
        if udp.source_port != config.control_port && udp.destination_port != config.control_port {
            continue;
        }
        if !matches!(udp.source_ip, ip if ip == config.door_ip || ip == config.room_ip) {
            continue;
        }
        if (udp.source_ip == config.door_ip && udp.source_mac != door_mac)
            || (udp.source_ip == config.room_ip && udp.source_mac != pad_mac)
        {
            continue;
        }
        for raw in split_coalesced(udp.payload) {
            let Ok(message) = Message::parse(raw) else {
                continue;
            };
            if message.family != FAMILY_SESSION {
                continue;
            }
            let Some(endpoints) = message.endpoints() else {
                continue;
            };
            if endpoints.door.id != config.door_id
                || endpoints.door.ip != config.door_ip
                || endpoints.room.id != config.room_id
                || endpoints.room.ip != config.room_ip
            {
                continue;
            }
            let is_idle =
                agent.call.lock().unwrap().machine.state().phase == CallPhase::Idle;
            match message.opcode {
                OP_REQUEST if is_idle => {
                    let id = next_session;
                    next_session += 1;
                    agent.on_call_started(id, endpoints.door.id, endpoints.room.id);
                }
                OP_ANSWER if udp.source_ip == config.room_ip => agent.on_pad_answer(),
                OP_UNLOCK if udp.source_ip == config.room_ip => agent.on_pad_unlock(),
                OP_HANGUP if !is_idle => agent.on_wire_hangup(),
                _ => {}
            }
            if message.opcode != OP_MEDIA || udp.source_ip != config.door_ip {
                continue;
            }
            let Some(media) = message.media() else {
                continue;
            };
            let pts_us = started.elapsed().as_micros() as u64;
            if media.media_type == MEDIA_AUDIO {
                agent.push_audio(AudioChunk {
                    pts_us,
                    pcm: Arc::from(media.data),
                });
            } else if let Some(frame) = jpeg.push(&media) {
                agent.push_video(VideoFrame {
                    pts_us,
                    jpeg: Arc::from(frame.as_slice()),
                });
            }
        }
    }
}

/// Install the silence table and inject a spoofed door→Pad hangup so the
/// physical Pad stops ringing at once. Every step is fail-open: a failure
/// leaves the Pad working and is only logged.
///
/// NOTE: needs authorized on-device validation. The capture shows the door
/// station uses a door→Pad `00b7/1e` to tear the call down, so the reset
/// reuses that exact envelope, but that a *mid-call* injected hangup silences
/// this Pad model is not proven by `pad.cap` alone.
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn silence_physical_pad(socket: &PacketSocket, config: &IntercomConfig, sequence: u32) {
    match crate::firewall::pad_silence_rules(config) {
        Ok(rules) => {
            if let Err(error) = nft_apply(&rules) {
                tracing::warn!(%error, "failed to install Pad silence rules; Pad stays live");
            } else {
                tracing::info!("physical Pad silenced (door<->Pad control dropped)");
            }
        }
        Err(error) => tracing::warn!(%error, "cannot build Pad silence rules"),
    }
    if let Err(error) = inject_pad_reset(socket, config, sequence) {
        tracing::warn!(%error, "failed to inject door->Pad hangup reset");
    }
}

/// Remove the silence table so the physical Pad path is restored.
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn restore_physical_pad() {
    if let Err(error) = nft_flush() {
        tracing::warn!(%error, "failed to flush Pad silence table");
    } else {
        tracing::info!("physical Pad path restored");
    }
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn nft_apply(rules: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("spawning nft")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(rules.as_bytes())?;
    let status = child.wait()?;
    anyhow::ensure!(status.success(), "nft -f exited with {status}");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn nft_flush() -> Result<()> {
    let status = std::process::Command::new("nft")
        .args(crate::firewall::flush_table_command().split_whitespace())
        .status()
        .context("running nft delete")?;
    // A missing table is fine; the goal is that it is gone.
    let _ = status;
    Ok(())
}

/// Inject a `00b7/1e` hangup addressed door→Pad (source door, dest Pad), the
/// reverse of [`inject_payload`], so only the physical Pad sees it.
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn inject_pad_reset(socket: &PacketSocket, config: &IntercomConfig, sequence: u32) -> Result<()> {
    let endpoints = Endpoints {
        door: crate::protocol::Station::new(&config.door_id, config.door_ip),
        room: crate::protocol::Station::new(&config.room_id, config.room_ip),
    };
    let payload = session_control(OP_HANGUP, &endpoints)?;
    let pad_mac = MacAddress::parse(config.pad_mac.as_deref().context("pad_mac missing")?)?;
    let door_mac = MacAddress::parse(config.door_mac.as_deref().context("door_mac missing")?)?;
    let ethernet = build_udp_ipv4(
        door_mac,
        pad_mac,
        config.door_ip,
        config.room_ip,
        config.control_port,
        config.control_port,
        &payload,
        sequence as u16,
    )?;
    let sent = socket.send(&ethernet)?;
    anyhow::ensure!(sent == ethernet.len(), "short AF_PACKET send");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn inject_control(
    socket: &PacketSocket,
    config: &IntercomConfig,
    opcode: u32,
    sequence: u32,
) -> Result<()> {
    let endpoints = Endpoints {
        door: crate::protocol::Station::new(&config.door_id, config.door_ip),
        room: crate::protocol::Station::new(&config.room_id, config.room_ip),
    };
    let payload = session_control(opcode, &endpoints)?;
    inject_payload(socket, config, &payload, sequence)
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn inject_audio(
    socket: &PacketSocket,
    config: &IntercomConfig,
    audio_sequence: u16,
    pcm: &[u8],
    ip_sequence: u32,
) -> Result<()> {
    let endpoints = Endpoints {
        door: crate::protocol::Station::new(&config.door_id, config.door_ip),
        room: crate::protocol::Station::new(&config.room_id, config.room_ip),
    };
    let payload = audio_packet(audio_sequence, pcm, &endpoints)?;
    inject_payload(socket, config, &payload, ip_sequence)
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn inject_payload(
    socket: &PacketSocket,
    config: &IntercomConfig,
    payload: &[u8],
    sequence: u32,
) -> Result<()> {
    let pad_mac = MacAddress::parse(config.pad_mac.as_deref().context("pad_mac missing")?)?;
    let door_mac = MacAddress::parse(config.door_mac.as_deref().context("door_mac missing")?)?;
    let ethernet = build_udp_ipv4(
        pad_mac,
        door_mac,
        config.room_ip,
        config.door_ip,
        config.control_port,
        config.control_port,
        payload,
        sequence as u16,
    )?;
    let sent = socket.send(&ethernet)?;
    anyhow::ensure!(sent == ethernet.len(), "short AF_PACKET send");
    Ok(())
}
