//! The Agent: one object that stands for the household's Pad on the wire and
//! serves the HTTP control plane, in one of two modes.
//!
//! - `pad` (实体): this process *is* the Pad. It binds the control port,
//!   answers the door's discovery and handshake itself, and sends
//!   answer/unlock/talk as the Pad. Cross-platform.
//! - `tap` (旁路): a physical Pad stays in place. The Agent taps the bridge
//!   (AF_PACKET) to follow the door<->Pad call and, when a remote backend takes
//!   over, injects Pad-originated packets to the door, silences the physical
//!   Pad and tells it the call ended. Linux only.
//!
//! Everything above the wire is shared; the mode lives in a [`Wire`] impl
//! (`wire_udp`, `wire_tap`). Identity is one device id, the Pad's room station
//! id. The Pad's IP, the door's identity and both MACs are discovered
//! (UDP 10008) or learned from the first call and then pinned: later frames
//! that claim the same station from another IP/MAC are dropped with a warning
//! (trust on first use).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{future::BoxFuture, FutureExt};
use tokio::sync::broadcast;

use crate::agent_api::{
    now_ms, AgentControl, AgentMedia, AudioChunk, AudioInfo, CallAction, CallError, CallState,
    CommandCache, CommandResult, Event, EventKind, EventLog, MediaHistory, MediaInfo, MediaRing,
    Owner, VideoFrame, VideoInfo,
};
use crate::agent_server::ServerConfig;
use crate::config::{AgentMode, IntercomConfig};
use crate::emitter::resolve_pad;
use crate::ethernet::MacAddress;
use crate::protocol::{
    audio_packet, bootstrap_reply, session_control, session_reply, Endpoints, JpegReassembler,
    Message, Station, FAMILY_BOOTSTRAP, FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP,
    OP_KEEPALIVE, OP_MEDIA, OP_REQUEST, OP_UNLOCK,
};
use crate::state::{CallMachine, CallPhase};

/// Which station a wire datagram came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Door,
    Pad,
}

/// The two stations of this household as currently known. Fields start from
/// the configuration and are filled by discovery / learning, then pinned.
#[derive(Clone, Debug)]
pub struct Peers {
    /// The Pad we are or stand in for; `ip` may be unspecified until learned.
    pub room: Station,
    /// The door station, once configured, discovered or seen ringing.
    pub door: Option<Station>,
    pub door_mac: Option<MacAddress>,
    pub pad_mac: Option<MacAddress>,
    pub control_port: u16,
}

impl Peers {
    /// The endpoint block for Pad-originated packets, once the door is known.
    pub fn endpoints(&self) -> Option<Endpoints> {
        self.door.clone().map(|door| Endpoints {
            door,
            room: self.room.clone(),
        })
    }
}

/// What differs between the modes: how bytes reach the door and what happens
/// to the physical Pad. Everything else in the Agent is shared.
pub trait Wire: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    /// Pad-side handshake replies (bootstrap, capability). `pad` sends them;
    /// `tap` does nothing because the physical Pad answers.
    fn handshake_reply(&self, payload: &[u8], peers: &Peers) -> Result<()>;
    /// A Pad-originated packet to the door: claim, unlock, hangup, keepalive,
    /// talk audio.
    fn send_as_pad(&self, payload: &[u8], peers: &Peers) -> Result<()>;
    /// A remote backend won the ringing call.
    fn on_remote_claim(&self, peers: &Peers);
    /// The call ended, from either side.
    fn on_call_end(&self, peers: &Peers);
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub cooldown: Duration,
    pub unlock_requires_answer: bool,
}

struct Call {
    machine: CallMachine,
    since_ms: Option<u64>,
    next_session: u64,
}

pub struct Agent {
    mode: AgentMode,
    wire: Arc<dyn Wire>,
    peers: Mutex<Peers>,
    call: Mutex<Call>,
    events: EventLog,
    commands: CommandCache,
    video: broadcast::Sender<VideoFrame>,
    audio: broadcast::Sender<AudioChunk>,
    latest: Mutex<Option<VideoFrame>>,
    history: MediaRing,
    jpeg: Mutex<JpegReassembler>,
    started: Instant,
    audio_seq: AtomicU32,
    mismatches: AtomicU32,
}

impl Agent {
    pub fn new(
        mode: AgentMode,
        wire: Arc<dyn Wire>,
        peers: Peers,
        policy: Policy,
        history: Duration,
        history_max_bytes: usize,
    ) -> Arc<Self> {
        let (video, _) = broadcast::channel(32);
        let (audio, _) = broadcast::channel(128);
        Arc::new(Self {
            mode,
            wire,
            peers: Mutex::new(peers),
            call: Mutex::new(Call {
                machine: CallMachine::with_policy(policy.cooldown, policy.unlock_requires_answer),
                since_ms: None,
                next_session: 1,
            }),
            events: EventLog::new(256, 64),
            commands: CommandCache::new(256),
            video,
            audio,
            latest: Mutex::new(None),
            history: MediaRing::new(history, history_max_bytes),
            jpeg: Mutex::new(JpegReassembler::default()),
            started: Instant::now(),
            audio_seq: AtomicU32::new(0),
            mismatches: AtomicU32::new(0),
        })
    }

    pub fn mode(&self) -> AgentMode {
        self.mode
    }

    /// The Pad's room station id: the one configured identity.
    pub fn device_id(&self) -> String {
        self.peers.lock().unwrap().room.id.clone()
    }

    pub fn peers(&self) -> Peers {
        self.peers.lock().unwrap().clone()
    }

    fn agent_id(&self) -> String {
        format!("michoi-{}", self.mode.as_str())
    }

    fn session_string(&self) -> String {
        self.call.lock().unwrap().machine.state().session_id.to_string()
    }

    fn warn_mismatch(&self, what: &str, detail: String) {
        let n = self.mismatches.fetch_add(1, Ordering::Relaxed);
        if n < 5 || n % 100 == 0 {
            tracing::warn!(count = n + 1, "{what} does not match the pinned identity, ignoring: {detail}");
        }
    }

    // ---------------------------------------------------------------- identity

    /// The Pad's own IP, once a wire learns it (pad mode: our address toward
    /// the door; tap mode: from the endpoint block).
    pub fn set_room_ip_if_unset(&self, ip: Ipv4Addr) {
        let mut peers = self.peers.lock().unwrap();
        if peers.room.ip.is_unspecified() && !ip.is_unspecified() {
            peers.room.ip = ip;
            tracing::info!(%ip, id = %peers.room.id, "learned the Pad's IP");
        }
    }

    /// A station's IP seen on the wire outside a session (the UDP 10008
    /// discovery exchange in tap mode): pin it, or reject a change.
    pub fn learn_address(&self, side: Side, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() {
            return false;
        }
        let mut peers = self.peers.lock().unwrap();
        match side {
            Side::Pad => {
                if peers.room.ip.is_unspecified() {
                    peers.room.ip = ip;
                    tracing::info!(%ip, "learned the Pad's IP from discovery");
                    true
                } else if peers.room.ip == ip {
                    true
                } else {
                    let detail = format!("Pad IP {ip} (pinned {})", peers.room.ip);
                    drop(peers);
                    self.warn_mismatch("Pad IP", detail);
                    false
                }
            }
            Side::Door => match peers.door.as_mut() {
                None => {
                    peers.door = Some(Station::new(String::new(), ip));
                    tracing::info!(%ip, "learned the door's IP from discovery (id comes with the ring)");
                    true
                }
                Some(door) if door.ip.is_unspecified() => {
                    door.ip = ip;
                    tracing::info!(%ip, id = %door.id, "learned the door's IP from discovery");
                    true
                }
                Some(door) if door.ip == ip => true,
                Some(door) => {
                    let detail = format!("door IP {ip} (pinned {})", door.ip);
                    drop(peers);
                    self.warn_mismatch("door IP", detail);
                    false
                }
            },
        }
    }

    /// Pin the MAC of a station on first sight; afterwards a different MAC for
    /// the same station is rejected. Returns whether the frame is accepted.
    pub fn pin_mac(&self, side: Side, mac: MacAddress) -> bool {
        let mut peers = self.peers.lock().unwrap();
        let slot = match side {
            Side::Door => &mut peers.door_mac,
            Side::Pad => &mut peers.pad_mac,
        };
        match slot {
            None => {
                *slot = Some(mac);
                tracing::info!(?side, ?mac, "learned and pinned MAC");
                true
            }
            Some(pinned) if *pinned == mac => true,
            Some(pinned) => {
                let detail = format!("{side:?} MAC {mac:?} (pinned {pinned:?})");
                drop(peers);
                self.warn_mismatch("MAC", detail);
                false
            }
        }
    }

    /// Check a session endpoint block against the pinned household and learn
    /// what is still unknown. Returns the peers snapshot when accepted.
    fn accept_endpoints(&self, endpoints: &Endpoints) -> Option<Peers> {
        let mut peers = self.peers.lock().unwrap();
        if endpoints.room.id != peers.room.id {
            return None; // another household on the same bridge
        }
        if peers.room.ip.is_unspecified() {
            if !endpoints.room.ip.is_unspecified() {
                peers.room.ip = endpoints.room.ip;
                tracing::info!(ip = %endpoints.room.ip, "learned the Pad's IP from the call");
            }
        } else if peers.room.ip != endpoints.room.ip {
            let detail = format!("Pad IP {} (pinned {})", endpoints.room.ip, peers.room.ip);
            drop(peers);
            self.warn_mismatch("Pad IP", detail);
            return None;
        }
        match peers.door.as_mut() {
            None => {
                tracing::info!(id = %endpoints.door.id, ip = %endpoints.door.ip, "learned and pinned the door station");
                peers.door = Some(endpoints.door.clone());
            }
            // Address pinned from the observed discovery exchange; the id
            // arrives with the first ring.
            Some(door) if door.id.is_empty() && door.ip == endpoints.door.ip => {
                door.id = endpoints.door.id.clone();
                tracing::info!(id = %door.id, ip = %door.ip, "learned the door's station id from the call");
            }
            Some(door) if door.id == endpoints.door.id && door.ip.is_unspecified() => {
                door.ip = endpoints.door.ip;
                tracing::info!(id = %door.id, ip = %door.ip, "learned the door's IP from the call");
            }
            Some(door) if door.id == endpoints.door.id && door.ip == endpoints.door.ip => {}
            Some(door) => {
                let detail = format!(
                    "door {}@{} (pinned {}@{})",
                    endpoints.door.id, endpoints.door.ip, door.id, door.ip
                );
                drop(peers);
                self.warn_mismatch("door station", detail);
                return None;
            }
        }
        Some(peers.clone())
    }

    // ---------------------------------------------------------------- wire in

    /// One PENGUIN0 message from the wire, already attributed to a side.
    pub fn on_wire(&self, side: Side, raw: &[u8]) {
        let Ok(message) = Message::parse(raw) else {
            return;
        };
        if message.family == FAMILY_BOOTSTRAP && message.opcode == OP_REQUEST {
            if side == Side::Door {
                let peers = self.peers();
                if let Ok(reply) = bootstrap_reply(&peers.room) {
                    if let Err(error) = self.wire.handshake_reply(&reply, &peers) {
                        tracing::warn!(%error, "bootstrap reply failed");
                    }
                }
            }
            return;
        }
        if message.family != FAMILY_SESSION {
            return;
        }
        let Some(endpoints) = message.endpoints() else {
            return;
        };
        let Some(peers) = self.accept_endpoints(&endpoints) else {
            return;
        };
        match message.opcode {
            OP_REQUEST if side == Side::Door => {
                if let Ok(reply) = session_reply(&endpoints) {
                    if let Err(error) = self.wire.handshake_reply(&reply, &peers) {
                        tracing::warn!(%error, "capability reply failed");
                    }
                }
                self.on_call_started(&endpoints);
            }
            OP_ANSWER if side == Side::Pad => self.on_pad_answer(),
            OP_UNLOCK if side == Side::Pad => self.on_pad_unlock(),
            OP_HANGUP => self.on_wire_hangup(&peers),
            OP_MEDIA if side == Side::Door => {
                let Some(media) = message.media() else {
                    return;
                };
                let pts_us = self.started.elapsed().as_micros() as u64;
                if media.media_type == MEDIA_AUDIO {
                    self.push_audio(AudioChunk {
                        pts_us,
                        pcm: Arc::from(media.data),
                    });
                } else if let Some(frame) = self.jpeg.lock().unwrap().push(&media) {
                    self.push_video(VideoFrame {
                        pts_us,
                        jpeg: Arc::from(frame.as_slice()),
                    });
                }
            }
            _ => {}
        }
    }

    fn on_call_started(&self, endpoints: &Endpoints) {
        let started = {
            let mut call = self.call.lock().unwrap();
            if call.machine.state().phase != CallPhase::Idle {
                None
            } else {
                let id = call.next_session;
                call.next_session += 1;
                call.machine.start_call(id);
                call.since_ms = Some(now_ms());
                Some(id)
            }
        };
        if let Some(id) = started {
            self.events.push(EventKind::CallStarted {
                session_id: id.to_string(),
                door_id: endpoints.door.id.clone(),
                room_id: endpoints.room.id.clone(),
            });
        }
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

    fn on_wire_hangup(&self, peers: &Peers) {
        let (active, id) = {
            let mut call = self.call.lock().unwrap();
            let id = call.machine.state().session_id;
            let active = call.machine.state().phase != CallPhase::Idle;
            call.machine.hangup();
            call.since_ms = Some(now_ms());
            (active, id)
        };
        if active {
            self.wire.on_call_end(peers);
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

    // --------------------------------------------------------------- wire out

    /// Pad keepalive for the current call (pad mode sends one per second, like
    /// a real Pad; in tap mode the physical Pad does).
    pub fn send_keepalive(&self) {
        let peers = self.peers();
        let active = self.call.lock().unwrap().machine.state().phase != CallPhase::Idle;
        if !active {
            return;
        }
        if let Some(endpoints) = peers.endpoints() {
            if let Ok(packet) = session_control(OP_KEEPALIVE, &endpoints) {
                let _ = self.wire.send_as_pad(&packet, &peers);
            }
        }
    }

    fn execute(&self, action: CallAction, command_id: &str) -> CommandResult {
        if let Some(replayed) = self.commands.get(command_id) {
            return replayed;
        }
        let peers = self.peers();
        let session = self.session_string();
        let built: Result<(EventKind, Vec<u8>), CallError> = match peers.endpoints() {
            None => Err(CallError::NoCall),
            Some(endpoints) => {
                let mut call = self.call.lock().unwrap();
                match action {
                    CallAction::Claim => call.machine.remote_answer().map_err(CallError::from).and_then(|()| {
                        call.since_ms = Some(now_ms());
                        session_control(OP_ANSWER, &endpoints)
                            .map(|p| (EventKind::RemoteAnswered { session_id: session.clone() }, p))
                            .map_err(|_| CallError::AgentOffline)
                    }),
                    CallAction::Unlock => call.machine.unlock(Instant::now()).map_err(CallError::from).and_then(|()| {
                        session_control(OP_UNLOCK, &endpoints)
                            .map(|p| (EventKind::Unlocked { session_id: session.clone(), by: Owner::Remote }, p))
                            .map_err(|_| CallError::AgentOffline)
                    }),
                    CallAction::Hangup => {
                        if call.machine.state().phase == CallPhase::Idle {
                            Err(CallError::NoCall)
                        } else {
                            call.machine.hangup();
                            call.since_ms = Some(now_ms());
                            session_control(OP_HANGUP, &endpoints)
                                .map(|p| (EventKind::CallEnded { session_id: session.clone(), reason: "remote_hangup".into() }, p))
                                .map_err(|_| CallError::AgentOffline)
                        }
                    }
                }
            }
        };
        let result = match built {
            Ok((event, packet)) => match self.wire.send_as_pad(&packet, &peers) {
                Ok(()) => {
                    match action {
                        CallAction::Claim => self.wire.on_remote_claim(&peers),
                        CallAction::Hangup => self.wire.on_call_end(&peers),
                        CallAction::Unlock => {}
                    }
                    self.events.push(event);
                    CommandResult::ok(command_id)
                }
                Err(error) => {
                    tracing::warn!(%error, ?action, "sending to the door failed");
                    CommandResult::rejected(command_id, CallError::AgentOffline)
                }
            },
            Err(error) => CommandResult::rejected(command_id, error),
        };
        self.commands.store(&result);
        tracing::info!(?action, command_id, ok = result.ok, error = ?result.error, "command");
        result
    }
}

impl AgentControl for Agent {
    fn agent_id(&self) -> String {
        Agent::agent_id(self)
    }

    fn state(&self) -> CallState {
        let peers = self.peers();
        let call = self.call.lock().unwrap();
        let state = call.machine.state();
        CallState {
            phase: state.phase,
            owner: state.owner,
            session_id: (state.phase != CallPhase::Idle).then(|| state.session_id.to_string()),
            door_id: peers.door.as_ref().map(|d| d.id.clone()),
            room_id: Some(peers.room.id.clone()),
            since_ms: call.since_ms,
            agent_id: Agent::agent_id(self),
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

impl AgentMedia for Agent {
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
        let result = (|| {
            let allowed = {
                let call = self.call.lock().unwrap();
                let state = call.machine.state();
                call.machine.remote_media_allowed(state.session_id)
            };
            if !allowed {
                return Err(CallError::UnlockNotAllowed);
            }
            let peers = self.peers();
            let endpoints = peers.endpoints().ok_or(CallError::AgentOffline)?;
            for frame in chunk.pcm.chunks(512) {
                let mut pcm = frame.to_vec();
                pcm.resize(512, 0);
                let seq = self.audio_seq.fetch_add(1, Ordering::Relaxed) as u16;
                let packet = audio_packet(seq, &pcm, &endpoints).map_err(|_| CallError::AgentOffline)?;
                self.wire
                    .send_as_pad(&packet, &peers)
                    .map_err(|_| CallError::AgentOffline)?;
            }
            Ok(())
        })();
        async move { result }.boxed()
    }
}

// ------------------------------------------------------------------- startup

/// Everything `run_agent` needs; the CLI builds it from the config file plus
/// overrides.
pub struct Run {
    pub server: ServerConfig,
    pub intercom: IntercomConfig,
    pub policy: Policy,
    pub history: Duration,
    pub history_max_bytes: usize,
    pub discover_timeout: Duration,
}

/// Parse one MAC from `/proc/net/arp` text for `ip` (complete entries only).
pub fn parse_arp_table(text: &str, ip: Ipv4Addr) -> Option<MacAddress> {
    let want = ip.to_string();
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let (Some(addr), Some(_hw), Some(flags), Some(mac)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        if addr == want && flags != "0x0" {
            return MacAddress::parse(mac).ok();
        }
    }
    None
}

fn parse_mac(text: Option<&str>, what: &str) -> Result<Option<MacAddress>> {
    match text {
        Some(text) if !text.is_empty() => MacAddress::parse(text)
            .map(Some)
            .with_context(|| format!("intercom.{what} is not a MAC address")),
        _ => Ok(None),
    }
}

/// Resolve identities, open the mode's wire, and serve the control plane.
pub async fn run_agent(run: Run) -> Result<()> {
    let ic = run.intercom;
    anyhow::ensure!(
        !ic.device_id.is_empty(),
        "intercom.device_id (the Pad's room station id) is required"
    );
    let broadcast = ic.discovery_broadcast()?;
    let mut peers = Peers {
        room: Station::new(ic.device_id.clone(), ic.room_ip.unwrap_or(Ipv4Addr::UNSPECIFIED)),
        door: ic
            .door_id
            .clone()
            .filter(|id| !id.is_empty())
            .map(|id| Station::new(id, ic.door_ip.unwrap_or(Ipv4Addr::UNSPECIFIED))),
        door_mac: parse_mac(ic.door_mac.as_deref(), "door_mac")?,
        pad_mac: parse_mac(ic.pad_mac.as_deref(), "pad_mac")?,
        control_port: ic.control_port,
    };

    // Discovery (the private UDP 10008 "who has this station?").
    if ic.mode == AgentMode::Tap && peers.room.ip.is_unspecified() {
        match resolve_pad(&ic.device_id, broadcast, run.discover_timeout).await {
            Ok(ip) => {
                tracing::info!(%ip, id = %ic.device_id, "discovered the physical Pad");
                peers.room.ip = ip;
            }
            Err(error) => tracing::warn!(%error, "physical Pad not found by discovery; will learn it from the first call"),
        }
    }
    if let Some(door) = peers.door.as_mut() {
        if door.ip.is_unspecified() {
            match resolve_pad(&door.id, broadcast, run.discover_timeout).await {
                Ok(ip) => {
                    tracing::info!(%ip, id = %door.id, "discovered the door station");
                    door.ip = ip;
                }
                Err(error) => tracing::warn!(%error, "door not found by discovery; will learn it from the first call"),
            }
        }
    }

    let agent = match ic.mode {
        AgentMode::Pad => {
            let wire = crate::wire_udp::UdpWire::bind(ic.pad_listen).await?;
            let agent = Agent::new(
                ic.mode,
                wire.clone() as Arc<dyn Wire>,
                peers,
                run.policy,
                run.history,
                run.history_max_bytes,
            );
            tokio::spawn(wire.clone().run(agent.clone()));
            tokio::spawn(crate::wire_udp::discovery_responder(ic.discovery_port, ic.device_id.clone()));
            let keepalive = agent.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    keepalive.send_keepalive();
                }
            });
            agent
        }
        AgentMode::Tap => {
            #[cfg(all(target_os = "linux", feature = "linux-packet"))]
            {
                let wire = crate::wire_tap::TapWire::open(&ic)?;
                // MACs from the neighbour table for anything discovery pinned.
                if peers.pad_mac.is_none() && !peers.room.ip.is_unspecified() {
                    peers.pad_mac = crate::wire_tap::neighbor_mac(peers.room.ip);
                    tracing::info!(mac = ?peers.pad_mac, "Pad MAC from the neighbour table");
                }
                if let Some(door) = &peers.door {
                    if peers.door_mac.is_none() && !door.ip.is_unspecified() {
                        peers.door_mac = crate::wire_tap::neighbor_mac(door.ip);
                        tracing::info!(mac = ?peers.door_mac, "door MAC from the neighbour table");
                    }
                }
                let agent = Agent::new(
                    ic.mode,
                    wire.clone() as Arc<dyn Wire>,
                    peers,
                    run.policy,
                    run.history,
                    run.history_max_bytes,
                );
                let capture = agent.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = wire.run(&capture) {
                        tracing::error!(%error, "bridge capture stopped");
                    }
                });
                agent
            }
            #[cfg(not(all(target_os = "linux", feature = "linux-packet")))]
            {
                let _ = peers;
                anyhow::bail!("tap mode needs Linux and --features linux-packet; use mode = \"pad\" here")
            }
        }
    };

    tracing::info!(
        mode = agent.mode().as_str(),
        device = %agent.device_id(),
        http = %run.server.listen,
        "Agent serving the HTTP control plane"
    );
    crate::agent_server::serve(run.server, agent).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_table_parsing_picks_complete_entries() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.124.61   0x1         0x2         aa:bb:cc:dd:ee:3d     *        br-lan\n\
                    192.168.124.2    0x1         0x0         00:00:00:00:00:00     *        br-lan\n";
        assert_eq!(
            parse_arp_table(text, Ipv4Addr::new(192, 168, 124, 61)),
            MacAddress::parse("aa:bb:cc:dd:ee:3d").ok()
        );
        // Incomplete (flags 0x0) entries are not trusted.
        assert_eq!(parse_arp_table(text, Ipv4Addr::new(192, 168, 124, 2)), None);
        assert_eq!(parse_arp_table(text, Ipv4Addr::new(10, 0, 0, 1)), None);
    }
}
