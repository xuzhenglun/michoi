//! User-space Pad-side Agent over a plain UDP socket (cross-platform).
//!
//! Unlike `LiveAgent` (which passively sniffs a real door<->Pad bridge with
//! AF_PACKET, Linux only), this Agent *is* the Pad endpoint: it binds the
//! control port, accepts a synthesized door station (`emit-door`), answers the
//! paging / bootstrap / session handshake, and fans the door's video and audio
//! out over the HTTP control plane. Backend actions (claim / unlock / hangup /
//! talk) are sent back to the door as Pad-originated packets.
//!
//! This closes the loop entirely on a laptop: `emit-door` <-> `pad-agent` <->
//! the browser Pad, with no hardware and no bridge.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

use crate::agent_api::{
    now_ms, AgentControl, AgentMedia, AudioChunk, AudioInfo, CallAction, CallError, CallState,
    CommandCache, CommandResult, Event, EventKind, EventLog, MediaHistory, MediaInfo, MediaRing,
    Owner, VideoFrame, VideoInfo,
};
use crate::agent_server::ServerConfig;
use crate::protocol::{
    audio_packet, bootstrap_reply, discovery_reply, discovery_request_room, session_control,
    session_reply, split_coalesced, Endpoints, JpegReassembler, Message, Station, DISCOVERY_PORT,
    FAMILY_BOOTSTRAP, FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP, OP_KEEPALIVE, OP_MEDIA,
    OP_REQUEST, OP_UNLOCK,
};
use crate::state::{CallMachine, CallPhase};

pub const AGENT_ID: &str = "socket-pad";

struct Call {
    machine: CallMachine,
    door_id: Option<String>,
    room_id: Option<String>,
    since_ms: Option<u64>,
    /// Endpoint block learned from the door's `00b7/01`, reused for every
    /// Pad-originated packet.
    endpoints: Option<Endpoints>,
    /// The door's socket address; replies go here.
    peer: Option<SocketAddr>,
}

/// A software Pad that also implements the Agent traits.
pub struct SocketAgent {
    call: Mutex<Call>,
    events: EventLog,
    commands: CommandCache,
    video: broadcast::Sender<VideoFrame>,
    audio: broadcast::Sender<AudioChunk>,
    latest: Mutex<Option<VideoFrame>>,
    history: MediaRing,
    started: Instant,
    socket: Arc<UdpSocket>,
    room: Station,
    audio_seq: AtomicU32,
}

impl SocketAgent {
    fn new(
        socket: Arc<UdpSocket>,
        room: Station,
        history: Duration,
        history_max_bytes: usize,
    ) -> Arc<Self> {
        let (video, _) = broadcast::channel(32);
        let (audio, _) = broadcast::channel(128);
        Arc::new(Self {
            call: Mutex::new(Call {
                machine: CallMachine::new(Duration::from_secs(1)),
                door_id: None,
                room_id: None,
                since_ms: None,
                endpoints: None,
                peer: None,
            }),
            events: EventLog::new(256, 64),
            commands: CommandCache::new(256),
            video,
            audio,
            latest: Mutex::new(None),
            history: MediaRing::new(history, history_max_bytes),
            started: Instant::now(),
            socket,
            room,
            audio_seq: AtomicU32::new(0),
        })
    }

    fn session_string(&self) -> String {
        self.call.lock().unwrap().machine.state().session_id.to_string()
    }

    // --- door side: handle one datagram from the door emulator ---

    async fn on_datagram(&self, raw: &[u8], from: SocketAddr, jpeg: &mut JpegReassembler) {
        let Ok(message) = Message::parse(raw) else {
            return;
        };
        // The bootstrap request precedes the session; reply so the door's
        // handshake completes even before we know the endpoints.
        if message.family == FAMILY_BOOTSTRAP && message.opcode == OP_REQUEST {
            if let Ok(reply) = bootstrap_reply(&self.room) {
                let _ = self.socket.send_to(&reply, from).await;
            }
            return;
        }
        if message.family != FAMILY_SESSION {
            return;
        }
        match message.opcode {
            OP_REQUEST => {
                let endpoints = message.endpoints().unwrap_or_else(Endpoints::captured);
                // Reply with the capability so the door treats us as a real Pad.
                if let Ok(reply) = session_reply(&endpoints) {
                    let _ = self.socket.send_to(&reply, from).await;
                }
                let start = {
                    let mut call = self.call.lock().unwrap();
                    call.peer = Some(from);
                    call.endpoints = Some(endpoints.clone());
                    let idle = call.machine.state().phase == CallPhase::Idle;
                    if idle {
                        let id = call.machine.state().session_id.wrapping_add(1).max(1);
                        call.machine.start_call(id);
                        call.door_id = Some(endpoints.door.id.clone());
                        call.room_id = Some(endpoints.room.id.clone());
                        call.since_ms = Some(now_ms());
                        Some(id)
                    } else {
                        None
                    }
                };
                if let Some(id) = start {
                    self.events.push(EventKind::CallStarted {
                        session_id: id.to_string(),
                        door_id: endpoints.door.id,
                        room_id: endpoints.room.id,
                    });
                }
            }
            OP_HANGUP => {
                let (active, id) = {
                    let mut call = self.call.lock().unwrap();
                    let id = call.machine.state().session_id;
                    let active = call.machine.state().phase != CallPhase::Idle;
                    call.machine.hangup();
                    call.since_ms = Some(now_ms());
                    (active, id)
                };
                if active {
                    self.events.push(EventKind::CallEnded {
                        session_id: id.to_string(),
                        reason: "door_hangup".into(),
                    });
                }
            }
            OP_MEDIA => {
                let Some(media) = message.media() else {
                    return;
                };
                let pts_us = self.started.elapsed().as_micros() as u64;
                if media.media_type == MEDIA_AUDIO {
                    self.push_audio(AudioChunk {
                        pts_us,
                        pcm: Arc::from(media.data),
                    });
                } else if let Some(frame) = jpeg.push(&media) {
                    self.push_video(VideoFrame {
                        pts_us,
                        jpeg: Arc::from(frame.as_slice()),
                    });
                }
            }
            _ => {}
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

    // --- backend side: send Pad-originated packets to the door ---

    async fn send_to_door(&self, packet: &[u8]) -> Result<(), CallError> {
        let peer = self.call.lock().unwrap().peer;
        match peer {
            Some(peer) => self
                .socket
                .send_to(packet, peer)
                .await
                .map(|_| ())
                .map_err(|_| CallError::AgentOffline),
            None => Err(CallError::AgentOffline),
        }
    }

    async fn execute(&self, action: CallAction, command_id: &str) -> CommandResult {
        if let Some(replayed) = self.commands.get(command_id) {
            return replayed;
        }
        let session = self.session_string();
        // Change state and build the Pad-originated packet under the lock.
        let built: Result<(EventKind, Vec<u8>), CallError> = {
            let mut call = self.call.lock().unwrap();
            let endpoints = match call.endpoints.clone() {
                Some(endpoints) => endpoints,
                None => return CommandResult::rejected(command_id, CallError::NoCall),
            };
            match action {
                CallAction::Claim => call
                    .machine
                    .remote_answer()
                    .map_err(CallError::from)
                    .and_then(|()| {
                        call.since_ms = Some(now_ms());
                        session_control(OP_ANSWER, &endpoints)
                            .map(|p| {
                                (
                                    EventKind::RemoteAnswered {
                                        session_id: session.clone(),
                                    },
                                    p,
                                )
                            })
                            .map_err(|_| CallError::AgentOffline)
                    }),
                CallAction::Unlock => call
                    .machine
                    .unlock(Instant::now())
                    .map_err(CallError::from)
                    .and_then(|()| {
                        session_control(OP_UNLOCK, &endpoints)
                            .map(|p| {
                                (
                                    EventKind::Unlocked {
                                        session_id: session.clone(),
                                        by: Owner::Remote,
                                    },
                                    p,
                                )
                            })
                            .map_err(|_| CallError::AgentOffline)
                    }),
                CallAction::Hangup => {
                    if call.machine.state().phase == CallPhase::Idle {
                        Err(CallError::NoCall)
                    } else {
                        call.machine.hangup();
                        call.since_ms = Some(now_ms());
                        session_control(OP_HANGUP, &endpoints)
                            .map(|p| {
                                (
                                    EventKind::CallEnded {
                                        session_id: session.clone(),
                                        reason: "remote_hangup".into(),
                                    },
                                    p,
                                )
                            })
                            .map_err(|_| CallError::AgentOffline)
                    }
                }
            }
        };
        let result = match built {
            Ok((event, packet)) => match self.send_to_door(&packet).await {
                Ok(()) => {
                    self.events.push(event);
                    CommandResult::ok(command_id)
                }
                Err(error) => CommandResult::rejected(command_id, error),
            },
            Err(error) => CommandResult::rejected(command_id, error),
        };
        self.commands.store(&result);
        tracing::info!(?action, command_id, ok = result.ok, error = ?result.error, "command");
        result
    }

    /// Receive door datagrams until the socket errors.
    async fn recv_loop(self: Arc<Self>) {
        let mut buffer = vec![0_u8; 65_536];
        let mut jpeg = JpegReassembler::default();
        loop {
            let Ok((size, from)) = self.socket.recv_from(&mut buffer).await else {
                break;
            };
            for raw in split_coalesced(&buffer[..size]) {
                self.on_datagram(raw, from, &mut jpeg).await;
            }
        }
    }

    /// Send a Pad keepalive to the door once per second during a call, matching
    /// what a real Pad does.
    async fn keepalive_loop(self: Arc<Self>) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let packet = {
                let call = self.call.lock().unwrap();
                if call.machine.state().phase == CallPhase::Idle {
                    continue;
                }
                match &call.endpoints {
                    Some(endpoints) => session_control(OP_KEEPALIVE, endpoints).ok(),
                    None => None,
                }
            };
            if let Some(packet) = packet {
                let _ = self.send_to_door(&packet).await;
            }
        }
    }
}

impl AgentControl for SocketAgent {
    fn agent_id(&self) -> String {
        AGENT_ID.into()
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
            agent_id: AGENT_ID.into(),
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
        let command_id = command_id.to_owned();
        async move { self.execute(action, &command_id).await }.boxed()
    }
}

impl AgentMedia for SocketAgent {
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
        async move {
            let (allowed, endpoints) = {
                let call = self.call.lock().unwrap();
                let state = call.machine.state();
                (
                    call.machine.remote_media_allowed(state.session_id),
                    call.endpoints.clone(),
                )
            };
            if !allowed {
                return Err(CallError::UnlockNotAllowed);
            }
            let Some(endpoints) = endpoints else {
                return Err(CallError::AgentOffline);
            };
            // The visitor audio is 8 kHz S16LE; the wire wants 512-byte frames.
            for frame in chunk.pcm.chunks(512) {
                let mut pcm = frame.to_vec();
                pcm.resize(512, 0);
                let seq = self.audio_seq.fetch_add(1, Ordering::Relaxed) as u16;
                if let Ok(packet) = audio_packet(seq, &pcm, &endpoints) {
                    self.send_to_door(&packet).await?;
                }
            }
            Ok(())
        }
        .boxed()
    }
}

/// Answer UDP 10008 discovery for our room id, so `emit-door --discover` finds
/// this Agent. Best-effort: a bind failure (e.g. the port is taken) is logged.
async fn discovery_responder(bind: SocketAddr, room_id: String) {
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(%error, %bind, "discovery responder disabled");
            return;
        }
    };
    let _ = socket.set_broadcast(true);
    let reply = match discovery_reply(&room_id) {
        Ok(reply) => reply,
        Err(_) => return,
    };
    let mut buffer = vec![0_u8; 1024];
    loop {
        let Ok((size, from)) = socket.recv_from(&mut buffer).await else {
            break;
        };
        if discovery_request_room(&buffer[..size]).as_deref() == Some(room_id.as_str()) {
            let _ = socket.send_to(&reply, from).await;
        }
    }
}

/// Bind the control port as a software Pad, accept a door emulator, and serve
/// it to backends over the HTTP control plane. Cross-platform (no AF_PACKET).
pub async fn run_socket_agent(
    server: ServerConfig,
    control_bind: SocketAddr,
    room: Station,
    history: Duration,
    history_max_bytes: usize,
    discovery: bool,
) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(control_bind)
            .await
            .with_context(|| format!("binding control port {control_bind}"))?,
    );
    let agent = SocketAgent::new(socket.clone(), room.clone(), history, history_max_bytes);

    tokio::spawn(agent.clone().recv_loop());
    tokio::spawn(agent.clone().keepalive_loop());
    if discovery {
        let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DISCOVERY_PORT);
        tokio::spawn(discovery_responder(bind, room.id.clone()));
    }

    tracing::info!(
        control = %control_bind, http = %server.listen, room = %room.id,
        "socket Pad Agent: ring me from `emit-door`, view from the browser Pad"
    );
    crate::agent_server::serve(server, agent).await
}
