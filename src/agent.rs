use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{sleep_until, Instant as TokioInstant};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::pcap::read_udp;
use crate::protocol::{
    audio_packet, session_control, split_coalesced, Endpoints, JpegReassembler, Message,
    FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP, OP_MEDIA, OP_REQUEST, OP_UNLOCK,
};
use crate::state::CallMachine;
use crate::transport::{AgentCommand, AgentEvent, CommandResult, FrameKind, WireFrame};

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::bridge::PacketSocket;
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::config::IntercomConfig;
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use crate::ethernet::{build_udp_ipv4, EthernetUdp, MacAddress};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(all(target_os = "linux", feature = "linux-packet"))]
use tokio::sync::broadcast;

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

struct AgentState {
    call: CallMachine,
    results: HashMap<u64, CommandResult>,
}

impl AgentState {
    fn new(cooldown: Duration) -> Self {
        Self::with_policy(cooldown, false)
    }

    fn with_policy(cooldown: Duration, unlock_requires_answer: bool) -> Self {
        Self {
            call: CallMachine::with_policy(cooldown, unlock_requires_answer),
            results: HashMap::new(),
        }
    }

    fn execute(&mut self, command: AgentCommand) -> CommandResult {
        let id = command.command_id().unwrap_or(0);
        if let Some(result) = self.results.get(&id) {
            return result.clone();
        }
        let result = match command {
            AgentCommand::RegisterBackend { .. } => Ok(()),
            AgentCommand::ClaimCall { .. } => self.call.remote_answer(),
            AgentCommand::Unlock { .. } => self.call.unlock(Instant::now()),
            AgentCommand::Hangup { .. } | AgentCommand::ReleaseCall { .. } => {
                self.call.hangup();
                Ok(())
            }
        };
        let response = CommandResult {
            command_id: id,
            ok: result.is_ok(),
            error: result.err().map(|e| e.to_string()),
        };
        if id != 0 {
            if self.results.len() >= 128 {
                if let Some(oldest) = self.results.keys().min().copied() {
                    self.results.remove(&oldest);
                }
            }
            self.results.insert(id, response.clone());
        }
        response
    }
}

/// Serve the capture over WebSocket. With `repeat` set, every connection
/// replays the call again after that idle gap instead of closing after one
/// pass, which gives a manual test a periodic doorbell ring.
pub async fn run_fake_agent(
    listen: SocketAddr,
    pcap: impl AsRef<Path>,
    speed: f64,
    cooldown: Duration,
    repeat: Option<Duration>,
) -> Result<()> {
    anyhow::ensure!(speed.is_finite() && speed > 0.0, "speed must be positive");
    let timeline = Arc::new(replay_timeline(pcap)?);
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, frames = timeline.len(), ?repeat, "fake Agent listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let timeline = timeline.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_replay(stream, peer, timeline, speed, cooldown, repeat).await
            {
                tracing::warn!(%peer, %error, "fake Agent connection ended");
            }
        });
    }
}

async fn serve_replay(
    stream: TcpStream,
    peer: SocketAddr,
    timeline: Arc<Vec<TimedFrame>>,
    speed: f64,
    cooldown: Duration,
    repeat: Option<Duration>,
) -> Result<()> {
    let websocket = tokio_tungstenite::accept_async(stream).await?;
    let (sink, mut source) = websocket.split();
    let sink = Arc::new(Mutex::new(sink));
    let state = Arc::new(Mutex::new(AgentState::new(cooldown)));
    let hello = AgentEvent::Hello {
        agent_id: "fake-pad-cap".into(),
        protocol: 1,
        capabilities: vec!["trace-replay".into(), "jpeg".into(), "pcm-s16le-8k".into()],
    };
    sink.lock()
        .await
        .send(WsMessage::Binary(
            WireFrame::cbor(FrameKind::Event, 0, 0, 0, &hello)?
                .encode()
                .into(),
        ))
        .await?;

    let replay_state = state.clone();
    let replay_sink = sink.clone();
    let replay = async {
        let mut pass = 0_u32;
        loop {
            let start = TokioInstant::now();
            for timed in timeline.iter() {
                let wait = Duration::from_micros((timed.offset_micros as f64 / speed) as u64);
                sleep_until(start + wait).await;
                if let Ok(event) = timed.frame.decode_cbor::<AgentEvent>() {
                    let mut locked = replay_state.lock().await;
                    match event {
                        AgentEvent::CallStarted { .. } => {
                            locked.call.start_call(timed.frame.session_id)
                        }
                        AgentEvent::PadActionObserved { opcode: OP_ANSWER } => {
                            let _ = locked.call.pad_answer();
                        }
                        AgentEvent::CallEnded { .. } => locked.call.hangup(),
                        _ => {}
                    }
                }
                replay_sink
                    .lock()
                    .await
                    .send(WsMessage::Binary(timed.frame.encode().into()))
                    .await?;
            }
            pass += 1;
            let Some(gap) = repeat else { break };
            tracing::info!(%peer, pass, gap_ms = gap.as_millis(), "replay pass complete; idling");
            tokio::time::sleep(gap).await;
        }
        replay_sink
            .lock()
            .await
            .send(WsMessage::Close(None))
            .await?;
        anyhow::Ok(())
    };

    let commands = async {
        while let Some(message) = source.next().await {
            let message = message?;
            let WsMessage::Binary(raw) = message else {
                continue;
            };
            let frame = WireFrame::decode(&raw)?;
            if frame.kind == FrameKind::TalkPcm {
                let allowed = state
                    .lock()
                    .await
                    .call
                    .remote_media_allowed(frame.session_id);
                if allowed {
                    // Validate the exact production audio encoder in replay mode.
                    let _ = audio_packet(
                        frame.sequence as u16,
                        &frame.payload,
                        &Endpoints::captured(),
                    )?;
                } else {
                    tracing::warn!(%peer, "dropping unauthorized talk audio");
                }
                continue;
            }
            if frame.kind != FrameKind::Command {
                continue;
            }
            let command: AgentCommand = frame.decode_cbor()?;
            let command_id = command.command_id().unwrap_or(0);
            // Packet construction is intentionally performed even by the fake
            // Agent, making the mock exercise the exact production wire encoder.
            let opcode = match command {
                AgentCommand::ClaimCall { .. } => Some(OP_ANSWER),
                AgentCommand::Unlock { .. } => Some(OP_UNLOCK),
                AgentCommand::Hangup { .. } => Some(OP_HANGUP),
                _ => None,
            };
            if let Some(opcode) = opcode {
                let _ = session_control(opcode, &Endpoints::captured())?;
            }
            let result = state.lock().await.execute(command);
            let response = WireFrame::cbor(
                FrameKind::Result,
                frame.session_id,
                frame.sequence,
                frame.timestamp_micros,
                &result,
            )?;
            sink.lock()
                .await
                .send(WsMessage::Binary(response.encode().into()))
                .await?;
            tracing::debug!(%peer, command_id, ok = result.ok, "Agent command");
        }
        anyhow::Ok(())
    };

    let mut commands = std::pin::pin!(commands);
    tokio::select! {
        result = replay => {
            result?;
            // Keep reading until the peer answers the close handshake so it
            // observes a clean close rather than a connection reset.
            let _ = tokio::time::timeout(Duration::from_secs(2), &mut commands).await;
            Ok(())
        }
        result = &mut commands => result,
    }
}

pub async fn run_backend(url: &str, scripted: bool) -> Result<()> {
    let (stream, _) = tokio_tungstenite::connect_async(url).await?;
    let (sink, mut source) = stream.split();
    let sink = Arc::new(Mutex::new(sink));
    send_command(
        &sink,
        0,
        0,
        AgentCommand::RegisterBackend {
            backend_id: "pag1-client".into(),
        },
    )
    .await?;
    while let Some(message) = source.next().await {
        let message = message?;
        let WsMessage::Binary(raw) = message else {
            continue;
        };
        let frame = WireFrame::decode(&raw)?;
        match frame.kind {
            FrameKind::Event => {
                let event: AgentEvent = frame.decode_cbor()?;
                tracing::info!(session = frame.session_id, ?event, "Agent event");
                if scripted && matches!(event, AgentEvent::CallStarted { .. }) {
                    let actions = sink.clone();
                    let session = frame.session_id;
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        let _ = send_command(
                            &actions,
                            session,
                            1,
                            AgentCommand::ClaimCall { command_id: 1 },
                        )
                        .await;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        let _ = send_command(
                            &actions,
                            session,
                            2,
                            AgentCommand::Unlock { command_id: 2 },
                        )
                        .await;
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        let _ = send_command(
                            &actions,
                            session,
                            3,
                            AgentCommand::Hangup { command_id: 3 },
                        )
                        .await;
                    });
                }
            }
            FrameKind::Result => {
                let result: CommandResult = frame.decode_cbor()?;
                tracing::info!(?result, "Agent command result");
            }
            FrameKind::Jpeg => tracing::trace!(bytes = frame.payload.len(), "JPEG frame"),
            FrameKind::DoorPcm => tracing::trace!(bytes = frame.payload.len(), "door PCM"),
            _ => {}
        }
    }
    Ok(())
}

async fn send_command<S>(
    sink: &Arc<Mutex<S>>,
    session_id: u64,
    sequence: u32,
    command: AgentCommand,
) -> Result<()>
where
    S: futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    let frame = WireFrame::cbor(FrameKind::Command, session_id, sequence, 0, &command)?;
    sink.lock()
        .await
        .send(WsMessage::Binary(frame.encode().into()))
        .await?;
    Ok(())
}

pub fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
pub struct LivePolicy {
    pub cooldown: Duration,
    pub unlock_requires_answer: bool,
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
pub async fn run_live_agent(
    listen: SocketAddr,
    intercom: IntercomConfig,
    policy: LivePolicy,
) -> Result<()> {
    let _pad_mac = MacAddress::parse(
        intercom
            .pad_mac
            .as_deref()
            .context("intercom.pad_mac is required in copy mode")?,
    )?;
    let _door_mac = MacAddress::parse(
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
    let state = Arc::new(Mutex::new(AgentState::with_policy(
        policy.cooldown,
        policy.unlock_requires_answer,
    )));
    let (events, _) = broadcast::channel::<WireFrame>(512);
    let sequence = Arc::new(AtomicU32::new(1));
    let session = Arc::new(AtomicU64::new(1));
    let started = Instant::now();

    let capture_socket = socket.clone();
    let capture_state = state.clone();
    let capture_events = events.clone();
    let capture_sequence = sequence.clone();
    let capture_session = session.clone();
    let capture_config = intercom.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(error) = capture_loop(
            &capture_socket,
            &capture_config,
            &capture_state,
            &capture_events,
            &capture_sequence,
            &capture_session,
            started,
        ) {
            tracing::error!(%error, "live packet capture stopped");
        }
    });

    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, interface = socket.interface(), "live Agent listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let connection_state = state.clone();
        let connection_events = events.clone();
        let connection_socket = socket.clone();
        let connection_config = intercom.clone();
        let connection_sequence = sequence.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_live(
                stream,
                peer,
                connection_state,
                connection_events,
                connection_socket,
                connection_config,
                connection_sequence,
            )
            .await
            {
                tracing::warn!(%peer, %error, "live Agent connection ended");
            }
        });
    }
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
fn capture_loop(
    socket: &PacketSocket,
    config: &IntercomConfig,
    state: &Arc<Mutex<AgentState>>,
    events: &broadcast::Sender<WireFrame>,
    sequence: &AtomicU32,
    next_session: &AtomicU64,
    started: Instant,
) -> Result<()> {
    let runtime = tokio::runtime::Handle::current();
    let door_mac = MacAddress::parse(config.door_mac.as_deref().context("door_mac missing")?)?;
    let pad_mac = MacAddress::parse(config.pad_mac.as_deref().context("pad_mac missing")?)?;
    let mut buffer = vec![0_u8; 65_536];
    let mut jpeg = JpegReassembler::default();
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
            let timestamp = started.elapsed().as_micros() as u64;
            let mut outbound = None;
            runtime.block_on(async {
                let mut locked = state.lock().await;
                match message.opcode {
                    OP_REQUEST if locked.call.state().phase == crate::state::CallPhase::Idle => {
                        let id = next_session.fetch_add(1, Ordering::Relaxed);
                        locked.call.start_call(id);
                        outbound = Some((
                            id,
                            AgentEvent::CallStarted {
                                door_id: endpoints.door.id,
                                room_id: endpoints.room.id,
                            },
                        ));
                    }
                    OP_ANSWER if udp.source_ip == config.room_ip => {
                        if locked.call.pad_answer().is_ok() {
                            outbound = Some((
                                locked.call.state().session_id,
                                AgentEvent::PadActionObserved { opcode: OP_ANSWER },
                            ));
                        }
                    }
                    OP_UNLOCK if udp.source_ip == config.room_ip => {
                        outbound = Some((
                            locked.call.state().session_id,
                            AgentEvent::PadActionObserved { opcode: OP_UNLOCK },
                        ));
                    }
                    OP_HANGUP if locked.call.state().phase != crate::state::CallPhase::Idle => {
                        let id = locked.call.state().session_id;
                        locked.call.hangup();
                        outbound = Some((
                            id,
                            AgentEvent::CallEnded {
                                reason: "wire_hangup".into(),
                            },
                        ));
                    }
                    _ => {}
                }
            });
            if let Some((id, event)) = outbound {
                // Any real hangup ends the takeover, so restore the Pad path.
                if matches!(event, AgentEvent::CallEnded { .. }) {
                    restore_physical_pad();
                }
                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                if let Ok(frame) = WireFrame::cbor(FrameKind::Event, id, seq, timestamp, &event) {
                    let _ = events.send(frame);
                }
            }
            if message.opcode != OP_MEDIA || udp.source_ip != config.door_ip {
                continue;
            }
            let Some(media) = message.media() else {
                continue;
            };
            let session_id = runtime.block_on(async { state.lock().await.call.state().session_id });
            let frame = if media.media_type == MEDIA_AUDIO {
                Some((FrameKind::DoorPcm, media.data.to_vec()))
            } else {
                jpeg.push(&media).map(|frame| (FrameKind::Jpeg, frame))
            };
            if let Some((kind, payload)) = frame {
                let seq = sequence.fetch_add(1, Ordering::Relaxed);
                let _ = events.send(WireFrame {
                    kind,
                    flags: 0,
                    session_id,
                    sequence: seq,
                    timestamp_micros: timestamp,
                    payload,
                });
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "linux-packet"))]
async fn serve_live(
    stream: TcpStream,
    peer: SocketAddr,
    state: Arc<Mutex<AgentState>>,
    events: broadcast::Sender<WireFrame>,
    socket: Arc<PacketSocket>,
    config: IntercomConfig,
    sequence: Arc<AtomicU32>,
) -> Result<()> {
    let websocket = tokio_tungstenite::accept_async(stream).await?;
    let (sink, mut source) = websocket.split();
    let sink = Arc::new(Mutex::new(sink));
    let hello = AgentEvent::Hello {
        agent_id: "openwrt-live".into(),
        protocol: 1,
        capabilities: vec!["af-packet".into(), "jpeg".into(), "pcm-s16le-8k".into()],
    };
    sink.lock()
        .await
        .send(WsMessage::Binary(
            WireFrame::cbor(FrameKind::Event, 0, 0, 0, &hello)?
                .encode()
                .into(),
        ))
        .await?;
    let snapshot = {
        let locked = state.lock().await;
        AgentEvent::Snapshot {
            phase: format!("{:?}", locked.call.state().phase).to_lowercase(),
            owner: format!("{:?}", locked.call.state().owner).to_lowercase(),
        }
    };
    sink.lock()
        .await
        .send(WsMessage::Binary(
            WireFrame::cbor(FrameKind::Event, 0, 0, 0, &snapshot)?
                .encode()
                .into(),
        ))
        .await?;

    let mut receiver = events.subscribe();
    loop {
        tokio::select! {
            event = receiver.recv() => {
                match event {
                    Ok(frame) => sink.lock().await.send(WsMessage::Binary(frame.encode().into())).await?,
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        tracing::warn!(%peer, count, "backend lagged; media frames dropped");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            message = source.next() => {
                let Some(message) = message else { break };
                let message = message?;
                let WsMessage::Binary(raw) = message else { continue };
                let frame = WireFrame::decode(&raw)?;
                if frame.kind == FrameKind::TalkPcm {
                    let allowed = state.lock().await.call.remote_media_allowed(frame.session_id);
                    if allowed {
                        if let Err(error) = inject_audio(
                            &socket,
                            &config,
                            frame.sequence as u16,
                            &frame.payload,
                            sequence.fetch_add(1, Ordering::Relaxed),
                        ) {
                            tracing::warn!(%peer, %error, "dropping talk audio");
                        }
                    } else {
                        tracing::warn!(%peer, "dropping unauthorized talk audio");
                    }
                    continue;
                }
                if frame.kind != FrameKind::Command { continue; }
                let command: AgentCommand = frame.decode_cbor()?;
                let command_id = command.command_id().unwrap_or(0);
                let opcode = match command {
                    AgentCommand::ClaimCall { .. } => Some(OP_ANSWER),
                    AgentCommand::Unlock { .. } => Some(OP_UNLOCK),
                    AgentCommand::Hangup { .. } | AgentCommand::ReleaseCall { .. } => Some(OP_HANGUP),
                    AgentCommand::RegisterBackend { .. } => None,
                };
                let result = state.lock().await.execute(command);
                let mut result = result;
                if result.ok {
                    if let Some(opcode) = opcode {
                        if let Err(error) = inject_control(&socket, &config, opcode, sequence.fetch_add(1, Ordering::Relaxed)) {
                            result.ok = false;
                            result.error = Some(error.to_string());
                        }
                    }
                    // First-answer takeover: when a remote backend wins the
                    // ringing call, silence and lock out the physical Pad, then
                    // tell it the call ended so it stops ringing immediately.
                    // Fail-open: rule/reset failures are logged, not fatal.
                    if opcode == Some(OP_ANSWER) {
                        silence_physical_pad(&socket, &config, sequence.fetch_add(1, Ordering::Relaxed));
                    }
                    if opcode == Some(OP_HANGUP) {
                        restore_physical_pad();
                    }
                }
                let response = WireFrame::cbor(FrameKind::Result, frame.session_id, frame.sequence, 0, &result)?;
                sink.lock().await.send(WsMessage::Binary(response.encode().into())).await?;
                tracing::info!(%peer, command_id, ok = result.ok, "live Agent command");
            }
        }
    }
    Ok(())
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
