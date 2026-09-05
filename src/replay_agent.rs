//! In-process Agent that replays `pad.cap` with capture timing.
//!
//! It implements the same [`AgentControl`] / [`AgentMedia`] interface as the
//! live capture Agent, so backends and the HTTP server cannot tell the two
//! apart. Commands still run through the production call state machine and
//! the exact packet encoders, they just are not injected anywhere.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use tokio::sync::broadcast;
use tokio::time::{sleep_until, Instant as TokioInstant};

use crate::agent_api::{
    now_ms, AgentControl, AgentMedia, AudioChunk, AudioInfo, CallAction, CallError, CallState,
    CommandCache, CommandResult, Event, EventKind, EventLog, MediaHistory, MediaInfo, MediaRing,
    Owner, VideoFrame, VideoInfo,
};
use crate::pcap::read_udp;
use crate::protocol::{
    audio_packet, session_control, split_coalesced, Endpoints, JpegReassembler, Message,
    FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP, OP_MEDIA, OP_REQUEST, OP_UNLOCK,
};
use crate::state::{CallMachine, CallPhase};
use crate::transport::{AgentEvent, FrameKind, WireFrame};

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

pub const AGENT_ID: &str = "fake-pad-cap";

struct CallInner {
    machine: CallMachine,
    door_id: Option<String>,
    room_id: Option<String>,
    since_ms: Option<u64>,
}

pub struct ReplayAgent {
    call: Mutex<CallInner>,
    events: EventLog,
    commands: CommandCache,
    video: broadcast::Sender<VideoFrame>,
    audio: broadcast::Sender<AudioChunk>,
    latest: Mutex<Option<VideoFrame>>,
    history: MediaRing,
    started: Instant,
}

impl ReplayAgent {
    /// Load the capture and start replaying it. With `repeat`, the call is
    /// replayed again after that idle gap; otherwise the Agent stays idle
    /// after one pass.
    pub fn spawn(
        pcap: impl AsRef<Path>,
        speed: f64,
        cooldown: Duration,
        repeat: Option<Duration>,
        history: Duration,
        history_max_bytes: usize,
    ) -> Result<Arc<Self>> {
        anyhow::ensure!(speed.is_finite() && speed > 0.0, "speed must be positive");
        let timeline = Arc::new(replay_timeline(pcap)?);
        let (video, _) = broadcast::channel(32);
        let (audio, _) = broadcast::channel(128);
        let agent = Arc::new(Self {
            call: Mutex::new(CallInner {
                machine: CallMachine::new(cooldown),
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
            started: Instant::now(),
        });
        let replay = agent.clone();
        tokio::spawn(async move { replay.run(timeline, speed, repeat).await });
        Ok(agent)
    }

    async fn run(
        self: Arc<Self>,
        timeline: Arc<Vec<TimedFrame>>,
        speed: f64,
        repeat: Option<Duration>,
    ) {
        let mut pass = 0_u32;
        loop {
            let start = TokioInstant::now();
            for timed in timeline.iter() {
                let wait = Duration::from_micros((timed.offset_micros as f64 / speed) as u64);
                sleep_until(start + wait).await;
                let pts_us = self.started.elapsed().as_micros() as u64;
                match timed.frame.kind {
                    FrameKind::Event => {
                        if let Ok(event) = timed.frame.decode_cbor::<AgentEvent>() {
                            self.apply(timed.frame.session_id, event);
                        }
                    }
                    FrameKind::Jpeg => {
                        let frame = VideoFrame {
                            pts_us,
                            jpeg: Arc::from(timed.frame.payload.as_slice()),
                        };
                        *self.latest.lock().unwrap() = Some(frame.clone());
                        self.history.push_video(&frame);
                        let _ = self.video.send(frame);
                    }
                    FrameKind::DoorPcm => {
                        let chunk = AudioChunk {
                            pts_us,
                            pcm: Arc::from(timed.frame.payload.as_slice()),
                        };
                        self.history.push_audio(&chunk);
                        let _ = self.audio.send(chunk);
                    }
                }
            }
            pass += 1;
            let Some(gap) = repeat else {
                tracing::info!(pass, "replay finished; Agent stays idle");
                return;
            };
            tracing::info!(
                pass,
                gap_ms = gap.as_millis(),
                "replay pass complete; idling"
            );
            tokio::time::sleep(gap).await;
        }
    }

    fn session_string(&self) -> String {
        self.call
            .lock()
            .unwrap()
            .machine
            .state()
            .session_id
            .to_string()
    }

    fn apply(&self, session_id: u64, event: AgentEvent) {
        match event {
            AgentEvent::CallStarted { door_id, room_id } => {
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
            AgentEvent::PadActionObserved { opcode } if opcode == OP_ANSWER => {
                let accepted = {
                    let mut call = self.call.lock().unwrap();
                    let accepted = call.machine.pad_answer().is_ok();
                    if accepted {
                        call.since_ms = Some(now_ms());
                    }
                    accepted
                };
                if accepted {
                    self.events.push(EventKind::PadAnswered {
                        session_id: session_id.to_string(),
                    });
                }
            }
            AgentEvent::PadActionObserved { opcode } if opcode == OP_UNLOCK => {
                let pad_owns = self.call.lock().unwrap().machine.state().owner == Owner::Pad;
                if pad_owns {
                    self.events.push(EventKind::Unlocked {
                        session_id: session_id.to_string(),
                        by: Owner::Pad,
                    });
                }
            }
            AgentEvent::CallEnded { reason } => {
                let active = {
                    let mut call = self.call.lock().unwrap();
                    let active = call.machine.state().phase != CallPhase::Idle;
                    call.machine.hangup();
                    call.since_ms = Some(now_ms());
                    active
                };
                if active {
                    self.events.push(EventKind::CallEnded {
                        session_id: session_id.to_string(),
                        reason,
                    });
                }
            }
            AgentEvent::Error { message } => {
                self.events.push(EventKind::AgentError { message });
            }
            _ => {}
        }
    }

    fn execute(&self, action: CallAction, command_id: &str) -> CommandResult {
        if let Some(replayed) = self.commands.get(command_id) {
            return replayed;
        }
        // The replay Agent still builds the production packet so the exact
        // encoders are exercised even without a door station.
        let opcode = match action {
            CallAction::Claim => OP_ANSWER,
            CallAction::Unlock => OP_UNLOCK,
            CallAction::Hangup => OP_HANGUP,
        };
        let encoded = session_control(opcode, &Endpoints::captured()).is_ok();
        let session = self.session_string();
        let outcome: Result<Option<EventKind>, CallError> = if !encoded {
            Err(CallError::AgentOffline)
        } else {
            let mut call = self.call.lock().unwrap();
            match action {
                CallAction::Claim => call
                    .machine
                    .remote_answer()
                    .map(|()| {
                        call.since_ms = Some(now_ms());
                        Some(EventKind::RemoteAnswered {
                            session_id: session.clone(),
                        })
                    })
                    .map_err(CallError::from),
                CallAction::Unlock => call
                    .machine
                    .unlock(Instant::now())
                    .map(|()| {
                        Some(EventKind::Unlocked {
                            session_id: session.clone(),
                            by: Owner::Remote,
                        })
                    })
                    .map_err(CallError::from),
                CallAction::Hangup => {
                    if call.machine.state().phase == CallPhase::Idle {
                        Err(CallError::NoCall)
                    } else {
                        call.machine.hangup();
                        call.since_ms = Some(now_ms());
                        Ok(Some(EventKind::CallEnded {
                            session_id: session.clone(),
                            reason: "remote_hangup".into(),
                        }))
                    }
                }
            }
        };
        let result = match outcome {
            Ok(event) => {
                if let Some(event) = event {
                    self.events.push(event);
                }
                CommandResult::ok(command_id)
            }
            Err(error) => CommandResult::rejected(command_id, error),
        };
        self.commands.store(&result);
        tracing::info!(?action, command_id, ok = result.ok, error = ?result.error, "command");
        result
    }
}

impl AgentControl for ReplayAgent {
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
        let result = self.execute(action, command_id);
        async move { result }.boxed()
    }
}

impl AgentMedia for ReplayAgent {
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
        let result = {
            let call = self.call.lock().unwrap();
            let state = call.machine.state();
            if call.machine.remote_media_allowed(state.session_id) {
                // Exercise the production audio encoder on the way out.
                audio_packet(0, &chunk.pcm, &Endpoints::captured())
                    .map(|_| ())
                    .map_err(|_| CallError::AgentOffline)
            } else {
                Err(CallError::UnlockNotAllowed)
            }
        };
        async move { result }.boxed()
    }
}
