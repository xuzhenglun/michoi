//! Software door station: an interactive Agent for manual testing.
//!
//! Unlike the pcap replay Agent, which drives a fixed demo timeline, this is
//! a virtual door you operate. It presents the saved capture as the door
//! camera and microphone, lets you ring and hang up from a console, invokes a
//! callback (default: log then noop) for unlock and other events, and plays
//! the visitor's talk-back audio through the host speakers.
//!
//! Backends and the browser Pad connect to its HTTP control plane exactly as
//! they would to a real Agent.

use std::fs::File;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::future::BoxFuture;
use futures_util::FutureExt;
use tokio::sync::broadcast;

use crate::replay_agent::replay_timeline;
use crate::agent_api::{
    now_ms, AgentControl, AgentMedia, AudioChunk, AudioInfo, CallAction, CallError, CallState,
    CommandCache, CommandResult, Event, EventKind, EventLog, MediaHistory, MediaInfo, MediaRing,
    Owner, VideoFrame, VideoInfo,
};
use crate::state::{CallMachine, CallPhase};
use crate::transport::FrameKind;

pub const AGENT_ID: &str = "software-door-station";

/// Shell commands invoked on call events; `None` logs and does nothing.
#[derive(Debug, Clone, Default)]
pub struct Callbacks {
    pub on_answer: Option<String>,
    pub on_unlock: Option<String>,
    pub on_hangup: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DoorStationConfig {
    pub door_id: String,
    pub room_id: String,
    /// Source door IPv4 used to pick door->Pad datagrams when emitting to a
    /// real Pad on the wire.
    pub door_ip: Ipv4Addr,
    /// Frames per second at which the saved camera loops.
    pub loop_fps: u16,
    pub cooldown: Duration,
    pub history: Duration,
    pub history_max_bytes: usize,
    pub callbacks: Callbacks,
    /// Play the visitor's talk audio through ffplay (the default player).
    pub play: bool,
    /// Custom player command for the visitor's talk audio (S16LE 8 kHz mono on
    /// stdin); implies playing. Overrides `play`.
    pub player: Option<String>,
    /// When not playing, write the visitor's talk audio as raw S16LE here
    /// (defaults to `visitor-talk.s16le`).
    pub audio_out: Option<PathBuf>,
}

impl Default for DoorStationConfig {
    fn default() -> Self {
        Self {
            door_id: "M00000000000".into(),
            room_id: "S00000000000".into(),
            door_ip: Ipv4Addr::new(192, 168, 124, 2),
            loop_fps: 8,
            cooldown: Duration::from_secs(1),
            history: Duration::from_secs(5),
            history_max_bytes: 2 * 1024 * 1024,
            callbacks: Callbacks::default(),
            play: false,
            player: None,
            audio_out: None,
        }
    }
}

struct CallInner {
    machine: CallMachine,
    since_ms: Option<u64>,
}

pub struct DoorStation {
    frames: Vec<Arc<[u8]>>,
    audio: Vec<Arc<[u8]>>,
    config: DoorStationConfig,
    call: Mutex<CallInner>,
    events: EventLog,
    commands: CommandCache,
    video: broadcast::Sender<VideoFrame>,
    door_audio: broadcast::Sender<AudioChunk>,
    latest: Mutex<Option<VideoFrame>>,
    history: MediaRing,
    streaming: AtomicBool,
    speaker: Mutex<Option<AudioSink>>,
    started: Instant,
    runtime: tokio::runtime::Handle,
}

impl DoorStation {
    /// Load the saved camera/microphone data from a capture and build a door
    /// station ready to be served.
    pub fn from_capture(pcap: impl AsRef<Path>, config: DoorStationConfig) -> Result<Arc<Self>> {
        let timeline = replay_timeline(pcap)?;
        let mut frames = Vec::new();
        let mut audio = Vec::new();
        for timed in &timeline {
            match timed.frame.kind {
                FrameKind::Jpeg => frames.push(Arc::from(timed.frame.payload.as_slice())),
                FrameKind::DoorPcm => audio.push(Arc::from(timed.frame.payload.as_slice())),
                _ => {}
            }
        }
        anyhow::ensure!(!frames.is_empty(), "capture has no JPEG frames to loop");
        tracing::info!(
            frames = frames.len(),
            audio_chunks = audio.len(),
            "door station media loaded"
        );
        let (video, _) = broadcast::channel(32);
        let (door_audio, _) = broadcast::channel(128);
        // Resolve the talk sink once: play only if asked, else write to a file.
        let speaker = AudioSink::open(
            config.play,
            config.player.as_deref(),
            config.audio_out.as_deref(),
            "visitor-talk.s16le",
        )
        .map_err(|error| tracing::warn!(%error, "talk audio sink disabled"))
        .ok();
        Ok(Arc::new(Self {
            frames,
            audio,
            call: Mutex::new(CallInner {
                machine: CallMachine::with_policy(config.cooldown, false),
                since_ms: None,
            }),
            events: EventLog::new(256, 64),
            commands: CommandCache::new(256),
            video,
            door_audio,
            latest: Mutex::new(None),
            history: MediaRing::new(config.history, config.history_max_bytes),
            streaming: AtomicBool::new(false),
            speaker: Mutex::new(speaker),
            started: Instant::now(),
            runtime: tokio::runtime::Handle::current(),
            config,
        }))
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

    /// Start an incoming call (operator pressed the doorbell).
    pub fn ring(self: &Arc<Self>) {
        {
            let mut call = self.call.lock().unwrap();
            if call.machine.state().phase != CallPhase::Idle {
                tracing::info!("already in a call; ignoring ring");
                return;
            }
            let session = now_ms().max(1);
            call.machine.start_call(session);
            call.since_ms = Some(now_ms());
        }
        let session = self.session_string();
        self.events.push(EventKind::CallStarted {
            session_id: session,
            door_id: self.config.door_id.clone(),
            room_id: self.config.room_id.clone(),
        });
        tracing::info!("ringing: door is calling the room");
        if !self.streaming.swap(true, Ordering::AcqRel) {
            let station = self.clone();
            self.runtime
                .spawn(async move { station.media_loop().await });
        }
    }

    /// Ring a real room Pad by replaying the captured door->Pad datagrams to
    /// `target` over the wire. Independent of the internal HTTP call state.
    pub fn emit_to(self: &Arc<Self>, target: SocketAddr) {
        let door = crate::protocol::Station::new(self.config.door_id.clone(), self.config.door_ip);
        let room = crate::protocol::Station::new(self.config.room_id.clone(), target_v4(&target));
        let identity = crate::emitter::DoorIdentity { door, room };
        let media = crate::emitter::MediaSource {
            frames: self.frames.iter().map(|f| f.to_vec()).collect(),
            audio: self.audio.iter().map(|a| a.to_vec()).collect(),
        };
        let fps = self.config.loop_fps;
        self.runtime.spawn(async move {
            if let Err(error) =
                crate::emitter::run_emulator(identity, media, target, fps, None, None).await
            {
                tracing::warn!(%error, %target, "door emulation failed");
            }
        });
    }

    /// End the current call (operator or a backend hung up).
    pub fn hangup_local(&self, reason: &str) {
        let active = {
            let mut call = self.call.lock().unwrap();
            let active = call.machine.state().phase != CallPhase::Idle;
            call.machine.hangup();
            call.since_ms = Some(now_ms());
            active
        };
        self.streaming.store(false, Ordering::Release);
        self.stop_speaker();
        if active {
            let session = self.session_string();
            self.events.push(EventKind::CallEnded {
                session_id: session,
                reason: reason.to_owned(),
            });
            tracing::info!(reason, "call ended");
            self.run_callback("hangup", self.config.callbacks.on_hangup.as_deref());
        }
    }

    async fn media_loop(self: Arc<Self>) {
        let fps = self.config.loop_fps.max(1) as u64;
        let frame_gap = Duration::from_micros(1_000_000 / fps);
        let mut frame_at = tokio::time::interval(frame_gap);
        // The door mic pushes 32 ms PCM chunks, the door station's native size.
        let mut audio_at = tokio::time::interval(Duration::from_millis(32));
        let mut fi = 0usize;
        let mut ai = 0usize;
        while self.streaming.load(Ordering::Acquire) {
            tokio::select! {
                _ = frame_at.tick() => {
                    let jpeg = self.frames[fi % self.frames.len()].clone();
                    fi += 1;
                    let frame = VideoFrame { pts_us: self.clock_us(), jpeg };
                    *self.latest.lock().unwrap() = Some(frame.clone());
                    self.history.push_video(&frame);
                    let _ = self.video.send(frame);
                }
                _ = audio_at.tick() => {
                    if self.audio.is_empty() { continue; }
                    let pcm = self.audio[ai % self.audio.len()].clone();
                    ai += 1;
                    let chunk = AudioChunk { pts_us: self.clock_us(), pcm };
                    self.history.push_audio(&chunk);
                    let _ = self.door_audio.send(chunk);
                }
            }
        }
        tracing::debug!("media loop stopped");
    }

    fn run_callback(&self, event: &str, command: Option<&str>) {
        let session = self.session_string();
        match command {
            None => {
                tracing::info!(event, session = %session, "door event (no callback configured)")
            }
            Some(command) => {
                let command = command.to_owned();
                let event = event.to_owned();
                // Detached; a slow or failing hook must not block call control.
                std::thread::spawn(move || {
                    let status = Command::new("sh")
                        .arg("-c")
                        .arg(&command)
                        .env("DOOR_EVENT", &event)
                        .env("DOOR_SESSION", &session)
                        .status();
                    match status {
                        Ok(status) if status.success() => {
                            tracing::info!(event, "callback ran")
                        }
                        Ok(status) => tracing::warn!(event, %status, "callback failed"),
                        Err(error) => tracing::warn!(event, %error, "callback could not start"),
                    }
                });
            }
        }
    }

    fn play_talk(&self, pcm: &[u8]) {
        let mut guard = self.speaker.lock().unwrap();
        if let Some(sink) = guard.as_mut() {
            if sink.write(pcm).is_err() {
                tracing::warn!("talk audio sink closed; dropping further talk");
                *guard = None;
            }
        }
    }

    fn stop_speaker(&self) {
        // Keep the sink open across calls; just flush the file if writing.
        if let Some(sink) = self.speaker.lock().unwrap().as_mut() {
            sink.flush();
        }
    }
}

/// The default player: ffplay reading raw S16LE 8 kHz mono from stdin.
pub const DEFAULT_PLAYER: &str =
    "ffplay -hide_banner -loglevel error -nodisp -autoexit -f s16le -ar 8000 -ch_layout mono -i pipe:0";

/// A subprocess that plays raw PCM written to its stdin, used to hear the
/// visitor's talk-back and, in the door emulator, the Pad's voice.
pub struct Player {
    child: Child,
    stdin: ChildStdin,
}

impl Player {
    pub fn start(command: &str) -> Result<Self> {
        let mut parts = command.split_whitespace();
        let program = parts.next().context("empty player command")?;
        let mut child = Command::new(program)
            .args(parts)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning audio player {program}"))?;
        let stdin = child.stdin.take().context("player stdin")?;
        Ok(Self { child, stdin })
    }

    pub fn write(&mut self, pcm: &[u8]) -> std::io::Result<()> {
        self.stdin.write_all(pcm)
    }
}

/// Where received PCM goes. Playing needs an explicit flag; otherwise the audio
/// is written as raw S16LE 8 kHz mono to a file (import it later with, e.g.,
/// `ffplay -f s16le -ar 8000 -ch_layout mono <file>`).
pub enum AudioSink {
    Play(Player),
    File { file: File, path: PathBuf },
}

impl AudioSink {
    /// Resolve from CLI intent. A custom `player` command or the `play` flag
    /// plays; otherwise the audio is written to `audio_out` (or `default_file`
    /// when unset). Returns `None` only when a player command was requested
    /// but could not start.
    pub fn open(
        play: bool,
        player: Option<&str>,
        audio_out: Option<&Path>,
        default_file: &str,
    ) -> Result<Self> {
        if let Some(cmd) = player.filter(|c| !c.is_empty()) {
            tracing::info!(player = cmd, "playing received audio");
            return Player::start(cmd).map(AudioSink::Play);
        }
        if play {
            tracing::info!("playing received audio through ffplay");
            return Player::start(DEFAULT_PLAYER).map(AudioSink::Play);
        }
        let path = audio_out
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(default_file));
        let file = File::create(&path)
            .with_context(|| format!("creating audio file {}", path.display()))?;
        tracing::info!(
            path = %path.display(),
            "writing received audio to file (raw S16LE 8 kHz mono); pass --play to hear it instead"
        );
        Ok(AudioSink::File { file, path })
    }

    /// Write one PCM chunk. The file variant writes unbuffered so audio is not
    /// lost if the process is terminated abruptly.
    pub fn write(&mut self, pcm: &[u8]) -> std::io::Result<()> {
        match self {
            AudioSink::Play(player) => player.write(pcm),
            AudioSink::File { file, .. } => file.write_all(pcm),
        }
    }

    pub fn flush(&mut self) {
        if let AudioSink::File { file, path } = self {
            if let Err(error) = file.flush() {
                tracing::warn!(%error, path = %path.display(), "flushing audio file");
            }
        }
    }
}

impl Drop for Player {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl AgentControl for DoorStation {
    fn agent_id(&self) -> String {
        AGENT_ID.into()
    }

    fn state(&self) -> CallState {
        let call = self.call.lock().unwrap();
        let state = call.machine.state();
        let active = state.phase != CallPhase::Idle;
        CallState {
            phase: state.phase,
            owner: state.owner,
            session_id: active.then(|| state.session_id.to_string()),
            door_id: active.then(|| self.config.door_id.clone()),
            room_id: active.then(|| self.config.room_id.clone()),
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
        if let Some(replayed) = self.commands.get(command_id) {
            return async move { replayed }.boxed();
        }
        let session = self.session_string();
        let outcome: Result<Option<(EventKind, &'static str, Option<String>)>, CallError> = {
            let mut call = self.call.lock().unwrap();
            match action {
                CallAction::Claim => call
                    .machine
                    .remote_answer()
                    .map(|()| {
                        call.since_ms = Some(now_ms());
                        Some((
                            EventKind::RemoteAnswered {
                                session_id: session.clone(),
                            },
                            "answer",
                            self.config.callbacks.on_answer.clone(),
                        ))
                    })
                    .map_err(CallError::from),
                CallAction::Unlock => call
                    .machine
                    .unlock(Instant::now())
                    .map(|()| {
                        Some((
                            EventKind::Unlocked {
                                session_id: session.clone(),
                                by: Owner::Remote,
                            },
                            "unlock",
                            self.config.callbacks.on_unlock.clone(),
                        ))
                    })
                    .map_err(CallError::from),
                CallAction::Hangup => {
                    if call.machine.state().phase == CallPhase::Idle {
                        Err(CallError::NoCall)
                    } else {
                        call.machine.hangup();
                        call.since_ms = Some(now_ms());
                        Ok(Some((
                            EventKind::CallEnded {
                                session_id: session.clone(),
                                reason: "remote_hangup".into(),
                            },
                            "hangup",
                            self.config.callbacks.on_hangup.clone(),
                        )))
                    }
                }
            }
        };
        let result = match outcome {
            Ok(Some((event, kind, callback))) => {
                let ended = matches!(event, EventKind::CallEnded { .. });
                self.events.push(event);
                self.run_callback(kind, callback.as_deref());
                if ended {
                    self.streaming.store(false, Ordering::Release);
                    self.stop_speaker();
                }
                CommandResult::ok(command_id)
            }
            Ok(None) => CommandResult::ok(command_id),
            Err(error) => CommandResult::rejected(command_id, error),
        };
        self.commands.store(&result);
        tracing::info!(?action, command_id, ok = result.ok, error = ?result.error, "command");
        async move { result }.boxed()
    }
}

impl AgentMedia for DoorStation {
    fn clock_us(&self) -> u64 {
        self.started.elapsed().as_micros() as u64
    }

    fn video(&self) -> broadcast::Receiver<VideoFrame> {
        self.video.subscribe()
    }

    fn audio(&self) -> broadcast::Receiver<AudioChunk> {
        self.door_audio.subscribe()
    }

    fn snapshot(&self) -> Option<VideoFrame> {
        self.latest.lock().unwrap().clone().or_else(|| {
            self.frames.first().map(|jpeg| VideoFrame {
                pts_us: self.clock_us(),
                jpeg: jpeg.clone(),
            })
        })
    }

    fn history(&self, since_us: u64) -> MediaHistory {
        self.history.history(since_us)
    }

    fn media_info(&self) -> MediaInfo {
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
            talk: self.call.lock().unwrap().machine.state().phase != CallPhase::Idle,
            history_ms: self.history.window().as_millis() as u64,
            buffered_ms: self.history.buffered().as_millis() as u64,
        }
    }

    fn talk(&self, chunk: AudioChunk) -> BoxFuture<'_, Result<(), CallError>> {
        // The door station always plays what the visitor hears; it does not
        // gate talk on ownership the way the packet Agent must.
        self.play_talk(&chunk.pcm);
        async move { Ok(()) }.boxed()
    }
}

/// Read operator commands from stdin: `ring`, `hangup`, `quit`, `help`.
fn target_v4(addr: &SocketAddr) -> Ipv4Addr {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

/// Parse `ip` or `ip:port`, defaulting the port to the PENGUIN0 control port.
fn parse_target(arg: &str) -> Option<SocketAddr> {
    if let Ok(addr) = arg.parse::<SocketAddr>() {
        return Some(addr);
    }
    let ip: Ipv4Addr = arg.parse().ok()?;
    Some(SocketAddr::new(ip.into(), crate::protocol::CONTROL_PORT))
}

pub fn spawn_console(station: Arc<DoorStation>) {
    std::thread::spawn(move || {
        use std::io::BufRead;
        println!("软件门口机就绪。命令：ring 内部呼叫 / ring <ip> 呼叫真实 Pad / hangup 挂断 / quit 退出");
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else { break };
            match line.trim() {
                other if other.starts_with("ring ") => {
                    let arg = other[5..].trim();
                    match parse_target(arg) {
                        Some(target) => {
                            println!(
                                "向 {target} 发送真实门口机呼叫（重放抓包的门口机->Pad 数据报）"
                            );
                            station.emit_to(target);
                        }
                        None => println!("无法解析目标地址：{arg}（示例 ring 192.168.124.61）"),
                    }
                }
                "ring" | "r" => station.ring(),
                "hangup" | "h" | "end" => station.hangup_local("operator_hangup"),
                "quit" | "q" | "exit" => {
                    println!("退出");
                    std::process::exit(0);
                }
                "help" | "?" | "" => {
                    println!(
                        "ring 内部呼叫 / ring <ip> 向真实 Pad 发送呼叫 / hangup 挂断 / quit 退出"
                    );
                }
                other => println!("未知命令：{other}（ring / hangup / quit）"),
            }
        }
    });
}
