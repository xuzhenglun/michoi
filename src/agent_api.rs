//! The Agent interface every backend programs against.
//!
//! Two implementations exist: the in-process Agent (capture or pcap replay),
//! reached through plain function calls and channels, and the remote Agent
//! reached through the HTTP control plane (`docs/openapi.yaml`) plus RTSP.
//! Both expose the same failure model: events carry sequence numbers and
//! can be resumed, commands carry idempotency keys, slow consumers lose
//! events and recover from a snapshot.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

pub use crate::state::{CallPhase, Owner, StateError};

/// Control-plane API version advertised by `GET /v1/`.
pub const API_VERSION: &str = "1";

/// Media types the control plane understands, with codec versions.
pub const MEDIA_TYPE_JSON: &str = "application/json; v=1";
pub const MEDIA_TYPE_EVENTS: &str = "text/event-stream";
pub const MEDIA_TYPE_JPEG: &str = "image/jpeg";
pub const MEDIA_TYPE_L16: &str = "audio/L16; rate=8000; channels=1";

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallState {
    pub phase: CallPhase,
    pub owner: Owner,
    pub session_id: Option<String>,
    pub door_id: Option<String>,
    pub room_id: Option<String>,
    pub since_ms: Option<u64>,
    pub agent_id: String,
    pub connected: bool,
    pub uptime_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Snapshot {
        state: CallState,
    },
    CallStarted {
        session_id: String,
        door_id: String,
        room_id: String,
    },
    PadAnswered {
        session_id: String,
    },
    RemoteAnswered {
        session_id: String,
    },
    Unlocked {
        session_id: String,
        by: Owner,
    },
    CallEnded {
        session_id: String,
        reason: String,
    },
    AgentError {
        message: String,
    },
    MonitorStarted {
        camera_id: String,
    },
    MonitorStopped {
        camera_id: String,
        reason: String,
    },
    ElevatorCalled {
        room_id: String,
    },
}

impl EventKind {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Snapshot { .. } => "snapshot",
            Self::CallStarted { .. } => "call_started",
            Self::PadAnswered { .. } => "pad_answered",
            Self::RemoteAnswered { .. } => "remote_answered",
            Self::Unlocked { .. } => "unlocked",
            Self::CallEnded { .. } => "call_ended",
            Self::AgentError { .. } => "agent_error",
            Self::MonitorStarted { .. } => "monitor_started",
            Self::MonitorStopped { .. } => "monitor_stopped",
            Self::ElevatorCalled { .. } => "elevator_called",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub seq: u64,
    pub at_ms: u64,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallAction {
    Claim,
    Unlock,
    Hangup,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum CallError {
    #[error("no ringing call is available")]
    NotRinging,
    #[error("the physical pad owns this call")]
    PadOwnsCall,
    #[error("unlock is allowed only after the remote session has answered")]
    UnlockNotAllowed,
    #[error("unlock cooldown is active")]
    UnlockCooldown,
    #[error("no call is active")]
    NoCall,
    #[error("the Agent is offline")]
    AgentOffline,
    #[error("this operation is not supported in this mode")]
    Unsupported,
}

impl CallError {
    /// HTTP status the control plane uses for this rejection.
    pub fn http_status(self) -> u16 {
        match self {
            Self::UnlockCooldown => 429,
            Self::AgentOffline => 503,
            Self::Unsupported => 501,
            _ => 409,
        }
    }
}

impl From<StateError> for CallError {
    fn from(error: StateError) -> Self {
        match error {
            StateError::NotRinging => Self::NotRinging,
            StateError::PadOwnsCall => Self::PadOwnsCall,
            StateError::UnlockNotAllowed => Self::UnlockNotAllowed,
            StateError::UnlockCooldown => Self::UnlockCooldown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandRequest {
    pub command_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResult {
    pub command_id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CallError>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub replayed: bool,
}

impl CommandResult {
    pub fn ok(command_id: &str) -> Self {
        Self {
            command_id: command_id.to_owned(),
            ok: true,
            error: None,
            replayed: false,
        }
    }

    pub fn rejected(command_id: &str, error: CallError) -> Self {
        Self {
            command_id: command_id.to_owned(),
            ok: false,
            error: Some(error),
            replayed: false,
        }
    }

    pub fn http_status(&self) -> u16 {
        match self.error {
            None => 200,
            Some(error) => error.http_status(),
        }
    }
}

/// One complete JPEG frame from the door station.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    /// Presentation time in microseconds on the Agent's monotonic clock.
    pub pts_us: u64,
    pub jpeg: Arc<[u8]>,
}

/// Door audio, S16LE 8 kHz mono.
#[derive(Debug, Clone)]
pub struct AudioChunk {
    pub pts_us: u64,
    pub pcm: Arc<[u8]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoInfo {
    pub codec: String,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioInfo {
    pub codec: String,
    pub sample_rate: u32,
    pub channels: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaInfo {
    pub rtsp_url: Option<String>,
    pub video: VideoInfo,
    pub audio: AudioInfo,
    pub talk: bool,
    /// Configured pre-roll window kept in memory, in milliseconds.
    pub history_ms: u64,
    /// Span currently held in the pre-roll buffer, in milliseconds.
    pub buffered_ms: u64,
}

/// Buffered media handed to a late joiner (RTSP `Range`, event clips).
#[derive(Debug, Clone, Default)]
pub struct MediaHistory {
    pub video: Vec<VideoFrame>,
    pub audio: Vec<AudioChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiInfo {
    pub api_version: String,
    pub agent_id: String,
    pub media_types: Vec<String>,
    pub capabilities: Vec<String>,
}

/// A door camera the Pad may view (from the provisioned roster), with its
/// current reachability by UDP 10008 discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CameraInfo {
    pub station_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    pub reachable: bool,
}

/// Call control: state, resumable events, idempotent commands. Monitor,
/// elevator and camera listing are the Pad's outbound operations; they default
/// to unsupported so replay / door-station implementations need not provide
/// them.
pub trait AgentControl: Send + Sync + 'static {
    fn agent_id(&self) -> String;
    fn state(&self) -> CallState;
    fn subscribe(&self) -> broadcast::Receiver<Event>;
    /// Events after `after_seq`, or `None` when they are no longer buffered
    /// and the caller must resynchronise from `state()`.
    fn recent(&self, after_seq: u64) -> Option<Vec<Event>>;
    fn command(&self, action: CallAction, command_id: &str) -> BoxFuture<'_, CommandResult>;

    /// The roster of door cameras and whether each answers discovery now.
    fn cameras(&self) -> BoxFuture<'_, Vec<CameraInfo>> {
        Box::pin(async { Vec::new() })
    }

    /// Call the elevator to this Pad's floor.
    fn call_elevator(&self, _command_id: &str) -> BoxFuture<'_, CommandResult> {
        Box::pin(async move { CommandResult::rejected("", CallError::Unsupported) })
    }

    /// Start viewing a door camera (no ring). Its video/audio then appear on
    /// the media routes just like an incoming call's.
    fn start_monitor(&self, _camera_id: &str) -> BoxFuture<'_, Result<(), CallError>> {
        Box::pin(async { Err(CallError::Unsupported) })
    }

    /// Stop the active monitor.
    fn stop_monitor(&self) -> BoxFuture<'_, Result<(), CallError>> {
        Box::pin(async { Err(CallError::Unsupported) })
    }
}

/// Media: door video/audio feeds, snapshot, talk-back.
pub trait AgentMedia: Send + Sync + 'static {
    /// Current time on the clock that stamps `pts_us`, so consumers can
    /// compute the age of a frame without agreeing on wall clocks.
    fn clock_us(&self) -> u64;
    fn video(&self) -> broadcast::Receiver<VideoFrame>;
    fn audio(&self) -> broadcast::Receiver<AudioChunk>;
    fn snapshot(&self) -> Option<VideoFrame>;
    /// Frames and audio with `pts_us > since_us` still held in the pre-roll
    /// buffer, oldest first.
    fn history(&self, since_us: u64) -> MediaHistory;
    fn media_info(&self) -> MediaInfo;
    fn talk(&self, chunk: AudioChunk) -> BoxFuture<'_, Result<(), CallError>>;
}

/// Time-bounded pre-roll buffer of door media, also capped in bytes so a
/// misconfiguration cannot exhaust a small Agent.
pub struct MediaRing {
    inner: Mutex<RingInner>,
    window_us: u64,
    max_bytes: usize,
}

#[derive(Default)]
struct RingInner {
    video: VecDeque<VideoFrame>,
    audio: VecDeque<AudioChunk>,
    bytes: usize,
}

impl MediaRing {
    pub fn new(window: Duration, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(RingInner::default()),
            window_us: window.as_micros() as u64,
            max_bytes,
        }
    }

    pub fn window(&self) -> Duration {
        Duration::from_micros(self.window_us)
    }

    pub fn push_video(&self, frame: &VideoFrame) {
        if self.window_us == 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.bytes += frame.jpeg.len();
        inner.video.push_back(frame.clone());
        Self::evict(&mut inner, self.window_us, self.max_bytes, frame.pts_us);
    }

    pub fn push_audio(&self, chunk: &AudioChunk) {
        if self.window_us == 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.bytes += chunk.pcm.len();
        inner.audio.push_back(chunk.clone());
        Self::evict(&mut inner, self.window_us, self.max_bytes, chunk.pts_us);
    }

    fn evict(inner: &mut RingInner, window_us: u64, max_bytes: usize, newest_us: u64) {
        let floor = newest_us.saturating_sub(window_us);
        while inner.video.front().is_some_and(|f| f.pts_us < floor) {
            let dropped = inner.video.pop_front().unwrap();
            inner.bytes -= dropped.jpeg.len();
        }
        while inner.audio.front().is_some_and(|a| a.pts_us < floor) {
            let dropped = inner.audio.pop_front().unwrap();
            inner.bytes -= dropped.pcm.len();
        }
        // Byte cap: drop the oldest of whichever stream is oldest.
        while inner.bytes > max_bytes {
            let video_oldest = inner.video.front().map(|f| f.pts_us);
            let audio_oldest = inner.audio.front().map(|a| a.pts_us);
            match (video_oldest, audio_oldest) {
                (Some(v), Some(a)) if a < v => {
                    let dropped = inner.audio.pop_front().unwrap();
                    inner.bytes -= dropped.pcm.len();
                }
                (Some(_), _) => {
                    let dropped = inner.video.pop_front().unwrap();
                    inner.bytes -= dropped.jpeg.len();
                }
                (None, Some(_)) => {
                    let dropped = inner.audio.pop_front().unwrap();
                    inner.bytes -= dropped.pcm.len();
                }
                (None, None) => break,
            }
        }
    }

    pub fn history(&self, since_us: u64) -> MediaHistory {
        let inner = self.inner.lock().unwrap();
        MediaHistory {
            video: inner
                .video
                .iter()
                .filter(|f| f.pts_us > since_us)
                .cloned()
                .collect(),
            audio: inner
                .audio
                .iter()
                .filter(|a| a.pts_us > since_us)
                .cloned()
                .collect(),
        }
    }

    /// Span between the oldest and newest buffered item.
    pub fn buffered(&self) -> Duration {
        let inner = self.inner.lock().unwrap();
        let oldest = inner
            .video
            .front()
            .map(|f| f.pts_us)
            .into_iter()
            .chain(inner.audio.front().map(|a| a.pts_us))
            .min();
        let newest = inner
            .video
            .back()
            .map(|f| f.pts_us)
            .into_iter()
            .chain(inner.audio.back().map(|a| a.pts_us))
            .max();
        match (oldest, newest) {
            (Some(o), Some(n)) => Duration::from_micros(n.saturating_sub(o)),
            _ => Duration::ZERO,
        }
    }

    pub fn bytes(&self) -> usize {
        self.inner.lock().unwrap().bytes
    }
}

/// Sequence-numbered event ring buffer with live fan-out.
pub struct EventLog {
    inner: Mutex<LogInner>,
    live: broadcast::Sender<Event>,
    capacity: usize,
}

struct LogInner {
    events: VecDeque<Event>,
    next_seq: u64,
}

impl EventLog {
    pub fn new(capacity: usize, live_capacity: usize) -> Self {
        let (live, _) = broadcast::channel(live_capacity);
        Self {
            inner: Mutex::new(LogInner {
                events: VecDeque::with_capacity(capacity),
                next_seq: 1,
            }),
            live,
            capacity,
        }
    }

    pub fn push(&self, kind: EventKind) -> Event {
        let event = {
            let mut inner = self.inner.lock().unwrap();
            let event = Event {
                seq: inner.next_seq,
                at_ms: now_ms(),
                kind,
            };
            inner.next_seq += 1;
            if inner.events.len() == self.capacity {
                inner.events.pop_front();
            }
            inner.events.push_back(event.clone());
            event
        };
        let _ = self.live.send(event.clone());
        event
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.live.subscribe()
    }

    pub fn last_seq(&self) -> u64 {
        self.inner.lock().unwrap().next_seq - 1
    }

    /// Events with `seq > after_seq`; `None` when `after_seq` fell out of
    /// the buffer (the caller has a gap it cannot fill).
    pub fn recent(&self, after_seq: u64) -> Option<Vec<Event>> {
        let inner = self.inner.lock().unwrap();
        let oldest = inner.events.front().map(|e| e.seq);
        if after_seq + 1 >= inner.next_seq {
            return Some(Vec::new());
        }
        match oldest {
            Some(oldest) if after_seq + 1 >= oldest => Some(
                inner
                    .events
                    .iter()
                    .filter(|e| e.seq > after_seq)
                    .cloned()
                    .collect(),
            ),
            _ => None,
        }
    }
}

/// Bounded idempotency cache for command results.
pub struct CommandCache {
    inner: Mutex<(HashMap<String, CommandResult>, VecDeque<String>)>,
    capacity: usize,
}

impl CommandCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
            capacity,
        }
    }

    /// Previously stored result for this id, flagged as replayed.
    pub fn get(&self, command_id: &str) -> Option<CommandResult> {
        self.inner
            .lock()
            .unwrap()
            .0
            .get(command_id)
            .cloned()
            .map(|mut result| {
                result.replayed = true;
                result
            })
    }

    pub fn store(&self, result: &CommandResult) {
        let mut inner = self.inner.lock().unwrap();
        if inner.0.len() >= self.capacity {
            if let Some(oldest) = inner.1.pop_front() {
                inner.0.remove(&oldest);
            }
        }
        inner.1.push_back(result.command_id.clone());
        inner.0.insert(result.command_id.clone(), result.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(pts_ms: u64, bytes: usize) -> VideoFrame {
        VideoFrame {
            pts_us: pts_ms * 1000,
            jpeg: Arc::from(vec![0_u8; bytes]),
        }
    }

    #[test]
    fn media_ring_evicts_by_time_and_bytes() {
        let ring = MediaRing::new(Duration::from_secs(2), 10_000);
        for i in 0..10 {
            ring.push_video(&frame(i * 500, 100));
        }
        // 4.5 s pushed, window 2 s: frames at >= 2.5 s remain (2.5..=4.5).
        let history = ring.history(0);
        assert_eq!(history.video.first().unwrap().pts_us, 2_500_000);
        assert_eq!(history.video.len(), 5);
        assert_eq!(ring.buffered(), Duration::from_millis(2000));
        // Byte cap wins over time.
        for i in 10..20 {
            ring.push_video(&frame(i * 500, 3_000));
        }
        assert!(ring.bytes() <= 10_000);
        assert!(ring.history(0).video.len() <= 3);
        // since_us filters.
        assert!(ring.history(u64::MAX).video.is_empty());
        // Zero window disables buffering.
        let off = MediaRing::new(Duration::ZERO, 10_000);
        off.push_video(&frame(1, 10));
        assert!(off.history(0).video.is_empty());
    }

    #[test]
    fn event_log_resumes_inside_window_and_reports_gaps() {
        let log = EventLog::new(3, 8);
        for _ in 0..5 {
            log.push(EventKind::AgentError {
                message: "x".into(),
            });
        }
        assert_eq!(log.last_seq(), 5);
        assert_eq!(log.recent(5).unwrap().len(), 0);
        assert_eq!(
            log.recent(3)
                .unwrap()
                .iter()
                .map(|e| e.seq)
                .collect::<Vec<_>>(),
            vec![4, 5]
        );
        // Oldest buffered is 3, so a client that saw 1 has a gap.
        assert!(log.recent(1).is_none());
        assert_eq!(log.recent(2).unwrap().len(), 3);
    }

    #[test]
    fn command_cache_replays_and_evicts() {
        let cache = CommandCache::new(2);
        cache.store(&CommandResult::ok("a"));
        cache.store(&CommandResult::rejected("b", CallError::NotRinging));
        assert!(cache.get("a").unwrap().replayed);
        cache.store(&CommandResult::ok("c"));
        assert!(cache.get("a").is_none());
        assert_eq!(cache.get("b").unwrap().error, Some(CallError::NotRinging));
    }

    #[test]
    fn events_serialize_with_flat_type_tag() {
        let event = Event {
            seq: 7,
            at_ms: 1,
            kind: EventKind::CallEnded {
                session_id: "1".into(),
                reason: "hangup".into(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"call_ended\""));
        assert!(json.contains("\"seq\":7"));
    }
}
