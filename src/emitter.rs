//! Software door-station emulator that speaks PENGUIN0 from the spec.
//!
//! It does not replay the capture: every datagram is built from
//! [`crate::protocol`] out of a configured door and room identity, so putting
//! it in front of a real Pad tests whether our protocol analysis is correct.
//! The camera and microphone are fake file devices — a directory of JPEG
//! frames and an optional raw-PCM file (silence otherwise).
//!
//! It rings the target, streams video and audio, sends keepalives, and
//! listens for the Pad's replies (answer, unlock, voice, hangup), so a person
//! can answer on the (possibly far-away) Pad and confirm the round trip.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::protocol::{
    audio_packet, jpeg_packets, session_control, split_coalesced, Endpoints, Message, Station,
    FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP, OP_KEEPALIVE, OP_MEDIA, OP_REPLY, OP_UNLOCK,
};

/// The door's own identity and the room Pad it calls.
#[derive(Debug, Clone)]
pub struct DoorIdentity {
    pub door: Station,
    pub room: Station,
}

impl DoorIdentity {
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            door: self.door.clone(),
            room: self.room.clone(),
        }
    }
}

/// Fake camera and microphone: JPEG frames and 512-byte PCM chunks.
#[derive(Debug, Clone, Default)]
pub struct MediaSource {
    pub frames: Vec<Vec<u8>>,
    pub audio: Vec<Vec<u8>>,
}

impl MediaSource {
    /// Read `*.jpg`/`*.jpeg` from `frames_dir` (sorted) as the camera, and,
    /// when given, raw S16LE 8 kHz PCM from `audio_file` as the microphone.
    pub fn load(
        frames_dir: &std::path::Path,
        audio_file: Option<&std::path::Path>,
    ) -> Result<Self> {
        let mut entries: Vec<_> = std::fs::read_dir(frames_dir)
            .with_context(|| format!("reading frames directory {}", frames_dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("jpg") | Some("jpeg")
                )
            })
            .collect();
        entries.sort();
        let frames: Vec<Vec<u8>> = entries
            .iter()
            .filter_map(|p| std::fs::read(p).ok())
            .filter(|b| b.starts_with(&[0xff, 0xd8]))
            .collect();
        anyhow::ensure!(
            !frames.is_empty(),
            "no JPEG frames in {}",
            frames_dir.display()
        );
        let audio = match audio_file {
            Some(path) => std::fs::read(path)
                .with_context(|| format!("reading audio file {}", path.display()))?
                .chunks(512)
                .map(|c| {
                    let mut chunk = c.to_vec();
                    chunk.resize(512, 0);
                    chunk
                })
                .collect(),
            None => Vec::new(),
        };
        Ok(Self { frames, audio })
    }
}

/// What the emulator observed coming back from the Pad.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DoorObservation {
    pub capability_reply: bool,
    pub answered: bool,
    pub unlocks: u64,
    pub hangups: u64,
    pub audio_packets: u64,
    pub audio_bytes: u64,
}

fn observe_reply(
    raw: &[u8],
    obs: &mut DoorObservation,
    speaker: &mut Option<crate::door_station::Player>,
) -> Option<String> {
    let msg = Message::parse(raw).ok()?;
    if msg.family != FAMILY_SESSION {
        return None;
    }
    match msg.opcode {
        OP_REPLY => {
            obs.capability_reply = true;
            Some("Pad accepted the ring (00b7/03 capability reply)".into())
        }
        OP_ANSWER => {
            obs.answered = true;
            Some("Pad answered (00b7/05)".into())
        }
        OP_UNLOCK => {
            obs.unlocks += 1;
            Some(format!("UNLOCK from Pad (00b7/06) x{}", obs.unlocks))
        }
        OP_HANGUP => {
            obs.hangups += 1;
            Some("Pad hung up (00b7/1e)".into())
        }
        OP_MEDIA => {
            let media = msg.media()?;
            if media.media_type == MEDIA_AUDIO {
                obs.audio_packets += 1;
                obs.audio_bytes += media.data.len() as u64;
                if let Some(player) = speaker.as_mut() {
                    let _ = player.write(media.data);
                }
                if obs.audio_packets == 1 || obs.audio_packets % 100 == 0 {
                    return Some(format!(
                        "voice from Pad: {} audio packets",
                        obs.audio_packets
                    ));
                }
            }
            None
        }
        _ => None,
    }
}

/// Ring `target` as a synthesized door station and drive the call until a Pad
/// hangup, `duration`, or the future is dropped. Returns what came back.
pub async fn run_emulator(
    identity: DoorIdentity,
    media: MediaSource,
    target: SocketAddr,
    fps: u16,
    duration: Option<Duration>,
    player: Option<String>,
) -> Result<DoorObservation> {
    let endpoints = identity.endpoints();
    let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), target.port());
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(%error, %bind, "cannot bind the control port; using an ephemeral port (a real Pad may expect the door on the control port)");
            UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?
        }
    };
    socket
        .connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))?;
    let socket = Arc::new(socket);
    tracing::info!(
        %target, local = %socket.local_addr()?, door = %identity.door.id, room = %identity.room.id,
        room_ip = %identity.room.ip, frames = media.frames.len(),
        "door emulator: sending synthesized ring; answer on the Pad"
    );

    let obs = Arc::new(std::sync::Mutex::new(DoorObservation::default()));
    let mut speaker = match player.as_deref() {
        Some("") => None,
        cmd => crate::door_station::Player::start_opt(cmd).ok().flatten(),
    };

    // Receiver: report control events and play the Pad's voice.
    let recv_socket = socket.clone();
    let recv_obs = obs.clone();
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let receiver = tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_536];
        loop {
            let Ok(size) = recv_socket.recv(&mut buf).await else {
                break;
            };
            let mut hung_up = false;
            for raw in split_coalesced(&buf[..size]) {
                if let Some(line) = observe_reply(raw, &mut recv_obs.lock().unwrap(), &mut speaker)
                {
                    tracing::info!("{line}");
                }
                if let Ok(msg) = Message::parse(raw) {
                    if msg.family == FAMILY_SESSION && msg.opcode == OP_HANGUP {
                        hung_up = true;
                    }
                }
            }
            if hung_up {
                let _ = stop_tx.send(true);
            }
        }
    });

    // Ring, then stream media and keepalives until stopped.
    socket
        .send(&crate::protocol::session_request(&endpoints)?)
        .await
        .context("sending session request")?;
    let frame_gap = Duration::from_micros(1_000_000 / fps.max(1) as u64);
    let mut frame_at = tokio::time::interval(frame_gap);
    let mut audio_at = tokio::time::interval(Duration::from_millis(32));
    let mut keepalive_at = tokio::time::interval(Duration::from_secs(1));
    let deadline = duration.map(|d| tokio::time::Instant::now() + d);
    let mut fi = 0usize;
    let mut ai = 0usize;
    let mut seq = 1u16;
    let mut aseq = 0u16;
    let silence = vec![0u8; 512];
    loop {
        if *stop_rx.borrow() {
            break;
        }
        if let Some(deadline) = deadline {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        tokio::select! {
            _ = frame_at.tick() => {
                let frame = &media.frames[fi % media.frames.len()];
                fi += 1;
                if let Ok(packets) = jpeg_packets(seq, frame, &endpoints) {
                    for p in packets {
                        let _ = socket.send(&p).await;
                    }
                }
                seq = seq.wrapping_add(1);
            }
            _ = audio_at.tick() => {
                let pcm = if media.audio.is_empty() {
                    &silence
                } else {
                    let chunk = &media.audio[ai % media.audio.len()];
                    ai += 1;
                    chunk
                };
                if let Ok(p) = audio_packet(aseq, pcm, &endpoints) {
                    let _ = socket.send(&p).await;
                }
                aseq = aseq.wrapping_add(1);
            }
            _ = keepalive_at.tick() => {
                if let Ok(p) = session_control(OP_KEEPALIVE, &endpoints) {
                    let _ = socket.send(&p).await;
                }
            }
            _ = stop_rx.changed() => {}
        }
    }
    // Tear the call down cleanly.
    if let Ok(p) = session_control(OP_HANGUP, &endpoints) {
        let _ = socket.send(&p).await;
    }
    receiver.abort();
    let observation = obs.lock().unwrap().clone();
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_source_loads_the_frame_files() {
        let media = MediaSource::load(std::path::Path::new("testdata/frames"), None).unwrap();
        assert!(media.frames.len() > 100);
        assert!(media.frames.iter().all(|f| f.starts_with(&[0xff, 0xd8])));
        assert!(media.audio.is_empty());
    }
}
