//! Replay the captured door-station traffic onto the wire.
//!
//! The software door station can present a saved call to HTTP clients, but to
//! test a *real* room Pad (or another Agent's capture path) it must speak the
//! real PENGUIN0 protocol. This module sends the door→Pad datagrams from a
//! capture, verbatim, to a target IP over UDP `control` — the session setup
//! (`00b7/01`), then the JPEG and audio media — so the target rings and shows
//! the door camera exactly as the original call did.
//!
//! GRO-coalesced capture records are split back into one datagram per
//! PENGUIN0 message, matching the original wire.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::time::{sleep_until, Instant as TokioInstant};

use crate::pcap::read_udp;
use crate::protocol::{
    split_coalesced, Message, FAMILY_SESSION, MAGIC, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP,
    OP_KEEPALIVE, OP_MEDIA, OP_REQUEST, OP_UNLOCK,
};

/// One datagram to emit, with its offset from the first emitted packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WirePacket {
    pub offset_micros: u64,
    pub payload: Vec<u8>,
}

/// Collect the datagrams a door station sends to the Pad: every PENGUIN0
/// message whose source is `door_ip`, split out of any coalesced record,
/// starting at the first session request so the target sees a clean call.
pub fn door_packets(
    path: impl AsRef<std::path::Path>,
    door_ip: Ipv4Addr,
) -> Result<Vec<WirePacket>> {
    let records = read_udp(path).context("reading capture")?;
    let mut out = Vec::new();
    let mut origin: Option<u64> = None;
    for record in &records {
        if record.source_ip != door_ip {
            continue;
        }
        for raw in split_coalesced(&record.payload) {
            if raw.len() < 8 || &raw[..8] != MAGIC {
                continue;
            }
            // Anchor the timeline on the first session request.
            if origin.is_none() {
                match Message::parse(raw) {
                    Ok(msg) if msg.family == FAMILY_SESSION && msg.opcode == OP_REQUEST => {
                        origin = Some(record.timestamp_micros);
                    }
                    _ => continue,
                }
            }
            let base = origin.unwrap();
            if record.timestamp_micros < base {
                continue;
            }
            out.push(WirePacket {
                offset_micros: record.timestamp_micros - base,
                payload: raw.to_vec(),
            });
        }
    }
    anyhow::ensure!(
        !out.is_empty(),
        "capture has no door->Pad session request from {door_ip}"
    );
    Ok(out)
}

/// Send the door datagrams to `target` over UDP, honoring capture timing
/// divided by `speed`. With `repeat`, the whole call is sent again after that
/// idle gap until the future is dropped.
pub async fn emit_to(
    packets: &[WirePacket],
    target: SocketAddr,
    speed: f64,
    repeat: Option<Duration>,
) -> Result<()> {
    anyhow::ensure!(speed.is_finite() && speed > 0.0, "speed must be positive");
    let socket = UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0))
        .await
        .context("binding UDP source socket")?;
    socket
        .connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))?;
    tracing::info!(%target, packets = packets.len(), ?repeat, "emitting door traffic");
    loop {
        let start = TokioInstant::now();
        let mut sent = 0_u64;
        for packet in packets {
            let wait = Duration::from_micros((packet.offset_micros as f64 / speed) as u64);
            sleep_until(start + wait).await;
            match socket.send(&packet.payload).await {
                Ok(_) => sent += 1,
                Err(error) => tracing::warn!(%error, "datagram send failed"),
            }
        }
        tracing::info!(%target, sent, "door call emitted");
        let Some(gap) = repeat else { return Ok(()) };
        tokio::time::sleep(gap).await;
    }
}

/// Load and emit in one call.
pub async fn emit_capture(
    path: impl AsRef<std::path::Path>,
    door_ip: Ipv4Addr,
    target: SocketAddr,
    speed: f64,
    repeat: Option<Duration>,
) -> Result<()> {
    let packets = door_packets(path, door_ip)?;
    emit_to(&packets, target, speed, repeat).await
}

/// What the emulator observed coming back from the Pad.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DoorObservation {
    pub answered: bool,
    pub unlocks: u64,
    pub hangups: u64,
    pub audio_packets: u64,
    pub audio_bytes: u64,
}

/// Classify one Pad→door datagram, playing audio and updating the tally.
/// Returns a human log line when the datagram is a notable control event.
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
        OP_ANSWER => {
            obs.answered = true;
            Some("Pad answered (00b7/05)".into())
        }
        OP_UNLOCK => {
            obs.unlocks += 1;
            Some(format!(
                "UNLOCK received from Pad (00b7/06) x{}",
                obs.unlocks
            ))
        }
        OP_HANGUP => {
            obs.hangups += 1;
            Some("Pad hung up (00b7/1e)".into())
        }
        OP_MEDIA => {
            if let Some(media) = msg.media() {
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
            }
            None
        }
        OP_KEEPALIVE => None,
        _ => None,
    }
}

/// Bidirectional door-station emulator: pretend to be the door, ring `target`,
/// and report/play what the Pad sends back (answer, unlock, and voice), so a
/// human can answer on the real Pad and confirm the round trip.
///
/// One UDP socket bound to the control port both sends the door traffic and
/// receives the Pad's replies (the Pad answers to the datagrams' source).
pub async fn run_emulator(
    path: impl AsRef<std::path::Path>,
    door_ip: Ipv4Addr,
    target: SocketAddr,
    speed: f64,
    repeat: Option<Duration>,
    player: Option<String>,
) -> Result<DoorObservation> {
    let packets = door_packets(path, door_ip)?;
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
    tracing::info!(%target, local = %socket.local_addr()?, packets = packets.len(), "door emulator ringing target; answer on the Pad");

    let obs = Arc::new(std::sync::Mutex::new(DoorObservation::default()));
    let mut speaker = match player.as_deref() {
        Some("") => None,
        cmd => crate::door_station::Player::start_opt(cmd).ok().flatten(),
    };

    // Receiver: report control events and play the Pad's voice.
    let recv_socket = socket.clone();
    let recv_obs = obs.clone();
    let receiver = tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_536];
        loop {
            let Ok(size) = recv_socket.recv(&mut buf).await else {
                break;
            };
            for raw in split_coalesced(&buf[..size]) {
                let line = observe_reply(raw, &mut recv_obs.lock().unwrap(), &mut speaker);
                if let Some(line) = line {
                    tracing::info!("{line}");
                }
            }
        }
    });

    // Sender: replay the door call, optionally repeating.
    let start = TokioInstant::now();
    loop {
        let base = TokioInstant::now();
        for packet in &packets {
            let wait = Duration::from_micros((packet.offset_micros as f64 / speed) as u64);
            sleep_until(base + wait).await;
            let _ = socket.send(&packet.payload).await;
        }
        // Let late replies (unlock, trailing audio) arrive before the next pass.
        tokio::time::sleep(Duration::from_millis(500)).await;
        match repeat {
            Some(gap) => tokio::time::sleep(gap).await,
            None => break,
        }
    }
    // After the last pass, keep listening briefly for replies.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    receiver.abort();
    let _ = start;
    let observation = obs.lock().unwrap().clone();
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn door_packets_start_at_the_session_request() {
        let door = Ipv4Addr::new(192, 168, 124, 2);
        let packets = door_packets("testdata/pad.cap", door).unwrap();
        assert!(!packets.is_empty());
        assert_eq!(packets[0].offset_micros, 0);
        // The first emitted datagram is the session request 00b7/01.
        let first = Message::parse(&packets[0].payload).unwrap();
        assert_eq!(first.family, FAMILY_SESSION);
        assert_eq!(first.opcode, OP_REQUEST);
        // Offsets are monotonically non-decreasing.
        assert!(packets
            .windows(2)
            .all(|w| w[0].offset_micros <= w[1].offset_micros));
        // Every datagram is a single PENGUIN0 message (coalescing undone).
        assert!(packets.iter().all(|p| p.payload.starts_with(MAGIC)));
    }
}
