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

use std::path::PathBuf;

use crate::protocol::{
    audio_packet, elevator_request, jpeg_packets, monitor_request, packet, session_control,
    split_coalesced, Endpoints, JpegReassembler, Message, Station, FAMILY_ELEVATOR, FAMILY_MONITOR,
    FAMILY_SESSION, MEDIA_AUDIO, OP_ANSWER, OP_HANGUP, OP_KEEPALIVE, OP_MEDIA, OP_REPLY, OP_REQUEST, OP_UNLOCK,
};

use crate::door_station::AudioSink;

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
    speaker: &mut Option<crate::door_station::AudioSink>,
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

/// Resolve a Pad's IPv4 from its room Station ID using the UDP 10008
/// discovery protocol (a private ARP): broadcast `01 + room_id`, and take the
/// source address of the `02 + room_id` reply. `broadcast` is where the query
/// is sent (e.g. the subnet broadcast or 255.255.255.255).
pub async fn resolve_pad(
    room_id: &str,
    broadcast: Ipv4Addr,
    timeout: Duration,
) -> Result<Ipv4Addr> {
    use crate::protocol::{discovery_reply_room, discovery_request, DISCOVERY_PORT};
    let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DISCOVERY_PORT);
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(_) => UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?,
    };
    socket
        .set_broadcast(true)
        .context("enabling UDP broadcast")?;
    let request = discovery_request(room_id)?;
    let dest = SocketAddr::new(broadcast.into(), DISCOVERY_PORT);
    crate::protocol::trace_packet("tx discovery", &request);
    socket
        .send_to(&request, dest)
        .await
        .context("sending discovery request")?;
    tracing::info!(%dest, room_id, "discovery: who has this room?");
    let mut buf = vec![0_u8; 1024];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let recv = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await;
        let (size, from) = match recv {
            Ok(Ok(pair)) => pair,
            Ok(Err(error)) => return Err(error).context("receiving discovery reply"),
            Err(_) => anyhow::bail!("no discovery reply for {room_id} within {timeout:?}"),
        };
        // Re-send the request periodically? One shot is enough on a LAN.
        crate::protocol::trace_packet("rx discovery", &buf[..size]);
        if let Some(reply_room) = discovery_reply_room(&buf[..size]) {
            if reply_room == room_id {
                if let std::net::IpAddr::V4(ip) = from.ip() {
                    tracing::info!(%ip, room_id, "discovery: resolved");
                    return Ok(ip);
                }
            }
        }
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
    sink: Option<crate::door_station::AudioSink>,
) -> Result<DoorObservation> {
    let mut identity = identity;
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
    // Auto-fill the door's own IP from the local address the kernel routes to
    // the Pad through (0.0.0.0 is the "detect me" sentinel). The Pad replies to
    // the IP written in the packet body, so it must be our real address.
    if identity.door.ip.is_unspecified() {
        if let std::net::IpAddr::V4(local) = socket.local_addr()?.ip() {
            identity.door.ip = local;
        }
    }
    let endpoints = identity.endpoints();
    let socket = Arc::new(socket);
    tracing::info!(
        %target, local = %socket.local_addr()?, door = %identity.door.id, room = %identity.room.id,
        room_ip = %identity.room.ip, frames = media.frames.len(),
        "door emulator: sending synthesized ring; answer on the Pad"
    );

    let obs = Arc::new(std::sync::Mutex::new(DoorObservation::default()));
    let mut speaker = sink;

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
                crate::protocol::trace_packet("rx pad", raw);
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

    // Pre-call handshake, in the order the real door does it:
    //  1. 005d/01 paging burst (~10x at 100 ms) -- this is what rings the Pad,
    //  2. 0098/01 bootstrap request (the Pad answers with 0098/02),
    //  3. 00b7/01 session request x3 (the media session; the Pad replies 00b7/03).
    // Only after this does the Pad actually ring, so a person can answer.
    for _ in 0..10 {
        let page = crate::protocol::page_request();
        crate::protocol::trace_packet("tx door", &page);
        let _ = socket.send(&page).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let boot = crate::protocol::bootstrap_request();
    crate::protocol::trace_packet("tx door", &boot);
    let _ = socket.send(&boot).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Ring, then stream media and keepalives until stopped.
    let ring = crate::protocol::session_request(&endpoints)?;
    for _ in 0..3 {
        crate::protocol::trace_packet("tx door", &ring);
        socket.send(&ring).await.context("sending session request")?;
    }
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
                // Hold audio until the Pad answers: the real door opens the
                // voice channel only after 00b7/05. Streaming audio during the
                // ring makes the Pad go straight to "in-call" and never ring.
                if !obs.lock().unwrap().answered {
                    continue;
                }
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
                    crate::protocol::trace_packet("tx door", &p);
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

/// What the monitor viewer saw from the door camera.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MonitorObservation {
    pub capability_reply: bool,
    pub jpeg_frames: u64,
    pub audio_packets: u64,
    pub audio_bytes: u64,
    pub hangups: u64,
}

/// View `target`'s camera as the Pad, without a ring: send `00b8/01`, keep the
/// session alive, and take in the door's video and audio (family `00b8`, same
/// framing as a call). This is the exact peer of an incoming call, only the
/// initiator and family tag differ. Runs until `duration`, a door hangup, or
/// the future is dropped.
pub async fn run_monitor(
    us: Station,
    target: Station,
    frames_out: Option<PathBuf>,
    duration: Option<Duration>,
    sink: Option<AudioSink>,
) -> Result<MonitorObservation> {
    let mut us = us;
    let dest = SocketAddr::new(target.ip.into(), crate::protocol::CONTROL_PORT);
    let socket = Arc::new(UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?);
    socket
        .connect(dest)
        .await
        .with_context(|| format!("connecting to {dest}"))?;
    if us.ip.is_unspecified() {
        if let std::net::IpAddr::V4(local) = socket.local_addr()?.ip() {
            us.ip = local;
        }
    }
    if let Some(dir) = &frames_out {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating frames directory {}", dir.display()))?;
    }
    // The monitor endpoint block is [initiator (us) | target], reused for
    // keepalive and hangup.
    let block = {
        let mut b = us.pack()?.to_vec();
        b.extend_from_slice(&target.pack()?);
        b
    };
    tracing::info!(
        %dest, local = %socket.local_addr()?, us = %us.id, target = %target.id,
        "monitor: requesting the door camera (00b8/01)"
    );

    let obs = Arc::new(std::sync::Mutex::new(MonitorObservation::default()));
    let recv_socket = socket.clone();
    let recv_obs = obs.clone();
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let mut speaker = sink;
    let receiver = tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_536];
        let mut jpeg = JpegReassembler::default();
        loop {
            let Ok(size) = recv_socket.recv(&mut buf).await else {
                break;
            };
            for raw in split_coalesced(&buf[..size]) {
                crate::protocol::trace_packet("rx monitor", raw);
                let Ok(msg) = Message::parse(raw) else { continue };
                if msg.family != FAMILY_MONITOR {
                    continue;
                }
                match msg.opcode {
                    OP_REPLY => {
                        let mut o = recv_obs.lock().unwrap();
                        if !o.capability_reply {
                            o.capability_reply = true;
                            tracing::info!("door accepted the monitor (00b8/03)");
                        }
                    }
                    OP_HANGUP => {
                        recv_obs.lock().unwrap().hangups += 1;
                        tracing::info!("door ended the monitor (00b8/1e)");
                        let _ = stop_tx.send(true);
                    }
                    OP_MEDIA => {
                        let Some(media) = msg.media() else { continue };
                        if media.media_type == MEDIA_AUDIO {
                            let mut o = recv_obs.lock().unwrap();
                            o.audio_packets += 1;
                            o.audio_bytes += media.data.len() as u64;
                            drop(o);
                            if let Some(sp) = speaker.as_mut() {
                                let _ = sp.write(media.data);
                            }
                        } else if let Some(frame) = jpeg.push(&media) {
                            let n = {
                                let mut o = recv_obs.lock().unwrap();
                                o.jpeg_frames += 1;
                                o.jpeg_frames
                            };
                            if let Some(dir) = &frames_out {
                                let path = dir.join(format!("frame-{n:04}.jpg"));
                                let _ = std::fs::write(path, &frame);
                            }
                            if n == 1 {
                                tracing::info!("first video frame from the door camera");
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    });

    let req = monitor_request(&us, &target)?;
    crate::protocol::trace_packet("tx monitor", &req);
    socket.send(&req).await.context("sending monitor request")?;

    let mut keepalive = tokio::time::interval(Duration::from_secs(1));
    let deadline = duration.map(|d| tokio::time::Instant::now() + d);
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
            _ = keepalive.tick() => {
                let p = packet(FAMILY_MONITOR, OP_KEEPALIVE, 80, &block);
                crate::protocol::trace_packet("tx monitor", &p);
                let _ = socket.send(&p).await;
            }
            _ = stop_rx.changed() => {}
        }
    }
    // Stop viewing.
    let bye = packet(FAMILY_MONITOR, OP_HANGUP, 80, &block);
    crate::protocol::trace_packet("tx monitor", &bye);
    let _ = socket.send(&bye).await;
    receiver.abort();
    let observation = obs.lock().unwrap().clone();
    Ok(observation)
}

/// Call the elevator to the requesting room's floor: send `0106/01` to the
/// door station and wait for its `0106/02` acknowledgement. Returns whether the
/// ack arrived within `timeout`.
/// Send a `0106/01` elevator call and return immediately (fire and forget).
/// The ack is observed elsewhere (the Agent watches its wire). Sources from the
/// control port like a real Pad, falling back to an ephemeral port.
pub async fn send_elevator(room_id: &str, target: SocketAddr) -> Result<()> {
    let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), crate::protocol::CONTROL_PORT);
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(_) => UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?,
    };
    socket.connect(target).await.with_context(|| format!("connecting to {target}"))?;
    let req = elevator_request(room_id)?;
    crate::protocol::trace_packet("tx elevator", &req);
    socket.send(&req).await.context("sending elevator call")?;
    tracing::info!(%target, room_id, "elevator: call sent (0106/01)");
    Ok(())
}

pub async fn request_elevator(
    room_id: &str,
    target: SocketAddr,
    timeout: Duration,
) -> Result<bool> {
    // Source from the control port like a real Pad; some doors only reply to
    // :10000. Fall back to an ephemeral port if it is taken.
    let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), crate::protocol::CONTROL_PORT);
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(_) => UdpSocket::bind(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)).await?,
    };
    socket
        .connect(target)
        .await
        .with_context(|| format!("connecting to {target}"))?;
    let req = elevator_request(room_id)?;
    crate::protocol::trace_packet("tx elevator", &req);
    socket.send(&req).await.context("sending elevator call")?;
    tracing::info!(%target, %bind, room_id, "elevator: call sent (0106/01)");
    let mut buf = vec![0_u8; 1024];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await {
            Ok(Ok(size)) => {
                crate::protocol::trace_packet("rx elevator", &buf[..size]);
                if let Ok(msg) = Message::parse(&buf[..size]) {
                    if msg.family == FAMILY_ELEVATOR && msg.opcode != OP_REQUEST {
                        tracing::info!("elevator acknowledged (0106/02)");
                        return Ok(true);
                    }
                }
            }
            Ok(Err(error)) => return Err(error).context("waiting for the elevator ack"),
            Err(_) => {
                tracing::warn!("no elevator ack within {timeout:?}");
                return Ok(false);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_request_reply_round_trip() {
        use crate::protocol::{discovery_reply_room, discovery_request, discovery_request_room};
        let req = discovery_request("S00000000000").unwrap();
        assert_eq!(req.len(), 100);
        assert_eq!(req[0], 1);
        assert_eq!(
            discovery_request_room(&req).as_deref(),
            Some("S00000000000")
        );
        let reply = crate::protocol::discovery_reply("S00000000000").unwrap();
        assert_eq!(
            discovery_reply_room(&reply).as_deref(),
            Some("S00000000000")
        );
        // A request is not mistaken for a reply and vice versa.
        assert!(discovery_reply_room(&req).is_none());
        assert!(discovery_request_room(&reply).is_none());
    }

    #[test]
    fn media_source_loads_the_frame_files() {
        let media = MediaSource::load(std::path::Path::new("testdata/frames"), None).unwrap();
        assert!(media.frames.len() >= 10);
        assert!(media.frames.iter().all(|f| f.starts_with(&[0xff, 0xd8])));
        assert!(media.audio.is_empty());
    }
}
