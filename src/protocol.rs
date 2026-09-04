use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;

use thiserror::Error;

pub const MAGIC: &[u8; 8] = b"PENGUIN0";
pub const CONTROL_PORT: u16 = 10_000;
pub const DISCOVERY_PORT: u16 = 10_008;

pub const FAMILY_PAGE: u16 = 0x005d;
pub const FAMILY_BOOTSTRAP: u16 = 0x0098;
pub const FAMILY_SESSION: u16 = 0x00b7;
pub const FAMILY_SNAPSHOT_NAME: u16 = 0x009b;
pub const FAMILY_SNAPSHOT_DATA: u16 = 0x00b4;

pub const OP_REQUEST: u32 = 0x01;
pub const OP_REPLY: u32 = 0x03;
pub const OP_ANSWER: u32 = 0x05;
pub const OP_UNLOCK: u32 = 0x06;
pub const OP_MEDIA: u32 = 0x0a;
pub const OP_KEEPALIVE: u32 = 0x0c;
pub const OP_HANGUP: u32 = 0x1e;

pub const MEDIA_JPEG: u16 = 1;
pub const MEDIA_AUDIO: u16 = 3;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("short PENGUIN0 message")]
    Short,
    #[error("invalid PENGUIN0 magic")]
    BadMagic,
    #[error("station id is longer than 20 bytes")]
    StationTooLong,
    #[error("invalid station endpoint")]
    BadStation,
    #[error("audio packets must contain exactly 512 PCM bytes")]
    BadAudioLength,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Station {
    pub id: String,
    pub ip: Ipv4Addr,
}

impl Station {
    pub fn new(id: impl Into<String>, ip: Ipv4Addr) -> Self {
        Self { id: id.into(), ip }
    }

    pub fn pack(&self) -> Result<[u8; 24], ProtocolError> {
        let id = self.id.as_bytes();
        if id.len() > 20 {
            return Err(ProtocolError::StationTooLong);
        }
        let mut out = [0_u8; 24];
        out[..id.len()].copy_from_slice(id);
        out[20..24].copy_from_slice(&self.ip.octets());
        Ok(out)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 24 {
            return Err(ProtocolError::BadStation);
        }
        let end = raw[..20].iter().position(|b| *b == 0).unwrap_or(20);
        let id = String::from_utf8_lossy(&raw[..end]).into_owned();
        Ok(Self::new(
            id,
            Ipv4Addr::new(raw[20], raw[21], raw[22], raw[23]),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoints {
    pub door: Station,
    pub room: Station,
}

impl Endpoints {
    pub fn captured() -> Self {
        Self {
            door: Station::new("M00000000000", Ipv4Addr::new(192, 168, 124, 2)),
            room: Station::new("S00000000000", Ipv4Addr::new(192, 168, 124, 61)),
        }
    }

    pub fn pack(&self) -> Result<[u8; 48], ProtocolError> {
        let mut out = [0_u8; 48];
        out[..24].copy_from_slice(&self.door.pack()?);
        out[24..].copy_from_slice(&self.room.pack()?);
        Ok(out)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 48 {
            return Err(ProtocolError::Short);
        }
        Ok(Self {
            door: Station::parse(&raw[..24])?,
            room: Station::parse(&raw[24..48])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub family: u16,
    pub opcode: u32,
    pub declared: u32,
    pub reserved: &'a [u8],
    pub body: &'a [u8],
    pub raw: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFragment<'a> {
    pub media_type: u16,
    pub sequence: u16,
    pub fragment_count: u16,
    pub fragment_index: u16,
    pub valid_length: u16,
    pub data: &'a [u8],
}

impl<'a> Message<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, ProtocolError> {
        if raw.len() < 32 {
            return Err(ProtocolError::Short);
        }
        if &raw[..8] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        Ok(Self {
            family: u16::from_le_bytes([raw[8], raw[9]]),
            opcode: u32::from_le_bytes(raw[10..14].try_into().unwrap()),
            declared: u32::from_le_bytes(raw[14..18].try_into().unwrap()),
            reserved: &raw[18..32],
            body: &raw[32..],
            raw,
        })
    }

    pub fn endpoints(&self) -> Option<Endpoints> {
        (self.family == FAMILY_SESSION && self.body.len() >= 48)
            .then(|| Endpoints::parse(&self.body[..48]).ok())
            .flatten()
    }

    pub fn media(&self) -> Option<MediaFragment<'a>> {
        if self.family != FAMILY_SESSION || self.opcode != OP_MEDIA || self.body.len() < 58 {
            return None;
        }
        let h = &self.body[48..58];
        let valid_length = u16::from_le_bytes([h[8], h[9]]);
        let data = &self.body[58..];
        if valid_length as usize > data.len() {
            return None;
        }
        Some(MediaFragment {
            media_type: u16::from_le_bytes([h[0], h[1]]),
            sequence: u16::from_le_bytes([h[2], h[3]]),
            fragment_count: u16::from_le_bytes([h[4], h[5]]),
            fragment_index: u16::from_le_bytes([h[6], h[7]]),
            valid_length,
            data: &data[..valid_length as usize],
        })
    }
}

pub fn packet(family: u16, opcode: u32, declared: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&family.to_le_bytes());
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(&declared.to_le_bytes());
    out.extend_from_slice(&[0_u8; 14]);
    out.extend_from_slice(body);
    out
}

/// The fixed 174-byte capability descriptor the door station sends in its
/// `00b7/01` session request, after the endpoint block. Begins with
/// `VIDEOA`. Its per-field meaning is not fully reverse-engineered, but it is
/// constant across the call, so a faithful door emulator reproduces it
/// verbatim while filling the endpoints from configuration.
pub const SESSION_REQUEST_CAPABILITY: [u8; 174] = [
    0x56, 0x49, 0x44, 0x45, 0x4f, 0x41, 0x06, 0x00, 0x32, 0x00, 0x33, 0x00, 0x34, 0x00, 0x64, 0x00,
    0x6e, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x1e, 0x00, 0x28, 0x00, 0x32, 0x00, 0x33, 0x00, 0x34, 0x00,
    0x64, 0x00, 0x6e, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Build the door's `00b7/01` session request (the ring) from the two
/// endpoint identities. This is synthesized from the protocol, not replayed:
/// only the endpoints vary per call; the capability descriptor is a constant.
pub fn session_request(endpoints: &Endpoints) -> Result<Vec<u8>, ProtocolError> {
    let mut body = endpoints.pack()?.to_vec();
    body.extend_from_slice(&SESSION_REQUEST_CAPABILITY);
    Ok(packet(FAMILY_SESSION, OP_REQUEST, 254, &body))
}

/// Fragment a complete JPEG frame into `00b7/0a` media packets, matching the
/// captured wire: 1200-byte slots, 1-based fragment index, `valid_length`
/// giving the real bytes in the final (zero-padded) slot.
pub fn jpeg_packets(
    sequence: u16,
    jpeg: &[u8],
    endpoints: &Endpoints,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    const SLOT: usize = 1200;
    let endpoint_block = endpoints.pack()?;
    let frag_count = jpeg.len().div_ceil(SLOT).max(1) as u16;
    let mut packets = Vec::with_capacity(frag_count as usize);
    for (index, chunk) in jpeg.chunks(SLOT).enumerate() {
        let mut body = endpoint_block.to_vec();
        for value in [
            MEDIA_JPEG,
            sequence,
            frag_count,
            index as u16 + 1,
            chunk.len() as u16,
        ] {
            body.extend_from_slice(&value.to_le_bytes());
        }
        body.extend_from_slice(chunk);
        // Pad the slot to its fixed size; valid_length says how much is real.
        body.resize(endpoint_block.len() + 10 + SLOT, 0);
        packets.push(packet(FAMILY_SESSION, OP_MEDIA, 1290, &body));
    }
    Ok(packets)
}

pub fn session_control(opcode: u32, endpoints: &Endpoints) -> Result<Vec<u8>, ProtocolError> {
    Ok(packet(FAMILY_SESSION, opcode, 80, &endpoints.pack()?))
}

pub fn session_reply(endpoints: &Endpoints) -> Result<Vec<u8>, ProtocolError> {
    let mut body = endpoints.pack()?.to_vec();
    body.extend_from_slice(b"VIDEOA\0\0");
    for value in [50_u16, 9, 9, 255] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    Ok(packet(FAMILY_SESSION, OP_REPLY, 96, &body))
}

pub fn bootstrap_reply(room: &Station) -> Result<Vec<u8>, ProtocolError> {
    let mut body = Vec::with_capacity(866);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&room.pack()?);
    body.extend_from_slice(&[0_u8; 840]);
    Ok(packet(FAMILY_BOOTSTRAP, 2, 898, &body))
}

/// The door's `005d/01` paging packet: the pre-call "ring" the door repeats
/// (~10x at 100 ms in the capture) before any session setup. This is what
/// actually makes the physical Pad ring; the body is a fixed 4-byte constant
/// (`00 1e 00 00`) with no per-call fields.
pub fn page_request() -> Vec<u8> {
    packet(FAMILY_PAGE, OP_REQUEST, 36, &[0x00, 0x1e, 0x00, 0x00])
}

/// The door's `0098/01` bootstrap request: an empty-bodied query the Pad
/// answers with `0098/02` ([`bootstrap_reply`]) describing itself. Sent once
/// between the paging burst and the `00b7/01` session request.
pub fn bootstrap_request() -> Vec<u8> {
    packet(FAMILY_BOOTSTRAP, OP_REQUEST, 20, &[])
}

pub fn audio_packet(
    sequence: u16,
    pcm: &[u8],
    endpoints: &Endpoints,
) -> Result<Vec<u8>, ProtocolError> {
    if pcm.len() != 512 {
        return Err(ProtocolError::BadAudioLength);
    }
    let mut body = endpoints.pack()?.to_vec();
    for value in [MEDIA_AUDIO, sequence, 1, 1, 512] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    body.extend_from_slice(pcm);
    Ok(packet(FAMILY_SESSION, OP_MEDIA, 602, &body))
}

pub fn discovery_request_room(payload: &[u8]) -> Option<String> {
    if payload.first().copied() != Some(1) {
        return None;
    }
    let data = &payload[1..];
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).into_owned())
}

/// Build the door's UDP 10008 discovery request: byte `01` then the room
/// Station ID, NUL-padded to the 100-byte datagram seen on the wire. This is
/// the "who has room X?" broadcast; the Pad answers from its own IP.
pub fn discovery_request(room_id: &str) -> Result<[u8; 100], ProtocolError> {
    if room_id.len() > 34 {
        return Err(ProtocolError::StationTooLong);
    }
    let mut out = [0_u8; 100];
    out[0] = 1;
    out[1..1 + room_id.len()].copy_from_slice(room_id.as_bytes());
    Ok(out)
}

/// Parse a discovery reply (`02` + room Station ID) and return the room ID.
/// The Pad's IP is the datagram's source address, not in the body.
pub fn discovery_reply_room(payload: &[u8]) -> Option<String> {
    if payload.first().copied() != Some(2) {
        return None;
    }
    let data = &payload[1..];
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).into_owned())
}

pub fn discovery_reply(room_id: &str) -> Result<[u8; 35], ProtocolError> {
    if room_id.len() > 34 {
        return Err(ProtocolError::StationTooLong);
    }
    let mut out = [0_u8; 35];
    out[0] = 2;
    out[1..1 + room_id.len()].copy_from_slice(room_id.as_bytes());
    Ok(out)
}

fn logical_size(data: &[u8]) -> Option<usize> {
    let msg = Message::parse(data).ok()?;
    if msg.family == FAMILY_SESSION && msg.opcode == OP_MEDIA && data.len() >= 90 {
        return match u16::from_le_bytes([data[80], data[81]]) {
            MEDIA_JPEG => Some(1290),
            MEDIA_AUDIO => Some(602),
            _ => None,
        };
    }
    if msg.declared >= 32 {
        return Some(msg.declared as usize);
    }
    (msg.family == FAMILY_SESSION && msg.opcode == OP_KEEPALIVE).then_some(80)
}

pub fn split_coalesced(mut payload: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !payload.is_empty() {
        if !payload.starts_with(MAGIC) {
            let Some(pos) = payload.windows(MAGIC.len()).position(|w| w == MAGIC) else {
                break;
            };
            payload = &payload[pos..];
        }
        let size = logical_size(payload)
            .filter(|n| *n <= payload.len())
            .unwrap_or_else(|| {
                payload[MAGIC.len()..]
                    .windows(MAGIC.len())
                    .position(|w| w == MAGIC)
                    .map(|p| p + MAGIC.len())
                    .unwrap_or(payload.len())
            });
        if size == 0 {
            break;
        }
        out.push(&payload[..size]);
        payload = &payload[size..];
    }
    out
}

#[derive(Default)]
pub struct JpegReassembler {
    frames: BTreeMap<u16, (u16, BTreeMap<u16, Vec<u8>>)>,
    order: VecDeque<u16>,
}

impl JpegReassembler {
    pub fn push(&mut self, fragment: &MediaFragment<'_>) -> Option<Vec<u8>> {
        if fragment.media_type != MEDIA_JPEG
            || fragment.fragment_count == 0
            || fragment.fragment_index == 0
            || fragment.fragment_index > fragment.fragment_count
        {
            return None;
        }
        if !self.frames.contains_key(&fragment.sequence) {
            self.order.push_back(fragment.sequence);
        }
        let entry = self
            .frames
            .entry(fragment.sequence)
            .or_insert_with(|| (fragment.fragment_count, BTreeMap::new()));
        if entry.0 != fragment.fragment_count {
            *entry = (fragment.fragment_count, BTreeMap::new());
        }
        entry
            .1
            .insert(fragment.fragment_index, fragment.data.to_vec());
        let complete = entry.1.len() == entry.0 as usize
            && (1..=entry.0).all(|index| entry.1.contains_key(&index));
        if !complete {
            self.trim();
            return None;
        }
        let (_, parts) = self.frames.remove(&fragment.sequence)?;
        self.order.retain(|seq| *seq != fragment.sequence);
        let frame: Vec<u8> = parts.into_values().flatten().collect();
        (frame.starts_with(&[0xff, 0xd8]) && frame.ends_with(&[0xff, 0xd9])).then_some(frame)
    }

    fn trim(&mut self) {
        while self.frames.len() > 8 {
            if let Some(old) = self.order.pop_front() {
                self.frames.remove(&old);
            }
        }
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use crate::pcap::read_udp;

    fn captured(opcode: u32) -> Option<Vec<u8>> {
        for record in read_udp("testdata/pad.cap").unwrap() {
            for raw in split_coalesced(&record.payload) {
                if let Ok(msg) = Message::parse(raw) {
                    if msg.family == FAMILY_SESSION && msg.opcode == opcode {
                        return Some(raw.to_vec());
                    }
                }
            }
        }
        None
    }

    fn captured_any(family: u16, opcode: u32) -> Option<Vec<u8>> {
        for record in read_udp("testdata/pad.cap").unwrap() {
            for raw in split_coalesced(&record.payload) {
                if let Ok(msg) = Message::parse(raw) {
                    if msg.family == family && msg.opcode == opcode {
                        return Some(raw.to_vec());
                    }
                }
            }
        }
        None
    }

    #[test]
    fn page_and_bootstrap_requests_reproduce_the_captured_setup() {
        let page = captured_any(FAMILY_PAGE, OP_REQUEST).expect("005d/01 in capture");
        assert_eq!(page_request(), page, "paging packet must match the wire");
        let boot = captured_any(FAMILY_BOOTSTRAP, OP_REQUEST).expect("0098/01 in capture");
        assert_eq!(
            bootstrap_request(),
            boot,
            "bootstrap request must match the wire"
        );
    }

    #[test]
    fn session_request_reproduces_the_captured_ring() {
        let capture = captured(OP_REQUEST).expect("00b7/01 in capture");
        let endpoints = Endpoints::parse(&capture[32..80]).unwrap();
        let built = session_request(&endpoints).unwrap();
        assert_eq!(
            built, capture,
            "synthesized ring must match the captured bytes"
        );
    }

    #[test]
    fn jpeg_packets_match_the_captured_fragmentation() {
        // Reassemble the first captured door frame, then re-fragment it.
        let mut reasm = JpegReassembler::default();
        let mut first_seq = None;
        let mut endpoints = None;
        let mut frame = None;
        'outer: for record in read_udp("testdata/pad.cap").unwrap() {
            if record.source_ip != std::net::Ipv4Addr::new(192, 168, 124, 2) {
                continue;
            }
            for raw in split_coalesced(&record.payload) {
                let Ok(msg) = Message::parse(raw) else {
                    continue;
                };
                if msg.family != FAMILY_SESSION || msg.opcode != OP_MEDIA {
                    continue;
                }
                let Some(media) = msg.media() else { continue };
                if media.media_type != MEDIA_JPEG {
                    continue;
                }
                first_seq.get_or_insert(media.sequence);
                endpoints.get_or_insert_with(|| Endpoints::parse(&msg.body[..48]).unwrap());
                if let Some(complete) = reasm.push(&media) {
                    frame = Some(complete);
                    break 'outer;
                }
            }
        }
        let frame = frame.expect("a complete captured frame");
        let seq = first_seq.unwrap();
        let endpoints = endpoints.unwrap();
        let packets = jpeg_packets(seq, &frame, &endpoints).unwrap();
        // Every packet is the fixed 1290-byte size and the valid_length of the
        // last fragment equals the remainder.
        assert!(packets.iter().all(|p| p.len() == 1290));
        assert_eq!(packets.len(), frame.len().div_ceil(1200));
        let last = Message::parse(packets.last().unwrap()).unwrap();
        let media = last.media().unwrap();
        assert_eq!(
            media.valid_length as usize,
            frame.len() - 1200 * (packets.len() - 1)
        );
        // Reassembling the synthesized packets yields the original frame.
        let mut check = JpegReassembler::default();
        let mut round = None;
        for p in &packets {
            let media = Message::parse(p).unwrap().media().unwrap();
            round = check.push(&media);
        }
        assert_eq!(round.unwrap(), frame);
    }
}
