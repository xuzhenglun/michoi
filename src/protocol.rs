use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;

use thiserror::Error;

pub const MAGIC: &[u8; 8] = b"PENGUIN0";
pub const CONTROL_PORT: u16 = 10_000;
pub const DISCOVERY_PORT: u16 = 10_008;

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
