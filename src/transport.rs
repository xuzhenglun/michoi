use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

const MAGIC: &[u8; 4] = b"PAG1";
const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    Event = 1,
    Command = 2,
    Result = 3,
    Jpeg = 4,
    DoorPcm = 5,
    TalkPcm = 6,
    Heartbeat = 7,
}

impl TryFrom<u8> for FrameKind {
    type Error = WireError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Event),
            2 => Ok(Self::Command),
            3 => Ok(Self::Result),
            4 => Ok(Self::Jpeg),
            5 => Ok(Self::DoorPcm),
            6 => Ok(Self::TalkPcm),
            7 => Ok(Self::Heartbeat),
            _ => Err(WireError::Kind(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub kind: FrameKind,
    pub flags: u16,
    pub session_id: u64,
    pub sequence: u32,
    pub timestamp_micros: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("short Agent frame")]
    Short,
    #[error("invalid Agent frame magic or version")]
    Header,
    #[error("unknown Agent frame kind {0}")]
    Kind(u8),
    #[error("Agent frame payload length mismatch")]
    Length,
    #[error("CBOR error: {0}")]
    Cbor(String),
}

impl WireFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.session_id.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.timestamp_micros.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, WireError> {
        if raw.len() < HEADER_LEN {
            return Err(WireError::Short);
        }
        if &raw[..4] != MAGIC || raw[4] != VERSION {
            return Err(WireError::Header);
        }
        let length = u32::from_be_bytes(raw[28..32].try_into().unwrap()) as usize;
        if raw.len() != HEADER_LEN + length {
            return Err(WireError::Length);
        }
        Ok(Self {
            kind: raw[5].try_into()?,
            flags: u16::from_be_bytes(raw[6..8].try_into().unwrap()),
            session_id: u64::from_be_bytes(raw[8..16].try_into().unwrap()),
            sequence: u32::from_be_bytes(raw[16..20].try_into().unwrap()),
            timestamp_micros: u64::from_be_bytes(raw[20..28].try_into().unwrap()),
            payload: raw[32..].to_vec(),
        })
    }

    pub fn cbor<T: Serialize>(
        kind: FrameKind,
        session_id: u64,
        sequence: u32,
        timestamp_micros: u64,
        value: &T,
    ) -> Result<Self, WireError> {
        let payload = serde_cbor::to_vec(value).map_err(|e| WireError::Cbor(e.to_string()))?;
        Ok(Self {
            kind,
            flags: 0,
            session_id,
            sequence,
            timestamp_micros,
            payload,
        })
    }

    pub fn decode_cbor<T: DeserializeOwned>(&self) -> Result<T, WireError> {
        serde_cbor::from_slice(&self.payload).map_err(|e| WireError::Cbor(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    Hello {
        agent_id: String,
        protocol: u16,
        capabilities: Vec<String>,
    },
    Snapshot {
        phase: String,
        owner: String,
    },
    CallStarted {
        door_id: String,
        room_id: String,
    },
    PadActionObserved {
        opcode: u32,
    },
    CallEnded {
        reason: String,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AgentCommand {
    RegisterBackend { backend_id: String },
    ClaimCall { command_id: u64 },
    Unlock { command_id: u64 },
    Hangup { command_id: u64 },
    ReleaseCall { command_id: u64 },
}

impl AgentCommand {
    pub fn command_id(&self) -> Option<u64> {
        match self {
            Self::RegisterBackend { .. } => None,
            Self::ClaimCall { command_id }
            | Self::Unlock { command_id }
            | Self::Hangup { command_id }
            | Self::ReleaseCall { command_id } => Some(*command_id),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandResult {
    pub command_id: u64,
    pub ok: bool,
    pub error: Option<String>,
}
