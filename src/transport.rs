//! Internal intermediate representation for the pcap replay pipeline.
//!
//! `replay_timeline` decodes `pad.cap` into a sequence of `WireFrame`s (control
//! `AgentEvent`s as CBOR, plus raw JPEG and PCM), and `ReplayAgent` turns those
//! back into control-plane events and media. This is not a wire protocol: the
//! only backend transport is the HTTP control plane (`agent_server`).

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Event,
    Jpeg,
    DoorPcm,
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
    #[error("CBOR error: {0}")]
    Cbor(String),
}

impl WireFrame {
    /// Build a control frame whose payload is the CBOR encoding of `value`.
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

/// Control events carried in the replay timeline, decoded back into
/// control-plane events by `ReplayAgent`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AgentEvent {
    CallStarted { door_id: String, room_id: String },
    PadActionObserved { opcode: u32 },
    CallEnded { reason: String },
    Error { message: String },
}
