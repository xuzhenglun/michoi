use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallPhase {
    Idle,
    Ringing,
    Connected,
    Ending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    None,
    Pad,
    Remote,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StateError {
    #[error("no ringing call is available")]
    NotRinging,
    #[error("the physical pad owns this call")]
    PadOwnsCall,
    #[error("unlock is allowed only after the remote Matter session has answered")]
    UnlockNotAllowed,
    #[error("unlock cooldown is active")]
    UnlockCooldown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCallState {
    pub session_id: u64,
    pub phase: CallPhase,
    pub owner: Owner,
    pub video_frames: u64,
    pub door_audio_packets: u64,
    pub unlocks: u64,
}

pub struct CallMachine {
    state: PublicCallState,
    unlock_cooldown: Duration,
    last_unlock: Option<Instant>,
}

impl CallMachine {
    pub fn new(unlock_cooldown: Duration) -> Self {
        Self {
            state: PublicCallState {
                session_id: 0,
                phase: CallPhase::Idle,
                owner: Owner::None,
                video_frames: 0,
                door_audio_packets: 0,
                unlocks: 0,
            },
            unlock_cooldown,
            last_unlock: None,
        }
    }

    pub fn start_call(&mut self, session_id: u64) {
        self.state = PublicCallState {
            session_id,
            phase: CallPhase::Ringing,
            owner: Owner::None,
            video_frames: 0,
            door_audio_packets: 0,
            unlocks: 0,
        };
        self.last_unlock = None;
    }

    pub fn pad_answer(&mut self) -> Result<(), StateError> {
        if self.state.phase != CallPhase::Ringing {
            return Err(StateError::NotRinging);
        }
        if self.state.owner == Owner::Remote {
            return Err(StateError::NotRinging);
        }
        self.state.owner = Owner::Pad;
        self.state.phase = CallPhase::Connected;
        Ok(())
    }

    pub fn remote_answer(&mut self) -> Result<(), StateError> {
        if self.state.phase != CallPhase::Ringing {
            return Err(StateError::NotRinging);
        }
        if self.state.owner == Owner::Pad {
            return Err(StateError::PadOwnsCall);
        }
        self.state.owner = Owner::Remote;
        self.state.phase = CallPhase::Connected;
        Ok(())
    }

    pub fn unlock(&mut self, now: Instant) -> Result<(), StateError> {
        if self.state.phase != CallPhase::Connected || self.state.owner != Owner::Remote {
            return Err(StateError::UnlockNotAllowed);
        }
        if self
            .last_unlock
            .is_some_and(|last| now.duration_since(last) < self.unlock_cooldown)
        {
            return Err(StateError::UnlockCooldown);
        }
        self.last_unlock = Some(now);
        self.state.unlocks += 1;
        Ok(())
    }

    pub fn video_frame(&mut self) {
        self.state.video_frames += 1;
    }

    pub fn door_audio(&mut self) {
        self.state.door_audio_packets += 1;
    }

    pub fn hangup(&mut self) {
        self.state.phase = CallPhase::Idle;
        self.state.owner = Owner::None;
        self.last_unlock = None;
    }

    pub fn state(&self) -> &PublicCallState {
        &self.state
    }

    pub fn remote_media_allowed(&self, session_id: u64) -> bool {
        self.state.session_id == session_id
            && self.state.phase == CallPhase::Connected
            && self.state.owner == Owner::Remote
    }
}
