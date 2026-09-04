use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub intercom: IntercomConfig,
    pub agent: AgentConfig,
    pub media: MediaConfig,
    pub coexistence: CoexistenceConfig,
    pub security: SecurityConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            intercom: IntercomConfig::default(),
            agent: AgentConfig::default(),
            media: MediaConfig::default(),
            coexistence: CoexistenceConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading configuration {}", path.display()))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("parsing configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.intercom.room_id.is_empty(), "room_id is empty");
        anyhow::ensure!(!self.intercom.door_id.is_empty(), "door_id is empty");
        anyhow::ensure!(
            self.security.unlock_cooldown_ms >= 250,
            "unlock cooldown must be at least 250 ms"
        );
        anyhow::ensure!(self.media.fps > 0, "media fps must be positive");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntercomConfig {
    pub bridge_interface: String,
    pub door_interface: String,
    pub pad_interface: String,
    pub door_id: String,
    pub room_id: String,
    pub door_ip: Ipv4Addr,
    pub room_ip: Ipv4Addr,
    pub door_mac: Option<String>,
    pub pad_mac: Option<String>,
    pub control_port: u16,
    pub discovery_port: u16,
}

impl Default for IntercomConfig {
    fn default() -> Self {
        Self {
            bridge_interface: "br-lan".into(),
            door_interface: "CONFIGURE_ME".into(),
            pad_interface: "CONFIGURE_ME".into(),
            door_id: "M00000000000".into(),
            room_id: "S00000000000".into(),
            door_ip: Ipv4Addr::new(192, 168, 124, 2),
            room_ip: Ipv4Addr::new(192, 168, 124, 61),
            door_mac: None,
            pad_mac: None,
            control_port: 10_000,
            discovery_port: 10_008,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// HTTP control plane (REST + SSE, see docs/openapi.yaml).
    pub http_listen: SocketAddr,
    /// Bearer token for the control plane; empty disables authentication.
    pub token: String,
    /// Serve Swagger UI at /swagger for testing.
    pub swagger: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub backend_ca: Option<PathBuf>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            http_listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            token: String::new(),
            swagger: false,
            tls_cert: None,
            tls_key: None,
            backend_ca: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MediaEngineKind {
    Lite,
    Ffmpeg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaConfig {
    pub engine: MediaEngineKind,
    pub fps: u16,
    pub width: u16,
    pub height: u16,
    pub static_jpeg: Option<PathBuf>,
    pub ffmpeg: PathBuf,
    /// Seconds of door video/audio kept in memory for late joiners and
    /// event clips; 0 disables the pre-roll buffer.
    pub history_secs: u64,
    /// Hard cap on the pre-roll buffer in KiB.
    pub history_max_kib: u64,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            engine: MediaEngineKind::Lite,
            fps: 8,
            width: 320,
            height: 240,
            static_jpeg: None,
            ffmpeg: PathBuf::from("ffmpeg"),
            history_secs: 5,
            history_max_kib: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CoexistenceMode {
    Manual,
    Automatic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CoexistenceConfig {
    pub mode: CoexistenceMode,
    pub nfqueue: u16,
    pub owner_timeout_ms: u64,
}

impl Default for CoexistenceConfig {
    fn default() -> Self {
        Self {
            mode: CoexistenceMode::Manual,
            nfqueue: 30,
            owner_timeout_ms: 2_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub unlock_cooldown_ms: u64,
    /// Only let the remote owner of an answered call unlock. Off by default:
    /// the door opens from the backend at any time, like from the Pad.
    pub unlock_requires_answer: bool,
    pub virtual_unlock_ms: u64,
    pub max_call_seconds: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            unlock_cooldown_ms: 1_000,
            unlock_requires_answer: false,
            virtual_unlock_ms: 1_500,
            max_call_seconds: 300,
        }
    }
}
