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
        anyhow::ensure!(
            !self.intercom.device_id.is_empty(),
            "intercom.device_id (the Pad's room station id) is required"
        );
        if let Some(subnet) = self.intercom.subnet.as_deref().filter(|s| !s.is_empty()) {
            subnet_broadcast(subnet)?;
        }
        anyhow::ensure!(
            self.security.unlock_cooldown_ms >= 250,
            "unlock cooldown must be at least 250 ms"
        );
        anyhow::ensure!(self.media.fps > 0, "media fps must be positive");
        Ok(())
    }
}

/// How the Agent stands on the wire. See `agent`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// 实体: this process is the Pad (UDP endpoint; cross-platform).
    Pad,
    /// 旁路: a physical Pad stays; tap the bridge and arbitrate (Linux).
    Tap,
}

impl AgentMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pad => "pad",
            Self::Tap => "tap",
        }
    }
}

impl std::str::FromStr for AgentMode {
    type Err = anyhow::Error;
    fn from_str(text: &str) -> Result<Self> {
        match text {
            "pad" => Ok(Self::Pad),
            "tap" => Ok(Self::Tap),
            other => anyhow::bail!("unknown agent mode {other:?}; use \"pad\" or \"tap\""),
        }
    }
}

/// The one identity plus the environment. Only `device_id` (and, for tap
/// mode, the interfaces) must be set: the Pad's IP, the door station and both
/// MACs are discovered or learned from the first call and then pinned. The
/// optional fields pin them up front instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntercomConfig {
    pub mode: AgentMode,
    /// The Pad's room station id: who this process is (pad) or stands in
    /// for (tap).
    #[serde(alias = "room_id")]
    pub device_id: String,
    /// LAN in CIDR form, e.g. "192.168.124.0/24", for the UDP 10008 discovery
    /// broadcast. Unset = 255.255.255.255.
    pub subnet: Option<String>,
    /// pad mode: UDP control endpoint to bind.
    pub pad_listen: SocketAddr,
    /// tap mode: the bridge to capture and its two member ports (for nft).
    pub bridge_interface: String,
    pub door_interface: String,
    pub pad_interface: String,
    /// Optional pins; learned when unset.
    pub door_id: Option<String>,
    pub door_ip: Option<Ipv4Addr>,
    pub room_ip: Option<Ipv4Addr>,
    pub door_mac: Option<String>,
    pub pad_mac: Option<String>,
    pub control_port: u16,
    pub discovery_port: u16,
    /// Door camera station ids offered as viewable cameras (the provisioned
    /// roster; the protocol has no discovery for these). Empty = none listed.
    pub cameras: Vec<String>,
    /// Station id of the door that fronts the elevator; resolved by discovery
    /// when the elevator is called. Unset = only a door learned from a call.
    pub elevator_door: Option<String>,
}

impl Default for IntercomConfig {
    fn default() -> Self {
        Self {
            mode: AgentMode::Tap,
            device_id: String::new(),
            subnet: None,
            pad_listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 10_000),
            bridge_interface: "br-lan".into(),
            door_interface: "CONFIGURE_ME".into(),
            pad_interface: "CONFIGURE_ME".into(),
            door_id: None,
            door_ip: None,
            room_ip: None,
            door_mac: None,
            pad_mac: None,
            control_port: 10_000,
            discovery_port: 10_008,
            cameras: Vec::new(),
            elevator_door: None,
        }
    }
}

impl IntercomConfig {
    /// Where discovery queries are broadcast: the subnet's directed broadcast,
    /// or the limited broadcast when no subnet is configured.
    pub fn discovery_broadcast(&self) -> Result<Ipv4Addr> {
        match self.subnet.as_deref().filter(|s| !s.is_empty()) {
            Some(cidr) => subnet_broadcast(cidr),
            None => Ok(Ipv4Addr::BROADCAST),
        }
    }
}

/// Directed broadcast address of an IPv4 CIDR such as "192.168.124.0/24".
pub fn subnet_broadcast(cidr: &str) -> Result<Ipv4Addr> {
    let (ip, prefix) = cidr
        .split_once('/')
        .with_context(|| format!("subnet {cidr:?} must look like 192.168.1.0/24"))?;
    let ip: Ipv4Addr = ip.parse().with_context(|| format!("bad subnet address in {cidr:?}"))?;
    let prefix: u32 = prefix.parse().with_context(|| format!("bad prefix length in {cidr:?}"))?;
    anyhow::ensure!(prefix <= 32, "prefix length in {cidr:?} exceeds 32");
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Ok(Ipv4Addr::from(u32::from(ip) | !mask))
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
    /// Serve the built-in browser Pad at `/`: a cross-platform fallback UI
    /// when no Matter/HAP backend is deployed. Off for headless deployments.
    pub web_ui: bool,
    /// Resolutions the browser Pad offers for the outbound camera, "WxH".
    /// Device-dependent: some Pads reject 720p, so keep this list to what the
    /// hardware actually displays.
    pub camera_resolutions: Vec<String>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub backend_ca: Option<PathBuf>,
}

fn default_camera_resolutions() -> Vec<String> {
    ["320x240", "640x480", "1024x768"]
        .into_iter()
        .map(String::from)
        .collect()
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            http_listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            token: String::new(),
            swagger: false,
            web_ui: true,
            camera_resolutions: default_camera_resolutions(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_broadcast_is_derived_from_cidr() {
        assert_eq!(
            subnet_broadcast("192.168.124.0/24").unwrap(),
            Ipv4Addr::new(192, 168, 124, 255)
        );
        assert_eq!(subnet_broadcast("10.1.2.3/16").unwrap(), Ipv4Addr::new(10, 1, 255, 255));
        assert_eq!(subnet_broadcast("10.0.0.0/30").unwrap(), Ipv4Addr::new(10, 0, 0, 3));
        assert!(subnet_broadcast("192.168.1.0").is_err());
        assert!(subnet_broadcast("192.168.1.0/33").is_err());
    }

    #[test]
    fn old_room_id_key_still_parses_as_device_id() {
        let config: Config =
            toml::from_str("[intercom]\nroom_id = \"S00000000000\"\n").unwrap();
        assert_eq!(config.intercom.device_id, "S00000000000");
        assert_eq!(config.intercom.mode, AgentMode::Tap);
        config.validate().unwrap();
    }
}
