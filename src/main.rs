use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use pad_gateway::agent::replay_timeline;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(version, about = "PENGUIN0 intercom Agent")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print a machine-readable summary of the capture replay.
    Analyze {
        #[arg(default_value = "testdata/pad.cap")]
        pcap: PathBuf,
    },
    /// Replay a pcap as an Agent over the HTTP control plane (REST + SSE),
    /// described in docs/openapi.yaml.
    FakeAgent {
        #[arg(default_value = "testdata/pad.cap")]
        pcap: PathBuf,
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        /// Replay the call again after this many idle seconds instead of
        /// staying idle after one pass.
        #[arg(long, value_name = "SECONDS")]
        repeat_after: Option<f64>,
        /// Serve the HTTP control plane (REST + SSE) on this address.
        #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
        http: SocketAddr,
        /// Bearer token for the HTTP control plane.
        #[arg(long)]
        token: Option<String>,
        /// Serve Swagger UI at /swagger on the HTTP control plane.
        #[arg(long)]
        swagger: bool,
        /// Close event streams after this many seconds (default: random 300-600).
        #[arg(long, value_name = "SECONDS")]
        events_lifetime: Option<u64>,
        /// Seconds of media kept for late joiners (0 = off).
        #[arg(long, default_value_t = 5)]
        history_secs: u64,
        /// Byte cap of the media history in KiB.
        #[arg(long, default_value_t = 2048)]
        history_max_kib: u64,
    },
    /// Run an interactive software door station you operate from the console.
    Door {
        #[arg(default_value = "testdata/pad.cap")]
        pcap: PathBuf,
        /// HTTP control plane address (REST + SSE) backends and the Pad connect to.
        #[arg(long, default_value = "127.0.0.1:8080")]
        http: SocketAddr,
        /// Bearer token for the control plane.
        #[arg(long)]
        token: Option<String>,
        /// Serve Swagger UI at /swagger.
        #[arg(long)]
        swagger: bool,
        /// Frames per second at which the saved camera loops.
        #[arg(long, default_value_t = 8)]
        loop_fps: u16,
        /// Shell command run on unlock (env DOOR_EVENT, DOOR_SESSION); default logs.
        #[arg(long, value_name = "CMD")]
        on_unlock: Option<String>,
        /// Shell command run when a backend answers.
        #[arg(long, value_name = "CMD")]
        on_answer: Option<String>,
        /// Shell command run on hangup.
        #[arg(long, value_name = "CMD")]
        on_hangup: Option<String>,
        /// Player for visitor talk audio (S16LE 8k mono on stdin); "off" to drop it, default ffplay.
        #[arg(long, value_name = "CMD")]
        player: Option<String>,
    },
    /// Emulate the door station from the protocol (not a replay): ring a
    /// target Pad with a synthesized call built from a door/room identity, so
    /// interacting with a real Pad validates the protocol. Camera frames come
    /// from a directory; audio from a file or silence.
    EmitDoor {
        /// Target Pad `ip` or `ip:port` (port defaults to the control port).
        /// Omit it to auto-discover the Pad from --room-id over UDP 10008.
        target: Option<String>,
        /// Door (own) Station ID.
        #[arg(long, default_value = "M00000000000")]
        door_id: String,
        /// Door (own) IPv4 written into the packet body. Defaults to this
        /// host's own address on the route to the Pad (auto-detected); the Pad
        /// replies to this address, so it must be reachable.
        #[arg(long, value_name = "IP")]
        door_ip: Option<std::net::Ipv4Addr>,
        /// Room (target) Station ID the Pad answers to.
        #[arg(long, default_value = "S00000000000")]
        room_id: String,
        /// Room IPv4 in the body; defaults to the target IP.
        #[arg(long, value_name = "IP")]
        room_ip: Option<std::net::Ipv4Addr>,
        /// Directory of JPEG frames used as the camera.
        #[arg(long, default_value = "testdata/frames")]
        frames: PathBuf,
        /// Raw S16LE 8 kHz mono PCM file used as the microphone (default: silence).
        #[arg(long, value_name = "FILE")]
        audio_file: Option<PathBuf>,
        /// Camera frame rate.
        #[arg(long, default_value_t = 8)]
        fps: u16,
        /// Stop after this many seconds (default: until the Pad hangs up or Ctrl-C).
        #[arg(long, value_name = "SECONDS")]
        seconds: Option<f64>,
        /// Player for the Pad's voice (S16LE 8k mono on stdin); "off" to drop it, default ffplay.
        #[arg(long, value_name = "CMD")]
        player: Option<String>,
        /// Broadcast address for UDP 10008 discovery, used when `target` is
        /// omitted (auto-discover the Pad by --room-id before ringing).
        #[arg(long, default_value = "255.255.255.255")]
        broadcast: std::net::Ipv4Addr,
        /// Seconds to wait for a discovery reply.
        #[arg(long, default_value_t = 3.0)]
        discover_timeout: f64,
    },
    /// Resolve a Pad's IP from its room Station ID over the UDP 10008
    /// discovery protocol (a private ARP): broadcast a query, read the reply.
    Resolve {
        /// Room Station ID to look up, e.g. S00000000000.
        room_id: String,
        /// Where to broadcast the query (subnet broadcast or 255.255.255.255).
        #[arg(long, default_value = "255.255.255.255")]
        broadcast: std::net::Ipv4Addr,
        /// Seconds to wait for a reply.
        #[arg(long, default_value_t = 3.0)]
        timeout: f64,
    },
    /// Software Pad Agent: bind the control port, accept a door emulator
    /// (`emit-door`) over UDP, and serve it to backends over the HTTP control
    /// plane. Cross-platform (no AF_PACKET); access it from the browser Pad.
    PadAgent {
        /// UDP control port to bind (the Pad endpoint the door rings).
        #[arg(long, default_value = "0.0.0.0:10000")]
        listen: SocketAddr,
        /// HTTP control plane (REST + SSE + browser Pad) address.
        #[arg(long, default_value = "127.0.0.1:8080")]
        http: SocketAddr,
        /// This Pad's room Station ID.
        #[arg(long, default_value = "S00000000000")]
        room_id: String,
        /// This Pad's IPv4 written into reply bodies (cosmetic on loopback).
        #[arg(long, default_value = "127.0.0.1")]
        room_ip: Ipv4Addr,
        /// Bearer token for the control plane.
        #[arg(long)]
        token: Option<String>,
        /// Serve Swagger UI at /swagger.
        #[arg(long)]
        swagger: bool,
        /// Also answer UDP 10008 discovery for --room-id.
        #[arg(long)]
        discover: bool,
        /// Seconds of media kept for late joiners (0 = off).
        #[arg(long, default_value_t = 5)]
        history_secs: u64,
        /// Byte cap of the media history in KiB.
        #[arg(long, default_value_t = 2048)]
        history_max_kib: u64,
    },
    /// Print the bridge-family nftables rules for manual/automatic coexistence.
    NftRules { config: PathBuf },
    /// Capture the real bridge and expose it to backends over the HTTP control
    /// plane (REST + SSE, see docs/openapi.yaml). Linux only.
    Agent { config: PathBuf },
    /// Validate and print a TOML configuration.
    CheckConfig { path: PathBuf },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
    match Cli::parse().command {
        Commands::Analyze { pcap } => {
            let bytes = std::fs::read(&pcap)?;
            let frames = replay_timeline(&pcap)?;
            let first = frames.first().map(|f| f.offset_micros).unwrap_or(0);
            let last = frames.last().map(|f| f.offset_micros).unwrap_or(0);
            let manifest = serde_json::json!({
                "capture": pcap,
                "sha256": hex::encode(Sha256::digest(bytes)),
                "agent_frames": frames.len(),
                "first_offset_micros": first,
                "last_offset_micros": last,
            });
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Commands::FakeAgent {
            pcap,
            speed,
            repeat_after,
            http,
            token,
            swagger,
            events_lifetime,
            history_secs,
            history_max_kib,
        } => {
            let repeat = repeat_after.map(Duration::from_secs_f64);
            let agent = pad_gateway::replay_agent::ReplayAgent::spawn(
                &pcap,
                speed,
                Duration::from_secs(1),
                repeat,
                Duration::from_secs(history_secs),
                (history_max_kib * 1024) as usize,
            )?;
            let mut config = pad_gateway::agent_server::ServerConfig {
                listen: http,
                token: token.filter(|t| !t.is_empty()),
                swagger,
                ..Default::default()
            };
            if let Some(seconds) = events_lifetime {
                let lifetime = Duration::from_secs(seconds);
                config.event_stream_lifetime = (lifetime, lifetime);
            }
            pad_gateway::agent_server::serve(config, agent).await?;
        }
        Commands::Door {
            pcap,
            http,
            token,
            swagger,
            loop_fps,
            on_unlock,
            on_answer,
            on_hangup,
            player,
        } => {
            use pad_gateway::door_station::{Callbacks, DoorStation, DoorStationConfig};
            let config = DoorStationConfig {
                loop_fps,
                callbacks: Callbacks {
                    on_answer,
                    on_unlock,
                    on_hangup,
                },
                player: player.map(|p| if p == "off" { String::new() } else { p }),
                ..Default::default()
            };
            let station = DoorStation::from_capture(&pcap, config)?;
            pad_gateway::door_station::spawn_console(station.clone());
            let server = pad_gateway::agent_server::ServerConfig {
                listen: http,
                token: token.filter(|t| !t.is_empty()),
                swagger,
                ..Default::default()
            };
            pad_gateway::agent_server::serve(server, station).await?;
        }
        Commands::EmitDoor {
            target,
            door_id,
            door_ip,
            room_id,
            room_ip,
            frames,
            audio_file,
            fps,
            seconds,
            player,
            broadcast,
            discover_timeout,
        } => {
            use pad_gateway::emitter::{resolve_pad, DoorIdentity, MediaSource};
            use pad_gateway::protocol::{Station, CONTROL_PORT};
            let target = match target {
                // Explicit target: `ip` or `ip:port`, no discovery.
                Some(target) => match target.parse::<SocketAddr>() {
                    Ok(addr) => addr,
                    Err(_) => {
                        let ip: std::net::Ipv4Addr = target
                            .parse()
                            .map_err(|_| anyhow::anyhow!("invalid target: {target}"))?;
                        SocketAddr::new(ip.into(), CONTROL_PORT)
                    }
                },
                // No target: auto-discover the Pad by room id (the private ARP).
                None => {
                    let ip = resolve_pad(
                        &room_id,
                        broadcast,
                        Duration::from_secs_f64(discover_timeout),
                    )
                    .await?;
                    SocketAddr::new(ip.into(), CONTROL_PORT)
                }
            };
            let room_ip = room_ip.unwrap_or(match target.ip() {
                std::net::IpAddr::V4(ip) => ip,
                std::net::IpAddr::V6(_) => anyhow::bail!("IPv6 target needs an explicit --room-ip"),
            });
            // 0.0.0.0 is the "auto-detect my own IP" sentinel for the emulator.
            let door_ip = door_ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
            let identity = DoorIdentity {
                door: Station::new(door_id, door_ip),
                room: Station::new(room_id, room_ip),
            };
            let media = MediaSource::load(&frames, audio_file.as_deref())?;
            let player = player.map(|p| if p == "off" { String::new() } else { p });
            let duration = seconds.map(Duration::from_secs_f64);
            let obs =
                pad_gateway::emitter::run_emulator(identity, media, target, fps, duration, player)
                    .await?;
            println!(
                "round trip: capability_reply={} answered={} unlocks={} hangups={} voice_packets={} voice_bytes={}",
                obs.capability_reply, obs.answered, obs.unlocks, obs.hangups, obs.audio_packets, obs.audio_bytes
            );
        }
        Commands::Resolve {
            room_id,
            broadcast,
            timeout,
        } => {
            let ip = pad_gateway::emitter::resolve_pad(
                &room_id,
                broadcast,
                Duration::from_secs_f64(timeout),
            )
            .await?;
            println!("{room_id} -> {ip}");
        }
        Commands::CheckConfig { path } => {
            let config = pad_gateway::config::Config::load(path)?;
            println!("{config:#?}");
        }
        Commands::PadAgent {
            listen,
            http,
            room_id,
            room_ip,
            token,
            swagger,
            discover,
            history_secs,
            history_max_kib,
        } => {
            let server = pad_gateway::agent_server::ServerConfig {
                listen: http,
                token: token.filter(|t| !t.is_empty()),
                swagger,
                ..Default::default()
            };
            pad_gateway::socket_agent::run_socket_agent(
                server,
                listen,
                pad_gateway::protocol::Station::new(room_id, room_ip),
                Duration::from_secs(history_secs),
                (history_max_kib * 1024) as usize,
                discover,
            )
            .await?;
        }
        Commands::NftRules { config } => {
            let config = pad_gateway::config::Config::load(config)?;
            print!("{}", pad_gateway::firewall::nft_rules(&config)?);
        }
        Commands::Agent { config } => run_agent(config).await?,
    }
    Ok(())
}

async fn run_agent(path: PathBuf) -> Result<()> {
    let config = pad_gateway::config::Config::load(path)?;
    #[cfg(all(target_os = "linux", feature = "linux-packet"))]
    {
        use pad_gateway::agent::{run_live_agent, LivePolicy};
        let policy = LivePolicy {
            cooldown: Duration::from_millis(config.security.unlock_cooldown_ms),
            unlock_requires_answer: config.security.unlock_requires_answer,
        };
        let server = pad_gateway::agent_server::ServerConfig {
            listen: config.agent.http_listen,
            token: Some(config.agent.token.clone()).filter(|t| !t.is_empty()),
            swagger: config.agent.swagger,
            ..Default::default()
        };
        let history = Duration::from_secs(config.media.history_secs);
        let history_max_bytes = (config.media.history_max_kib * 1024) as usize;
        run_live_agent(server, config.intercom, policy, history, history_max_bytes).await
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-packet")))]
    {
        let _ = config;
        anyhow::bail!("real Agent requires Linux and --features linux-packet")
    }
}
