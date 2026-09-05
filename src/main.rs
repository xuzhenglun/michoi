use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use michoi::replay_agent::replay_timeline;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(version, about = "michoi: PENGUIN0 intercom Agent")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// The Agent: stands for the household's Pad on the wire and serves the
    /// HTTP control plane (REST + SSE, browser Pad, see docs/openapi.yaml).
    /// `--mode pad` is the Pad itself (cross-platform); `--mode tap` taps the
    /// bridge next to a physical Pad (Linux router). Flags override the config.
    Agent {
        /// TOML configuration (config.example.toml); optional for pad mode.
        config: Option<PathBuf>,
        /// pad = this process is the Pad; tap = a physical Pad stays, tap the bridge.
        #[arg(long, value_name = "pad|tap")]
        mode: Option<michoi::config::AgentMode>,
        /// The Pad's room station id: who I am (pad) or stand in for (tap).
        #[arg(long, value_name = "ID")]
        device_id: Option<String>,
        /// LAN in CIDR form for discovery broadcasts, e.g. 192.168.124.0/24.
        #[arg(long, value_name = "CIDR")]
        subnet: Option<String>,
        /// HTTP control plane address.
        #[arg(long, value_name = "ADDR")]
        http: Option<SocketAddr>,
        /// Bearer token for the control plane (empty = no auth, development only).
        #[arg(long)]
        token: Option<String>,
        /// Serve Swagger UI at /swagger.
        #[arg(long)]
        swagger: bool,
        /// Do not serve the built-in browser Pad at / and /pad (headless).
        #[arg(long)]
        no_web_ui: bool,
        /// pad mode: UDP control endpoint to bind (default 0.0.0.0:10000).
        #[arg(long, value_name = "ADDR")]
        listen: Option<SocketAddr>,
        /// Seconds of media kept for late joiners (0 = off).
        #[arg(long, value_name = "SECONDS")]
        history_secs: Option<u64>,
        /// Seconds to wait for a UDP 10008 discovery reply at startup.
        #[arg(long, default_value_t = 3.0)]
        discover_timeout: f64,
    },
    /// The software door station you operate from the console: the saved
    /// capture is its camera and microphone, backends and the browser Pad
    /// connect to its HTTP control plane.
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
        /// Do not serve the built-in browser Pad at / and /pad (headless).
        #[arg(long)]
        no_web_ui: bool,
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
        /// Play the visitor's talk audio through ffplay instead of writing it.
        #[arg(long)]
        play: bool,
        /// Custom player command for the visitor's talk audio (S16LE 8k mono on
        /// stdin); implies playing.
        #[arg(long, value_name = "CMD")]
        player: Option<String>,
        /// When not playing, write the visitor's talk audio as raw S16LE here
        /// (default: visitor-talk.s16le).
        #[arg(long, value_name = "FILE")]
        audio_out: Option<PathBuf>,
    },
    /// Debugging and validation tools.
    Tools {
        #[command(subcommand)]
        tool: Tools,
    },
}

#[derive(Subcommand)]
enum Tools {
    /// Print a machine-readable summary of the capture replay.
    Analyze {
        #[arg(default_value = "testdata/pad.cap")]
        pcap: PathBuf,
    },
    /// Replay a pcap as an Agent over the HTTP control plane (a locked demo).
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
        /// Do not serve the built-in browser Pad at / and /pad (headless).
        #[arg(long)]
        no_web_ui: bool,
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
    /// Emulate a door station from the protocol (not a replay): ring a target
    /// Pad with a synthesized call, so interacting with a real Pad (or an
    /// `agent --mode pad`) validates the protocol. Camera frames come from a
    /// directory; audio from a file or silence.
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
        /// Play the Pad's voice through ffplay instead of writing it to a file.
        #[arg(long)]
        play: bool,
        /// Custom player command for the Pad's voice (S16LE 8k mono on stdin);
        /// implies playing.
        #[arg(long, value_name = "CMD")]
        player: Option<String>,
        /// When not playing, write the Pad's voice as raw S16LE 8k mono here
        /// (default: pad-voice.s16le).
        #[arg(long, value_name = "FILE")]
        audio_out: Option<PathBuf>,
        /// Broadcast address for UDP 10008 discovery, used when `target` is
        /// omitted (auto-discover the Pad by --room-id before ringing).
        #[arg(long, default_value = "255.255.255.255")]
        broadcast: std::net::Ipv4Addr,
        /// Seconds to wait for a discovery reply.
        #[arg(long, default_value_t = 3.0)]
        discover_timeout: f64,
    },
    /// View a door camera as the Pad, without a ring (the peer of an incoming
    /// call, family 00b8): send the monitor request and take in its video and
    /// audio. Frames are saved to a directory; audio to a file or a player.
    Monitor {
        /// Door camera station id to view; its IP is resolved over UDP 10008.
        door_id: String,
        /// Our own (room/Pad) station id, written into the request.
        #[arg(long, default_value = "S00000000000")]
        room_id: String,
        /// Directory to save received JPEG frames into.
        #[arg(long, value_name = "DIR", default_value = "monitor-frames")]
        out_dir: PathBuf,
        /// Stop after this many seconds (default: until the door hangs up or Ctrl-C).
        #[arg(long, value_name = "SECONDS")]
        seconds: Option<f64>,
        /// Play the camera audio through ffplay instead of writing it.
        #[arg(long)]
        play: bool,
        /// Custom player command for the camera audio (S16LE 8k mono on stdin).
        #[arg(long, value_name = "CMD")]
        player: Option<String>,
        /// When not playing, write the camera audio as raw S16LE here
        /// (default: monitor-audio.s16le).
        #[arg(long, value_name = "FILE")]
        audio_out: Option<PathBuf>,
        /// Where to broadcast the UDP 10008 discovery query (subnet broadcast
        /// or 255.255.255.255).
        #[arg(long, default_value = "255.255.255.255")]
        broadcast: std::net::Ipv4Addr,
        /// Seconds to wait for a discovery reply.
        #[arg(long, default_value_t = 3.0)]
        discover_timeout: f64,
    },
    /// Call the elevator to the requesting room's floor: resolve the door
    /// station by id over UDP 10008, send 0106/01 and wait for its ack.
    Elevator {
        /// Door station id that fronts the elevator; its IP is resolved.
        door_id: String,
        /// The requesting room's station id (its floor is derived from the id).
        #[arg(long, default_value = "S00000000000")]
        room_id: String,
        /// Where to broadcast the UDP 10008 discovery query.
        #[arg(long, default_value = "255.255.255.255")]
        broadcast: std::net::Ipv4Addr,
        /// Seconds to wait for the discovery reply.
        #[arg(long, default_value_t = 3.0)]
        discover_timeout: f64,
        /// Seconds to wait for the elevator ack.
        #[arg(long, default_value_t = 3.0)]
        timeout: f64,
    },
    /// Resolve a station's IP from its id over the UDP 10008 discovery
    /// protocol (a private ARP): broadcast a query, read the reply.
    Resolve {
        /// Station id to look up (room or door), e.g. S00000000000.
        station_id: String,
        /// Where to broadcast the query (subnet broadcast or 255.255.255.255).
        #[arg(long, default_value = "255.255.255.255")]
        broadcast: std::net::Ipv4Addr,
        /// Seconds to wait for a reply.
        #[arg(long, default_value_t = 3.0)]
        timeout: f64,
    },
    /// Print the bridge-family nftables rules for manual/automatic coexistence.
    NftRules { config: PathBuf },
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
        Commands::Agent {
            config,
            mode,
            device_id,
            subnet,
            http,
            token,
            swagger,
            no_web_ui,
            listen,
            history_secs,
            discover_timeout,
        } => {
            let mut cfg = match config {
                Some(path) => michoi::config::Config::load(path)?,
                None => michoi::config::Config::default(),
            };
            if let Some(mode) = mode {
                cfg.intercom.mode = mode;
            }
            if let Some(id) = device_id {
                cfg.intercom.device_id = id;
            }
            if let Some(subnet) = subnet {
                cfg.intercom.subnet = Some(subnet);
            }
            if let Some(listen) = listen {
                cfg.intercom.pad_listen = listen;
            }
            if let Some(http) = http {
                cfg.agent.http_listen = http;
            }
            if let Some(token) = token {
                cfg.agent.token = token;
            }
            if swagger {
                cfg.agent.swagger = true;
            }
            if no_web_ui {
                cfg.agent.web_ui = false;
            }
            if let Some(secs) = history_secs {
                cfg.media.history_secs = secs;
            }
            cfg.validate()
                .context("configuration (pass --device-id or a config file)")?;
            let roster = cfg.intercom.cameras.clone();
            let broadcast = cfg.intercom.discovery_broadcast()?;
            let run = michoi::agent::Run {
                server: michoi::agent_server::ServerConfig {
                    listen: cfg.agent.http_listen,
                    token: Some(cfg.agent.token.clone()).filter(|t| !t.is_empty()),
                    swagger: cfg.agent.swagger,
                    web_ui: cfg.agent.web_ui,
                    ..Default::default()
                },
                intercom: cfg.intercom,
                policy: michoi::agent::Policy {
                    cooldown: Duration::from_millis(cfg.security.unlock_cooldown_ms),
                    unlock_requires_answer: cfg.security.unlock_requires_answer,
                },
                history: Duration::from_secs(cfg.media.history_secs),
                history_max_bytes: (cfg.media.history_max_kib * 1024) as usize,
                discover_timeout: Duration::from_secs_f64(discover_timeout),
                roster,
                broadcast,
            };
            michoi::agent::run_agent(run).await?;
        }
        Commands::Door {
            pcap,
            http,
            token,
            swagger,
            no_web_ui,
            loop_fps,
            on_unlock,
            on_answer,
            on_hangup,
            play,
            player,
            audio_out,
        } => {
            use michoi::door_station::{Callbacks, DoorStation, DoorStationConfig};
            let config = DoorStationConfig {
                loop_fps,
                callbacks: Callbacks {
                    on_answer,
                    on_unlock,
                    on_hangup,
                },
                play,
                player,
                audio_out,
                ..Default::default()
            };
            let station = DoorStation::from_capture(&pcap, config)?;
            michoi::door_station::spawn_console(station.clone());
            let server = michoi::agent_server::ServerConfig {
                listen: http,
                token: token.filter(|t| !t.is_empty()),
                swagger,
                web_ui: !no_web_ui,
                ..Default::default()
            };
            michoi::agent_server::serve(server, station).await?;
        }
        Commands::Tools { tool } => run_tool(tool).await?,
    }
    Ok(())
}

async fn run_tool(tool: Tools) -> Result<()> {
    match tool {
        Tools::Analyze { pcap } => {
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
        Tools::FakeAgent {
            pcap,
            speed,
            repeat_after,
            http,
            token,
            swagger,
            no_web_ui,
            events_lifetime,
            history_secs,
            history_max_kib,
        } => {
            let repeat = repeat_after.map(Duration::from_secs_f64);
            let agent = michoi::replay_agent::ReplayAgent::spawn(
                &pcap,
                speed,
                Duration::from_secs(1),
                repeat,
                Duration::from_secs(history_secs),
                (history_max_kib * 1024) as usize,
            )?;
            let mut config = michoi::agent_server::ServerConfig {
                listen: http,
                token: token.filter(|t| !t.is_empty()),
                swagger,
                web_ui: !no_web_ui,
                ..Default::default()
            };
            if let Some(seconds) = events_lifetime {
                let lifetime = Duration::from_secs(seconds);
                config.event_stream_lifetime = (lifetime, lifetime);
            }
            michoi::agent_server::serve(config, agent).await?;
        }
        Tools::EmitDoor {
            target,
            door_id,
            door_ip,
            room_id,
            room_ip,
            frames,
            audio_file,
            fps,
            seconds,
            play,
            player,
            audio_out,
            broadcast,
            discover_timeout,
        } => {
            use michoi::emitter::{resolve_pad, DoorIdentity, MediaSource};
            use michoi::protocol::{Station, CONTROL_PORT};
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
            let sink = michoi::door_station::AudioSink::open(
                play,
                player.as_deref(),
                audio_out.as_deref(),
                "pad-voice.s16le",
            )?;
            let duration = seconds.map(Duration::from_secs_f64);
            let obs = michoi::emitter::run_emulator(
                identity,
                media,
                target,
                fps,
                duration,
                Some(sink),
            )
            .await?;
            println!(
                "round trip: capability_reply={} answered={} unlocks={} hangups={} voice_packets={} voice_bytes={}",
                obs.capability_reply, obs.answered, obs.unlocks, obs.hangups, obs.audio_packets, obs.audio_bytes
            );
        }
        Tools::Monitor {
            door_id,
            room_id,
            out_dir,
            seconds,
            play,
            player,
            audio_out,
            broadcast,
            discover_timeout,
        } => {
            use michoi::emitter::{resolve_pad, run_monitor};
            use michoi::protocol::Station;
            let door_ip =
                resolve_pad(&door_id, broadcast, Duration::from_secs_f64(discover_timeout)).await?;
            println!("{door_id} -> {door_ip}");
            let sink = michoi::door_station::AudioSink::open(
                play,
                player.as_deref(),
                audio_out.as_deref(),
                "monitor-audio.s16le",
            )?;
            let obs = run_monitor(
                Station::new(room_id, std::net::Ipv4Addr::UNSPECIFIED),
                Station::new(door_id, door_ip),
                Some(out_dir),
                seconds.map(Duration::from_secs_f64),
                Some(sink),
            )
            .await?;
            println!(
                "monitor: capability_reply={} jpeg_frames={} audio_packets={} audio_bytes={} hangups={}",
                obs.capability_reply, obs.jpeg_frames, obs.audio_packets, obs.audio_bytes, obs.hangups
            );
        }
        Tools::Elevator {
            door_id,
            room_id,
            broadcast,
            discover_timeout,
            timeout,
        } => {
            use michoi::protocol::CONTROL_PORT;
            let ip = michoi::emitter::resolve_pad(
                &door_id,
                broadcast,
                Duration::from_secs_f64(discover_timeout),
            )
            .await?;
            println!("{door_id} -> {ip}");
            let target = SocketAddr::new(ip.into(), CONTROL_PORT);
            let ok = michoi::emitter::request_elevator(
                &room_id,
                target,
                Duration::from_secs_f64(timeout),
            )
            .await?;
            println!("elevator: {}", if ok { "acknowledged" } else { "no ack" });
            if !ok {
                std::process::exit(1);
            }
        }
        Tools::Resolve {
            station_id,
            broadcast,
            timeout,
        } => {
            let ip = michoi::emitter::resolve_pad(
                &station_id,
                broadcast,
                Duration::from_secs_f64(timeout),
            )
            .await?;
            println!("{station_id} -> {ip}");
        }
        Tools::NftRules { config } => {
            let config = michoi::config::Config::load(config)?;
            print!("{}", michoi::firewall::nft_rules(&config)?);
        }
        Tools::CheckConfig { path } => {
            let config = michoi::config::Config::load(path)?;
            println!("{config:#?}");
        }
    }
    Ok(())
}
