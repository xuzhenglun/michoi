use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use pad_gateway::agent::{replay_timeline, run_backend, run_fake_agent};
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
    /// Replay a pcap as an Agent: legacy PAG1 WebSocket plus, with --http,
    /// the HTTP control plane described in docs/openapi.yaml.
    FakeAgent {
        #[arg(default_value = "testdata/pad.cap")]
        pcap: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9443")]
        listen: SocketAddr,
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        /// Replay the call again after this many idle seconds instead of
        /// closing the connection after one pass.
        #[arg(long, value_name = "SECONDS")]
        repeat_after: Option<f64>,
        /// Also serve the HTTP control plane (REST + SSE) on this address.
        #[arg(long, value_name = "ADDR")]
        http: Option<SocketAddr>,
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
    /// Pretend to be the door station: ring a target (a real room Pad or
    /// another Agent) with the captured call and report/play what comes back
    /// (answer, unlock, voice). Answer on the Pad to test the round trip.
    EmitDoor {
        /// Target `ip` or `ip:port` (port defaults to the control port).
        target: String,
        #[arg(default_value = "testdata/pad.cap")]
        pcap: PathBuf,
        /// Source door IPv4 in the capture, used to pick door->Pad datagrams.
        #[arg(long, default_value = "192.168.124.2")]
        door_ip: std::net::Ipv4Addr,
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        /// Send the call again after this many idle seconds.
        #[arg(long, value_name = "SECONDS")]
        repeat_after: Option<f64>,
        /// Player for the Pad's voice (S16LE 8k mono on stdin); "off" to drop it, default ffplay.
        #[arg(long, value_name = "CMD")]
        player: Option<String>,
        /// Fire and forget: do not listen for the Pad's replies.
        #[arg(long)]
        no_listen: bool,
    },
    /// Consume the legacy PAG1 WebSocket feed of an Agent (smoke test).
    Pag1Client {
        #[arg(long, default_value = "ws://127.0.0.1:9443")]
        agent: String,
        /// Run answer/unlock/hangup automatically on the first call.
        #[arg(long)]
        scripted: bool,
    },
    /// Print the bridge-family nftables rules for manual/automatic coexistence.
    NftRules { config: PathBuf },
    /// Capture the real bridge and expose it to remote backends (Linux only).
    Agent { config: PathBuf },
    /// Run the real Agent and the PAG1 smoke client together (Linux only).
    Standalone { config: PathBuf },
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
            listen,
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
            if let Some(http) = http {
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
                tokio::spawn(async move {
                    if let Err(error) = pad_gateway::agent_server::serve(config, agent).await {
                        tracing::error!(%error, "control plane stopped");
                    }
                });
            }
            run_fake_agent(listen, pcap, speed, Duration::from_secs(1), repeat).await?;
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
            pcap,
            door_ip,
            speed,
            repeat_after,
            player,
            no_listen,
        } => {
            let target = match target.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(_) => {
                    let ip: std::net::Ipv4Addr = target
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid target: {target}"))?;
                    SocketAddr::new(ip.into(), pad_gateway::protocol::CONTROL_PORT)
                }
            };
            let repeat = repeat_after.map(Duration::from_secs_f64);
            if no_listen {
                pad_gateway::emitter::emit_capture(&pcap, door_ip, target, speed, repeat).await?;
            } else {
                let player = player.map(|p| if p == "off" { String::new() } else { p });
                let obs = pad_gateway::emitter::run_emulator(
                    &pcap, door_ip, target, speed, repeat, player,
                )
                .await?;
                println!(
                    "round trip: answered={} unlocks={} hangups={} voice_packets={} voice_bytes={}",
                    obs.answered, obs.unlocks, obs.hangups, obs.audio_packets, obs.audio_bytes
                );
            }
        }
        Commands::Pag1Client { agent, scripted } => run_backend(&agent, scripted).await?,
        Commands::CheckConfig { path } => {
            let config = pad_gateway::config::Config::load(path)?;
            println!("{config:#?}");
        }
        Commands::NftRules { config } => {
            let config = pad_gateway::config::Config::load(config)?;
            print!("{}", pad_gateway::firewall::nft_rules(&config)?);
        }
        Commands::Agent { config } => run_agent(config, false).await?,
        Commands::Standalone { config } => run_agent(config, true).await?,
    }
    Ok(())
}

async fn run_agent(path: PathBuf, standalone: bool) -> Result<()> {
    let config = pad_gateway::config::Config::load(path)?;
    #[cfg(all(target_os = "linux", feature = "linux-packet"))]
    {
        use pad_gateway::agent::{run_live_agent, LivePolicy};
        let policy = LivePolicy {
            cooldown: Duration::from_millis(config.security.unlock_cooldown_ms),
            unlock_requires_answer: config.security.unlock_requires_answer,
        };
        if standalone {
            let url = format!("ws://{}", config.agent.listen);
            let listen = config.agent.listen;
            let intercom = config.intercom;
            let agent = tokio::spawn(async move { run_live_agent(listen, intercom, policy).await });
            tokio::time::sleep(Duration::from_millis(50)).await;
            let backend = run_backend(&url, false).await;
            agent.abort();
            backend
        } else {
            run_live_agent(config.agent.listen, config.intercom, policy).await
        }
    }
    #[cfg(not(all(target_os = "linux", feature = "linux-packet")))]
    {
        let _ = (config, standalone);
        anyhow::bail!("real Agent requires Linux and --features linux-packet")
    }
}
