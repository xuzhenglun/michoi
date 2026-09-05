//! `tap` mode wire (Linux): a physical Pad stays in place; the Agent taps the
//! bridge with AF_PACKET.
//!
//! Receiving: every bridged frame is parsed; PENGUIN0 session messages for our
//! household are attributed to the door or the Pad by IP, MAC-pinned, and
//! handed to the core. The door's UDP 10008 discovery exchange is also
//! observed, so both stations' IP and MAC are learned before the first ring
//! even on a bridge that has no IP address of its own.
//!
//! Sending: Pad-originated packets are injected with a spoofed L2/L3 header
//! (Pad MAC/IP -> door MAC/IP). When a remote backend claims the call, an
//! nftables bridge table drops door<->Pad control so the physical Pad stops
//! ringing, and a spoofed door->Pad hangup tells it the call ended; both are
//! removed when the call ends (fail-open).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::agent::{parse_arp_table, Agent, Peers, Side, Wire};
use crate::bridge::PacketSocket;
use crate::config::IntercomConfig;
use crate::ethernet::{build_udp_ipv4, EthernetUdp, MacAddress};
use crate::protocol::{
    discovery_reply_room, discovery_request_room, session_control, split_coalesced, Message,
    FAMILY_SESSION, OP_HANGUP,
};

pub struct TapWire {
    socket: PacketSocket,
    pad_interface: String,
    door_interface: String,
    discovery_port: u16,
    seq: AtomicU32,
}

impl TapWire {
    pub fn open(ic: &IntercomConfig) -> Result<Arc<Self>> {
        for (name, value) in [
            ("bridge_interface", &ic.bridge_interface),
            ("pad_interface", &ic.pad_interface),
            ("door_interface", &ic.door_interface),
        ] {
            anyhow::ensure!(
                !value.is_empty() && value != "CONFIGURE_ME",
                "intercom.{name} is required in tap mode"
            );
        }
        let socket = PacketSocket::open(&ic.bridge_interface)?;
        // Clear any silence table left over from a previous run (fail-open).
        restore_physical_pad();
        tracing::info!(bridge = %ic.bridge_interface, "tap mode: capturing the bridge");
        Ok(Arc::new(Self {
            socket,
            pad_interface: ic.pad_interface.clone(),
            door_interface: ic.door_interface.clone(),
            discovery_port: ic.discovery_port,
            seq: AtomicU32::new(1),
        }))
    }

    fn next_seq(&self) -> u16 {
        self.seq.fetch_add(1, Ordering::Relaxed) as u16
    }

    /// Blocking capture loop; runs until the socket errors.
    pub fn run(&self, agent: &Agent) -> Result<()> {
        let device_id = agent.device_id();
        let mut buffer = vec![0_u8; 65_536];
        loop {
            let size = self.socket.receive(&mut buffer)?;
            let Ok(udp) = EthernetUdp::parse(&buffer[..size]) else {
                continue;
            };
            let control = agent.peers().control_port;
            // The door's discovery exchange: learn both stations passively.
            if udp.destination_port == self.discovery_port || udp.source_port == self.discovery_port
            {
                crate::protocol::trace_packet("rx discovery", udp.payload);
                if discovery_request_room(udp.payload).as_deref() == Some(device_id.as_str()) {
                    if agent.learn_address(Side::Door, udp.source_ip) {
                        agent.pin_mac(Side::Door, udp.source_mac);
                    }
                } else if discovery_reply_room(udp.payload).as_deref() == Some(device_id.as_str()) {
                    if agent.learn_address(Side::Pad, udp.source_ip) {
                        agent.pin_mac(Side::Pad, udp.source_mac);
                    }
                }
                continue;
            }
            if udp.source_port != control && udp.destination_port != control {
                continue;
            }
            for raw in split_coalesced(udp.payload) {
                crate::protocol::trace_packet("rx bridge", raw);
                let Ok(message) = Message::parse(raw) else {
                    continue;
                };
                if message.family != FAMILY_SESSION {
                    continue;
                }
                let Some(endpoints) = message.endpoints() else {
                    continue;
                };
                if endpoints.room.id != device_id {
                    continue;
                }
                let side = if udp.source_ip == endpoints.room.ip {
                    Side::Pad
                } else if udp.source_ip == endpoints.door.ip {
                    Side::Door
                } else {
                    continue;
                };
                if !agent.pin_mac(side, udp.source_mac) {
                    continue;
                }
                agent.on_wire(side, raw);
            }
        }
    }

    fn inject(
        &self,
        src_mac: MacAddress,
        dst_mac: MacAddress,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        port: u16,
        payload: &[u8],
    ) -> Result<()> {
        crate::protocol::trace_packet("tx inject", payload);
        let frame = build_udp_ipv4(src_mac, dst_mac, src_ip, dst_ip, port, port, payload, self.next_seq())?;
        let sent = self.socket.send(&frame)?;
        anyhow::ensure!(sent == frame.len(), "short AF_PACKET send");
        Ok(())
    }

    /// Both stations fully known (IPs and MACs), or an error saying what is
    /// still missing.
    fn addresses(peers: &Peers) -> Result<(MacAddress, MacAddress, Ipv4Addr, Ipv4Addr)> {
        let door = peers.door.as_ref().context("door station not learned yet")?;
        anyhow::ensure!(!door.ip.is_unspecified(), "door IP not learned yet");
        anyhow::ensure!(!peers.room.ip.is_unspecified(), "Pad IP not learned yet");
        let door_mac = peers.door_mac.context("door MAC not learned yet")?;
        let pad_mac = peers.pad_mac.context("Pad MAC not learned yet")?;
        Ok((pad_mac, door_mac, peers.room.ip, door.ip))
    }
}

impl Wire for TapWire {
    fn name(&self) -> &'static str {
        "tap"
    }

    /// The physical Pad answers the handshake; we only watch.
    fn handshake_reply(&self, _payload: &[u8], _peers: &Peers) -> Result<()> {
        Ok(())
    }

    fn send_as_pad(&self, payload: &[u8], peers: &Peers) -> Result<()> {
        let (pad_mac, door_mac, pad_ip, door_ip) = Self::addresses(peers)?;
        self.inject(pad_mac, door_mac, pad_ip, door_ip, peers.control_port, payload)
    }

    /// Silence the physical Pad and tell it the call ended. Every step is
    /// fail-open: a failure leaves the Pad working and is only logged.
    ///
    /// NOTE: needs authorized on-device validation. The capture shows the door
    /// tears the call down with a door->Pad `00b7/1e`, so the reset reuses that
    /// envelope, but that a *mid-call* injected hangup silences this Pad model
    /// is not proven by `pad.cap` alone.
    fn on_remote_claim(&self, peers: &Peers) {
        let (pad_mac, door_mac, pad_ip, door_ip) = match Self::addresses(peers) {
            Ok(addresses) => addresses,
            Err(error) => {
                tracing::warn!(%error, "cannot silence the physical Pad");
                return;
            }
        };
        match crate::firewall::pad_silence_rules(
            &self.pad_interface,
            &self.door_interface,
            door_ip,
            pad_ip,
            peers.control_port,
        ) {
            Ok(rules) => match nft_apply(&rules) {
                Ok(()) => tracing::info!("physical Pad silenced (door<->Pad control dropped)"),
                Err(error) => tracing::warn!(%error, "failed to install Pad silence rules; Pad stays live"),
            },
            Err(error) => tracing::warn!(%error, "cannot build Pad silence rules"),
        }
        if let Some(endpoints) = peers.endpoints() {
            match session_control(OP_HANGUP, &endpoints) {
                Ok(reset) => {
                    if let Err(error) =
                        self.inject(door_mac, pad_mac, door_ip, pad_ip, peers.control_port, &reset)
                    {
                        tracing::warn!(%error, "failed to inject door->Pad hangup reset");
                    }
                }
                Err(error) => tracing::warn!(%error, "cannot build the Pad reset"),
            }
        }
    }

    fn on_call_end(&self, _peers: &Peers) {
        restore_physical_pad();
    }
}

/// Remove the silence table so the physical Pad path is restored.
fn restore_physical_pad() {
    match nft_flush() {
        Ok(()) => tracing::info!("physical Pad path restored"),
        Err(error) => tracing::warn!(%error, "failed to flush Pad silence table"),
    }
}

fn nft_apply(rules: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .spawn()
        .context("spawning nft")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(rules.as_bytes())?;
    let status = child.wait()?;
    anyhow::ensure!(status.success(), "nft -f exited with {status}");
    Ok(())
}

fn nft_flush() -> Result<()> {
    let status = std::process::Command::new("nft")
        .args(crate::firewall::flush_table_command().split_whitespace())
        .status()
        .context("running nft delete")?;
    // A missing table is fine; the goal is that it is gone.
    let _ = status;
    Ok(())
}

/// The MAC for `ip` from the kernel neighbour table, if complete.
pub fn neighbor_mac(ip: Ipv4Addr) -> Option<MacAddress> {
    let text = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_arp_table(&text, ip)
}
