//! `pad` mode wire: this process is the Pad, on a plain UDP socket.
//!
//! It binds the control port, remembers the door's socket address from what
//! it receives, answers the handshake and sends Pad-originated packets with
//! `send_to`. Cross-platform; this is also what closes the loop on a laptop
//! with `tools emit-door`.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::agent::{Agent, Peers, Side, Wire};
use crate::protocol::{discovery_reply, discovery_request_room, split_coalesced};

pub struct UdpWire {
    socket: Arc<UdpSocket>,
    /// The door's address; replies and Pad-originated packets go here.
    peer: Mutex<Option<SocketAddr>>,
}

impl UdpWire {
    pub async fn bind(addr: SocketAddr) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding the control port {addr}"))?;
        tracing::info!(%addr, "pad mode: listening for the door station");
        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            peer: Mutex::new(None),
        }))
    }

    /// Receive until the socket errors, attributing everything to the door.
    pub async fn run(self: Arc<Self>, agent: Arc<Agent>) {
        let mut buffer = vec![0_u8; 65_536];
        loop {
            let Ok((size, from)) = self.socket.recv_from(&mut buffer).await else {
                break;
            };
            *self.peer.lock().unwrap() = Some(from);
            if let IpAddr::V4(door_ip) = from.ip() {
                // Our own address toward the door is the Pad's IP.
                if let Some(local) = local_ip_toward(from) {
                    agent.set_room_ip_if_unset(local);
                }
                agent.learn_address(Side::Door, door_ip);
            }
            for raw in split_coalesced(&buffer[..size]) {
                agent.on_wire(Side::Door, raw);
            }
        }
    }

    fn send(&self, payload: &[u8]) -> Result<()> {
        let peer = self
            .peer
            .lock()
            .unwrap()
            .context("no door station has contacted this Pad yet")?;
        self.socket
            .try_send_to(payload, peer)
            .map(|_| ())
            .with_context(|| format!("sending to the door at {peer}"))
    }
}

impl Wire for UdpWire {
    fn name(&self) -> &'static str {
        "pad"
    }

    fn handshake_reply(&self, payload: &[u8], _peers: &Peers) -> Result<()> {
        self.send(payload)
    }

    fn send_as_pad(&self, payload: &[u8], _peers: &Peers) -> Result<()> {
        self.send(payload)
    }

    fn on_remote_claim(&self, _peers: &Peers) {}

    fn on_call_end(&self, _peers: &Peers) {}
}

/// The local IPv4 the kernel would use to reach `peer` (no packet is sent).
fn local_ip_toward(peer: SocketAddr) -> Option<std::net::Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect(peer).ok()?;
    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

/// Answer UDP 10008 discovery for our device id so the door can find this Pad.
/// Best-effort: a bind failure (port taken) is logged and discovery is off.
pub async fn discovery_responder(port: u16, device_id: String) {
    let bind = SocketAddr::from(([0, 0, 0, 0], port));
    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(error) => {
            tracing::warn!(%error, %bind, "discovery responder disabled");
            return;
        }
    };
    let _ = socket.set_broadcast(true);
    let Ok(reply) = discovery_reply(&device_id) else {
        return;
    };
    let mut buffer = vec![0_u8; 1024];
    loop {
        let Ok((size, from)) = socket.recv_from(&mut buffer).await else {
            break;
        };
        if discovery_request_room(&buffer[..size]).as_deref() == Some(device_id.as_str()) {
            let _ = socket.send_to(&reply, from).await;
        }
    }
}
