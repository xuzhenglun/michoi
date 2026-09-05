//! One shared UDP 10008 endpoint for the Agent.
//!
//! Real devices reply to a discovery query on the well-known port 10008, not
//! to the query's source port. So the Agent cannot answer queries from one
//! socket and resolve ids from another: the second socket would never see the
//! replies. This service owns the single `:10008` socket and does both --
//! answer "who has <our id>" and resolve other ids for camera listing and
//! elevator calls. Cross-platform (tokio UDP).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::protocol::{
    discovery_reply, discovery_reply_room, discovery_request, discovery_request_room,
    DISCOVERY_PORT,
};

pub struct DiscoveryService {
    socket: Arc<UdpSocket>,
    /// Our own station id to answer queries for; `None` = do not answer (e.g.
    /// tap mode, where the physical Pad answers).
    device_id: Option<String>,
    /// Pending resolves keyed by the queried station id.
    pending: Mutex<HashMap<String, Vec<oneshot::Sender<Ipv4Addr>>>>,
}

impl DiscoveryService {
    pub async fn bind(port: u16, device_id: Option<String>) -> Result<Arc<Self>> {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding discovery port {addr}"))?;
        socket.set_broadcast(true).context("enabling UDP broadcast")?;
        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            device_id,
            pending: Mutex::new(HashMap::new()),
        }))
    }

    /// Run the receive loop: answer queries for our id, complete resolves.
    pub async fn run(self: Arc<Self>) {
        let mut buf = vec![0_u8; 2048];
        loop {
            let Ok((size, from)) = self.socket.recv_from(&mut buf).await else {
                break;
            };
            let datagram = &buf[..size];
            crate::protocol::trace_packet("rx discovery", datagram);
            // A reply (02 + id): complete any waiters for that id.
            if let Some(id) = discovery_reply_room(datagram) {
                if let SocketAddr::V4(v4) = from {
                    let waiters = self.pending.lock().unwrap().remove(&id);
                    if let Some(waiters) = waiters {
                        for tx in waiters {
                            let _ = tx.send(*v4.ip());
                        }
                    }
                }
                continue;
            }
            // A query (01 + id): answer if it is us.
            if let (Some(id), Some(ours)) = (discovery_request_room(datagram), &self.device_id) {
                if &id == ours {
                    if let Ok(reply) = discovery_reply(ours) {
                        crate::protocol::trace_packet("tx discovery", &reply);
                        let _ = self.socket.send_to(&reply, from).await;
                    }
                }
            }
        }
    }

    /// Resolve `id` to an IPv4 by broadcasting a query on the shared socket and
    /// awaiting the reply (which real devices send to port 10008).
    pub async fn resolve(
        &self,
        id: &str,
        broadcast: Ipv4Addr,
        timeout: Duration,
    ) -> Option<Ipv4Addr> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .entry(id.to_owned())
            .or_default()
            .push(tx);
        let request = discovery_request(id).ok()?;
        crate::protocol::trace_packet("tx discovery", &request);
        let dest = SocketAddr::from((broadcast, DISCOVERY_PORT));
        if self.socket.send_to(&request, dest).await.is_err() {
            return None;
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(ip)) => Some(ip),
            _ => {
                // Drop our waiter on timeout.
                if let Some(v) = self.pending.lock().unwrap().get_mut(id) {
                    v.clear();
                }
                None
            }
        }
    }
}
