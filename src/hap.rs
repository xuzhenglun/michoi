//! Apple HomeKit (HAP over IP) controller — P0, control-only.
//!
//! This is a Controller (the "C" in the MVCS split) built on the
//! [`AgentControl`] trait (the "S"). It drives the Agent purely through that
//! trait, exactly like [`crate::agent_server`] does, so it runs against the
//! in-process Agent by direct function call today and could run against a
//! remote trait implementation unchanged later.
//!
//! Three services, no camera or media:
//!
//! * **Lock Mechanism** → unlock: claim the ringing call (become owner, which
//!   the state machine also needs before it will unlock), send the unlock,
//!   show "unlocked" briefly, then relock by itself. Not a stateful switch.
//! * **Switch** → call the elevator to this Pad's floor. Momentary: it flips
//!   itself back off after firing.
//! * **Doorbell** → an incoming call ([`EventKind::CallStarted`]) raises a
//!   single press, so the Home app notifies "someone's at the door".
//!
//! The camera / RTP / two-way-audio half is a later phase and pulls its own
//! dependencies then. The vendored `hap` crate provides pairing, the encrypted
//! session, mDNS and the characteristic database.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hap::accessory::{AccessoryCategory, AccessoryInformation, HapAccessory};
use hap::characteristic::HapCharacteristic;
use hap::server::{IpServer, Server};
use hap::service::accessory_information::AccessoryInformationService;
use hap::service::doorbell::DoorbellService;
use hap::service::lock_mechanism::LockMechanismService;
use hap::service::switch::SwitchService;
use hap::service::HapService;
use hap::storage::{FileStorage, Storage};
use hap::{HapType, MacAddress, Pin};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use crate::agent_api::{AgentControl, CallAction, EventKind};
use crate::config::HapConfig;

const LOCK_SECURED: u8 = 1;
const LOCK_UNSECURED: u8 = 0;
const SINGLE_PRESS: u8 = 0;
/// The lock auto-relocks this long after a successful unlock.
const RELOCK_MS: u64 = 1_500;

/// A stable, locally-administered MAC derived from the serial number, so the
/// HomeKit identity is reproducible when pairing state is recreated.
fn device_id(serial: &str) -> MacAddress {
    let digest = Sha256::digest(format!("michoi-hap:{serial}").as_bytes());
    let mut mac = [0_u8; 6];
    mac.copy_from_slice(&digest[..6]);
    mac[0] = (mac[0] | 0x02) & 0xfe; // locally administered, unicast
    MacAddress::from(mac)
}

/// First usable IPv4, preferring `interface` when it is set and has one.
fn local_ipv4(interface: &str) -> Result<Ipv4Addr> {
    let usable = |ip: &Ipv4Addr| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified();
    let interfaces = if_addrs::get_if_addrs().context("enumerating interfaces")?;
    let pick = |want: Option<&str>| {
        interfaces.iter().find_map(|iface| match iface.ip() {
            IpAddr::V4(ip)
                if usable(&ip) && !iface.is_loopback() && want.is_none_or(|n| n == iface.name) =>
            {
                Some(ip)
            }
            _ => None,
        })
    };
    if !interface.is_empty() {
        if let Some(ip) = pick(Some(interface)) {
            return Ok(ip);
        }
        tracing::warn!(interface, "configured HAP interface has no IPv4; using the first usable one");
    }
    pick(None).context("no usable IPv4 interface for HomeKit")
}

/// The control-only accessory: information + doorbell + lock + elevator switch.
struct IntercomAccessory {
    id: u64,
    accessory_information: AccessoryInformationService,
    doorbell: DoorbellService,
    lock: LockMechanismService,
    elevator: SwitchService,
}

impl IntercomAccessory {
    fn new(id: u64, information: AccessoryInformation) -> Result<Self> {
        let accessory_information = information.to_service(1, id)?;
        // Optional information characteristics get non-contiguous IDs, so
        // continue after the highest one instead of counting.
        let mut next_iid = accessory_information
            .get_characteristics()
            .iter()
            .map(|c| c.get_id())
            .max()
            .unwrap_or(1)
            + 1;

        let mut doorbell = DoorbellService::new(next_iid, id);
        doorbell.set_primary(true);
        doorbell.brightness = None;
        doorbell.mute = None;
        doorbell.name = None;
        doorbell.operating_state_response = None;
        doorbell.volume = None;
        next_iid += 1 + doorbell.get_characteristics().len() as u64;

        let mut lock = LockMechanismService::new(next_iid, id);
        lock.name = None;
        next_iid += 1 + lock.get_characteristics().len() as u64;

        let elevator = SwitchService::new(next_iid, id);

        Ok(Self {
            id,
            accessory_information,
            doorbell,
            lock,
            elevator,
        })
    }
}

impl HapAccessory for IntercomAccessory {
    fn get_id(&self) -> u64 {
        self.id
    }

    fn set_id(&mut self, id: u64) {
        self.id = id;
    }

    fn get_service(&self, hap_type: HapType) -> Option<&dyn HapService> {
        self.get_services()
            .into_iter()
            .find(|service| service.get_type() == hap_type)
    }

    fn get_mut_service(&mut self, hap_type: HapType) -> Option<&mut dyn HapService> {
        self.get_mut_services()
            .into_iter()
            .find(|service| service.get_type() == hap_type)
    }

    fn get_services(&self) -> Vec<&dyn HapService> {
        vec![
            &self.accessory_information,
            &self.doorbell,
            &self.lock,
            &self.elevator,
        ]
    }

    fn get_mut_services(&mut self) -> Vec<&mut dyn HapService> {
        vec![
            &mut self.accessory_information,
            &mut self.doorbell,
            &mut self.lock,
            &mut self.elevator,
        ]
    }
}

impl Serialize for IntercomAccessory {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("HapAccessory", 2)?;
        state.serialize_field("aid", &self.get_id())?;
        state.serialize_field("services", &self.get_services())?;
        state.end()
    }
}

/// Monotonic idempotency keys for the commands this controller issues.
fn next_id(seq: &AtomicU32, kind: &str) -> String {
    format!("hap-{kind}-{}", seq.fetch_add(1, Ordering::Relaxed))
}

async fn set_lock_states(accessory: &hap::pointer::Accessory, current: u8, target: u8) {
    let mut guard = accessory.lock().await;
    let Some(lock) = guard.get_mut_service(HapType::LockMechanism) else {
        return;
    };
    if let Some(c) = lock.get_mut_characteristic(HapType::LockCurrentState) {
        let _ = c.set_value(json!(current)).await;
    }
    if let Some(t) = lock.get_mut_characteristic(HapType::LockTargetState) {
        let _ = t.set_value(json!(target)).await;
    }
}

async fn set_switch(accessory: &hap::pointer::Accessory, on: bool) {
    let mut guard = accessory.lock().await;
    if let Some(sw) = guard.get_mut_service(HapType::Switch) {
        if let Some(p) = sw.get_mut_characteristic(HapType::PowerState) {
            let _ = p.set_value(json!(on)).await;
        }
    }
}

/// Run the HAP server: build the accessory, pair, and drive the three services
/// against `agent` until the process exits.
pub async fn serve<A: AgentControl>(config: HapConfig, agent: Arc<A>) -> Result<()> {
    let local_ip = local_ipv4(&config.interface)?;
    let pin = Pin::new(config.pin_digits()?)?;

    let mut accessory = IntercomAccessory::new(
        1,
        AccessoryInformation {
            name: config.name.clone(),
            manufacturer: "michoi".into(),
            model: "michoi-agent".into(),
            serial_number: config.serial.clone(),
            firmware_revision: Some(env!("CARGO_PKG_VERSION").into()),
            ..Default::default()
        },
    )?;
    accessory
        .lock
        .lock_current_state
        .set_value(json!(LOCK_SECURED))
        .await?;
    accessory
        .lock
        .lock_target_state
        .set_value(json!(LOCK_SECURED))
        .await?;
    accessory.elevator.power_state.set_value(json!(false)).await?;
    // A visible service name so the Home tile reads "Elevator", not "Switch".
    if let Some(name) = accessory.elevator.name.as_mut() {
        name.set_value(json!("Elevator")).await?;
    }

    let mut storage = FileStorage::new(&config.storage).await?;
    let server_config = match storage.load_config().await {
        Ok(mut existing) => {
            existing.host = IpAddr::V4(local_ip);
            existing.port = config.port;
            existing.name = config.name.clone();
            existing.pin = pin;
            storage.save_config(&existing).await?;
            existing
        }
        Err(_) => {
            let fresh = hap::Config {
                host: IpAddr::V4(local_ip),
                port: config.port,
                pin,
                name: config.name.clone(),
                device_id: device_id(&config.serial),
                category: AccessoryCategory::Other,
                ..Default::default()
            };
            storage.save_config(&fresh).await?;
            fresh
        }
    };

    // Precompute SRP pair-setup material before advertising, so the first (and
    // usually only) pairing stays under HomeKit's timeout on the slow MT7628:
    // the M2 modexps run now, off the runtime, not during the live exchange.
    {
        let warm_pin = Pin::new(config.pin_digits()?)?;
        let _ = tokio::task::spawn_blocking(move || hap::precompute_pairing(&warm_pin)).await;
    }

    let server = IpServer::new(server_config, storage).await?;
    let accessory = server.add_accessory(accessory).await?;

    let cmd_seq = Arc::new(AtomicU32::new(1));
    let relock = Duration::from_millis(RELOCK_MS.max(500));

    // Unlock trigger: hap-rs offers only the JSON interface on the shared
    // accessory, so we react to LockTargetState changes by polling (the
    // vendored crate's own doorbell example does the same).
    {
        let poll = accessory.clone();
        let agent = agent.clone();
        let cmd_seq = cmd_seq.clone();
        tokio::spawn(async move {
            let mut last = LOCK_SECURED;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let current = {
                    let mut guard = poll.lock().await;
                    let Some(lock) = guard.get_mut_service(HapType::LockMechanism) else {
                        continue;
                    };
                    let Some(target) = lock.get_mut_characteristic(HapType::LockTargetState) else {
                        continue;
                    };
                    match target.get_value().await {
                        Ok(value) => value.as_u64().unwrap_or(LOCK_SECURED as u64) as u8,
                        Err(_) => continue,
                    }
                };
                if current == last {
                    continue;
                }
                last = current;
                if current != LOCK_UNSECURED {
                    continue;
                }
                tracing::info!("HomeKit unlock requested");
                // Engage: claim the ringing call (best effort — NotRinging when
                // idle is fine), which also makes the state machine allow the
                // unlock, then unlock.
                let _ = agent
                    .command(CallAction::Claim, &next_id(&cmd_seq, "claim"))
                    .await;
                let result = agent
                    .command(CallAction::Unlock, &next_id(&cmd_seq, "unlock"))
                    .await;
                let shown = if result.ok {
                    tracing::info!("door unlocked from HomeKit");
                    LOCK_UNSECURED
                } else {
                    tracing::warn!(error = ?result.error, "unlock rejected");
                    LOCK_SECURED
                };
                set_lock_states(&poll, shown, LOCK_UNSECURED).await;
                if result.ok {
                    tokio::time::sleep(relock).await;
                }
                set_lock_states(&poll, LOCK_SECURED, LOCK_SECURED).await;
                last = LOCK_SECURED;
            }
        });
    }

    // Elevator: a momentary Switch. Flipping it on calls the elevator to this
    // Pad's floor, then we flip it back off.
    {
        let poll = accessory.clone();
        let agent = agent.clone();
        let cmd_seq = cmd_seq.clone();
        tokio::spawn(async move {
            let mut last = false;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let on = {
                    let mut guard = poll.lock().await;
                    let Some(sw) = guard.get_mut_service(HapType::Switch) else {
                        continue;
                    };
                    let Some(power) = sw.get_mut_characteristic(HapType::PowerState) else {
                        continue;
                    };
                    match power.get_value().await {
                        Ok(value) => value.as_bool().unwrap_or(false),
                        Err(_) => continue,
                    }
                };
                if on && !last {
                    tracing::info!("HomeKit elevator call requested");
                    let result = agent
                        .call_elevator(&next_id(&cmd_seq, "elevator"), None)
                        .await;
                    if result.ok {
                        tracing::info!("elevator called");
                    } else {
                        tracing::warn!(error = ?result.error, "elevator call rejected");
                    }
                    set_switch(&poll, false).await;
                    last = false;
                } else {
                    last = on;
                }
            }
        });
    }

    // Doorbell: an incoming call raises a single press.
    {
        let ring = accessory.clone();
        let mut updates = agent.subscribe();
        tokio::spawn(async move {
            loop {
                match updates.recv().await {
                    Ok(event) => {
                        if !matches!(event.kind, EventKind::CallStarted { .. }) {
                            continue;
                        }
                        let mut guard = ring.lock().await;
                        if let Some(press) = guard
                            .get_mut_service(HapType::Doorbell)
                            .and_then(|s| s.get_mut_characteristic(HapType::ProgrammableSwitchEvent))
                        {
                            match press.set_value(json!(SINGLE_PRESS)).await {
                                Ok(()) => tracing::info!("doorbell press sent to HomeKit"),
                                Err(error) => tracing::warn!(%error, "doorbell event failed"),
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    tracing::info!(ip = %local_ip, port = config.port, "HAP server starting");
    println!("HomeKit setup code: {}", config.pin);
    println!(
        "HomeKit accessory \"{}\" on {}:{} (Lock + Elevator + Doorbell)",
        config.name, local_ip, config.port
    );
    server.run_handle().await?;
    Ok(())
}
