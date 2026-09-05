#![allow(warnings)]
// Vendored from https://github.com/ewilken/hap-rs (0.1.0-pre.15) with local patches:
// if-addrs instead of get_if_addrs, base64 tlv8/data values, /resource snapshots.
pub use ed25519_dalek::Keypair as Ed25519Keypair;
pub use futures;
pub use macaddr::MacAddr6 as MacAddress;
pub use serde_json;

pub use crate::{
    config::Config,
    error::Error,
    hap_type::HapType,
    pin::Pin,
    transport::bonjour::{BonjourFeatureFlag, BonjourStatusFlag},
};

mod config;
mod error;
mod event;
mod hap_type;
mod pin;
pub mod pointer;
mod tlv;
mod transport;

/// Definitions of HomeKit accessories.
pub mod accessory;
/// Definitions of HomeKit characteristics.
pub mod characteristic;
/// Representation of paired controllers.
pub mod pairing;
/// The HomeKit Accessory Server implementation.
pub mod server;
/// Definitions of HomeKit services.
pub mod service;
/// Representations of persistent storage.
pub mod storage;

/// Snapshot provider for the `/resource` image endpoint (pad-gateway patch).
pub mod snapshot {
    pub use crate::transport::http::handler::resource::{set_snapshot_provider, SnapshotProvider};
}

/// Precompute pair-setup (SRP M2) material for a pin so the first pairing stays
/// under the controller's timeout on a slow CPU (michoi patch). Call once at
/// startup, off the async runtime — it runs two 3072-bit modexps.
pub use crate::transport::http::handler::pair_setup::precompute as precompute_pairing;

/// `Result` type redefinition.
pub type Result<T> = std::result::Result<T, Error>;
