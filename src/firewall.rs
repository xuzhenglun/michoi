use std::net::Ipv4Addr;

use anyhow::{Context, Result};

use crate::config::{CoexistenceMode, Config};

/// nftables bridge table the Agent owns. Removing it restores the physical
/// Pad path (fail-open), so the Agent flushes it on shutdown.
pub const TABLE: &str = "michoi";

/// Produce an atomic nftables table for the selected coexistence mode.
/// The rule matches the physical bridge ingress interface, so AF_PACKET frames
/// injected locally by the Agent are not mistaken for physical Pad traffic.
///
/// This is the *static* table printed by `nft-rules` and applied at start in
/// copy mode. First-answer silencing of the physical Pad is a separate,
/// dynamic step, see [`pad_silence_rules`].
pub fn nft_rules(config: &Config) -> Result<String> {
    let pad = &config.intercom.pad_interface;
    anyhow::ensure!(pad != "CONFIGURE_ME", "pad_interface is not configured");
    let room = config
        .intercom
        .room_ip
        .context("intercom.room_ip must be set to print static rules (the agent learns it at runtime)")?;
    let control = config.intercom.control_port;
    let discovery = config.intercom.discovery_port;
    let body = match config.coexistence.mode {
        CoexistenceMode::Manual => format!(
            "iifname \"{pad}\" ip saddr {room} udp dport {{ {control}, {discovery} }} counter drop"
        ),
        CoexistenceMode::Automatic => format!(
            "iifname \"{pad}\" ip saddr {room} udp dport {control} counter queue num {} bypass",
            config.coexistence.nfqueue
        ),
    };
    Ok(format!(
        "table bridge {TABLE} {{\n  chain forward {{\n    type filter hook forward priority -200; policy accept;\n    {body}\n  }}\n}}\n"
    ))
}

/// The dynamic table installed when a *remote* backend wins the call, so the
/// physical Pad is taken over: silenced and prevented from a late takeover.
///
/// The ring at the physical Pad is sustained by door→Pad session setup
/// (`00b7/01`) and the media stream, so two directions of UDP `control` are
/// dropped between the door station and the Pad:
///
/// * **door→Pad** (`iifname door_interface ip saddr door_ip`): stops the ring
///   and the picture at the physical Pad.
/// * **Pad→door** (`iifname pad_interface ip saddr room_ip`): stops the
///   physical Pad from injecting a competing answer/unlock after the remote
///   already owns the call.
///
/// The Agent still sees door→Pad media on the AF_PACKET RX path (the bridge
/// `forward` drop happens after capture), so it keeps relaying video and audio
/// to the remote owner. The owner's control and audio are injected by the
/// Agent as Pad→door frames that originate from the host, not from the
/// `pad_interface` ingress, so they are not matched by the Pad→door rule.
///
/// Discovery (`discovery_port`) is intentionally left alone so the Pad can
/// still be found on the LAN while a call is owned remotely.
pub fn pad_silence_rules(
    pad: &str,
    door: &str,
    door_ip: Ipv4Addr,
    room: Ipv4Addr,
    control: u16,
) -> Result<String> {
    anyhow::ensure!(pad != "CONFIGURE_ME", "pad_interface is not configured");
    anyhow::ensure!(door != "CONFIGURE_ME", "door_interface is not configured");
    Ok(format!(
        "table bridge {TABLE} {{\n  chain forward {{\n    type filter hook forward priority -200; policy accept;\n    \
iifname \"{door}\" ip saddr {door_ip} udp dport {control} counter drop\n    \
iifname \"{pad}\" ip saddr {room} udp dport {control} counter drop\n  }}\n}}\n"
    ))
}

/// The fail-open teardown, as an idempotent `nft -f` script: `add` ensures the
/// table exists so the following `delete` never errors on a fresh boot with no
/// residual table. The net effect is that the table is gone, and nft stays
/// silent instead of printing "No such file or directory".
pub fn flush_table_command() -> String {
    format!("add table bridge {TABLE}\ndelete table bridge {TABLE}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> Config {
        let mut config = Config::default();
        config.intercom.pad_interface = "eth0.1".into();
        config.intercom.door_interface = "eth0.2".into();
        config.intercom.room_ip = Some(Ipv4Addr::new(192, 168, 124, 61));
        config
    }

    fn silence() -> String {
        pad_silence_rules(
            "eth0.1",
            "eth0.2",
            Ipv4Addr::new(192, 168, 124, 2),
            Ipv4Addr::new(192, 168, 124, 61),
            10_000,
        )
        .unwrap()
    }

    #[test]
    fn manual_rule_is_interface_scoped() {
        let rules = nft_rules(&configured()).unwrap();
        assert!(rules.contains("iifname \"eth0.1\""));
        assert!(rules.contains("udp dport { 10000, 10008 }"));
        assert!(rules.contains("drop"));
    }

    #[test]
    fn pad_silence_drops_both_directions_of_control() {
        let rules = silence();
        // door -> Pad (silences the ring and picture)
        assert!(rules
            .contains("iifname \"eth0.2\" ip saddr 192.168.124.2 udp dport 10000 counter drop"));
        // Pad -> door (blocks a late physical takeover)
        assert!(rules
            .contains("iifname \"eth0.1\" ip saddr 192.168.124.61 udp dport 10000 counter drop"));
        // Discovery is left alone.
        assert!(!rules.contains("10008"));
    }

    #[test]
    fn silence_and_static_share_one_table() {
        assert!(silence().contains("table bridge michoi"));
        assert_eq!(
            flush_table_command(),
            "add table bridge michoi\ndelete table bridge michoi\n"
        );
    }
}
