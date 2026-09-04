use anyhow::Result;

use crate::config::{CoexistenceMode, Config};

/// Produce an atomic nftables table for the selected coexistence mode.
/// The rule matches the physical bridge ingress interface, so AF_PACKET frames
/// injected locally by the Agent are not mistaken for physical Pad traffic.
pub fn nft_rules(config: &Config) -> Result<String> {
    let pad = &config.intercom.pad_interface;
    anyhow::ensure!(pad != "CONFIGURE_ME", "pad_interface is not configured");
    let room = config.intercom.room_ip;
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
        "table bridge pad_gateway {{\n  chain forward {{\n    type filter hook forward priority -200; policy accept;\n    {body}\n  }}\n}}\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_rule_is_interface_scoped() {
        let mut config = Config::default();
        config.intercom.pad_interface = "eth0.1".into();
        let rules = nft_rules(&config).unwrap();
        assert!(rules.contains("iifname \"eth0.1\""));
        assert!(rules.contains("udp dport { 10000, 10008 }"));
        assert!(rules.contains("drop"));
    }
}
