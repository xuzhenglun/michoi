use std::net::Ipv4Addr;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EthernetError {
    #[error("MAC address must be six hexadecimal octets")]
    Mac,
    #[error("Ethernet/IPv4/UDP frame is truncated or unsupported")]
    Frame,
    #[error("UDP payload is too large")]
    TooLarge,
}

impl MacAddress {
    pub fn parse(text: &str) -> Result<Self, EthernetError> {
        let mut out = [0_u8; 6];
        let mut parts = text.split(':');
        for octet in &mut out {
            let value = parts.next().ok_or(EthernetError::Mac)?;
            if value.len() != 2 {
                return Err(EthernetError::Mac);
            }
            *octet = u8::from_str_radix(value, 16).map_err(|_| EthernetError::Mac)?;
        }
        if parts.next().is_some() {
            return Err(EthernetError::Mac);
        }
        Ok(Self(out))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EthernetUdp<'a> {
    pub source_mac: MacAddress,
    pub destination_mac: MacAddress,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}

impl<'a> EthernetUdp<'a> {
    pub fn parse(frame: &'a [u8]) -> Result<Self, EthernetError> {
        if frame.len() < 14 {
            return Err(EthernetError::Frame);
        }
        let mut offset = 14;
        let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
        while matches!(ether_type, 0x8100 | 0x88a8) {
            if frame.len() < offset + 4 {
                return Err(EthernetError::Frame);
            }
            ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
            offset += 4;
        }
        if ether_type != 0x0800 || frame.len() < offset + 28 {
            return Err(EthernetError::Frame);
        }
        let ip = &frame[offset..];
        if ip[0] >> 4 != 4 || ip[9] != 17 {
            return Err(EthernetError::Frame);
        }
        let ihl = usize::from(ip[0] & 0x0f) * 4;
        if ihl < 20 || ip.len() < ihl + 8 {
            return Err(EthernetError::Frame);
        }
        let udp = &ip[ihl..];
        let udp_length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if udp_length < 8 || udp.len() < udp_length {
            return Err(EthernetError::Frame);
        }
        Ok(Self {
            destination_mac: MacAddress(frame[..6].try_into().unwrap()),
            source_mac: MacAddress(frame[6..12].try_into().unwrap()),
            source_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
            destination_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
            source_port: u16::from_be_bytes([udp[0], udp[1]]),
            destination_port: u16::from_be_bytes([udp[2], udp[3]]),
            payload: &udp[8..udp_length],
        })
    }
}

pub fn build_udp_ipv4(
    source_mac: MacAddress,
    destination_mac: MacAddress,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    identification: u16,
) -> Result<Vec<u8>, EthernetError> {
    let udp_length = 8_usize
        .checked_add(payload.len())
        .ok_or(EthernetError::TooLarge)?;
    let ip_length = 20_usize
        .checked_add(udp_length)
        .ok_or(EthernetError::TooLarge)?;
    if ip_length > u16::MAX as usize {
        return Err(EthernetError::TooLarge);
    }
    let mut out = vec![0_u8; 14 + ip_length];
    out[..6].copy_from_slice(&destination_mac.0);
    out[6..12].copy_from_slice(&source_mac.0);
    out[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = &mut out[14..];
    ip[0] = 0x45;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&(ip_length as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&identification.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&source_ip.octets());
    ip[16..20].copy_from_slice(&destination_ip.octets());
    let checksum = internet_checksum(&ip[..20]);
    ip[10..12].copy_from_slice(&checksum.to_be_bytes());
    let udp = &mut ip[20..];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_length as u16).to_be_bytes());
    // IPv4 permits zero UDP checksum. This matches the least restrictive
    // receiver behavior and avoids inventing undocumented appliance quirks.
    udp[6..8].copy_from_slice(&0_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    Ok(out)
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in data.chunks(2) {
        let word = if pair.len() == 2 {
            u16::from_be_bytes([pair[0], pair[1]])
        } else {
            u16::from(pair[0]) << 8
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_parseable_frame() {
        let source = MacAddress::parse("02:00:00:00:00:3d").unwrap();
        let destination = MacAddress::parse("02:00:00:00:00:02").unwrap();
        let frame = build_udp_ipv4(
            source,
            destination,
            Ipv4Addr::new(192, 168, 124, 61),
            Ipv4Addr::new(192, 168, 124, 2),
            10_000,
            10_000,
            b"PENGUIN0",
            7,
        )
        .unwrap();
        let parsed = EthernetUdp::parse(&frame).unwrap();
        assert_eq!(parsed.source_mac, source);
        assert_eq!(parsed.destination_mac, destination);
        assert_eq!(parsed.payload, b"PENGUIN0");
    }
}
