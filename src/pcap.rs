use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::Ipv4Addr;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcapError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("unsupported or truncated classic pcap")]
    Format,
}

#[derive(Debug, Clone)]
pub struct UdpRecord {
    pub frame: u32,
    pub timestamp_micros: u64,
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: Vec<u8>,
}

pub fn read_udp(path: impl AsRef<Path>) -> Result<Vec<UdpRecord>, PcapError> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut global = [0_u8; 24];
    reader
        .read_exact(&mut global)
        .map_err(|_| PcapError::Format)?;
    let (little, scale): (bool, u64) = match &global[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, 1_000_000),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, 1_000_000),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, 1_000_000_000),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, 1_000_000_000),
        _ => return Err(PcapError::Format),
    };
    let u32_at = |v: &[u8]| {
        if little {
            u32::from_le_bytes(v.try_into().unwrap())
        } else {
            u32::from_be_bytes(v.try_into().unwrap())
        }
    };
    let mut first_ns = None;
    let mut frame = 0_u32;
    let mut records = Vec::new();
    loop {
        let mut header = [0_u8; 16];
        match reader.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(error.into()),
        }
        frame += 1;
        let seconds = u32_at(&header[..4]) as u64;
        let fraction = u32_at(&header[4..8]) as u64;
        let captured = u32_at(&header[8..12]) as usize;
        let mut raw = vec![0; captured];
        reader.read_exact(&mut raw).map_err(|_| PcapError::Format)?;
        let nanos = seconds * 1_000_000_000 + fraction * (1_000_000_000 / scale);
        let base = *first_ns.get_or_insert(nanos);
        if let Some(mut record) = decode_udp(frame, &raw) {
            record.timestamp_micros = (nanos - base) / 1_000;
            records.push(record);
        }
    }
    Ok(records)
}

fn decode_udp(frame: u32, raw: &[u8]) -> Option<UdpRecord> {
    if raw.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ether_type = u16::from_be_bytes([raw[12], raw[13]]);
    while matches!(ether_type, 0x8100 | 0x88a8) {
        if raw.len() < offset + 4 {
            return None;
        }
        ether_type = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
    }
    if ether_type != 0x0800 || raw.len() < offset + 20 {
        return None;
    }
    let ip = &raw[offset..];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 8 || ip[9] != 17 {
        return None;
    }
    let udp = &ip[ihl..];
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 {
        return None;
    }
    Some(UdpRecord {
        frame,
        timestamp_micros: 0,
        source_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        destination_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        source_port: u16::from_be_bytes([udp[0], udp[1]]),
        destination_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: udp[8..udp.len().min(udp_len)].to_vec(),
    })
}
