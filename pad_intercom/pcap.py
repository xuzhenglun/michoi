"""Small dependency-free classic-pcap/IPv4/UDP reader used by the analyzer."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import socket
import struct
from typing import Iterator


@dataclass(frozen=True)
class UdpRecord:
    frame_number: int
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    payload: bytes


def read_udp(path: str | Path) -> Iterator[UdpRecord]:
    with open(path, "rb") as capture:
        global_header = capture.read(24)
        if len(global_header) != 24:
            raise ValueError("short pcap global header")
        magic = global_header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian, scale = "<", 1_000_000
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian, scale = ">", 1_000_000
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian, scale = "<", 1_000_000_000
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian, scale = ">", 1_000_000_000
        else:
            raise ValueError("unsupported capture format (classic pcap required)")
        packet_header = struct.Struct(endian + "IIII")
        frame = 0
        first_timestamp: float | None = None
        while header := capture.read(packet_header.size):
            if len(header) != packet_header.size:
                raise ValueError("truncated pcap packet header")
            seconds, fraction, captured_length, _ = packet_header.unpack(header)
            raw = capture.read(captured_length)
            if len(raw) != captured_length:
                raise ValueError("truncated pcap packet")
            frame += 1
            timestamp = seconds + fraction / scale
            if first_timestamp is None:
                first_timestamp = timestamp
            record = _decode_udp(frame, timestamp - first_timestamp, raw)
            if record is not None:
                yield record


def _decode_udp(frame: int, timestamp: float, raw: bytes) -> UdpRecord | None:
    if len(raw) < 14 or raw[12:14] != b"\x08\x00":
        return None
    ip = raw[14:]
    if len(ip) < 20 or ip[9] != socket.IPPROTO_UDP:
        return None
    header_length = (ip[0] & 0x0F) * 4
    if header_length < 20 or len(ip) < header_length + 8:
        return None
    source_ip = socket.inet_ntoa(ip[12:16])
    destination_ip = socket.inet_ntoa(ip[16:20])
    udp = ip[header_length:]
    source_port, destination_port, udp_length, _ = struct.unpack_from("!HHHH", udp)
    # GRO captures can carry a length larger than an ordinary Ethernet MTU.
    payload = udp[8 : min(len(udp), udp_length)]
    return UdpRecord(
        frame,
        timestamp,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        payload,
    )
