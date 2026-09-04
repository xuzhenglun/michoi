"""Wire format recovered from ``pad.cap``.

The names used by the vendor are not known.  ``family`` and ``opcode`` are
therefore deliberately neutral terms.  All integer fields are little endian;
embedded IPv4 addresses are in network byte order.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import struct
from typing import Iterable


MAGIC = b"PENGUIN0"
CONTROL_PORT = 10_000
DISCOVERY_PORT = 10_008

ROOM_STATION = "S00000000000"
ROOM_IP = "192.168.124.61"
DOOR_STATION = "M00000000000"
DOOR_IP = "192.168.124.2"

FAMILY_BOOTSTRAP = 0x0098
FAMILY_SESSION = 0x00B7
FAMILY_SNAPSHOT_NAME = 0x009B
FAMILY_SNAPSHOT_DATA = 0x00B4

OP_REQUEST = 0x01
OP_REPLY = 0x03
OP_ANSWER = 0x05
OP_UNLOCK = 0x06
OP_MEDIA = 0x0A
OP_KEEPALIVE = 0x0C
OP_HANGUP = 0x1E

MEDIA_JPEG = 0x01
MEDIA_AUDIO = 0x03

_HEADER = struct.Struct("<8sHII14s")
_MEDIA_HEADER = struct.Struct("<HHHHH")
_ENDPOINT_SIZE = 24
_SESSION_ENVELOPE_SIZE = 80


@dataclass(frozen=True)
class Station:
    station_id: str
    ip: str

    def pack(self) -> bytes:
        station = self.station_id.encode("ascii")
        if len(station) > 20:
            raise ValueError("station ID is longer than 20 bytes")
        return station.ljust(20, b"\0") + ipaddress.ip_address(self.ip).packed

    @classmethod
    def unpack(cls, data: bytes) -> "Station":
        if len(data) < _ENDPOINT_SIZE:
            raise ValueError("short station endpoint")
        station_id = data[:20].split(b"\0", 1)[0].decode("ascii", "replace")
        return cls(station_id, str(ipaddress.ip_address(data[20:24])))


@dataclass(frozen=True)
class SessionEndpoints:
    door: Station = Station(DOOR_STATION, DOOR_IP)
    room: Station = Station(ROOM_STATION, ROOM_IP)

    def pack(self) -> bytes:
        return self.door.pack() + self.room.pack()

    @classmethod
    def unpack(cls, data: bytes) -> "SessionEndpoints":
        if len(data) < 48:
            raise ValueError("short session address block")
        return cls(Station.unpack(data[:24]), Station.unpack(data[24:48]))


@dataclass(frozen=True)
class MediaFragment:
    media_type: int
    sequence: int
    fragment_count: int
    fragment_index: int
    valid_length: int
    data: bytes


@dataclass(frozen=True)
class PenguinMessage:
    family: int
    opcode: int
    length_or_status: int
    reserved: bytes
    body: bytes
    raw: bytes

    @classmethod
    def parse(cls, raw: bytes) -> "PenguinMessage":
        if len(raw) < _HEADER.size:
            raise ValueError("short PENGUIN0 message")
        magic, family, opcode, length_or_status, reserved = _HEADER.unpack_from(raw)
        if magic != MAGIC:
            raise ValueError("not a PENGUIN0 message")
        return cls(family, opcode, length_or_status, reserved, raw[32:], raw)

    @property
    def endpoints(self) -> SessionEndpoints | None:
        if self.family != FAMILY_SESSION or len(self.body) < 48:
            return None
        return SessionEndpoints.unpack(self.body[:48])

    @property
    def media(self) -> MediaFragment | None:
        if self.family != FAMILY_SESSION or self.opcode != OP_MEDIA:
            return None
        if len(self.body) < 48 + _MEDIA_HEADER.size:
            return None
        fields = _MEDIA_HEADER.unpack_from(self.body, 48)
        valid_length = fields[4]
        start = 48 + _MEDIA_HEADER.size
        return MediaFragment(*fields, self.body[start : start + valid_length])


def pack_header(family: int, opcode: int, length_or_status: int, body: bytes = b"") -> bytes:
    return _HEADER.pack(MAGIC, family, opcode, length_or_status, b"\0" * 14) + body


def session_control(opcode: int, endpoints: SessionEndpoints) -> bytes:
    """Create the exact 80-byte session control datagram seen from the pad."""
    body = endpoints.pack()
    return pack_header(FAMILY_SESSION, opcode, _SESSION_ENVELOPE_SIZE, body)


def session_reply(endpoints: SessionEndpoints) -> bytes:
    # Response capability bytes are copied from frame 21.  They select VIDEOA
    # with the same codec/options accepted by the real room station.
    capabilities = b"VIDEOA\0\0" + struct.pack("<HHHH", 50, 9, 9, 255)
    body = endpoints.pack() + capabilities
    return pack_header(FAMILY_SESSION, OP_REPLY, 32 + len(body), body)


def audio_message(sequence: int, pcm_s16le: bytes, endpoints: SessionEndpoints) -> bytes:
    """Build one 8 kHz, mono, signed-16-bit little-endian audio message."""
    if len(pcm_s16le) != 512:
        raise ValueError("audio messages contain exactly 512 PCM bytes")
    media_header = _MEDIA_HEADER.pack(MEDIA_AUDIO, sequence & 0xFFFF, 1, 1, 512)
    body = endpoints.pack() + media_header + pcm_s16le
    return pack_header(FAMILY_SESSION, OP_MEDIA, 32 + len(body), body)


def bootstrap_reply(room: Station) -> bytes:
    """Reply to family 0x98/opcode 1 as observed in frame 15."""
    body = b"\x01\x00" + room.pack() + bytes(840)
    assert 32 + len(body) == 898
    return pack_header(FAMILY_BOOTSTRAP, 2, 898, body)


def discovery_reply(room_station: str) -> bytes:
    station = room_station.encode("ascii")
    if len(station) > 34:
        raise ValueError("room station ID is too long")
    return b"\x02" + station.ljust(34, b"\0")


def discovery_request_room(payload: bytes) -> str | None:
    if not payload or payload[0] != 1:
        return None
    return payload[1:].split(b"\0", 1)[0].decode("ascii", "replace")


def _logical_size(data: bytes) -> int | None:
    """Return one logical message size, including UDP-GRO coalesced captures."""
    if len(data) < _HEADER.size or not data.startswith(MAGIC):
        return None
    _, family, opcode, declared, _ = _HEADER.unpack_from(data)
    if family == FAMILY_SESSION and opcode == OP_MEDIA and len(data) >= 90:
        media_type = struct.unpack_from("<H", data, 80)[0]
        if media_type == MEDIA_JPEG:
            return 1290  # 80-byte envelope + 10-byte header + 1200-byte slot
        if media_type == MEDIA_AUDIO:
            return 602  # 80-byte envelope + 10-byte header + 512 PCM bytes
    if declared >= _HEADER.size:
        return declared
    # The door unit writes zero in this field for its keepalives and media.
    if family == FAMILY_SESSION and opcode == OP_KEEPALIVE:
        return 80
    return None


def split_coalesced(payload: bytes) -> list[bytes]:
    """Split logical messages merged by UDP generic receive offload.

    Real sockets normally receive one message at a time.  The supplied pcap has
    GRO records containing two to five adjacent PENGUIN0 messages.
    """
    messages: list[bytes] = []
    remaining = payload
    while remaining:
        if not remaining.startswith(MAGIC):
            marker = remaining.find(MAGIC)
            if marker < 0:
                break
            remaining = remaining[marker:]
        size = _logical_size(remaining)
        if size is None or size > len(remaining):
            # A standalone incoming datagram may have a zero/unknown length.
            next_marker = remaining.find(MAGIC, len(MAGIC))
            size = next_marker if next_marker >= 0 else len(remaining)
        messages.append(remaining[:size])
        remaining = remaining[size:]
    return messages


class JpegReassembler:
    """Reassemble out-of-order type-1 media fragments into JPEG frames."""

    def __init__(self) -> None:
        self._frames: dict[int, tuple[int, dict[int, bytes]]] = {}

    def push(self, fragment: MediaFragment) -> bytes | None:
        if fragment.media_type != MEDIA_JPEG:
            return None
        total, parts = self._frames.setdefault(
            fragment.sequence, (fragment.fragment_count, {})
        )
        if total != fragment.fragment_count:
            self._frames[fragment.sequence] = (fragment.fragment_count, {})
            total, parts = self._frames[fragment.sequence]
        parts[fragment.fragment_index] = fragment.data
        if len(parts) != total or any(i not in parts for i in range(1, total + 1)):
            self._discard_old(fragment.sequence)
            return None
        frame = b"".join(parts[i] for i in range(1, total + 1))
        del self._frames[fragment.sequence]
        self._discard_old(fragment.sequence)
        if not frame.startswith(b"\xff\xd8") or not frame.endswith(b"\xff\xd9"):
            return None
        return frame

    def _discard_old(self, current: int) -> None:
        if len(self._frames) <= 8:
            return
        for sequence in list(self._frames)[:-8]:
            if sequence != current:
                del self._frames[sequence]


def parse_messages(payload: bytes) -> Iterable[PenguinMessage]:
    for raw in split_coalesced(payload):
        try:
            yield PenguinMessage.parse(raw)
        except ValueError:
            continue
