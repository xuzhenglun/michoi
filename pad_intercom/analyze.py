"""Analyze the supplied capture and optionally extract its JPEG frames."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from .pcap import read_udp
from .protocol import (
    DISCOVERY_PORT,
    FAMILY_SESSION,
    JpegReassembler,
    MAGIC,
    MEDIA_AUDIO,
    OP_ANSWER,
    OP_HANGUP,
    OP_KEEPALIVE,
    OP_MEDIA,
    OP_REPLY,
    OP_UNLOCK,
    discovery_request_room,
    parse_messages,
)


OPCODE_NAMES = {
    OP_REPLY: "session-setup-reply",
    OP_ANSWER: "answer",
    OP_UNLOCK: "unlock",
    OP_MEDIA: "media",
    OP_KEEPALIVE: "keepalive",
    OP_HANGUP: "hangup",
}


def analyze(path: Path, extract: Path | None = None) -> dict[str, object]:
    counts: Counter[str] = Counter()
    events: list[dict[str, object]] = []
    room_ids: set[str] = set()
    jpeg = JpegReassembler()
    first_jpeg: float | None = None
    last_jpeg: float | None = None
    first_audio: float | None = None
    last_audio: float | None = None
    extracted = 0
    if extract is not None:
        extract.mkdir(parents=True, exist_ok=True)

    for record in read_udp(path):
        if record.destination_port == DISCOVERY_PORT and not record.payload.startswith(MAGIC):
            station = discovery_request_room(record.payload)
            if station:
                room_ids.add(station)
                events.append(_event(record, "discovery", station=station))
            continue
        for message in parse_messages(record.payload):
            key = f"0x{message.family:04x}/0x{message.opcode:02x}"
            counts[key] += 1
            if message.family != FAMILY_SESSION:
                continue
            if message.opcode in (OP_REPLY, OP_ANSWER, OP_UNLOCK, OP_HANGUP):
                events.append(
                    _event(record, OPCODE_NAMES[message.opcode], family=message.family)
                )
            media = message.media
            if media is None:
                continue
            if media.media_type == MEDIA_AUDIO:
                first_audio = record.timestamp if first_audio is None else first_audio
                last_audio = record.timestamp
                continue
            frame = jpeg.push(media)
            if frame is None:
                continue
            first_jpeg = record.timestamp if first_jpeg is None else first_jpeg
            last_jpeg = record.timestamp
            extracted += 1
            if extract is not None:
                (extract / f"frame-{extracted:04d}.jpg").write_bytes(frame)

    return {
        "capture": str(path),
        "room_ids": sorted(room_ids),
        "logical_message_counts": dict(sorted(counts.items())),
        "jpeg_frames": extracted,
        "jpeg_interval_seconds": [first_jpeg, last_jpeg],
        "audio_interval_seconds": [first_audio, last_audio],
        "events": events,
    }


def _event(record, name: str, **extra) -> dict[str, object]:
    return {
        "frame": record.frame_number,
        "time": round(record.timestamp, 6),
        "source": f"{record.source_ip}:{record.source_port}",
        "destination": f"{record.destination_ip}:{record.destination_port}",
        "event": name,
        **extra,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--extract-jpegs", type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture, args.extract_jpegs), indent=2))


if __name__ == "__main__":
    main()
