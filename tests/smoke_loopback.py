"""End-to-end smoke test for a service already running on loopback.

Run the service as documented in the README, then execute this file. It never
addresses the real intercom subnet.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import urllib.error
import urllib.request

from pad_intercom.pcap import read_udp
from pad_intercom.protocol import PenguinMessage, parse_messages


ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:18080"
TOKEN = "smoke-test-token"


def request(path: str, method: str = "GET") -> dict:
    separator = "&" if "?" in path else "?"
    with urllib.request.urlopen(
        urllib.request.Request(f"{BASE}{path}{separator}token={TOKEN}", method=method),
        timeout=2,
    ) as response:
        return json.load(response)


def receive_opcode(sock: socket.socket, opcode: int) -> PenguinMessage:
    while True:
        payload, _ = sock.recvfrom(65_535)
        for message in parse_messages(payload):
            if message.opcode == opcode:
                return message


def main() -> None:
    records = {record.frame_number: record for record in read_udp(ROOT / "testdata" / "pad.cap")}
    door = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    door.bind(("127.0.0.1", 10_000))
    door.settimeout(2)
    target = ("127.0.0.1", 11_000)

    # Incoming call setup, followed by one complete seven-fragment JPEG.
    door.sendto(records[18].payload, target)
    receive_opcode(door, 3)
    for frame_number in range(37, 44):
        door.sendto(records[frame_number].payload, target)
    state = request("/api/state")
    assert state["phase"] == "ringing", state
    assert state["video_frames"] == 1, state

    assert request("/api/answer", "POST")["ok"]
    receive_opcode(door, 5)
    assert request("/api/unlock", "POST")["ok"]
    receive_opcode(door, 6)
    assert request("/api/hangup", "POST")["ok"]
    receive_opcode(door, 0x1E)
    assert request("/api/state")["phase"] == "idle"

    try:
        urllib.request.urlopen(f"{BASE}/api/state?token=wrong", timeout=2)
    except urllib.error.HTTPError as exc:
        assert exc.code == 401
    else:
        raise AssertionError("web API accepted an invalid token")
    print("loopback smoke test: ok")


if __name__ == "__main__":
    main()
