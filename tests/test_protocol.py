from pathlib import Path
import struct
import unittest

from pad_intercom.analyze import analyze
from pad_intercom.pcap import read_udp
from pad_intercom.protocol import (
    DOOR_IP,
    DOOR_STATION,
    OP_ANSWER,
    OP_HANGUP,
    OP_UNLOCK,
    ROOM_IP,
    ROOM_STATION,
    SessionEndpoints,
    audio_message,
    bootstrap_reply,
    session_reply,
    session_control,
    split_coalesced,
)


ROOT = Path(__file__).resolve().parents[1]


class ProtocolTests(unittest.TestCase):
    def test_control_packets_match_capture_shape(self):
        endpoints = SessionEndpoints()
        for opcode in (OP_ANSWER, OP_UNLOCK, OP_HANGUP):
            packet = session_control(opcode, endpoints)
            self.assertEqual(len(packet), 80)
            self.assertEqual(packet[:8], b"PENGUIN0")
            self.assertEqual(struct.unpack_from("<I", packet, 10)[0], opcode)
            self.assertEqual(endpoints.door.station_id, DOOR_STATION)
            self.assertEqual(endpoints.door.ip, DOOR_IP)
            self.assertEqual(endpoints.room.station_id, ROOM_STATION)
            self.assertEqual(endpoints.room.ip, ROOM_IP)

    def test_split_gro_payload(self):
        endpoints = SessionEndpoints()
        one = session_control(OP_ANSWER, endpoints)
        two = session_control(OP_UNLOCK, endpoints)
        self.assertEqual(split_coalesced(one + two), [one, two])

    def test_supplied_capture(self):
        capture = ROOT / "testdata" / "pad.cap"
        if not capture.exists():
            self.skipTest("pad.cap is not present")
        report = analyze(capture)
        self.assertEqual(report["room_ids"], [ROOM_STATION])
        events = report["events"]
        answer = next(event for event in events if event["event"] == "answer")
        unlock = next(event for event in events if event["event"] == "unlock")
        room_hangup = next(
            event
            for event in events
            if event["event"] == "hangup" and event["source"].startswith(ROOM_IP)
        )
        self.assertEqual(answer["frame"], 919)
        self.assertEqual(unlock["frame"], 1296)
        self.assertEqual(room_hangup["frame"], 1985)
        self.assertEqual(report["jpeg_frames"], 230)

    def test_generated_replies_and_controls_match_capture_exactly(self):
        capture = ROOT / "testdata" / "pad.cap"
        if not capture.exists():
            self.skipTest("pad.cap is not present")
        wanted = {15, 21, 919, 1296, 1985}
        payloads = {
            record.frame_number: record.payload
            for record in read_udp(capture)
            if record.frame_number in wanted
        }
        endpoints = SessionEndpoints()
        self.assertEqual(bootstrap_reply(endpoints.room), payloads[15])
        self.assertEqual(session_reply(endpoints), payloads[21])
        self.assertEqual(session_control(OP_ANSWER, endpoints), payloads[919])
        self.assertEqual(session_control(OP_UNLOCK, endpoints), payloads[1296])
        self.assertEqual(session_control(OP_HANGUP, endpoints), payloads[1985])

        audio_record = next(record for record in read_udp(capture) if record.frame_number == 1150)
        from pad_intercom.protocol import PenguinMessage

        captured_audio = PenguinMessage.parse(audio_record.payload).media
        self.assertIsNotNone(captured_audio)
        self.assertEqual(
            audio_message(captured_audio.sequence, captured_audio.data, endpoints),
            audio_record.payload,
        )


if __name__ == "__main__":
    unittest.main()
