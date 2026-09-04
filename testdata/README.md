# Test fixtures

- `pad.cap` — the packet capture of one PENGUIN0 door call that every parser
  test, the fake Agent and the pcap replay Agent use. Room station
  `S00000000000`, door station `M00000000000`.
- `frames/` — the 230 JPEG frames reconstructed from that capture, used for
  inspecting the door image and for RTP/JPEG (RFC 2435) compliance checks.
