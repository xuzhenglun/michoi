# Test fixtures

- `pad.cap` — **not in git.** The packet capture of one PENGUIN0 door call is
  a private recording of the author's installation and is gitignored. Tests
  that need it (`builder_tests`, `tests/rust_protocol.rs`) skip when it is
  absent; `fake-agent`, `door` and the Python tools need it locally.
- `frames/` — the first 10 JPEG frames reconstructed from that capture, kept
  as a small fake camera for `emit-door --frames` and for RTP/JPEG
  (RFC 2435) compliance checks. The full 230-frame set is not committed.

Station IDs in code, docs and examples (`M00000000000`, `S00000000000`) are
synthetic placeholders. Pass your own with `--door-id` / `--room-id` or the
`[intercom]` config section.
