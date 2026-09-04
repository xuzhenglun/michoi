#!/usr/bin/env python3
"""Contract test for the Agent HTTP control plane (docs/openapi.yaml).

Standard library only. Run against a replay Agent:

    cargo run -- fake-agent --repeat-after 4 --http 127.0.0.1:8080 --token secret --events-lifetime 8
    python3 scripts/agent-http-test.py http://127.0.0.1:8080 --token secret

Checks: capability discovery, mandatory Accept / Content-Type negotiation,
bearer authentication, the claim -> unlock -> cooldown -> hangup flow with
idempotent replay, snapshot with X-Frame-Age-Ms, exclusive talk-back, media
info, the OpenAPI / Swagger endpoints, and the SSE feed including
Last-Event-ID resume. Exits non-zero on the first failure.
"""
import argparse
import http.client
import json
import socket
import sys
import threading
import time
import urllib.parse

JSON = "application/json"


class Client:
    def __init__(self, base, token):
        url = urllib.parse.urlparse(base)
        self.host, self.port = url.hostname, url.port or 80
        self.token = token

    def request(self, method, path, body=None, accept=JSON, content_type=None, auth=True, extra=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
        headers = {}
        if accept is not None:
            headers["Accept"] = accept
        if content_type is not None:
            headers["Content-Type"] = content_type
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if extra:
            headers.update(extra)
        data = None
        if body is not None:
            data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        payload = resp.read()
        conn.close()
        return resp.status, dict(resp.getheaders()), payload

    def json(self, method, path, body=None, **kw):
        status, headers, payload = self.request(method, path, body, content_type=JSON if body is not None else None, **kw)
        try:
            decoded = json.loads(payload) if payload else None
        except ValueError:
            decoded = payload
        return status, headers, decoded


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        raise SystemExit(1)


def sse_stream(client, seconds, last_event_id=None):
    """Collect SSE messages for `seconds`; returns (messages, closed_by_server)."""
    request = [f"GET /v1/events HTTP/1.1", f"Host: {client.host}:{client.port}", "Accept: text/event-stream"]
    if client.token:
        request.append(f"Authorization: Bearer {client.token}")
    if last_event_id is not None:
        request.append(f"Last-Event-ID: {last_event_id}")
    sock = socket.create_connection((client.host, client.port), timeout=5)
    sock.sendall(("\r\n".join(request) + "\r\n\r\n").encode())
    raw = b""
    while b"\r\n\r\n" not in raw:
        piece = sock.recv(4096)
        if not piece:
            raise SystemExit("event stream closed before headers")
        raw += piece
    head, raw = raw.split(b"\r\n\r\n", 1)
    status_line, *header_lines = head.decode().split("\r\n")
    status = int(status_line.split()[1])
    headers = {k.strip().lower(): v.strip() for k, v in (h.split(":", 1) for h in header_lines if ":" in h)}
    check(status == 200, f"events stream status {status}")
    check(headers.get("content-type", "").startswith("text/event-stream"), "events content type")
    chunked = "chunked" in headers.get("transfer-encoding", "")
    messages, closed, body = [], False, b""
    deadline = time.monotonic() + seconds
    sock.settimeout(0.5)
    while time.monotonic() < deadline:
        try:
            piece = sock.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            closed = True
            break
        if not piece:
            closed = True
            break
        raw += piece
        if chunked:
            # De-chunk whatever complete chunks we have.
            while True:
                line_end = raw.find(b"\r\n")
                if line_end < 0:
                    break
                size = int(raw[:line_end].split(b";")[0] or b"0", 16)
                if size == 0:
                    closed = True
                    raw = b""
                    break
                if len(raw) < line_end + 2 + size + 2:
                    break
                body += raw[line_end + 2:line_end + 2 + size]
                raw = raw[line_end + 2 + size + 2:]
            if closed:
                break
        else:
            body += raw
            raw = b""
        while b"\n\n" in body:
            block, body = body.split(b"\n\n", 1)
            msg = {}
            for line in block.decode().split("\n"):
                if line.startswith(":"):
                    msg.setdefault("comments", []).append(line[1:].strip())
                elif ":" in line:
                    key, value = line.split(":", 1)
                    msg[key] = value.strip()
            messages.append(msg)
    sock.close()
    return messages, closed


def wait_for(client, event_type, seconds):
    """Block until an event of `event_type` arrives on a fresh stream."""
    started = time.monotonic()
    while time.monotonic() - started < seconds:
        messages, _ = sse_stream(client, 3)
        for m in messages:
            if m.get("event") == event_type:
                return m
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base", nargs="?", default="http://127.0.0.1:8080")
    parser.add_argument("--token", default="")
    parser.add_argument("--sse-seconds", type=float, default=10.0, help="how long to hold the event stream")
    args = parser.parse_args()
    c = Client(args.base, args.token)

    # Discovery and negotiation
    status, _, info = c.json("GET", "/v1/")
    check(status == 200 and info["api_version"] == "1", f"GET /v1/ -> {status} api {info and info.get('api_version')}")
    check("application/json; v=1" in info["media_types"], "media types advertised")
    status, _, err = c.json("GET", "/v1/state", accept=None)
    check(status == 406 and err["error"] == "not_acceptable", "missing Accept -> 406")
    status, _, err = c.json("GET", "/v1/state", accept="application/cbor")
    check(status == 406, "unsupported Accept -> 406")
    status, headers, _ = c.request("GET", "/v1/state", accept="text/html;q=0.9, */*;q=0.1")
    check(status == 200 and headers.get("Content-Type", "").startswith("application/json"), "wildcard Accept honoured")
    status, _, err = c.request("POST", "/v1/call/claim", body=b'{"command_id":"x"}', content_type="text/plain")
    check(status == 415, "wrong Content-Type -> 415")
    if args.token:
        status, _, _ = c.json("GET", "/v1/state", auth=False)
        check(status == 401, "missing token -> 401")
    else:
        print("skip missing-token check (server runs without a token)")

    # Docs endpoints
    status, headers, payload = c.request("GET", "/openapi.yaml", accept="*/*", auth=False)
    check(status == 200 and payload.startswith(b"openapi: 3.1.0"), "GET /openapi.yaml")
    status, _, payload = c.request("GET", "/swagger", accept="text/html", auth=False)
    check(status in (200, 404), f"GET /swagger -> {status} ({'enabled' if status == 200 else 'disabled'})")

    # Media info and snapshot
    status, _, media = c.json("GET", "/v1/media")
    check(status == 200 and media["video"]["codec"] == "jpeg", "GET /v1/media")
    print(f"     history_ms={media['history_ms']} buffered_ms={media['buffered_ms']} rtsp={media['rtsp_url']}")

    # Call flow: wait for a ring, then claim / replay / unlock / cooldown / hangup
    print("waiting for call_started (needs --repeat-after on the Agent) ...")
    ring = wait_for(c, "call_started", 40)
    check(ring is not None, "call_started event received")
    ring_id = int(ring["id"])
    status, _, state = c.json("GET", "/v1/state")
    check(status == 200 and state["phase"] in ("ringing", "connected"), f"state after ring: {state['phase']}")
    cid = f"test-{int(time.time())}"
    status, _, result = c.json("POST", "/v1/call/claim", {"command_id": cid})
    check(status == 200 and result["ok"], f"claim -> {status} {result}")
    status, _, result = c.json("POST", "/v1/call/claim", {"command_id": cid})
    check(status == 200 and result.get("replayed") is True, "claim replayed from idempotency cache")
    status, _, result = c.json("POST", "/v1/call/unlock", {"command_id": cid + "-u1"})
    check(status == 200 and result["ok"], f"unlock -> {status}")
    status, _, result = c.json("POST", "/v1/call/unlock", {"command_id": cid + "-u2"})
    check(status == 429 and result["error"] == "unlock_cooldown", "second unlock inside cooldown -> 429")
    status, headers, payload = c.request("GET", "/v1/snapshot.jpg", accept="image/jpeg")
    check(status == 200 and payload[:2] == b"\xff\xd8", f"snapshot is a JPEG ({len(payload)} bytes)")
    check("X-Frame-Age-Ms" in headers, f"snapshot age header {headers.get('X-Frame-Age-Ms')} ms")

    # Exclusive talk-back: first upload streams, second is refused.
    def talk(duration, result):
        """Stream silence as chunked L16 for `duration` seconds; record the status."""
        head = ["POST /v1/talk HTTP/1.1", f"Host: {c.host}:{c.port}", "Accept: application/json",
                "Content-Type: audio/L16; rate=8000; channels=1", "Transfer-Encoding: chunked"]
        if c.token:
            head.append(f"Authorization: Bearer {c.token}")
        sock = socket.create_connection((c.host, c.port), timeout=10)
        sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode())
        end = time.monotonic() + duration
        chunk = b"\x00" * 512
        try:
            while time.monotonic() < end:
                sock.sendall(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                time.sleep(0.032)
            sock.sendall(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError):
            pass  # the server already answered (e.g. 409) and closed
        raw = b""
        try:
            while b"\r\n" not in raw:
                piece = sock.recv(4096)
                if not piece:
                    break
                raw += piece
        except OSError:
            pass
        sock.close()
        result.append(int(raw.split(b" ")[1]) if raw.startswith(b"HTTP/1.1 ") else None)

    first, second = [], []
    t1 = threading.Thread(target=talk, args=(2.0, first))
    t1.start()
    time.sleep(0.5)
    talk(0.3, second)
    t1.join()
    check(first == [204], f"talk upload accepted while owning the call -> {first}")
    check(second == [409], f"concurrent talk upload refused -> {second}")

    status, _, result = c.json("POST", "/v1/call/hangup", {"command_id": cid + "-h"})
    check(status == 200 and result["ok"], "hangup")
    status, _, result = c.json("POST", "/v1/call/unlock", {"command_id": cid + "-u3"})
    check(status == 409 and result["error"] in ("unlock_not_allowed", "not_ringing"), "unlock after hangup -> 409")

    # SSE: resume after the ring event must replay what followed it.
    messages, _ = sse_stream(c, 3, last_event_id=ring_id)
    ids = [int(m["id"]) for m in messages if "id" in m and m["id"] != "0"]
    check(ids and min(ids) == ring_id + 1, f"Last-Event-ID resume replays from {ring_id + 1} (got {ids[:4]})")
    kinds = {m.get("event") for m in messages}
    check("remote_answered" in kinds and "unlocked" in kinds, f"replayed events include our actions: {sorted(k for k in kinds if k)}")
    latest = max(ids)
    messages, _ = sse_stream(c, 2, last_event_id=latest)
    check(any("resumed" in x for m in messages for x in m.get("comments", [])) or not [m for m in messages if "id" in m], "resume at the newest id yields no replay")
    messages, closed = sse_stream(c, args.sse_seconds)
    check(messages and messages[0].get("event") == "snapshot", "fresh stream starts with a snapshot")
    if closed:
        print(f"     server closed the stream within {args.sse_seconds}s (events-lifetime in effect)")
    print("all checks passed")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
