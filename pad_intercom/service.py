"""LAN replacement for the captured indoor intercom pad."""

from __future__ import annotations

import argparse
import base64
from collections import deque
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import socket
import ssl
import threading
import time
from urllib.parse import parse_qs, urlparse

from .protocol import (
    CONTROL_PORT,
    DISCOVERY_PORT,
    DOOR_IP,
    DOOR_STATION,
    FAMILY_BOOTSTRAP,
    FAMILY_SESSION,
    JpegReassembler,
    OP_ANSWER,
    OP_HANGUP,
    OP_KEEPALIVE,
    OP_MEDIA,
    OP_REPLY,
    OP_REQUEST,
    OP_UNLOCK,
    ROOM_IP,
    ROOM_STATION,
    SessionEndpoints,
    Station,
    bootstrap_reply,
    audio_message,
    discovery_reply,
    discovery_request_room,
    parse_messages,
    session_control,
    session_reply,
)


@dataclass
class PublicState:
    phase: str = "idle"
    caller_ip: str | None = None
    call_started_at: float | None = None
    answered_at: float | None = None
    last_unlock_at: float | None = None
    video_frames: int = 0
    audio_fragments: int = 0
    last_error: str | None = None


class Intercom:
    def __init__(
        self,
        listen_ip: str,
        endpoints: SessionEndpoints,
        expected_door_ip: str,
        unlock_cooldown: float = 1.0,
        control_port: int = CONTROL_PORT,
        door_port: int = CONTROL_PORT,
    ) -> None:
        self.listen_ip = listen_ip
        self.endpoints = endpoints
        self.expected_door_ip = expected_door_ip
        self.unlock_cooldown = unlock_cooldown
        self.control_port = control_port
        self.door_port = door_port
        self.state = PublicState()
        self._state_lock = threading.RLock()
        self._frame_condition = threading.Condition()
        self._jpeg = JpegReassembler()
        self._latest_frame: bytes | None = None
        self._frame_version = 0
        self._remote: tuple[str, int] | None = None
        self._running = threading.Event()
        self._control: socket.socket | None = None
        self._discovery: socket.socket | None = None
        self._last_setup_reply = 0.0
        self._audio_packets: deque[tuple[int, bytes]] = deque(maxlen=96)
        self._audio_version = 0
        self._outgoing_audio_sequence = 0

    def start(self) -> None:
        self._control = self._udp_socket(self.listen_ip, self.control_port)
        self._discovery = self._udp_socket("0.0.0.0", DISCOVERY_PORT)
        self._running.set()
        threading.Thread(target=self._receive_control, daemon=True).start()
        threading.Thread(target=self._receive_discovery, daemon=True).start()
        threading.Thread(target=self._keepalive_loop, daemon=True).start()

    def close(self) -> None:
        self._running.clear()
        for sock in (self._control, self._discovery):
            if sock is not None:
                sock.close()

    @staticmethod
    def _udp_socket(host: str, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((host, port))
        sock.settimeout(0.5)
        return sock

    def _receive_discovery(self) -> None:
        assert self._discovery is not None
        while self._running.is_set():
            try:
                payload, peer = self._discovery.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if peer[0] != self.expected_door_ip:
                continue
            requested = discovery_request_room(payload)
            if requested != self.endpoints.room.station_id:
                continue
            self._discovery.sendto(
                discovery_reply(self.endpoints.room.station_id),
                (peer[0], DISCOVERY_PORT),
            )

    def _receive_control(self) -> None:
        assert self._control is not None
        while self._running.is_set():
            try:
                payload, peer = self._control.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                return
            if peer[0] != self.expected_door_ip:
                continue
            for message in parse_messages(payload):
                self._handle_message(message, peer)

    def _handle_message(self, message, peer: tuple[str, int]) -> None:
        assert self._control is not None
        if message.family == FAMILY_BOOTSTRAP and message.opcode == OP_REQUEST:
            self._control.sendto(
                bootstrap_reply(self.endpoints.room), (peer[0], self.door_port)
            )
            return
        if message.family != FAMILY_SESSION:
            return
        if message.opcode == OP_REQUEST:
            incoming = message.endpoints
            if incoming is None or incoming.room.station_id != self.endpoints.room.station_id:
                return
            now = time.monotonic()
            self._remote = (peer[0], self.door_port)
            with self._state_lock:
                self.state.phase = "ringing"
                self.state.caller_ip = peer[0]
                self.state.call_started_at = time.time()
                self.state.answered_at = None
                self.state.last_unlock_at = None
                self.state.video_frames = 0
                self.state.audio_fragments = 0
            if now - self._last_setup_reply > 0.5:
                self._control.sendto(session_reply(self.endpoints), self._remote)
                self._last_setup_reply = now
            return
        if message.opcode == OP_HANGUP:
            with self._state_lock:
                was_active = self.state.phase != "idle"
                self.state.phase = "idle"
            if was_active:
                self._control.sendto(
                    session_control(OP_HANGUP, self.endpoints),
                    (peer[0], self.door_port),
                )
            self._remote = None
            return
        media = message.media
        if message.opcode != OP_MEDIA or media is None:
            return
        if media.media_type == 3:
            with self._state_lock:
                self.state.audio_fragments += 1
                self._audio_version += 1
                self._audio_packets.append((self._audio_version, media.data))
            return
        frame = self._jpeg.push(media)
        if frame is not None:
            with self._state_lock:
                self.state.video_frames += 1
            with self._frame_condition:
                self._latest_frame = frame
                self._frame_version += 1
                self._frame_condition.notify_all()

    def _keepalive_loop(self) -> None:
        while self._running.is_set():
            time.sleep(0.11)
            if not self._running.is_set():
                return
            remote = self._remote
            if remote is None or self._control is None:
                continue
            try:
                self._control.sendto(session_control(OP_KEEPALIVE, self.endpoints), remote)
            except OSError as exc:
                with self._state_lock:
                    self.state.last_error = str(exc)

    def answer(self) -> None:
        self._send_action(OP_ANSWER, allowed=("ringing",))
        with self._state_lock:
            self.state.phase = "connected"
            self.state.answered_at = time.time()

    def unlock(self) -> None:
        with self._state_lock:
            if self.state.phase != "connected":
                raise RuntimeError("unlock is allowed only after answering an active call")
            now = time.monotonic()
            last = getattr(self, "_last_unlock_monotonic", 0.0)
            if now - last < self.unlock_cooldown:
                raise RuntimeError("unlock cooldown is active")
            self._last_unlock_monotonic = now
        self._send_action(OP_UNLOCK, allowed=("connected",))
        with self._state_lock:
            self.state.last_unlock_at = time.time()

    def hangup(self) -> None:
        self._send_action(OP_HANGUP, allowed=("ringing", "connected"))
        with self._state_lock:
            self.state.phase = "idle"
        self._remote = None

    def audio_since(self, version: int) -> tuple[int, list[bytes]]:
        with self._state_lock:
            packets = [data for item_version, data in self._audio_packets if item_version > version]
            return self._audio_version, packets[-16:]

    def send_audio(self, pcm_s16le: bytes) -> None:
        with self._state_lock:
            if self.state.phase != "connected":
                raise RuntimeError("audio is allowed only during an answered call")
        if len(pcm_s16le) != 512:
            raise RuntimeError("audio body must be exactly 512 bytes")
        if self._control is None or self._remote is None:
            raise RuntimeError("there is no active door-station session")
        self._outgoing_audio_sequence = (self._outgoing_audio_sequence + 1) & 0xFFFF
        self._control.sendto(
            audio_message(self._outgoing_audio_sequence, pcm_s16le, self.endpoints),
            self._remote,
        )

    def _send_action(self, opcode: int, allowed: tuple[str, ...]) -> None:
        with self._state_lock:
            if self.state.phase not in allowed:
                raise RuntimeError(f"action is not valid while {self.state.phase}")
        if self._control is None or self._remote is None:
            raise RuntimeError("there is no active door-station session")
        self._control.sendto(session_control(opcode, self.endpoints), self._remote)

    def public_state(self) -> dict[str, object]:
        with self._state_lock:
            return asdict(self.state)

    def wait_for_frame(self, version: int, timeout: float = 10.0) -> tuple[int, bytes | None]:
        with self._frame_condition:
            self._frame_condition.wait_for(
                lambda: self._frame_version != version or not self._running.is_set(),
                timeout,
            )
            return self._frame_version, self._latest_frame


HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Room 11-03 intercom</title>
<style>
body{font:16px system-ui;background:#101418;color:#eef2f4;max-width:760px;margin:20px auto;padding:0 16px}
.panel{background:#1b2229;border-radius:14px;padding:16px;margin-bottom:14px}img{width:100%;aspect-ratio:4/3;object-fit:contain;background:#050607;border-radius:9px}
button{font:inherit;font-weight:650;padding:13px 18px;margin:6px;border:0;border-radius:9px;cursor:pointer}.answer{background:#4caf73}.unlock{background:#f3b544}.hangup{background:#e45c5c}code{color:#9bd1ff}
</style></head><body><h1>Room 11-03 intercom</h1><div class="panel"><div id="state">Connecting…</div></div>
<div class="panel"><img id="video" alt="Waiting for door camera"></div><div class="panel">
<button onclick="enableAlerts()">Enable call alerts</button><button class="answer" onclick="answer()">Answer + audio</button><button class="unlock" onclick="act('unlock')">Unlock</button><button class="hangup" onclick="act('hangup')">Hang up</button><p id="result"></p></div>
<script>
const token=new URLSearchParams(location.search).get('token')||'';
let audioCtx=null,alertCtx=null,nextPlay=0,audioVersion=0,pcmOut=[],previousPhase='idle';
document.querySelector('#video').src='/stream.mjpg?token='+encodeURIComponent(token);
async function enableAlerts(){if('Notification'in window)await Notification.requestPermission();alertCtx=alertCtx||new AudioContext();await alertCtx.resume();document.querySelector('#result').textContent='Call alerts enabled while this page is open'}
function ring(){if(Notification.permission==='granted')new Notification('Door intercom',{body:'Incoming call for room 11-03'});if(alertCtx){let o=alertCtx.createOscillator(),g=alertCtx.createGain();o.frequency.value=740;g.gain.value=.08;o.connect(g);g.connect(alertCtx.destination);o.start();o.stop(alertCtx.currentTime+.35)}}
async function refresh(){try{let r=await fetch('/api/state?token='+encodeURIComponent(token));let s=await r.json();document.querySelector('#state').textContent=`${s.phase} · video ${s.video_frames} frames · audio ${s.audio_fragments} fragments`;if(s.phase==='ringing'&&previousPhase!=='ringing')ring();previousPhase=s.phase;}catch(e){}setTimeout(refresh,500)}
async function act(name){let r=await fetch('/api/'+name+'?token='+encodeURIComponent(token),{method:'POST'});let x=await r.json();document.querySelector('#result').textContent=x.ok?'Sent '+name:x.error;refresh();return x.ok}
async function answer(){if(await act('answer')) await startAudio()}
function bytesToBase64(bytes){let s='';for(let b of bytes)s+=String.fromCharCode(b);return btoa(s)}
async function startAudio(){
  if(audioCtx)return; audioCtx=new AudioContext(); nextPlay=audioCtx.currentTime+.1;
  try{
    const stream=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true},video:false});
    const source=audioCtx.createMediaStreamSource(stream),node=audioCtx.createScriptProcessor(2048,1,1),ratio=audioCtx.sampleRate/8000;
    node.onaudioprocess=e=>{const input=e.inputBuffer.getChannelData(0);for(let pos=0;pos<input.length;pos+=ratio){let end=Math.min(input.length,Math.floor(pos+ratio)),sum=0,n=0;for(let i=Math.floor(pos);i<end;i++){sum+=input[i];n++}let v=Math.max(-1,Math.min(1,sum/Math.max(1,n))),s=v<0?v*32768:v*32767,q=Math.round(s);pcmOut.push(q&255,(q>>8)&255)}while(pcmOut.length>=512){let chunk=new Uint8Array(pcmOut.splice(0,512));fetch('/api/audio?token='+encodeURIComponent(token),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pcm:bytesToBase64(chunk)})})}};
    source.connect(node);node.connect(audioCtx.destination);
  }catch(e){document.querySelector('#result').textContent='Receive audio enabled; microphone unavailable: '+e}
  pollAudio();
}
async function pollAudio(){if(!audioCtx)return;try{let r=await fetch('/api/audio?after='+audioVersion+'&token='+encodeURIComponent(token)),x=await r.json();audioVersion=x.version;for(let encoded of x.packets){let raw=atob(encoded),samples=raw.length/2,buf=audioCtx.createBuffer(1,samples,8000),out=buf.getChannelData(0);for(let i=0;i<samples;i++){let v=raw.charCodeAt(i*2)|(raw.charCodeAt(i*2+1)<<8);if(v&0x8000)v-=0x10000;out[i]=v/32768}let src=audioCtx.createBufferSource();src.buffer=buf;src.connect(audioCtx.destination);let when=Math.max(audioCtx.currentTime+.04,nextPlay);src.start(when);nextPlay=when+samples/8000}}catch(e){}setTimeout(pollAudio,60)}
refresh();
</script></body></html>"""


class WebHandler(BaseHTTPRequestHandler):
    server: "WebServer"

    def _authorized(self) -> bool:
        query = parse_qs(urlparse(self.path).query)
        supplied = query.get("token", [""])[0]
        bearer = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return secrets.compare_digest(supplied or bearer, self.server.token)

    def do_GET(self) -> None:
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid token"})
            return
        path = urlparse(self.path).path
        if path == "/":
            body = HTML.encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/state":
            self._json(HTTPStatus.OK, self.server.intercom.public_state())
        elif path == "/api/audio":
            query = parse_qs(urlparse(self.path).query)
            try:
                after = int(query.get("after", ["0"])[0])
            except ValueError:
                after = 0
            version, packets = self.server.intercom.audio_since(after)
            self._json(
                HTTPStatus.OK,
                {
                    "version": version,
                    "packets": [base64.b64encode(packet).decode() for packet in packets],
                },
            )
        elif path == "/stream.mjpg":
            self._stream()
        else:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid token"})
            return
        action = urlparse(self.path).path.removeprefix("/api/")
        if action == "audio":
            self._post_audio()
            return
        methods = {
            "answer": self.server.intercom.answer,
            "unlock": self.server.intercom.unlock,
            "hangup": self.server.intercom.hangup,
        }
        if action not in methods:
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            methods[action]()
        except RuntimeError as exc:
            self._json(HTTPStatus.CONFLICT, {"ok": False, "error": str(exc)})
        else:
            self._json(HTTPStatus.OK, {"ok": True})

    def _post_audio(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 4096:
                raise ValueError("request is too large")
            value = json.loads(self.rfile.read(length))
            pcm = base64.b64decode(value["pcm"], validate=True)
            self.server.intercom.send_audio(pcm)
        except (ValueError, KeyError, json.JSONDecodeError, RuntimeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        else:
            self._json(HTTPStatus.OK, {"ok": True})

    def _stream(self) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        version = -1
        try:
            while True:
                version, frame = self.server.intercom.wait_for_frame(version)
                if frame is None:
                    continue
                self.wfile.write(
                    b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                    + str(len(frame)).encode()
                    + b"\r\n\r\n"
                    + frame
                    + b"\r\n"
                )
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return

    def _json(self, status: HTTPStatus, value: object) -> None:
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class WebServer(ThreadingHTTPServer):
    def __init__(self, address, intercom: Intercom, token: str):
        self.intercom = intercom
        self.token = token
        super().__init__(address, WebHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-ip", default=ROOM_IP, help="local IP replacing the pad")
    parser.add_argument("--door-ip", default=DOOR_IP)
    parser.add_argument("--control-port", type=int, default=CONTROL_PORT, help=argparse.SUPPRESS)
    parser.add_argument("--door-port", type=int, default=CONTROL_PORT, help=argparse.SUPPRESS)
    parser.add_argument("--room-id", default=ROOM_STATION)
    parser.add_argument("--door-id", default=DOOR_STATION)
    parser.add_argument("--http-host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--tls-cert", help="PEM certificate for direct HTTPS")
    parser.add_argument("--tls-key", help="PEM private key for direct HTTPS")
    parser.add_argument("--token", help="web access token (random if omitted)")
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be supplied together")
    token = args.token or secrets.token_urlsafe(24)
    endpoints = SessionEndpoints(
        Station(args.door_id, args.door_ip), Station(args.room_id, args.listen_ip)
    )
    intercom = Intercom(
        args.listen_ip,
        endpoints,
        args.door_ip,
        control_port=args.control_port,
        door_port=args.door_port,
    )
    try:
        intercom.start()
    except OSError as exc:
        parser.error(
            f"cannot bind the captured room IP {args.listen_ip}: {exc}. "
            "Disconnect the original pad and assign that address to this host first."
        )
    server = WebServer((args.http_host, args.http_port), intercom, token)
    if args.tls_cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    shown_host = "<server-ip>" if args.http_host == "0.0.0.0" else args.http_host
    scheme = "https" if args.tls_cert else "http"
    print(f"Intercom UI: {scheme}://{shown_host}:{args.http_port}/?token={token}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        intercom.close()


if __name__ == "__main__":
    main()
