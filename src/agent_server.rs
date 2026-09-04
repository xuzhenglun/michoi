//! HTTP/1.1 control plane of an Agent (`docs/openapi.yaml`).
//!
//! A deliberately small, dependency-free server: REST for commands, a
//! Server-Sent Events stream for the downstream feed, strict `Accept` /
//! `Content-Type` negotiation, bearer-token authentication, and optional
//! `/openapi.yaml` + `/swagger` endpoints for testing. It serves any
//! `AgentControl + AgentMedia` implementation, so the live capture Agent and
//! the pcap replay expose exactly the same API.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::agent_api::{
    AgentControl, AgentMedia, ApiInfo, AudioChunk, CallAction, CommandRequest, EventKind,
    API_VERSION, MEDIA_TYPE_EVENTS, MEDIA_TYPE_JPEG, MEDIA_TYPE_JSON, MEDIA_TYPE_L16,
};

/// The OpenAPI document, embedded so `/openapi.yaml` always matches the
/// binary.
pub const OPENAPI_YAML: &str = include_str!("../docs/openapi.yaml");

/// The browser Pad, a single self-contained page served at `/pad`.
pub const PAD_HTML: &str = include_str!("../web/pad.html");

const MEDIA_TYPE_MJPEG: &str = "multipart/x-mixed-replace; boundary=frame";

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const HEARTBEAT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: SocketAddr,
    /// Bearer token; `None` disables authentication (development only).
    pub token: Option<String>,
    /// Serve `/swagger` (Swagger UI loaded from a CDN).
    pub swagger: bool,
    /// Range after which an event stream is closed so clients reconnect.
    pub event_stream_lifetime: (Duration, Duration),
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8080".parse().unwrap(),
            token: None,
            swagger: false,
            event_stream_lifetime: (Duration::from_secs(300), Duration::from_secs(600)),
        }
    }
}

/// Only one talk-back upload may run at a time; a second caller is told
/// the slot is busy instead of having its audio interleaved with the first.
static TALK_BUSY: AtomicBool = AtomicBool::new(false);

pub async fn serve<A: AgentControl + AgentMedia>(
    config: ServerConfig,
    agent: Arc<A>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding control plane on {}", config.listen))?;
    tracing::info!(
        listen = %config.listen,
        auth = config.token.is_some(),
        swagger = config.swagger,
        "Agent control plane listening"
    );
    if config.token.is_none() {
        tracing::warn!("control plane runs without a bearer token; development only");
    }
    let config = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let config = config.clone();
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(error) = connection(stream, peer, config, agent).await {
                tracing::debug!(%peer, %error, "control plane connection ended");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    keep_alive: bool,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// First value of a query parameter, percent-decoded for the common cases.
    fn query_param(&self, name: &str) -> Option<String> {
        self.query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| v.replace("%3D", "=").replace("%2B", "+").replace('+', " "))
        })
    }
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), content_type.into())],
            body,
        }
    }

    fn json<T: Serialize>(status: u16, value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self::new(status, MEDIA_TYPE_JSON, body)
    }

    fn error(status: u16, error: &str, message: impl Into<String>) -> Self {
        Self::json(
            status,
            &serde_json::json!({ "error": error, "message": message.into() }),
        )
    }

    fn negotiation(status: u16, error: &str, supported: &[&str]) -> Self {
        Self::json(
            status,
            &serde_json::json!({ "error": error, "supported": supported }),
        )
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

async fn read_request(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
) -> Result<Option<Request>> {
    let mut head = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(IDLE_TIMEOUT, reader.read(&mut byte))
            .await
            .context("idle timeout")??;
        if read == 0 {
            return Ok(None);
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        anyhow::ensure!(head.len() <= MAX_HEAD, "request head too large");
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().context("empty request")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing method")?.to_owned();
    let target = parts.next().context("missing target")?;
    let version = parts.next().unwrap_or("HTTP/1.1");
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target.to_owned(), String::new()),
    };
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    let connection = headers
        .iter()
        .find(|(k, _)| k == "connection")
        .map(|(_, v)| v.to_ascii_lowercase());
    let keep_alive = match connection.as_deref() {
        Some("close") => false,
        Some("keep-alive") => true,
        _ => version == "HTTP/1.1",
    };
    let mut request = Request {
        method,
        path,
        query,
        headers,
        body: Vec::new(),
        keep_alive,
    };
    // curl and friends wait for this before sending a chunked body.
    if request
        .header("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    {
        writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        writer.flush().await?;
    }
    // Bodies other than the streaming talk upload are read here in full.
    if request.path != "/v1/talk" {
        if let Some(length) = request.header("content-length") {
            let length: usize = length.parse().context("bad content-length")?;
            anyhow::ensure!(length <= MAX_BODY, "body too large");
            let mut body = vec![0_u8; length];
            reader.read_exact(&mut body).await?;
            request.body = body;
        } else if request
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            request.body = read_chunked(reader, MAX_BODY).await?;
        }
    }
    Ok(Some(request))
}

async fn read_chunked(reader: &mut BufReader<OwnedReadHalf>, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let size = read_chunk_size(reader).await?;
        if size == 0 {
            // Trailer section ends with an empty line.
            loop {
                let line = read_line(reader).await?;
                if line.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        anyhow::ensure!(body.len() + size <= limit, "body too large");
        let mut chunk = vec![0_u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);
        let _ = read_line(reader).await?; // CRLF after the chunk
    }
}

async fn read_line(reader: &mut BufReader<OwnedReadHalf>) -> Result<String> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = reader.read(&mut byte).await?;
        anyhow::ensure!(read == 1, "connection closed inside chunked body");
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(String::from_utf8_lossy(&line).into_owned());
        }
        anyhow::ensure!(line.len() <= 1024, "chunk line too long");
    }
}

async fn read_chunk_size(reader: &mut BufReader<OwnedReadHalf>) -> Result<usize> {
    let line = read_line(reader).await?;
    let size = line.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(size, 16).context("bad chunk size")
}

async fn write_response(
    stream: &mut OwnedWriteHalf,
    response: &Response,
    keep_alive: bool,
) -> Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Negotiation and authentication
// ---------------------------------------------------------------------------

/// Media type without parameters, lower-cased.
fn media_base(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Pick the first offered type acceptable to the client, honouring q values.
fn negotiate<'a>(accept: Option<&str>, offered: &[&'a str]) -> Option<&'a str> {
    let accept = accept?;
    let mut candidates: Vec<(f32, usize, String)> = Vec::new();
    for (index, item) in accept.split(',').enumerate() {
        let mut parts = item.split(';');
        let base = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        if base.is_empty() {
            continue;
        }
        let mut q = 1.0_f32;
        for param in parts {
            if let Some((k, v)) = param.split_once('=') {
                if k.trim().eq_ignore_ascii_case("q") {
                    q = v.trim().parse().unwrap_or(0.0);
                }
            }
        }
        if q > 0.0 {
            candidates.push((q, index, base));
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap().then(a.1.cmp(&b.1)));
    for (_, _, wanted) in candidates {
        for offer in offered {
            let base = media_base(offer);
            let matches = wanted == base
                || wanted == "*/*"
                || wanted
                    .strip_suffix("/*")
                    .is_some_and(|prefix| base.starts_with(&format!("{prefix}/")));
            if matches {
                return Some(offer);
            }
        }
    }
    None
}

fn require_accept<'a>(request: &Request, offered: &[&'a str]) -> Result<&'a str, Response> {
    negotiate(request.header("accept"), offered)
        .ok_or_else(|| Response::negotiation(406, "not_acceptable", offered))
}

fn require_content_type(request: &Request, expected: &str) -> Result<(), Response> {
    match request.header("content-type") {
        Some(value) if media_base(value) == media_base(expected) => Ok(()),
        _ => Err(Response::negotiation(
            415,
            "unsupported_media_type",
            &[expected],
        )),
    }
}

/// Bearer header, or `?token=` for clients that cannot set headers
/// (`EventSource`, `<img>`, `<audio>`, WebSocket).
fn authorized(request: &Request, token: Option<&str>) -> bool {
    let Some(token) = token else { return true };
    let from_header = request
        .header("authorization")
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .is_some_and(|presented| presented.trim() == token);
    from_header || request.query_param("token").is_some_and(|t| t == token)
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

async fn connection<A: AgentControl + AgentMedia>(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<ServerConfig>,
    agent: Arc<A>,
) -> Result<()> {
    let (read_half, mut writer) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    loop {
        let request = match read_request(&mut reader, &mut writer).await? {
            Some(request) => request,
            None => return Ok(()),
        };
        tracing::debug!(%peer, method = %request.method, path = %request.path, "request");
        let public = matches!(
            request.path.as_str(),
            "/openapi.yaml" | "/swagger" | "/" | "/pad"
        );
        if !public && !authorized(&request, config.token.as_deref()) {
            let response = Response::error(401, "unauthorized", "bearer token required")
                .header("WWW-Authenticate", "Bearer");
            write_response(&mut writer, &response, false).await?;
            return Ok(());
        }
        if request.method == "GET" && request.path == "/v1/events" {
            return events_stream(&mut reader, &mut writer, &request, &config, agent.as_ref())
                .await;
        }
        if request.method == "POST" && request.path == "/v1/talk" {
            // Streaming upload: consumed chunk by chunk from the connection.
            let response = talk_upload(&mut reader, &request, agent.as_ref()).await?;
            write_response(&mut writer, &response, false).await?;
            return Ok(());
        }
        if request.method == "GET" && request.path == "/v1/stream.mjpeg" {
            return mjpeg_stream(&mut reader, &mut writer, &request, agent.as_ref()).await;
        }
        if request.method == "GET" && request.path == "/v1/audio.pcm" {
            return pcm_stream(&mut reader, &mut writer, &request, agent.as_ref()).await;
        }
        if request.method == "GET" && request.path == "/v1/talk.ws" {
            return talk_websocket(reader, writer, &request, agent).await;
        }
        let response = route(&request, &config, agent.as_ref()).await;
        let keep_alive = request.keep_alive;
        write_response(&mut writer, &response, keep_alive).await?;
        if !keep_alive {
            return Ok(());
        }
    }
}

async fn route<A: AgentControl + AgentMedia>(
    request: &Request,
    config: &ServerConfig,
    agent: &A,
) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/openapi.yaml") => Response::new(200, "application/yaml", OPENAPI_YAML.into()),
        ("GET", "/") | ("GET", "/pad") => {
            Response::new(200, "text/html; charset=utf-8", PAD_HTML.into())
                .header("Cache-Control", "no-cache")
        }
        ("GET", "/swagger") => {
            if config.swagger {
                Response::new(200, "text/html; charset=utf-8", SWAGGER_HTML.into())
            } else {
                Response::error(404, "not_found", "Swagger UI is disabled on this server")
            }
        }
        ("GET", "/v1/") | ("GET", "/v1") => match require_accept(request, &[MEDIA_TYPE_JSON]) {
            Ok(_) => Response::json(
                200,
                &ApiInfo {
                    api_version: API_VERSION.into(),
                    agent_id: agent.agent_id(),
                    media_types: vec![
                        MEDIA_TYPE_JSON.into(),
                        MEDIA_TYPE_EVENTS.into(),
                        MEDIA_TYPE_JPEG.into(),
                        MEDIA_TYPE_L16.into(),
                    ],
                    capabilities: vec![
                        "events".into(),
                        "snapshot".into(),
                        "mjpeg".into(),
                        "pcm".into(),
                        "talk".into(),
                        "talk-ws".into(),
                        "pad".into(),
                    ],
                },
            ),
            Err(response) => response,
        },
        ("GET", "/v1/state") => match require_accept(request, &[MEDIA_TYPE_JSON]) {
            Ok(_) => Response::json(200, &agent.state()),
            Err(response) => response,
        },
        ("GET", "/v1/media") => match require_accept(request, &[MEDIA_TYPE_JSON]) {
            Ok(_) => Response::json(200, &agent.media_info()),
            Err(response) => response,
        },
        ("GET", "/v1/snapshot.jpg") => match require_accept(request, &[MEDIA_TYPE_JPEG]) {
            Ok(_) => match agent.snapshot() {
                Some(frame) => {
                    let age_ms = agent.clock_us().saturating_sub(frame.pts_us) / 1000;
                    Response::new(200, MEDIA_TYPE_JPEG, frame.jpeg.to_vec())
                        .header("Cache-Control", "no-store")
                        .header("X-Frame-Age-Ms", &age_ms.to_string())
                }
                None => Response::error(404, "no_frame", "no door frame received yet"),
            },
            Err(response) => response,
        },
        ("POST", "/v1/call/claim") => command(request, agent, CallAction::Claim).await,
        ("POST", "/v1/call/unlock") => command(request, agent, CallAction::Unlock).await,
        ("POST", "/v1/call/hangup") => command(request, agent, CallAction::Hangup).await,
        ("GET", "/v1/events")
        | ("POST", "/v1/talk")
        | ("GET", "/v1/stream.mjpeg")
        | ("GET", "/v1/audio.pcm")
        | ("GET", "/v1/talk.ws") => {
            Response::error(500, "internal", "streaming route reached the plain router")
        }
        (_, path) if path.starts_with("/v1/") => {
            Response::error(404, "not_found", format!("no route for {path}"))
        }
        _ => Response::error(404, "not_found", "unknown path"),
    }
}

async fn command<A: AgentControl>(request: &Request, agent: &A, action: CallAction) -> Response {
    if let Err(response) = require_accept(request, &[MEDIA_TYPE_JSON]) {
        return response;
    }
    if let Err(response) = require_content_type(request, MEDIA_TYPE_JSON) {
        return response;
    }
    let body: CommandRequest = match serde_json::from_slice(&request.body) {
        Ok(body) => body,
        Err(error) => return Response::error(400, "bad_request", format!("invalid body: {error}")),
    };
    if body.command_id.is_empty() || body.command_id.len() > 128 {
        return Response::error(400, "bad_request", "command_id must be 1..128 characters");
    }
    let result = agent.command(action, &body.command_id).await;
    Response::json(result.http_status(), &result)
}

// ---------------------------------------------------------------------------
// Server-Sent Events
// ---------------------------------------------------------------------------

fn sse_message(id: u64, event: &str, data: &str) -> String {
    format!("id: {id}\nevent: {event}\ndata: {data}\n\n")
}

async fn write_chunk(stream: &mut OwnedWriteHalf, data: &[u8]) -> Result<()> {
    stream
        .write_all(format!("{:x}\r\n", data.len()).as_bytes())
        .await?;
    stream.write_all(data).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    Ok(())
}

/// Cheap jitter without pulling a random-number crate into the Agent.
fn jitter(range: (Duration, Duration)) -> Duration {
    let span = range.1.saturating_sub(range.0).as_millis() as u64;
    if span == 0 {
        return range.0;
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    let mut x = seed ^ 0x9e37_79b9_7f4a_7c15;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    range.0 + Duration::from_millis(x % span)
}

async fn events_stream<A: AgentControl>(
    reader: &mut BufReader<OwnedReadHalf>,
    stream: &mut OwnedWriteHalf,
    request: &Request,
    config: &ServerConfig,
    agent: &A,
) -> Result<()> {
    if let Err(response) = require_accept(request, &[MEDIA_TYPE_EVENTS]) {
        write_response(stream, &response, false).await?;
        return Ok(());
    }
    // Subscribe before replaying so nothing slips between the two.
    let mut live = agent.subscribe();
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    stream.write_all(head.as_bytes()).await?;

    let last_event_id = request
        .header("last-event-id")
        .and_then(|v| v.trim().parse::<u64>().ok());
    let mut initial = String::new();
    match last_event_id.and_then(|after| agent.recent(after)) {
        Some(missed) => {
            for event in missed {
                initial.push_str(&sse_message(
                    event.seq,
                    event.kind.name(),
                    &serde_json::to_string(&event)?,
                ));
            }
            // A resumed client that missed nothing still gets a heartbeat
            // so it can tell the connection is live.
            if initial.is_empty() {
                initial.push_str(": resumed\n\n");
            }
        }
        None => {
            let snapshot = crate::agent_api::Event {
                seq: agent.recent(u64::MAX - 1).map(|_| 0).unwrap_or(0),
                at_ms: crate::agent_api::now_ms(),
                kind: EventKind::Snapshot {
                    state: agent.state(),
                },
            };
            initial.push_str(&sse_message(
                0,
                "snapshot",
                &serde_json::to_string(&snapshot)?,
            ));
        }
    }
    initial.push_str("retry: 1000\n\n");
    write_chunk(stream, initial.as_bytes()).await?;

    let lifetime = jitter(config.event_stream_lifetime);
    let deadline = tokio::time::sleep(lifetime);
    tokio::pin!(deadline);
    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    heartbeat.tick().await;
    let mut detector = [0_u8; 1];
    loop {
        tokio::select! {
            event = live.recv() => match event {
                Ok(event) => {
                    let message = sse_message(event.seq, event.kind.name(), &serde_json::to_string(&event)?);
                    write_chunk(stream, message.as_bytes()).await?;
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let snapshot = crate::agent_api::Event {
                        seq: 0,
                        at_ms: crate::agent_api::now_ms(),
                        kind: EventKind::Snapshot { state: agent.state() },
                    };
                    write_chunk(stream, sse_message(0, "snapshot", &serde_json::to_string(&snapshot)?).as_bytes()).await?;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = heartbeat.tick() => {
                write_chunk(stream, b": keep-alive\n\n").await?;
            }
            _ = &mut deadline => {
                tracing::debug!("closing event stream after {:?} so the client reconnects", lifetime);
                break;
            }
            // A client that goes away is noticed through the read side.
            read = reader.read(&mut detector) => {
                if matches!(read, Ok(0) | Err(_)) {
                    return Ok(());
                }
            }
        }
    }
    stream.write_all(b"0\r\n\r\n").await?;
    stream.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Talk-back upload
// ---------------------------------------------------------------------------

async fn talk_upload<A: AgentControl + AgentMedia>(
    reader: &mut BufReader<OwnedReadHalf>,
    request: &Request,
    agent: &A,
) -> Result<Response> {
    if let Err(response) = require_content_type(request, MEDIA_TYPE_L16) {
        return Ok(response);
    }
    let chunked = request
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let mut remaining: Option<usize> = match request.header("content-length") {
        Some(length) => Some(length.parse().context("bad content-length")?),
        None => None,
    };
    anyhow::ensure!(
        chunked || remaining.is_some(),
        "talk upload needs a length or chunked encoding"
    );
    if TALK_BUSY.swap(true, Ordering::AcqRel) {
        return Ok(Response::error(
            409,
            "talk_busy",
            "another talk-back upload is active",
        ));
    }
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            TALK_BUSY.store(false, Ordering::Release);
        }
    }
    let _release = Release;
    let mut pending: Vec<u8> = Vec::new();
    let started = std::time::Instant::now();
    loop {
        let piece: Vec<u8> = if chunked {
            let size = read_chunk_size(reader).await?;
            if size == 0 {
                loop {
                    if read_line(reader).await?.is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut buf = vec![0_u8; size.min(64 * 1024)];
            reader.read_exact(&mut buf).await?;
            let _ = read_line(reader).await?;
            buf
        } else {
            let left = remaining.unwrap_or(0);
            if left == 0 {
                break;
            }
            let mut buf = vec![0_u8; left.min(4096)];
            let read = reader.read(&mut buf).await?;
            anyhow::ensure!(read > 0, "connection closed inside talk body");
            buf.truncate(read);
            remaining = Some(left - read);
            buf
        };
        pending.extend_from_slice(&piece);
        // Forward in 32 ms chunks, the door station's native packet size.
        while pending.len() >= 512 {
            let chunk: Vec<u8> = pending.drain(..512).collect();
            let audio = AudioChunk {
                pts_us: started.elapsed().as_micros() as u64,
                pcm: Arc::from(chunk),
            };
            if let Err(error) = agent.talk(audio).await {
                let result = crate::agent_api::CommandResult::rejected("talk", error);
                return Ok(Response::json(error.http_status(), &result));
            }
        }
    }
    Ok(Response::new(204, MEDIA_TYPE_JSON, Vec::new()))
}

// ---------------------------------------------------------------------------
// Browser media: MJPEG, raw PCM, WebSocket talk-back
// ---------------------------------------------------------------------------

/// Stop a stream as soon as the client goes away, without blocking sends.
async fn client_gone(reader: &mut BufReader<OwnedReadHalf>) {
    let mut buf = [0_u8; 64];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => continue,
        }
    }
}

/// `multipart/x-mixed-replace` MJPEG: the latest frame first, then live.
async fn mjpeg_stream<A: AgentControl + AgentMedia>(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    request: &Request,
    agent: &A,
) -> Result<()> {
    if let Err(response) = require_accept(request, &[MEDIA_TYPE_MJPEG, MEDIA_TYPE_JPEG]) {
        write_response(writer, &response, false).await?;
        return Ok(());
    }
    let mut live = agent.video();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {MEDIA_TYPE_MJPEG}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    );
    writer.write_all(head.as_bytes()).await?;
    async fn part(writer: &mut OwnedWriteHalf, jpeg: &[u8], pts_us: u64) -> Result<()> {
        let part = format!(
            "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\nX-Pts-Us: {}\r\n\r\n",
            jpeg.len(),
            pts_us
        );
        writer.write_all(part.as_bytes()).await?;
        writer.write_all(jpeg).await?;
        writer.write_all(b"\r\n").await?;
        writer.flush().await?;
        Ok(())
    }
    if let Some(frame) = agent.snapshot() {
        part(writer, &frame.jpeg, frame.pts_us).await?;
    }
    loop {
        tokio::select! {
            frame = live.recv() => match frame {
                Ok(frame) => part(writer, &frame.jpeg, frame.pts_us).await?,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = client_gone(reader) => break,
        }
    }
    Ok(())
}

/// Raw door audio as `audio/L16` (big-endian, as the RFC 2586 type says).
async fn pcm_stream<A: AgentControl + AgentMedia>(
    reader: &mut BufReader<OwnedReadHalf>,
    writer: &mut OwnedWriteHalf,
    request: &Request,
    agent: &A,
) -> Result<()> {
    if let Err(response) = require_accept(request, &[MEDIA_TYPE_L16]) {
        write_response(writer, &response, false).await?;
        return Ok(());
    }
    let mut live = agent.audio();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {MEDIA_TYPE_L16}\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    writer.write_all(head.as_bytes()).await?;
    loop {
        tokio::select! {
            chunk = live.recv() => match chunk {
                Ok(chunk) => {
                    let mut swapped = chunk.pcm.to_vec();
                    for pair in swapped.chunks_exact_mut(2) {
                        pair.swap(0, 1);
                    }
                    write_chunk(writer, &swapped).await?;
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
            _ = client_gone(reader) => return Ok(()),
        }
    }
    writer.write_all(b"0\r\n\r\n").await?;
    Ok(())
}

/// A TCP stream with bytes the HTTP parser had already buffered put back in
/// front, so the WebSocket layer sees the exact byte sequence.
struct PrefixedStream {
    prefix: Vec<u8>,
    inner: TcpStream,
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let bytes: Vec<u8> = self.prefix.drain(..n).collect();
            buf.put_slice(&bytes);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// WebSocket talk-back: binary messages carry PCM S16LE 8 kHz mono. Browsers
/// cannot stream an HTTP request body over HTTP/1.1, so this is their path.
async fn talk_websocket<A: AgentControl + AgentMedia>(
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    request: &Request,
    agent: Arc<A>,
) -> Result<()> {
    let mut writer = writer;
    let key = match request.header("sec-websocket-key") {
        Some(key)
            if request
                .header("upgrade")
                .is_some_and(|u| u.eq_ignore_ascii_case("websocket")) =>
        {
            key.trim().to_owned()
        }
        _ => {
            let response = Response::error(400, "bad_request", "WebSocket upgrade expected");
            write_response(&mut writer, &response, false).await?;
            return Ok(());
        }
    };
    if TALK_BUSY.swap(true, Ordering::AcqRel) {
        let response = Response::error(409, "talk_busy", "another talk-back upload is active");
        write_response(&mut writer, &response, false).await?;
        return Ok(());
    }
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            TALK_BUSY.store(false, Ordering::Release);
        }
    }
    let _release = Release;

    use sha1::Digest as _;
    let accept = base64_encode(&sha1::Sha1::digest(
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    ));
    let head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    writer.write_all(head.as_bytes()).await?;
    writer.flush().await?;
    let prefix = reader.buffer().to_vec();
    let read_half = reader.into_inner();
    let stream = read_half
        .reunite(writer)
        .map_err(|_| anyhow::anyhow!("reuniting TCP halves"))?;
    let stream = PrefixedStream {
        prefix,
        inner: stream,
    };
    let mut socket = tokio_tungstenite::WebSocketStream::from_raw_socket(
        stream,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    use futures_util::{SinkExt, StreamExt};
    let started = std::time::Instant::now();
    let mut pending: Vec<u8> = Vec::new();
    let mut forwarded = 0_u64;
    while let Some(message) = socket.next().await {
        let message = match message {
            Ok(message) => message,
            Err(_) => break,
        };
        match message {
            WsMessage::Binary(bytes) => {
                pending.extend_from_slice(&bytes);
                while pending.len() >= 512 {
                    let chunk: Vec<u8> = pending.drain(..512).collect();
                    let audio = AudioChunk {
                        pts_us: started.elapsed().as_micros() as u64,
                        pcm: Arc::from(chunk),
                    };
                    if let Err(error) = agent.talk(audio).await {
                        let result = crate::agent_api::CommandResult::rejected("talk", error);
                        let _ = socket
                            .send(WsMessage::Text(
                                serde_json::to_string(&result).unwrap_or_default().into(),
                            ))
                            .await;
                        let _ = socket.close(None).await;
                        tracing::info!(forwarded, %error, "WebSocket talk ended by the Agent");
                        return Ok(());
                    }
                    forwarded += 1;
                }
            }
            WsMessage::Ping(payload) => {
                let _ = socket.send(WsMessage::Pong(payload)).await;
            }
            WsMessage::Close(_) => break,
            _ => {}
        }
    }
    tracing::info!(forwarded, "WebSocket talk closed");
    Ok(())
}

const SWAGGER_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>pad-gateway Agent API</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.ui = SwaggerUIBundle({ url: "/openapi.yaml", dom_id: "#swagger-ui", persistAuthorization: true });
</script>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_honours_q_and_wildcards() {
        assert_eq!(
            negotiate(Some("application/json"), &[MEDIA_TYPE_JSON]),
            Some(MEDIA_TYPE_JSON)
        );
        assert_eq!(
            negotiate(Some("application/json; v=1"), &[MEDIA_TYPE_JSON]),
            Some(MEDIA_TYPE_JSON)
        );
        assert_eq!(
            negotiate(Some("*/*"), &[MEDIA_TYPE_JSON]),
            Some(MEDIA_TYPE_JSON)
        );
        assert_eq!(
            negotiate(
                Some("text/*, application/json;q=0.5"),
                &[MEDIA_TYPE_JSON, MEDIA_TYPE_EVENTS]
            ),
            Some(MEDIA_TYPE_EVENTS)
        );
        assert_eq!(
            negotiate(Some("application/cbor"), &[MEDIA_TYPE_JSON]),
            None
        );
        assert_eq!(negotiate(None, &[MEDIA_TYPE_JSON]), None);
        assert_eq!(
            negotiate(Some("application/json;q=0"), &[MEDIA_TYPE_JSON]),
            None
        );
    }

    #[test]
    fn content_type_matches_ignoring_parameters() {
        let request = Request {
            method: "POST".into(),
            path: "/v1/call/claim".into(),
            headers: vec![(
                "content-type".into(),
                "application/json; charset=utf-8".into(),
            )],
            body: Vec::new(),
            keep_alive: true,
        };
        assert!(require_content_type(&request, MEDIA_TYPE_JSON).is_ok());
        let request = Request {
            headers: vec![("content-type".into(), "text/plain".into())],
            ..request
        };
        assert_eq!(
            require_content_type(&request, MEDIA_TYPE_JSON)
                .unwrap_err()
                .status,
            415
        );
    }

    #[test]
    fn openapi_document_is_embedded() {
        assert!(OPENAPI_YAML.starts_with("openapi: 3.1.0"));
        assert!(OPENAPI_YAML.contains("/v1/events"));
    }
}
