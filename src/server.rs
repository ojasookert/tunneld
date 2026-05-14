use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::Engine;
use bytes::Bytes;
use clap::Args as ClapArgs;
use dashmap::DashMap;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::proto::{self, AuthReply, Prelude};
use crate::tls;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_PIPE_BUF: usize = 16 * 1024;

const HEAD_TIMEOUT: Duration = Duration::from_secs(120);
const TLS_ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const PRELUDE_TIMEOUT: Duration = Duration::from_secs(10);
const ATTACH_DEADLINE: Duration = Duration::from_secs(60);
const REAPER_INTERVAL: Duration = Duration::from_secs(15);
const MAX_TUNNELS: usize = 1024;
const API_BODY_LIMIT: usize = 8 * 1024;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[arg(long, env = "TUNNELD_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,
    #[arg(long, env = "TUNNELD_DATA_BIND", default_value = "0.0.0.0:7844")]
    pub data_bind: SocketAddr,
    #[arg(long, env = "TUNNELD_SECRET")]
    pub secret: String,
    #[arg(long, env = "TUNNELD_DOMAIN", default_value = "tunnel.le.ht")]
    pub domain: String,
    #[arg(
        long,
        env = "TUNNELD_PUBLIC_BASE",
        default_value = "https://tunnel.le.ht"
    )]
    pub public_base: String,
    #[arg(long, env = "TUNNELD_DATA_PUBLIC", default_value = "tunnel.le.ht:7844")]
    pub data_public: String,
    #[arg(long, env = "TUNNELD_DIST_DIR", default_value = "/dist")]
    pub dist_dir: String,
    #[arg(long, env = "TUNNELD_CERT_PATH", default_value = "/tls/tls.crt")]
    pub cert_path: PathBuf,
    #[arg(long, env = "TUNNELD_KEY_PATH", default_value = "/tls/tls.key")]
    pub key_path: PathBuf,
}

pub struct AppState {
    secret: String,
    domain: String,
    public_base: String,
    data_public: String,
    tunnels: DashMap<String, Arc<TunnelHandle>>,
    by_id: DashMap<Uuid, String>,
}

const INSTALL_SCRIPT: &str = r#"#!/bin/sh
set -eu
BASE="${TUNNELD_BASE:-__BASE__}"
DEST="${TUNNELD_INSTALL_DEST:-/usr/local/bin/tunneld}"
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=x86_64 ;;
  aarch64|arm64) arch=aarch64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
case "$os" in
  linux) name="tunneld-linux-${arch}" ;;
  darwin) name="tunneld-darwin-${arch}" ;;
  *) echo "unsupported os: $os; for windows fetch tunneld-windows-${arch}.exe manually" >&2; exit 1 ;;
esac
echo "downloading ${BASE}/dl/${name} -> ${DEST}"
if command -v curl >/dev/null 2>&1; then
  curl -fSL "${BASE}/dl/${name}" -o "${DEST}.tmp"
elif command -v wget >/dev/null 2>&1; then
  wget -O "${DEST}.tmp" "${BASE}/dl/${name}"
else
  echo "need curl or wget" >&2; exit 1
fi
chmod +x "${DEST}.tmp"
mv "${DEST}.tmp" "${DEST}"
"${DEST}" --version
"#;

struct TunnelHandle {
    subdomain: String,
    tunnel_id: Uuid,
    sender: Mutex<Option<h2::client::SendRequest<Bytes>>>,
    created_at: Instant,
}

pub async fn run(args: Args) -> Result<()> {
    if args.secret.len() < 16 {
        anyhow::bail!("TUNNELD_SECRET must be at least 16 chars");
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let bind = args.bind;
    let data_bind = args.data_bind;
    let dist_dir = args.dist_dir.clone();
    let state = Arc::new(AppState {
        secret: args.secret,
        domain: args.domain,
        public_base: args.public_base,
        data_public: args.data_public,
        tunnels: DashMap::new(),
        by_id: DashMap::new(),
    });

    let serve_dist = tower_http::services::ServeDir::new(&dist_dir)
        .precompressed_gzip()
        .append_index_html_on_directories(false);

    use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
    use tracing::Level;

    let api = Router::new()
        .route("/api/tunnels", post(create_tunnel).get(list_tunnels))
        .route("/api/tunnels/:id", delete(delete_tunnel))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            API_BODY_LIMIT,
        ));

    let traced = Router::new()
        .merge(api)
        .route("/install", get(install_script))
        .nest_service("/dl", serve_dist)
        .fallback(host_fallback)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state.clone());

    let app = Router::new().route("/health", get(health)).merge(traced);

    let reaper_state = state.clone();
    tokio::spawn(async move { run_reaper(reaper_state).await });

    let tls_config = tls::server_config(&args.cert_path, &args.key_path)
        .context("load tls cert/key for data plane")?;
    let acceptor = TlsAcceptor::from(tls_config);

    let data_listener = TcpListener::bind(data_bind).await.context("bind data")?;
    tracing::info!(addr = %data_listener.local_addr()?, "tunneld data plane listening");
    let data_state = state.clone();
    tokio::spawn(async move {
        loop {
            let (sock, peer) = match data_listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(error = %e, "data accept");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let state = data_state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_data_conn(sock, peer, acceptor, state).await {
                    tracing::debug!(peer = %peer, error = %e, "data conn closed");
                }
            });
        }
    });

    let listener = TcpListener::bind(bind).await.context("bind")?;
    tracing::info!(bind = %listener.local_addr()?, domain = %state.domain, "tunneld control plane listening");
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

async fn handle_data_conn(
    sock: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    state: Arc<AppState>,
) -> Result<()> {
    let _ = sock.set_nodelay(true);
    tracing::info!(peer = %peer, "data conn accepted");

    let mut tls = tokio::time::timeout(TLS_ACCEPT_TIMEOUT, acceptor.accept(sock))
        .await
        .map_err(|_| anyhow::anyhow!("tls accept timeout"))?
        .context("tls accept")?;

    let prelude_res = tokio::time::timeout(PRELUDE_TIMEOUT, Prelude::read(&mut tls)).await;
    let prelude = match prelude_res {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            let _ = proto::write_reply(&mut tls, AuthReply::Reject).await;
            return Err(e);
        }
        Err(_) => {
            let _ = proto::write_reply(&mut tls, AuthReply::Reject).await;
            anyhow::bail!("prelude read timeout from {peer}");
        }
    };

    if prelude.token.as_slice() != state.secret.as_bytes() {
        proto::write_reply(&mut tls, AuthReply::Reject).await.ok();
        anyhow::bail!("rejected (bad token) from {peer}");
    }

    let Some(handle) = state.by_id.get(&prelude.tunnel_id).and_then(|sub| {
        let sub = sub.value().clone();
        state.tunnels.get(&sub).map(|h| h.value().clone())
    }) else {
        proto::write_reply(&mut tls, AuthReply::Reject).await.ok();
        anyhow::bail!("rejected (no such tunnel) from {peer}");
    };

    let mut slot = handle.sender.lock().await;
    if slot.is_some() {
        drop(slot);
        proto::write_reply(&mut tls, AuthReply::Reject).await.ok();
        anyhow::bail!("rejected (already attached): {}", handle.subdomain);
    }

    proto::write_reply(&mut tls, AuthReply::Ok).await?;

    let (send_request, conn) = h2::client::handshake(tls)
        .await
        .context("h2 client handshake")?;

    *slot = Some(send_request);
    drop(slot);
    tracing::info!(subdomain = %handle.subdomain, "tunnel attached");

    let drive = conn.await;

    *handle.sender.lock().await = None;
    state.tunnels.remove(&handle.subdomain);
    state.by_id.remove(&handle.tunnel_id);
    tracing::info!(subdomain = %handle.subdomain, "tunnel detached");

    drive.context("h2 conn drive")?;
    Ok(())
}

async fn run_reaper(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(REAPER_INTERVAL);
    loop {
        tick.tick().await;
        let now = Instant::now();
        let stale: Vec<(String, Uuid)> = state
            .tunnels
            .iter()
            .filter_map(|e| {
                let h = e.value();
                let attached = h.sender.try_lock().map(|s| s.is_some()).unwrap_or(true);
                if !attached && now.duration_since(h.created_at) > ATTACH_DEADLINE {
                    Some((h.subdomain.clone(), h.tunnel_id))
                } else {
                    None
                }
            })
            .collect();
        for (sub, id) in stale {
            state.tunnels.remove(&sub);
            state.by_id.remove(&id);
            tracing::info!(subdomain = %sub, "reaped orphan tunnel");
        }
    }
}

async fn health() -> &'static str {
    "ok"
}

async fn install_script(State(state): State<Arc<AppState>>) -> Response {
    let body = INSTALL_SCRIPT.replace("__BASE__", state.public_base.trim_end_matches('/'));
    (
        [
            (header::CONTENT_TYPE, "text/x-shellscript"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

async fn host_fallback(State(state): State<Arc<AppState>>, req: Request<Body>) -> Response {
    let host_hdr = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let host = host_hdr.split(':').next().unwrap_or("").to_lowercase();
    let domain = state.domain.to_lowercase();

    if host == domain {
        return generic_404();
    }
    if let Some(sub) = host.strip_suffix(&format!(".{domain}")) {
        if sub.is_empty() || sub.contains('.') {
            return generic_404();
        }
        return proxy_request(state, sub.to_string(), req).await;
    }
    generic_404()
}

fn generic_404() -> Response {
    (StatusCode::NOT_FOUND, "Not Found").into_response()
}

fn generic_502() -> Response {
    (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response()
}

fn unauth_as_404() -> Response {
    generic_404()
}

fn check_auth(headers: &HeaderMap, secret: &str) -> bool {
    let Some(v) = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
    else {
        return false;
    };
    v.strip_prefix("Bearer ")
        .map(|t| constant_time_eq(t.as_bytes(), secret.as_bytes()))
        .unwrap_or(false)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

static WORDLIST: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
const MIN_WORDS: usize = 10240;

fn wordlist() -> &'static [&'static str] {
    WORDLIST
        .get_or_init(|| {
            let words: Vec<&'static str> = include_str!("wordlist.txt")
                .lines()
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .collect();
            assert!(
                words.len() >= MIN_WORDS,
                "embedded wordlist has {} words, need at least {}",
                words.len(),
                MIN_WORDS
            );
            words
        })
        .as_slice()
}

fn generate_subdomain() -> String {
    use rand::Rng;
    let words = wordlist();
    let mut rng = rand::thread_rng();
    (0..4)
        .map(|_| words[rng.gen_range(0..words.len())])
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Serialize)]
struct CreateResp {
    tunnel_id: Uuid,
    subdomain: String,
    public_url: String,
    connect_addr: String,
}

#[derive(Serialize)]
struct ListItem {
    tunnel_id: Uuid,
    subdomain: String,
    public_url: String,
}

async fn create_tunnel(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !check_auth(&headers, &state.secret) {
        return unauth_as_404();
    }

    let mut subdomain = generate_subdomain();
    for _ in 0..8 {
        if !state.tunnels.contains_key(&subdomain) {
            break;
        }
        subdomain = generate_subdomain();
    }
    if state.tunnels.contains_key(&subdomain) {
        return (StatusCode::CONFLICT, "could not allocate subdomain").into_response();
    }

    if state.tunnels.len() >= MAX_TUNNELS {
        return (StatusCode::SERVICE_UNAVAILABLE, "too many tunnels").into_response();
    }

    let tunnel_id = Uuid::new_v4();
    let handle = Arc::new(TunnelHandle {
        subdomain: subdomain.clone(),
        tunnel_id,
        sender: Mutex::new(None),
        created_at: Instant::now(),
    });

    state.tunnels.insert(subdomain.clone(), handle);
    state.by_id.insert(tunnel_id, subdomain.clone());

    let scheme = state
        .public_base
        .split_once("://")
        .map(|s| s.0)
        .unwrap_or("https");
    let public_url = format!("{scheme}://{subdomain}.{}", state.domain);

    (
        StatusCode::CREATED,
        Json(CreateResp {
            tunnel_id,
            subdomain,
            public_url,
            connect_addr: state.data_public.clone(),
        }),
    )
        .into_response()
}

async fn list_tunnels(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !check_auth(&headers, &state.secret) {
        return unauth_as_404();
    }
    let scheme = state
        .public_base
        .split_once("://")
        .map(|s| s.0)
        .unwrap_or("https");
    let items: Vec<_> = state
        .tunnels
        .iter()
        .map(|e| ListItem {
            tunnel_id: e.value().tunnel_id,
            subdomain: e.key().clone(),
            public_url: format!("{scheme}://{}.{}", e.key(), state.domain),
        })
        .collect();
    Json(items).into_response()
}

async fn delete_tunnel(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    if !check_auth(&headers, &state.secret) {
        return unauth_as_404();
    }
    if let Some((_, sub)) = state.by_id.remove(&id) {
        if let Some((_, handle)) = state.tunnels.remove(&sub) {
            *handle.sender.lock().await = None;
        }
        return StatusCode::NO_CONTENT.into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn proxy_request(state: Arc<AppState>, sub: String, req: Request<Body>) -> Response {
    tracing::info!(
        subdomain = %sub,
        method = %req.method(),
        path = %req.uri().path(),
        "proxy"
    );
    let Some(tunnel) = state.tunnels.get(&sub).map(|e| e.value().clone()) else {
        return generic_502();
    };
    let mut send_request = match tunnel.sender.lock().await.clone() {
        Some(s) => s,
        None => return generic_502(),
    };

    if is_ws_upgrade(&req) {
        return proxy_ws(state, sub, req, send_request).await;
    }

    let (mut parts, body) = req.into_parts();

    parts.headers.remove(header::CONNECTION);
    parts.headers.remove("keep-alive");
    parts.headers.remove(header::PROXY_AUTHENTICATE);
    parts.headers.remove(header::PROXY_AUTHORIZATION);
    parts.headers.remove(header::TE);
    parts.headers.remove(header::TRAILER);
    parts.headers.remove(header::TRANSFER_ENCODING);
    parts.headers.remove(header::UPGRADE);
    parts.headers.remove(header::HOST);

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".into());
    let abs_uri: Uri = format!("https://{sub}.{}{path_and_query}", state.domain)
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/"));
    parts.uri = abs_uri;
    parts.version = http::Version::HTTP_2;
    let h2_req = http::Request::from_parts(parts, ());

    let send_result = send_request.send_request(h2_req, false);
    let (resp_future, mut send_body) = match send_result {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "h2 send failed");
            return generic_502();
        }
    };

    tokio::spawn(async move {
        let mut body = body;
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                if !data.is_empty()
                    && proto::send_h2_with_backpressure(&mut send_body, data, false)
                        .await
                        .is_err()
                {
                    return;
                }
            }
        }
        let _ = proto::send_h2_with_backpressure(&mut send_body, Bytes::new(), true).await;
    });

    let resp = match tokio::time::timeout(HEAD_TIMEOUT, resp_future).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "upstream error");
            return generic_502();
        }
        Err(_) => return (StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout").into_response(),
    };

    let (parts, mut h2_body) = resp.into_parts();

    let body_stream = async_stream::stream! {
        while let Some(chunk) = h2_body.data().await {
            match chunk {
                Ok(data) => {
                    let len = data.len();
                    yield Ok::<_, std::io::Error>(data);
                    let _ = h2_body.flow_control().release_capacity(len);
                }
                Err(_) => break,
            }
        }
    };
    let body = Body::from_stream(body_stream);

    let mut builder = Response::builder().status(parts.status);
    for (k, v) in &parts.headers {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(
            HeaderName::from_bytes(k.as_str().as_bytes())
                .unwrap_or_else(|_| HeaderName::from_static("x-tunneld-bad-header")),
            v.clone(),
        );
    }
    let _ = builder.headers_mut();
    builder.body(body).unwrap_or_else(|e| {
        tracing::debug!(error = %e, "response build");
        generic_502()
    })
}

fn is_ws_upgrade(req: &Request<Body>) -> bool {
    if req.method() != http::Method::GET {
        return false;
    }
    let upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return false;
    }
    // Connection header is a comma-separated list; the spec requires it to
    // contain "Upgrade" (case-insensitive).
    let conn = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    conn.split(',')
        .any(|p| p.trim().eq_ignore_ascii_case("upgrade"))
}

fn ws_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Handle a browser WebSocket Upgrade: translate it to an h2 Extended CONNECT
/// stream on the data plane, return 101 to the browser, and bidirectionally
/// pipe bytes between the upgraded browser socket and the h2 stream.
async fn proxy_ws(
    state: Arc<AppState>,
    sub: String,
    mut req: Request<Body>,
    mut send_request: h2::client::SendRequest<Bytes>,
) -> Response {
    // Validate browser handshake.
    let Some(key_hdr) = req.headers().get(header::SEC_WEBSOCKET_KEY) else {
        return (StatusCode::BAD_REQUEST, "missing sec-websocket-key").into_response();
    };
    let Ok(key_str) = key_hdr.to_str() else {
        return (StatusCode::BAD_REQUEST, "bad sec-websocket-key").into_response();
    };
    let accept = ws_accept(key_str);

    // Build the h2 CONNECT request: same path/query as the browser, :authority
    // set to <sub>.<domain>, and :protocol = websocket via the h2 extension.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".into());
    let abs_uri: Uri = match format!("https://{sub}.{}{path_and_query}", state.domain).parse() {
        Ok(u) => u,
        Err(_) => return generic_502(),
    };

    let mut h2_req_builder = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(abs_uri)
        .version(http::Version::HTTP_2);
    for (k, v) in req.headers() {
        let lower = k.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "connection"
                | "upgrade"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "content-length"
                | "transfer-encoding"
                | "te"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "trailers"
        ) {
            continue;
        }
        h2_req_builder = h2_req_builder.header(k.as_str(), v.clone());
    }
    let mut h2_req = match h2_req_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "build h2 CONNECT");
            return generic_502();
        }
    };
    h2_req
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("websocket"));

    let send_result = send_request.send_request(h2_req, false);
    let (resp_future, send_body) = match send_result {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "h2 send CONNECT failed");
            return generic_502();
        }
    };

    let resp = match tokio::time::timeout(HEAD_TIMEOUT, resp_future).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "ws upstream error");
            return generic_502();
        }
        Err(_) => return (StatusCode::GATEWAY_TIMEOUT, "Gateway Timeout").into_response(),
    };

    if resp.status() != http::StatusCode::OK {
        tracing::debug!(status = %resp.status(), "upstream rejected ws CONNECT");
        return generic_502();
    }

    let mut response_builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .header(header::SEC_WEBSOCKET_ACCEPT, accept);
    if let Some(p) = resp.headers().get(header::SEC_WEBSOCKET_PROTOCOL) {
        response_builder = response_builder.header(header::SEC_WEBSOCKET_PROTOCOL, p.clone());
    }
    if let Some(p) = resp.headers().get(header::SEC_WEBSOCKET_EXTENSIONS) {
        response_builder = response_builder.header(header::SEC_WEBSOCKET_EXTENSIONS, p.clone());
    }

    let on_upgrade = hyper::upgrade::on(&mut req);

    let (_resp_parts, h2_recv) = resp.into_parts();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) = pipe_browser_h2(upgraded, h2_recv, send_body).await {
                    tracing::debug!(error = %e, "ws pipe ended");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "browser upgrade failed");
            }
        }
    });

    response_builder
        .body(Body::empty())
        .unwrap_or_else(|_| generic_502())
}

async fn pipe_browser_h2(
    upgraded: hyper::upgrade::Upgraded,
    h2_recv: h2::RecvStream,
    h2_send: h2::SendStream<Bytes>,
) -> Result<()> {
    let upgraded = TokioIo::new(upgraded);
    let (read_half, write_half) = tokio::io::split(upgraded);
    let a = tokio::spawn(ws_copy_h2_to_writer(h2_recv, write_half));
    let b = tokio::spawn(ws_copy_reader_to_h2(read_half, h2_send));
    tokio::select! {
        _ = a => {}
        _ = b => {}
    }
    Ok(())
}

async fn ws_copy_h2_to_writer(
    mut recv: h2::RecvStream,
    mut w: tokio::io::WriteHalf<TokioIo<hyper::upgrade::Upgraded>>,
) -> Result<()> {
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.context("h2 recv data")?;
        let len = chunk.len();
        if !chunk.is_empty() {
            w.write_all(&chunk).await.context("write to browser")?;
        }
        let _ = recv.flow_control().release_capacity(len);
    }
    let _ = w.shutdown().await;
    Ok(())
}

async fn ws_copy_reader_to_h2(
    mut r: tokio::io::ReadHalf<TokioIo<hyper::upgrade::Upgraded>>,
    mut send: h2::SendStream<Bytes>,
) -> Result<()> {
    let mut buf = vec![0u8; WS_PIPE_BUF];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => {
                let _ = send.send_data(Bytes::new(), true);
                return Ok(());
            }
            Ok(n) => n,
            Err(e) => return Err(e.into()),
        };
        proto::send_h2_with_backpressure(&mut send, Bytes::copy_from_slice(&buf[..n]), false)
            .await
            .context("forward to h2 send")?;
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
            | "host"
    )
}

// keep an unused HeaderValue path so unused-import lint doesn't fire
#[allow(dead_code)]
fn _unused(_: HeaderValue) {}
