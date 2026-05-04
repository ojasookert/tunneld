use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State, ws::{Message, WebSocket, WebSocketUpgrade}},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use bytes::Bytes;
use clap::Args as ClapArgs;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
};
use uuid::Uuid;

use crate::proto::{Frame, FrameType, MAX_BODY_CHUNK, ReqHead, RespHead};

const FRAME_QUEUE: usize = 256;
const RESP_QUEUE: usize = 64;
const HEAD_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    #[arg(long, env = "TUNNELD_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,
    #[arg(long, env = "TUNNELD_SECRET")]
    pub secret: String,
    #[arg(long, env = "TUNNELD_DOMAIN", default_value = "tunnel.le.ht")]
    pub domain: String,
    #[arg(long, env = "TUNNELD_PUBLIC_BASE", default_value = "https://tunnel.le.ht")]
    pub public_base: String,
    #[arg(long, env = "TUNNELD_DIST_DIR", default_value = "/dist")]
    pub dist_dir: String,
}

pub struct AppState {
    secret: String,
    domain: String,
    public_base: String,
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
    frame_tx: Mutex<Option<mpsc::Sender<Frame>>>,
    next_request_id: AtomicU32,
    pending: DashMap<u32, mpsc::Sender<Frame>>,
}

impl TunnelHandle {
    fn next_request_id(&self) -> u32 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }
}

pub async fn run(args: Args) -> Result<()> {
    if args.secret.len() < 16 {
        anyhow::bail!("TUNNELD_SECRET must be at least 16 chars");
    }

    let bind = args.bind;
    let dist_dir = args.dist_dir.clone();
    let state = Arc::new(AppState {
        secret: args.secret,
        domain: args.domain,
        public_base: args.public_base,
        tunnels: DashMap::new(),
        by_id: DashMap::new(),
    });

    let serve_dist = tower_http::services::ServeDir::new(&dist_dir)
        .precompressed_gzip()
        .append_index_html_on_directories(false);

    let app = Router::new()
        .route("/api/tunnels", post(create_tunnel).get(list_tunnels))
        .route("/api/tunnels/:id", delete(delete_tunnel))
        .route("/ws/:id", get(ws_upgrade))
        .route("/health", get(health))
        .route("/install", get(install_script))
        .nest_service("/dl", serve_dist)
        .fallback(host_fallback)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state.clone());

    let listener = TcpListener::bind(bind).await.context("bind")?;
    tracing::info!(bind = %listener.local_addr()?, domain = %state.domain, "tunneld listening");
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

async fn health() -> &'static str { "ok" }

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

async fn host_fallback(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    let host_hdr = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let host = host_hdr.split(':').next().unwrap_or("").to_lowercase();
    let domain = state.domain.to_lowercase();

    if host == domain {
        return (StatusCode::NOT_FOUND, "tunneld: unknown path").into_response();
    }
    if let Some(sub) = host.strip_suffix(&format!(".{domain}")) {
        if sub.is_empty() || sub.contains('.') {
            return (StatusCode::NOT_FOUND, "nested or empty subdomain unsupported").into_response();
        }
        return proxy_request(state, sub.to_string(), req).await;
    }
    (StatusCode::NOT_FOUND, format!("unknown host: {host}")).into_response()
}

fn check_auth(headers: &HeaderMap, secret: &str) -> bool {
    let Some(v) = headers.get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()) else {
        return false;
    };
    v.strip_prefix("Bearer ")
        .map(|t| constant_time_eq(t.as_bytes(), secret.as_bytes()))
        .unwrap_or(false)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CreateReq {
    name: Option<String>,
}

#[derive(Serialize)]
struct CreateResp {
    tunnel_id: Uuid,
    subdomain: String,
    public_url: String,
    ws_url: String,
}

#[derive(Serialize)]
struct ListItem {
    tunnel_id: Uuid,
    subdomain: String,
    public_url: String,
}

async fn create_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<CreateReq>>,
) -> Response {
    if !check_auth(&headers, &state.secret) {
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    }

    let req = body.map(|Json(b)| b).unwrap_or_default();
    let subdomain = match req.name {
        Some(n) if is_valid_name(&n) => n,
        Some(_) => return (StatusCode::BAD_REQUEST, "invalid name").into_response(),
        None => nanoid::nanoid!(8, &SAFE_ALPHABET),
    };

    if state.tunnels.contains_key(&subdomain) {
        return (StatusCode::CONFLICT, "subdomain in use").into_response();
    }

    let tunnel_id = Uuid::new_v4();
    let handle = Arc::new(TunnelHandle {
        subdomain: subdomain.clone(),
        tunnel_id,
        frame_tx: Mutex::new(None),
        next_request_id: AtomicU32::new(1),
        pending: DashMap::new(),
    });

    state.tunnels.insert(subdomain.clone(), handle);
    state.by_id.insert(tunnel_id, subdomain.clone());

    let scheme = state.public_base.split("://").next().unwrap_or("https");
    let host_port = state
        .public_base
        .splitn(2, "://")
        .nth(1)
        .unwrap_or(&state.domain);
    let public_url = format!("{scheme}://{subdomain}.{domain}", domain = state.domain);
    let ws_scheme = if scheme == "https" { "wss" } else { "ws" };
    let ws_url = format!("{ws_scheme}://{host_port}/ws/{tunnel_id}");

    (
        StatusCode::CREATED,
        Json(CreateResp { tunnel_id, subdomain, public_url, ws_url }),
    )
        .into_response()
}

const SAFE_ALPHABET: [char; 32] = [
    '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'j', 'k', 'm', 'n', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0',
];

fn is_valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 32
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !n.starts_with('-')
        && !n.ends_with('-')
}

async fn list_tunnels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if !check_auth(&headers, &state.secret) {
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    let scheme = state.public_base.split("://").next().unwrap_or("https");
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
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    }
    if let Some((_, sub)) = state.by_id.remove(&id) {
        if let Some((_, handle)) = state.tunnels.remove(&sub) {
            *handle.frame_tx.lock().await = None;
            handle.pending.clear();
        }
        return StatusCode::NO_CONTENT.into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}

#[derive(Deserialize)]
struct WsAuth {
    token: Option<String>,
}

async fn ws_upgrade(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<WsAuth>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let token_ok = check_auth(&headers, &state.secret)
        || q.token
            .as_deref()
            .map(|t| constant_time_eq(t.as_bytes(), state.secret.as_bytes()))
            .unwrap_or(false);
    if !token_ok {
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
    }

    let Some(sub) = state.by_id.get(&id).map(|e| e.value().clone()) else {
        return (StatusCode::NOT_FOUND, "no such tunnel").into_response();
    };
    let Some(handle) = state.tunnels.get(&sub).map(|e| e.value().clone()) else {
        return (StatusCode::NOT_FOUND, "no such tunnel").into_response();
    };

    {
        let mut slot = handle.frame_tx.lock().await;
        if slot.is_some() {
            return (StatusCode::CONFLICT, "already attached").into_response();
        }
        let (tx, rx) = mpsc::channel::<Frame>(FRAME_QUEUE);
        *slot = Some(tx);
        let st = state.clone();
        let h = handle.clone();
        upgrade.on_upgrade(move |ws| async move { run_tunnel_ws(ws, h, st, rx).await })
    }
}

async fn run_tunnel_ws(
    ws: WebSocket,
    handle: Arc<TunnelHandle>,
    state: Arc<AppState>,
    mut frame_rx: mpsc::Receiver<Frame>,
) {
    let (mut sink, mut stream) = ws.split();

    let writer = tokio::spawn(async move {
        while let Some(f) = frame_rx.recv().await {
            let bytes = f.encode();
            if sink.send(Message::Binary(bytes.to_vec())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    tracing::info!(subdomain = %handle.subdomain, "tunnel attached");

    while let Some(msg) = stream.next().await {
        let Ok(msg) = msg else { break };
        match msg {
            Message::Binary(bytes) => {
                let frame = match Frame::decode(&bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad frame");
                        continue;
                    }
                };
                let req_id = frame.request_id;
                let drop_after = matches!(
                    frame.typ,
                    FrameType::RespEnd | FrameType::Cancel
                );
                let send_ok = if let Some(entry) = handle.pending.get(&req_id) {
                    entry.value().send(frame).await.is_ok()
                } else {
                    false
                };
                if !send_ok || drop_after {
                    handle.pending.remove(&req_id);
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    *handle.frame_tx.lock().await = None;
    handle.pending.clear();
    state.tunnels.remove(&handle.subdomain);
    state.by_id.remove(&handle.tunnel_id);
    let _ = writer.await;
    tracing::info!(subdomain = %handle.subdomain, "tunnel disconnected");
}

async fn proxy_request(
    state: Arc<AppState>,
    sub: String,
    req: Request<Body>,
) -> Response {
    let Some(tunnel) = state.tunnels.get(&sub).map(|e| e.value().clone()) else {
        return (StatusCode::BAD_GATEWAY, format!("no tunnel for {sub}")).into_response();
    };
    let frame_tx = match tunnel.frame_tx.lock().await.clone() {
        Some(tx) => tx,
        None => return (StatusCode::BAD_GATEWAY, "tunnel client offline").into_response(),
    };

    let request_id = tunnel.next_request_id();
    let (resp_tx, mut resp_rx) = mpsc::channel::<Frame>(RESP_QUEUE);
    tunnel.pending.insert(request_id, resp_tx);

    let (parts, body) = req.into_parts();
    let host_full = parts
        .headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let head = ReqHead {
        method: parts.method.to_string(),
        uri: parts
            .uri
            .path_and_query()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "/".into()),
        host: host_full,
        headers: parts
            .headers
            .iter()
            .filter(|(k, _)| !is_hop_by_hop(k.as_str()))
            .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect(),
    };

    let head_frame = match Frame::head_req(request_id, &head) {
        Ok(f) => f,
        Err(_) => {
            tunnel.pending.remove(&request_id);
            return (StatusCode::INTERNAL_SERVER_ERROR, "head encode").into_response();
        }
    };

    if frame_tx.send(head_frame).await.is_err() {
        tunnel.pending.remove(&request_id);
        return (StatusCode::BAD_GATEWAY, "tunnel closed").into_response();
    }

    let body_tx = frame_tx.clone();
    tokio::spawn(async move {
        let mut body = body;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        for chunk in data.chunks(MAX_BODY_CHUNK) {
                            let f = Frame::new(
                                FrameType::ReqBody,
                                request_id,
                                Bytes::copy_from_slice(chunk),
                            );
                            if body_tx.send(f).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                Some(Err(_)) => break,
                None => break,
            }
        }
        let _ = body_tx
            .send(Frame::end(FrameType::ReqEnd, request_id))
            .await;
    });

    let head_frame = match tokio::time::timeout(HEAD_TIMEOUT, resp_rx.recv()).await {
        Ok(Some(f)) if f.typ == FrameType::RespHead => f,
        _ => {
            tunnel.pending.remove(&request_id);
            return (StatusCode::BAD_GATEWAY, "no response").into_response();
        }
    };

    let resp_head: RespHead = match serde_json::from_slice(&head_frame.payload) {
        Ok(h) => h,
        Err(_) => {
            tunnel.pending.remove(&request_id);
            return (StatusCode::BAD_GATEWAY, "bad response head").into_response();
        }
    };

    let pending = tunnel.pending.clone();
    let body_stream = build_body_stream(resp_rx, request_id, pending);
    let body = Body::from_stream(body_stream);

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(resp_head.status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (k, v) in resp_head.headers {
        if is_hop_by_hop(&k) {
            continue;
        }
        let Ok(name) = HeaderName::from_bytes(k.as_bytes()) else { continue };
        let Ok(val) = HeaderValue::from_str(&v) else { continue };
        builder = builder.header(name, val);
    }
    builder.body(body).unwrap_or_else(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("response build: {e}")).into_response()
    })
}

fn build_body_stream(
    mut resp_rx: mpsc::Receiver<Frame>,
    request_id: u32,
    pending: DashMap<u32, mpsc::Sender<Frame>>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    async_stream::stream! {
        loop {
            match resp_rx.recv().await {
                Some(f) if f.typ == FrameType::RespBody => yield Ok(f.payload),
                Some(f) if f.typ == FrameType::RespEnd => break,
                Some(f) if f.typ == FrameType::Cancel => break,
                Some(_) => {}
                None => break,
            }
        }
        pending.remove(&request_id);
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
            | "content-length"
    )
}
