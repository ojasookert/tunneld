use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use bytes::Bytes;
use clap::Args as ClapArgs;
use dashmap::DashMap;
use http_body_util::BodyExt;
use serde::Serialize;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::proto::{self, AuthReply, Prelude};
use crate::tls;

const HEAD_TIMEOUT: Duration = Duration::from_secs(120);

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

    let app = Router::new()
        .route("/api/tunnels", post(create_tunnel).get(list_tunnels))
        .route("/api/tunnels/:id", delete(delete_tunnel))
        .route("/health", get(health))
        .route("/install", get(install_script))
        .nest_service("/dl", serve_dist)
        .fallback(host_fallback)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state.clone());

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
    let mut tls = acceptor.accept(sock).await.context("tls accept")?;

    let prelude = match Prelude::read(&mut tls).await {
        Ok(p) => p,
        Err(e) => {
            let _ = proto::write_reply(&mut tls, AuthReply::Generic).await;
            return Err(e);
        }
    };

    if prelude.token.as_slice() != state.secret.as_bytes() {
        proto::write_reply(&mut tls, AuthReply::BadToken).await.ok();
        anyhow::bail!("bad token from {peer}");
    }

    let Some(handle) = state.by_id.get(&prelude.tunnel_id).and_then(|sub| {
        let sub = sub.value().clone();
        state.tunnels.get(&sub).map(|h| h.value().clone())
    }) else {
        proto::write_reply(&mut tls, AuthReply::NoSuchTunnel)
            .await
            .ok();
        anyhow::bail!("no such tunnel: {}", prelude.tunnel_id);
    };

    {
        let slot = handle.sender.lock().await;
        if slot.is_some() {
            drop(slot);
            proto::write_reply(&mut tls, AuthReply::AlreadyAttached)
                .await
                .ok();
            anyhow::bail!("already attached: {}", handle.subdomain);
        }
    }

    proto::write_reply(&mut tls, AuthReply::Ok).await?;

    let (send_request, conn) = h2::client::handshake(tls)
        .await
        .context("h2 client handshake")?;

    *handle.sender.lock().await = Some(send_request);
    tracing::info!(subdomain = %handle.subdomain, "tunnel attached");

    let drive = conn.await;

    *handle.sender.lock().await = None;
    state.tunnels.remove(&handle.subdomain);
    state.by_id.remove(&handle.tunnel_id);
    tracing::info!(subdomain = %handle.subdomain, "tunnel detached");

    drive.context("h2 conn drive")?;
    Ok(())
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
        return (StatusCode::NOT_FOUND, "tunneld: unknown path").into_response();
    }
    if let Some(sub) = host.strip_suffix(&format!(".{domain}")) {
        if sub.is_empty() || sub.contains('.') {
            return (
                StatusCode::NOT_FOUND,
                "nested or empty subdomain unsupported",
            )
                .into_response();
        }
        return proxy_request(state, sub.to_string(), req).await;
    }
    (StatusCode::NOT_FOUND, format!("unknown host: {host}")).into_response()
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
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
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

    let tunnel_id = Uuid::new_v4();
    let handle = Arc::new(TunnelHandle {
        subdomain: subdomain.clone(),
        tunnel_id,
        sender: Mutex::new(None),
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
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
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
        return (StatusCode::UNAUTHORIZED, "bad token").into_response();
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
    let Some(tunnel) = state.tunnels.get(&sub).map(|e| e.value().clone()) else {
        return (StatusCode::BAD_GATEWAY, format!("no tunnel for {sub}")).into_response();
    };
    let mut send_request = match tunnel.sender.lock().await.clone() {
        Some(s) => s,
        None => return (StatusCode::BAD_GATEWAY, "tunnel client offline").into_response(),
    };

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
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("h2 send: {e}")).into_response(),
    };

    tokio::spawn(async move {
        let mut body = body;
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                if !data.is_empty() && send_body.send_data(data, false).is_err() {
                    return;
                }
            }
        }
        let _ = send_body.send_data(Bytes::new(), true);
    });

    let resp = match tokio::time::timeout(HEAD_TIMEOUT, resp_future).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return (StatusCode::BAD_GATEWAY, format!("upstream: {e}")).into_response();
        }
        Err(_) => return (StatusCode::GATEWAY_TIMEOUT, "upstream timeout").into_response(),
    };

    let (parts, mut h2_body) = resp.into_parts();

    let body_stream = async_stream::stream! {
        while let Some(chunk) = h2_body.data().await {
            match chunk {
                Ok(data) => {
                    let _ = h2_body.flow_control().release_capacity(data.len());
                    yield Ok::<_, std::io::Error>(data);
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("response build: {e}"),
        )
            .into_response()
    })
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
