use anyhow::{anyhow, Context, Result};
use base64::Engine;
use bytes::Bytes;
use clap::Args as ClapArgs;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use rustls_pki_types::ServerName;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use crate::proto::{self, AuthReply, Prelude};
use crate::tls;

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const WS_PIPE_BUF: usize = 16 * 1024;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Public base URL of tunneld server
    #[arg(long, env = "TUNNELD_URL", default_value = "https://tunnel.le.ht")]
    pub url: String,
    /// Bearer token (server's TUNNELD_SECRET)
    #[arg(long, env = "TUNNELD_SECRET")]
    pub secret: String,
    /// Local upstream address, e.g. 127.0.0.1:3000
    #[arg(long)]
    pub local: String,
    /// Override data-plane addr (else use server-provided connect_addr)
    #[arg(long, env = "TUNNELD_CONNECT_ADDR")]
    pub connect_addr: Option<String>,
    /// Skip TLS cert verification (testing only)
    #[arg(long, env = "TUNNELD_INSECURE")]
    pub insecure: bool,
}

#[derive(Deserialize, Debug)]
struct CreateResp {
    tunnel_id: Uuid,
    subdomain: String,
    public_url: String,
    connect_addr: String,
}

pub async fn run(args: Args) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let create_url = format!("{}/api/tunnels", args.url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&create_url)
        .bearer_auth(&args.secret)
        .send()
        .await
        .context("POST /api/tunnels")?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "create tunnel failed: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let info: CreateResp = resp.json().await.context("parse create resp")?;
    tracing::info!(public_url = %info.public_url, subdomain = %info.subdomain, "tunnel registered");
    println!("→ {}", info.public_url);
    println!("  forwarding to http://{}", args.local);

    let connect_addr = args.connect_addr.unwrap_or(info.connect_addr);
    let (sni_host, _) = connect_addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("connect_addr missing port: {connect_addr}"))?;

    let tls_config = tls::client_config(args.insecure).context("build client tls config")?;
    let connector = TlsConnector::from(tls_config);

    tracing::info!(addr = %connect_addr, "dialing data plane");
    let tcp = TcpStream::connect(&connect_addr)
        .await
        .context("data tcp connect")?;
    let _ = tcp.set_nodelay(true);
    let server_name = ServerName::try_from(sni_host.to_string())
        .map_err(|_| anyhow!("bad SNI host: {sni_host}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("tls handshake")?;

    let prelude = Prelude {
        tunnel_id: info.tunnel_id,
        token: args.secret.as_bytes().to_vec(),
    };
    prelude.write(&mut tls).await.context("write prelude")?;
    let reply = proto::read_reply(&mut tls).await.context("read reply")?;
    if reply != AuthReply::Ok {
        anyhow::bail!("server rejected the connection");
    }
    tracing::info!("data plane attached");

    // Enable Extended CONNECT (RFC 8441) so we can accept WebSocket-over-HTTP/2 streams.
    let mut h2_conn = h2::server::Builder::new()
        .enable_connect_protocol()
        .handshake(tls)
        .await
        .context("h2 server handshake")?;

    let local = Arc::new(args.local);
    while let Some(stream_result) = h2_conn.accept().await {
        let (req, respond) = match stream_result {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "h2 accept");
                break;
            }
        };
        let local = local.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(req, respond, &local).await {
                tracing::warn!(error = %e, "request failed");
            }
        });
    }

    Ok(())
}

async fn handle_request(
    h2_req: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    local: &str,
) -> Result<()> {
    // Detect Extended CONNECT (WebSocket-over-HTTP/2).
    let is_ws = h2_req.method() == http::Method::CONNECT
        && h2_req
            .extensions()
            .get::<h2::ext::Protocol>()
            .map(|p| p.as_str().eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
    if is_ws {
        handle_ws(h2_req, respond, local).await
    } else {
        handle_http(h2_req, respond, local).await
    }
}

async fn handle_http(
    h2_req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    local: &str,
) -> Result<()> {
    let stream = TcpStream::connect(local)
        .await
        .context("connect upstream")?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("http1 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream conn closed");
        }
    });

    let (parts, mut h2_body) = h2_req.into_parts();

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".into());
    let local_uri: Uri = path_and_query
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/"));

    let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        while let Some(chunk) = h2_body.data().await {
            match chunk {
                Ok(data) => {
                    let _ = h2_body.flow_control().release_capacity(data.len());
                    if !data.is_empty() && body_tx.send(Ok(data)).await.is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
    });
    let body_stream = tokio_stream::wrappers::ReceiverStream::new(body_rx);
    let body = http_body_util::StreamBody::new(body_stream.map(|r| r.map(http_body::Frame::data)));
    let body: BoxBody<Bytes, std::io::Error> = BodyExt::boxed(body);

    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(local_uri);
    for (k, v) in &parts.headers {
        if k.as_str().eq_ignore_ascii_case("host")
            || k.as_str().eq_ignore_ascii_case("content-length")
            || k.as_str().starts_with(':')
        {
            continue;
        }
        builder = builder.header(k.as_str(), v.clone());
    }
    if let Some(h) = parts.uri.authority().map(|a| a.as_str().to_string()) {
        builder = builder.header("host", h);
    }

    let upstream_req = builder.body(body).context("build upstream request")?;
    let upstream_resp = sender
        .send_request(upstream_req)
        .await
        .context("send upstream")?;

    let (uparts, mut uincoming) = upstream_resp.into_parts();

    let mut h2_resp_builder = http::Response::builder().status(uparts.status);
    for (k, v) in &uparts.headers {
        let lower = k.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
        ) {
            continue;
        }
        h2_resp_builder = h2_resp_builder.header(k.as_str(), v.clone());
    }
    let h2_resp = h2_resp_builder.body(()).context("build h2 response")?;

    let mut send_body = respond
        .send_response(h2_resp, false)
        .context("send_response")?;

    while let Some(frame) = uincoming.frame().await {
        let frame = frame.context("read upstream body")?;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                proto::send_h2_with_backpressure(&mut send_body, data, false)
                    .await
                    .context("send_data")?;
            }
        }
    }
    proto::send_h2_with_backpressure(&mut send_body, Bytes::new(), true)
        .await
        .context("send_data end")?;
    Ok(())
}

/// Bridge an h2 Extended CONNECT (RFC 8441) stream to an HTTP/1.1 WebSocket upstream.
///
/// Procedure: open an HTTP/1.1 connection to the upstream, send a fresh
/// `Upgrade: websocket` handshake with our own Sec-WebSocket-Key (the server
/// already authenticated the browser's handshake), take ownership of the raw
/// upgraded socket on a 101, then pipe bytes between the h2 stream and that
/// socket in both directions.
async fn handle_ws(
    h2_req: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    local: &str,
) -> Result<()> {
    let stream = TcpStream::connect(local)
        .await
        .context("connect upstream for ws")?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("http1 handshake (ws)")?;
    // Drive the upstream connection and keep upgrades alive.
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "ws upstream conn ended");
        }
    });

    let (parts, h2_body) = h2_req.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".into());
    let local_uri: Uri = path_and_query
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/"));
    let host_hdr = parts
        .uri
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_else(|| String::from("localhost"));

    let key = new_ws_key();

    let mut builder = Request::builder()
        .method(http::Method::GET)
        .uri(local_uri)
        .header(http::header::HOST, host_hdr)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_KEY, &key)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13");

    for (k, v) in &parts.headers {
        let name = k.as_str();
        // Don't double up on the headers we just set, and skip h2 pseudo-headers
        // and hop-by-hop stuff.
        if name.starts_with(':')
            || matches!(
                name.to_ascii_lowercase().as_str(),
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
            )
        {
            continue;
        }
        builder = builder.header(name, v.clone());
    }

    let upstream_req = builder
        .body(Empty::<Bytes>::new())
        .context("build upstream ws request")?;
    let upstream_resp = sender
        .send_request(upstream_req)
        .await
        .context("send upstream ws request")?;

    if upstream_resp.status() != http::StatusCode::SWITCHING_PROTOCOLS {
        // Upstream refused the upgrade. Bubble the failure back as a non-200
        // h2 response so the browser sees an error.
        let status = upstream_resp.status();
        tracing::debug!(%status, "upstream did not switch protocols");
        let h2_resp = http::Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(())
            .context("build h2 502 response")?;
        let mut send_body = respond.send_response(h2_resp, false).ok().context("send 502")?;
        let _ = proto::send_h2_with_backpressure(&mut send_body, Bytes::new(), true).await;
        return Ok(());
    }

    // Capture sec-websocket-protocol / extensions before we lose access to headers.
    let mut h2_resp_builder = http::Response::builder().status(http::StatusCode::OK);
    for h in [
        http::header::SEC_WEBSOCKET_PROTOCOL,
        http::header::SEC_WEBSOCKET_EXTENSIONS,
    ] {
        if let Some(v) = upstream_resp.headers().get(&h) {
            h2_resp_builder = h2_resp_builder.header(h, v.clone());
        }
    }

    // Take ownership of the raw upgraded TCP stream.
    let upgraded = hyper::upgrade::on(upstream_resp)
        .await
        .context("hyper upgrade (upstream)")?;

    let h2_resp = h2_resp_builder.body(()).context("build h2 200 response")?;
    let send_body = respond
        .send_response(h2_resp, false)
        .context("send h2 200 (ws)")?;

    pipe_ws(h2_body, send_body, upgraded).await
}

async fn pipe_ws(
    h2_recv: h2::RecvStream,
    h2_send: h2::SendStream<Bytes>,
    upgraded: hyper::upgrade::Upgraded,
) -> Result<()> {
    let upgraded = TokioIo::new(upgraded);
    let (read_half, write_half) = tokio::io::split(upgraded);
    let a = tokio::spawn(copy_h2_to_writer(h2_recv, write_half));
    let b = tokio::spawn(copy_reader_to_h2(read_half, h2_send));
    // When either side finishes, abort the other so we don't keep a half-open pipe forever.
    tokio::select! {
        _ = a => {}
        _ = b => {}
    }
    Ok(())
}

async fn copy_h2_to_writer(
    mut recv: h2::RecvStream,
    mut w: tokio::io::WriteHalf<TokioIo<hyper::upgrade::Upgraded>>,
) -> Result<()> {
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.context("h2 recv data")?;
        let len = chunk.len();
        if !chunk.is_empty() {
            w.write_all(&chunk).await.context("write to upstream")?;
        }
        let _ = recv.flow_control().release_capacity(len);
    }
    let _ = w.shutdown().await;
    Ok(())
}

async fn copy_reader_to_h2(
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

fn new_ws_key() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::STANDARD.encode(buf)
}

/// Compute Sec-WebSocket-Accept from a Sec-WebSocket-Key per RFC 6455.
#[allow(dead_code)]
pub fn ws_accept(key: &str) -> String {
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

use futures_util::StreamExt;
