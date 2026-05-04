use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use clap::Args as ClapArgs;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use uuid::Uuid;

use crate::proto::{self, AuthReply, Prelude};
use crate::tls;

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

    let mut h2_conn = h2::server::handshake(tls)
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

use futures_util::StreamExt;
