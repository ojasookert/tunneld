use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Args as ClapArgs;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{net::TcpStream, sync::mpsc};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::proto::{Frame, FrameType, ReqHead, RespHead, MAX_BODY_CHUNK};

const WRITE_QUEUE: usize = 256;
const PER_REQ_QUEUE: usize = 64;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Public base URL of tunneld server, e.g. https://tunnel.le.ht
    #[arg(long, env = "TUNNELD_URL")]
    pub url: String,
    /// Bearer token (server's TUNNELD_SECRET)
    #[arg(long, env = "TUNNELD_SECRET")]
    pub secret: String,
    /// Local upstream address, e.g. 127.0.0.1:3000
    #[arg(long)]
    pub local: String,
    /// Optional fixed subdomain name (else random)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Serialize)]
struct CreateReq<'a> {
    name: Option<&'a str>,
}

#[derive(Deserialize, Debug)]
struct CreateResp {
    #[allow(dead_code)]
    tunnel_id: String,
    subdomain: String,
    public_url: String,
    ws_url: String,
}

pub async fn run(args: Args) -> Result<()> {
    let create_url = format!("{}/api/tunnels", args.url.trim_end_matches('/'));
    let body = CreateReq {
        name: args.name.as_deref(),
    };
    let resp = reqwest::Client::new()
        .post(&create_url)
        .bearer_auth(&args.secret)
        .json(&body)
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

    let ws_url = if info.ws_url.contains('?') {
        format!(
            "{}&token={}",
            info.ws_url,
            urlencoding::encode_str(&args.secret)
        )
    } else {
        format!(
            "{}?token={}",
            info.ws_url,
            urlencoding::encode_str(&args.secret)
        )
    };

    let (ws, _) = connect_async(&ws_url).await.context("ws connect")?;
    tracing::info!("ws connected");
    let (mut sink, mut stream) = ws.split();

    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(WRITE_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(f) = out_rx.recv().await {
            if sink
                .send(Message::Binary(f.encode().to_vec()))
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let pending: Arc<DashMap<u32, mpsc::Sender<Frame>>> = Arc::new(DashMap::new());
    let local = Arc::new(args.local);

    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = %e, "ws read");
                break;
            }
        };
        match msg {
            Message::Binary(bytes) => {
                let frame = match Frame::decode(&bytes) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "bad frame");
                        continue;
                    }
                };
                match frame.typ {
                    FrameType::ReqHead => {
                        let req_id = frame.request_id;
                        let (req_tx, req_rx) = mpsc::channel::<Frame>(PER_REQ_QUEUE);
                        pending.insert(req_id, req_tx);
                        let out = out_tx.clone();
                        let local = local.clone();
                        let pending2 = pending.clone();
                        tokio::spawn(async move {
                            let res = handle_request(frame, req_rx, out.clone(), &local).await;
                            if let Err(e) = res {
                                tracing::warn!(req_id, error = %e, "request failed");
                                let _ = out.send(Frame::end(FrameType::Cancel, req_id)).await;
                            }
                            pending2.remove(&req_id);
                        });
                    }
                    FrameType::ReqBody | FrameType::ReqEnd | FrameType::Cancel => {
                        if let Some(entry) = pending.get(&frame.request_id) {
                            let _ = entry.value().send(frame).await;
                        }
                    }
                    _ => {}
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    drop(out_tx);
    let _ = writer.await;
    Ok(())
}

async fn handle_request(
    head_frame: Frame,
    mut req_rx: mpsc::Receiver<Frame>,
    out_tx: mpsc::Sender<Frame>,
    local: &str,
) -> Result<()> {
    let req_id = head_frame.request_id;
    let head: ReqHead = serde_json::from_slice(&head_frame.payload).context("parse req head")?;

    let stream = TcpStream::connect(local)
        .await
        .context("connect upstream")?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "upstream conn closed");
        }
    });

    let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(PER_REQ_QUEUE);
    tokio::spawn(async move {
        while let Some(f) = req_rx.recv().await {
            match f.typ {
                FrameType::ReqBody if body_tx.send(Ok(f.payload)).await.is_err() => break,
                FrameType::ReqEnd | FrameType::Cancel => break,
                _ => {}
            }
        }
    });

    let body_stream = tokio_stream::wrappers::ReceiverStream::new(body_rx);
    let body = http_body_util::StreamBody::new(body_stream.map(|r| r.map(http_body::Frame::data)));
    let body: BoxBody<Bytes, std::io::Error> = BodyExt::boxed(body);

    let uri: Uri = head.uri.parse().unwrap_or_else(|_| Uri::from_static("/"));
    let mut builder = Request::builder().method(head.method.as_str()).uri(uri);
    for (k, v) in &head.headers {
        if k.eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder = builder.header("host", &head.host);

    let req = builder.body(body).context("build upstream request")?;
    let resp = sender
        .send_request(req)
        .await
        .context("send upstream request")?;

    let (parts, mut incoming) = resp.into_parts();
    let resp_head = RespHead {
        status: parts.status.as_u16(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
            .collect(),
    };
    out_tx
        .send(Frame::head_resp(req_id, &resp_head)?)
        .await
        .ok();

    while let Some(frame) = incoming.frame().await {
        let frame = frame.context("read upstream body")?;
        if let Ok(data) = frame.into_data() {
            for chunk in data.chunks(MAX_BODY_CHUNK) {
                let f = Frame::new(FrameType::RespBody, req_id, Bytes::copy_from_slice(chunk));
                out_tx.send(f).await.ok();
            }
        }
    }
    out_tx
        .send(Frame::end(FrameType::RespEnd, req_id))
        .await
        .ok();
    Ok(())
}

mod urlencoding {
    pub fn encode_str(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}
