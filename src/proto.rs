use anyhow::{anyhow, Result};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Send `data` over an h2 SendStream while respecting the remote flow-control
/// window. Without this, send_data queues into h2's local buffer regardless of
/// downstream consumer speed, letting the upstream HTTP body flood RAM.
pub async fn send_h2_with_backpressure(
    send: &mut h2::SendStream<Bytes>,
    mut data: Bytes,
    end: bool,
) -> Result<()> {
    if data.is_empty() {
        send.send_data(data, end)?;
        return Ok(());
    }
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx)).await;
        let cap = match cap {
            Some(Ok(c)) if c > 0 => c,
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Err(e.into()),
            None => return Ok(()),
        };
        let take = cap.min(data.len());
        let chunk = data.split_to(take);
        let is_last = data.is_empty() && end;
        send.send_data(chunk, is_last)?;
    }
    Ok(())
}

pub const MAGIC: [u8; 8] = *b"TUNNELD\0";
pub const VERSION: u8 = 1;
pub const MAX_TOKEN_LEN: usize = 128;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthReply {
    Ok,
    Reject,
}

pub struct Prelude {
    pub tunnel_id: Uuid,
    pub token: Vec<u8>,
}

impl Prelude {
    pub async fn write<W: AsyncWriteExt + Unpin>(&self, w: &mut W) -> Result<()> {
        if self.token.len() > MAX_TOKEN_LEN {
            return Err(anyhow!("token too long"));
        }
        w.write_all(&MAGIC).await?;
        w.write_all(&[VERSION]).await?;
        w.write_all(self.tunnel_id.as_bytes()).await?;
        w.write_all(&[self.token.len() as u8]).await?;
        w.write_all(&self.token).await?;
        w.flush().await?;
        Ok(())
    }

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Self> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).await?;
        if magic != MAGIC {
            return Err(anyhow!("bad magic"));
        }
        let mut version = [0u8; 1];
        r.read_exact(&mut version).await?;
        if version[0] != VERSION {
            return Err(anyhow!("unsupported version: {}", version[0]));
        }
        let mut id_bytes = [0u8; 16];
        r.read_exact(&mut id_bytes).await?;
        let tunnel_id = Uuid::from_bytes(id_bytes);
        let mut len = [0u8; 1];
        r.read_exact(&mut len).await?;
        let n = len[0] as usize;
        if n > MAX_TOKEN_LEN {
            return Err(anyhow!("token len {} > max {}", n, MAX_TOKEN_LEN));
        }
        let mut token = vec![0u8; n];
        r.read_exact(&mut token).await?;
        Ok(Self { tunnel_id, token })
    }
}

pub async fn write_reply<W: AsyncWriteExt + Unpin>(w: &mut W, reply: AuthReply) -> Result<()> {
    let b: u8 = match reply {
        AuthReply::Ok => 0x00,
        AuthReply::Reject => 0xff,
    };
    w.write_all(&[b]).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_reply<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<AuthReply> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).await?;
    Ok(if b[0] == 0x00 {
        AuthReply::Ok
    } else {
        AuthReply::Reject
    })
}
