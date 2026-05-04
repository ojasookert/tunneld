use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub const MAGIC: [u8; 8] = *b"TUNNELD\0";
pub const VERSION: u8 = 1;
pub const MAX_TOKEN_LEN: usize = 128;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthReply {
    Ok = 0x00,
    BadToken = 0x01,
    NoSuchTunnel = 0x02,
    AlreadyAttached = 0x03,
    Generic = 0xff,
}

impl AuthReply {
    pub fn message(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BadToken => "bad token",
            Self::NoSuchTunnel => "no such tunnel",
            Self::AlreadyAttached => "tunnel already attached",
            Self::Generic => "generic error",
        }
    }
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
    w.write_all(&[reply as u8]).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_reply<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<AuthReply> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).await?;
    Ok(match b[0] {
        0x00 => AuthReply::Ok,
        0x01 => AuthReply::BadToken,
        0x02 => AuthReply::NoSuchTunnel,
        0x03 => AuthReply::AlreadyAttached,
        _ => AuthReply::Generic,
    })
}
