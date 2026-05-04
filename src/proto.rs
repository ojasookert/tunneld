use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

pub const MAX_BODY_CHUNK: usize = 256 * 1024;

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FrameType {
    ReqHead = 0x01,
    ReqBody = 0x02,
    ReqEnd = 0x03,
    RespHead = 0x11,
    RespBody = 0x12,
    RespEnd = 0x13,
    Cancel = 0xF0,
}

impl TryFrom<u8> for FrameType {
    type Error = ProtoError;
    fn try_from(b: u8) -> Result<Self, Self::Error> {
        Ok(match b {
            0x01 => Self::ReqHead,
            0x02 => Self::ReqBody,
            0x03 => Self::ReqEnd,
            0x11 => Self::RespHead,
            0x12 => Self::RespBody,
            0x13 => Self::RespEnd,
            0xF0 => Self::Cancel,
            other => return Err(ProtoError::UnknownFrameType(other)),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("frame too short ({0} bytes)")]
    FrameTooShort(usize),
    #[error("unknown frame type 0x{0:02X}")]
    UnknownFrameType(u8),
    #[error("invalid head: {0}")]
    InvalidHead(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReqHead {
    pub method: String,
    pub uri: String,
    pub host: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RespHead {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub typ: FrameType,
    pub request_id: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn new(typ: FrameType, request_id: u32, payload: impl Into<Bytes>) -> Self {
        Self { typ, request_id, payload: payload.into() }
    }

    pub fn head_req(request_id: u32, head: &ReqHead) -> serde_json::Result<Self> {
        Ok(Self::new(FrameType::ReqHead, request_id, serde_json::to_vec(head)?))
    }

    pub fn head_resp(request_id: u32, head: &RespHead) -> serde_json::Result<Self> {
        Ok(Self::new(FrameType::RespHead, request_id, serde_json::to_vec(head)?))
    }

    pub fn end(typ: FrameType, request_id: u32) -> Self {
        Self::new(typ, request_id, Bytes::new())
    }

    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + self.payload.len());
        buf.put_u8(self.typ as u8);
        buf.put_u32(self.request_id);
        buf.put_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        if bytes.len() < 5 {
            return Err(ProtoError::FrameTooShort(bytes.len()));
        }
        let typ = FrameType::try_from(bytes[0])?;
        let request_id = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let payload = Bytes::copy_from_slice(&bytes[5..]);
        Ok(Self { typ, request_id, payload })
    }
}
