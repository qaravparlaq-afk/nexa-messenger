//! Transport primitives for M. The transport never interprets plaintext.
#![forbid(unsafe_code)]

use std::collections::VecDeque;

pub const PROTOCOL_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 8;
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
pub const MAX_QUEUE: usize = 1024;

/// Server-facing frame types. Payloads remain opaque encrypted protocol data.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    ClientHello = 1,
    EncryptedMessage = 2,
    MessageAck = 3,
    MessageBatch = 4,
    PreKeyBundle = 5,
    PreKeyRequest = 6,
    Ping = 7,
    Pong = 8,
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::EncryptedMessage),
            3 => Ok(Self::MessageAck),
            4 => Ok(Self::MessageBatch),
            5 => Ok(Self::PreKeyBundle),
            6 => Ok(Self::PreKeyRequest),
            7 => Ok(Self::Ping),
            8 => Ok(Self::Pong),
            _ => Err(FrameError::UnknownKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u16,
    pub kind: u8,
    pub flags: u8,
    pub payload_len: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    InvalidVersion,
    UnknownKind,
    EmptyPayload,
    PayloadTooLarge,
    LengthMismatch,
    Truncated,
}

impl Frame {
    pub fn new(kind: FrameKind, flags: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        if payload.is_empty() {
            return Err(FrameError::EmptyPayload);
        }
        if payload.len() > MAX_FRAME {
            return Err(FrameError::PayloadTooLarge);
        }
        Ok(Self {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                kind: kind as u8,
                flags,
                payload_len: payload.len() as u32,
            },
            payload,
        })
    }

    pub fn kind(&self) -> Result<FrameKind, FrameError> {
        FrameKind::try_from(self.header.kind)
    }

    pub fn validate(&self) -> Result<(), FrameError> {
        if self.header.version != PROTOCOL_VERSION {
            return Err(FrameError::InvalidVersion);
        }
        self.kind()?;
        if self.payload.is_empty() {
            return Err(FrameError::EmptyPayload);
        }
        if self.payload.len() > MAX_FRAME {
            return Err(FrameError::PayloadTooLarge);
        }
        if self.header.payload_len as usize != self.payload.len() {
            return Err(FrameError::LengthMismatch);
        }
        Ok(())
    }

    /// Encodes the stable wire header followed by the opaque payload.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FrameError> {
        self.validate()?;
        let total = HEADER_LEN
            .checked_add(self.payload.len())
            .ok_or(FrameError::PayloadTooLarge)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.header.version.to_be_bytes());
        out.push(self.header.kind);
        out.push(self.header.flags);
        out.extend_from_slice(&self.header.payload_len.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a complete frame. No plaintext parsing is performed here.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < HEADER_LEN {
            return Err(FrameError::Truncated);
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        let kind = bytes[2];
        let flags = bytes[3];
        let payload_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let payload_len_usize = payload_len as usize;
        if payload_len_usize == 0 {
            return Err(FrameError::EmptyPayload);
        }
        if payload_len_usize > MAX_FRAME {
            return Err(FrameError::PayloadTooLarge);
        }
        let expected = HEADER_LEN
            .checked_add(payload_len_usize)
            .ok_or(FrameError::PayloadTooLarge)?;
        if bytes.len() != expected {
            return Err(FrameError::LengthMismatch);
        }
        let frame = Self {
            header: FrameHeader { version, kind, flags, payload_len },
            payload: bytes[HEADER_LEN..].to_vec(),
        };
        frame.validate()?;
        Ok(frame)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Full,
}

/// Bounded outbound queue. Dropping messages is explicit: callers decide whether to retry.
pub struct OutboundQueue {
    inner: VecDeque<Frame>,
    capacity: usize,
}

impl OutboundQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: VecDeque::new(),
            capacity: capacity.min(MAX_QUEUE),
        }
    }

    pub fn push(&mut self, frame: Frame) -> Result<(), QueueError> {
        if self.inner.len() >= self.capacity {
            return Err(QueueError::Full);
        }
        self.inner.push_back(frame);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Frame> {
        self.inner.pop_front()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_validates() {
        let frame = Frame::new(FrameKind::EncryptedMessage, 0, b"ciphertext".to_vec()).unwrap();
        assert_eq!(frame.kind().unwrap(), FrameKind::EncryptedMessage);
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn frame_round_trips_binary_encoding() {
        let frame = Frame::new(FrameKind::EncryptedMessage, 3, b"ciphertext".to_vec()).unwrap();
        let encoded = frame.to_bytes().unwrap();
        assert_eq!(Frame::from_bytes(&encoded).unwrap(), frame);
    }

    #[test]
    fn truncated_wire_frame_is_rejected() {
        assert_eq!(Frame::from_bytes(&[0, 1, 2]), Err(FrameError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let frame = Frame::new(FrameKind::Ping, 0, vec![1]).unwrap();
        let mut encoded = frame.to_bytes().unwrap();
        encoded.push(2);
        assert_eq!(Frame::from_bytes(&encoded), Err(FrameError::LengthMismatch));
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let frame = Frame {
            header: FrameHeader {
                version: PROTOCOL_VERSION,
                kind: 255,
                flags: 0,
                payload_len: 1,
            },
            payload: vec![1],
        };
        assert_eq!(frame.validate(), Err(FrameError::UnknownKind));
    }

    #[test]
    fn queue_is_bounded() {
        let mut q = OutboundQueue::new(1);
        let f = Frame::new(FrameKind::EncryptedMessage, 0, vec![1]).unwrap();
        q.push(f.clone()).unwrap();
        assert_eq!(q.push(f), Err(QueueError::Full));
        assert_eq!(q.len(), 1);
        assert!(q.pop().is_some());
        assert!(q.is_empty());
    }

    #[test]
    fn rejects_oversized_frame() {
        assert_eq!(
            Frame::new(FrameKind::EncryptedMessage, 0, vec![0; MAX_FRAME + 1]),
            Err(FrameError::PayloadTooLarge)
        );
    }
}
