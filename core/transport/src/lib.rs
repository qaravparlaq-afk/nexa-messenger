//! Transport primitives for M. The transport never interprets plaintext.
#![forbid(unsafe_code)]

use std::collections::VecDeque;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME: usize = 16 * 1024 * 1024;
pub const MAX_QUEUE: usize = 1024;

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
    EmptyPayload,
    PayloadTooLarge,
    LengthMismatch,
}

impl Frame {
    pub fn new(kind: u8, flags: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        if payload.is_empty() { return Err(FrameError::EmptyPayload); }
        if payload.len() > MAX_FRAME { return Err(FrameError::PayloadTooLarge); }
        Ok(Self { header: FrameHeader { version: PROTOCOL_VERSION, kind, flags, payload_len: payload.len() as u32 }, payload })
    }

    pub fn validate(&self) -> Result<(), FrameError> {
        if self.header.version != PROTOCOL_VERSION { return Err(FrameError::InvalidVersion); }
        if self.payload.is_empty() { return Err(FrameError::EmptyPayload); }
        if self.payload.len() > MAX_FRAME { return Err(FrameError::PayloadTooLarge); }
        if self.header.payload_len as usize != self.payload.len() { return Err(FrameError::LengthMismatch); }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError { Full }

/// Bounded outbound queue. Dropping messages is explicit: callers decide whether to retry.
pub struct OutboundQueue { inner: VecDeque<Frame>, capacity: usize }

impl OutboundQueue {
    pub fn new(capacity: usize) -> Self { Self { inner: VecDeque::new(), capacity: capacity.min(MAX_QUEUE) } }
    pub fn push(&mut self, frame: Frame) -> Result<(), QueueError> {
        if self.inner.len() >= self.capacity { return Err(QueueError::Full); }
        self.inner.push_back(frame); Ok(())
    }
    pub fn pop(&mut self) -> Option<Frame> { self.inner.pop_front() }
    pub fn len(&self) -> usize { self.inner.len() }
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_validates() {
        let frame = Frame::new(1, 0, b"ciphertext".to_vec()).unwrap();
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn queue_is_bounded() {
        let mut q = OutboundQueue::new(1);
        let f = Frame::new(1, 0, vec![1]).unwrap();
        q.push(f.clone()).unwrap();
        assert_eq!(q.push(f), Err(QueueError::Full));
        assert_eq!(q.len(), 1);
        assert!(q.pop().is_some());
        assert!(q.is_empty());
    }

    #[test]
    fn rejects_oversized_frame() {
        assert_eq!(Frame::new(1, 0, vec![0; MAX_FRAME + 1]), Err(FrameError::PayloadTooLarge));
    }
}
