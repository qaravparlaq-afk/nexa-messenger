//! Canonical wire envelope for encrypted NEXA messages.
//! Plaintext is never represented here.

#![forbid(unsafe_code)]

use nexa_protocol::{EncryptedMessage, ProtocolVersion, PROTOCOL_VERSION};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

const MAX_HEADER: usize = 256;
const MAX_CIPHERTEXT: usize = 1024 * 1024 * 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    Decode,
    UnsupportedVersion,
    HeaderTooLarge,
    CiphertextTooLarge,
    InvalidIds,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEnvelope {
    pub version: ProtocolVersion,
    pub message_id: [u8; 16],
    pub conversation_id: [u8; 16],
    pub sender_device_id: [u8; 16],
    pub recipient_device_id: [u8; 16],
    pub ratchet_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl From<EncryptedMessage> for WireEnvelope {
    fn from(m: EncryptedMessage) -> Self {
        Self {
            version: m.version,
            message_id: m.message_id,
            conversation_id: m.conversation_id,
            sender_device_id: m.sender_device_id,
            recipient_device_id: m.recipient_device_id,
            ratchet_header: m.ratchet_header,
            ciphertext: m.ciphertext,
        }
    }
}

impl WireEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        to_allocvec(self).map_err(|_| EnvelopeError::Decode)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let value: Self = from_bytes(bytes).map_err(|_| EnvelopeError::Decode)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.version.0 != PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if self.ratchet_header.len() > MAX_HEADER {
            return Err(EnvelopeError::HeaderTooLarge);
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT {
            return Err(EnvelopeError::CiphertextTooLarge);
        }
        if self.message_id == [0; 16] || self.conversation_id == [0; 16] {
            return Err(EnvelopeError::InvalidIds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WireEnvelope {
        WireEnvelope {
            version: ProtocolVersion(PROTOCOL_VERSION),
            message_id: [1; 16],
            conversation_id: [2; 16],
            sender_device_id: [3; 16],
            recipient_device_id: [4; 16],
            ratchet_header: vec![5, 6],
            ciphertext: vec![7, 8, 9],
        }
    }

    #[test]
    fn round_trip() {
        let e = sample();
        let bytes = e.encode().unwrap();
        assert_eq!(WireEnvelope::decode(&bytes).unwrap(), e);
    }

    #[test]
    fn oversized_header_is_rejected() {
        let mut e = sample();
        e.ratchet_header = vec![0; MAX_HEADER + 1];
        assert_eq!(e.encode(), Err(EnvelopeError::HeaderTooLarge));
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut e = sample();
        e.version = ProtocolVersion(PROTOCOL_VERSION + 1);
        assert_eq!(e.encode(), Err(EnvelopeError::UnsupportedVersion));
    }
}
