//! Versioned server-facing protocol types.
//!
//! The server-facing objects contain public key material, routing metadata and
//! ciphertext. They do not model plaintext message content.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub protocol_version: ProtocolVersion,
    pub device_id: [u8; 16],
    pub identity_signing_key: [u8; 32],
    pub signed_prekey_id: u32,
    pub signed_prekey: [u8; 32],
    pub signed_prekey_signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub version: ProtocolVersion,
    pub message_id: [u8; 16],
    pub conversation_id: [u8; 16],
    pub sender_device_id: [u8; 16],
    pub recipient_device_id: [u8; 16],
    pub ratchet_header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub sent_at_ms: u64,
}

impl EncryptedMessage {
    pub fn new(
        message_id: [u8; 16],
        conversation_id: [u8; 16],
        sender_device_id: [u8; 16],
        recipient_device_id: [u8; 16],
        ratchet_header: Vec<u8>,
        ciphertext: Vec<u8>,
        sent_at_ms: u64,
    ) -> Self {
        Self {
            version: ProtocolVersion(PROTOCOL_VERSION),
            message_id,
            conversation_id,
            sender_device_id,
            recipient_device_id,
            ratchet_header,
            ciphertext,
            sent_at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_is_ciphertext_only() {
        let msg = EncryptedMessage::new(
            [1; 16], [2; 16], [3; 16], [4; 16],
            vec![9], vec![8, 7], 1
        );
        assert_eq!(msg.version.0, PROTOCOL_VERSION);
        assert_eq!(msg.ciphertext, vec![8, 7]);
    }

    #[test]
    fn prekey_bundle_is_versioned() {
        let bundle = PreKeyBundle {
            protocol_version: ProtocolVersion(PROTOCOL_VERSION),
            device_id: [1; 16],
            identity_signing_key: [2; 32],
            signed_prekey_id: 3,
            signed_prekey: [4; 32],
            signed_prekey_signature: [5; 64],
        };
        assert_eq!(bundle.protocol_version.0, 1);
    }
}
