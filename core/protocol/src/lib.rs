//! Versioned server-facing protocol types.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekeyPublic {
    pub key_id: u32,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub protocol_version: ProtocolVersion,
    pub device_id: [u8; 16],
    pub identity_signing_key: [u8; 32],
    pub signed_prekey_id: u32,
    pub signed_prekey: [u8; 32],
    #[serde(with = "BigArray")]
    pub signed_prekey_signature: [u8; 64],
    pub one_time_prekeys: Vec<OneTimePrekeyPublic>,
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
        message_id: [u8; 16], conversation_id: [u8; 16],
        sender_device_id: [u8; 16], recipient_device_id: [u8; 16],
        ratchet_header: Vec<u8>, ciphertext: Vec<u8>, sent_at_ms: u64,
    ) -> Self {
        Self {
            version: ProtocolVersion(PROTOCOL_VERSION),
            message_id, conversation_id, sender_device_id, recipient_device_id,
            ratchet_header, ciphertext, sent_at_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prekey_bundle_has_version_and_public_prekeys() {
        let bundle = PreKeyBundle {
            protocol_version: ProtocolVersion(PROTOCOL_VERSION),
            device_id: [1; 16],
            identity_signing_key: [2; 32],
            signed_prekey_id: 3,
            signed_prekey: [4; 32],
            signed_prekey_signature: [5; 64],
            one_time_prekeys: vec![OneTimePrekeyPublic { key_id: 6, public_key: [7; 32] }],
        };
        assert_eq!(bundle.protocol_version.0, 1);
        assert_eq!(bundle.one_time_prekeys.len(), 1);
    }
}
