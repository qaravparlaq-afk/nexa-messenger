//! Versioned server-facing protocol types.
//!
//! Ratchet headers are canonical, fixed-width metadata. They are not secret,
//! but the envelope AAD authenticates their exact encoded bytes.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

pub const PROTOCOL_VERSION: u16 = 1;
pub const RATCHET_HEADER_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion(pub u16);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekeyPublic { pub key_id: u32, pub public_key: [u8; 32] }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub protocol_version: ProtocolVersion,
    pub device_id: [u8; 16],
    pub identity_signing_key: [u8; 32],
    pub identity_agreement_key: [u8; 32],
    pub signed_prekey_id: u32,
    pub signed_prekey: [u8; 32],
    #[serde(with = "BigArray")]
    pub signed_prekey_signature: [u8; 64],
    pub one_time_prekeys: Vec<OneTimePrekeyPublic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetHeader {
    pub version: u16,
    pub message_counter: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetHeaderError {
    Truncated,
    InvalidVersion,
    TrailingBytes,
}

impl RatchetHeader {
    pub const ENCODED_LEN: usize = 10;

    pub fn new(message_counter: u64) -> Self {
        Self { version: RATCHET_HEADER_VERSION, message_counter }
    }

    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..2].copy_from_slice(&self.version.to_be_bytes());
        out[2..].copy_from_slice(&self.message_counter.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RatchetHeaderError> {
        if bytes.len() < Self::ENCODED_LEN {
            return Err(RatchetHeaderError::Truncated);
        }
        if bytes.len() > Self::ENCODED_LEN {
            return Err(RatchetHeaderError::TrailingBytes);
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != RATCHET_HEADER_VERSION {
            return Err(RatchetHeaderError::InvalidVersion);
        }
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&bytes[2..]);
        Ok(Self { version, message_counter: u64::from_be_bytes(counter) })
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageCodecError { Truncated, InvalidVersion, LengthOverflow, LengthMismatch, TrailingBytes }

impl EncryptedMessage {
    pub fn new(message_id: [u8; 16], conversation_id: [u8; 16], sender_device_id: [u8; 16], recipient_device_id: [u8; 16], ratchet_header: Vec<u8>, ciphertext: Vec<u8>, sent_at_ms: u64) -> Self {
        Self { version: ProtocolVersion(PROTOCOL_VERSION), message_id, conversation_id, sender_device_id, recipient_device_id, ratchet_header, ciphertext, sent_at_ms }
    }
    pub fn encode(&self) -> Result<Vec<u8>, MessageCodecError> {
        let header_len = u32::try_from(self.ratchet_header.len()).map_err(|_| MessageCodecError::LengthOverflow)?;
        let ciphertext_len = u32::try_from(self.ciphertext.len()).map_err(|_| MessageCodecError::LengthOverflow)?;
        let total = 2usize.checked_add(16 * 4).and_then(|v| v.checked_add(4)).and_then(|v| v.checked_add(self.ratchet_header.len())).and_then(|v| v.checked_add(4)).and_then(|v| v.checked_add(self.ciphertext.len())).and_then(|v| v.checked_add(8)).ok_or(MessageCodecError::LengthOverflow)?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&self.version.0.to_be_bytes()); out.extend_from_slice(&self.message_id); out.extend_from_slice(&self.conversation_id); out.extend_from_slice(&self.sender_device_id); out.extend_from_slice(&self.recipient_device_id);
        out.extend_from_slice(&header_len.to_be_bytes()); out.extend_from_slice(&self.ratchet_header); out.extend_from_slice(&ciphertext_len.to_be_bytes()); out.extend_from_slice(&self.ciphertext); out.extend_from_slice(&self.sent_at_ms.to_be_bytes()); Ok(out)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageCodecError> {
        let mut cursor = 0usize; let version = read_u16(bytes, &mut cursor)?; if version != PROTOCOL_VERSION { return Err(MessageCodecError::InvalidVersion); }
        let message_id = read_array_16(bytes, &mut cursor)?; let conversation_id = read_array_16(bytes, &mut cursor)?; let sender_device_id = read_array_16(bytes, &mut cursor)?; let recipient_device_id = read_array_16(bytes, &mut cursor)?;
        let header_len = read_u32(bytes, &mut cursor)? as usize; let ratchet_header = read_vec(bytes, &mut cursor, header_len)?; let ciphertext_len = read_u32(bytes, &mut cursor)? as usize; let ciphertext = read_vec(bytes, &mut cursor, ciphertext_len)?; let sent_at_ms = read_u64(bytes, &mut cursor)?;
        if cursor != bytes.len() { return Err(MessageCodecError::TrailingBytes); }
        Ok(Self { version: ProtocolVersion(version), message_id, conversation_id, sender_device_id, recipient_device_id, ratchet_header, ciphertext, sent_at_ms })
    }
}

pub fn encode_message_ack(message_id: &[u8; 16]) -> [u8; 16] { *message_id }
pub fn decode_message_ack(bytes: &[u8]) -> Result<[u8; 16], MessageCodecError> {
    if bytes.len() != 16 { return if bytes.len() < 16 { Err(MessageCodecError::Truncated) } else { Err(MessageCodecError::LengthMismatch) }; }
    let mut out = [0u8; 16]; out.copy_from_slice(bytes); Ok(out)
}
fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, MessageCodecError> { if bytes.len().saturating_sub(*cursor) < 2 { return Err(MessageCodecError::Truncated); } let value = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]); *cursor += 2; Ok(value) }
fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, MessageCodecError> { if bytes.len().saturating_sub(*cursor) < 4 { return Err(MessageCodecError::Truncated); } let value = u32::from_be_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap()); *cursor += 4; Ok(value) }
fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, MessageCodecError> { if bytes.len().saturating_sub(*cursor) < 8 { return Err(MessageCodecError::Truncated); } let value = u64::from_be_bytes(bytes[*cursor..*cursor + 8].try_into().unwrap()); *cursor += 8; Ok(value) }
fn read_array_16(bytes: &[u8], cursor: &mut usize) -> Result<[u8; 16], MessageCodecError> { if bytes.len().saturating_sub(*cursor) < 16 { return Err(MessageCodecError::Truncated); } let mut out = [0u8; 16]; out.copy_from_slice(&bytes[*cursor..*cursor + 16]); *cursor += 16; Ok(out) }
fn read_vec(bytes: &[u8], cursor: &mut usize, len: usize) -> Result<Vec<u8>, MessageCodecError> { if bytes.len().saturating_sub(*cursor) < len { return Err(MessageCodecError::Truncated); } let end = cursor.checked_add(len).ok_or(MessageCodecError::LengthOverflow)?; let out = bytes[*cursor..end].to_vec(); *cursor = end; Ok(out) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn prekey_bundle_has_version_and_public_prekeys() {
        let bundle = PreKeyBundle { protocol_version: ProtocolVersion(PROTOCOL_VERSION), device_id: [1; 16], identity_signing_key: [2; 32], identity_agreement_key: [3; 32], signed_prekey_id: 4, signed_prekey: [5; 32], signed_prekey_signature: [6; 64], one_time_prekeys: vec![OneTimePrekeyPublic { key_id: 7, public_key: [8; 32] }] };
        assert_eq!(bundle.protocol_version.0, 1); assert_eq!(bundle.one_time_prekeys.len(), 1);
    }
    #[test] fn ratchet_header_is_canonical_and_strict() {
        let header = RatchetHeader::new(42);
        let encoded = header.encode();
        assert_eq!(encoded.len(), RatchetHeader::ENCODED_LEN);
        assert_eq!(RatchetHeader::decode(&encoded).unwrap(), header);
        assert_eq!(RatchetHeader::decode(&encoded[..9]), Err(RatchetHeaderError::Truncated));
        let mut invalid = encoded.to_vec(); invalid[1] = 2;
        assert_eq!(RatchetHeader::decode(&invalid), Err(RatchetHeaderError::InvalidVersion));
        let mut trailing = encoded.to_vec(); trailing.push(0);
        assert_eq!(RatchetHeader::decode(&trailing), Err(RatchetHeaderError::TrailingBytes));
    }
    #[test] fn encrypted_message_binary_codec_round_trips() {
        let message = EncryptedMessage::new([1; 16], [2; 16], [3; 16], [4; 16], RatchetHeader::new(0).encode().to_vec(), vec![7, 8, 9], 123); let encoded = message.encode().unwrap(); assert_eq!(EncryptedMessage::decode(&encoded).unwrap(), message);
    }
    #[test] fn message_codec_rejects_truncation_and_trailing_data() {
        let message = EncryptedMessage::new([1; 16], [2; 16], [3; 16], [4; 16], vec![5], vec![6], 123); let mut encoded = message.encode().unwrap(); encoded.pop(); assert_eq!(EncryptedMessage::decode(&encoded), Err(MessageCodecError::Truncated)); let mut encoded = message.encode().unwrap(); encoded.push(0); assert_eq!(EncryptedMessage::decode(&encoded), Err(MessageCodecError::TrailingBytes));
    }
    #[test] fn ack_codec_is_exactly_one_message_id() {
        let id = [9; 16]; assert_eq!(decode_message_ack(&encode_message_ack(&id)).unwrap(), id); assert_eq!(decode_message_ack(&[0; 15]), Err(MessageCodecError::Truncated)); assert_eq!(decode_message_ack(&[0; 17]), Err(MessageCodecError::LengthMismatch));
    }
}
