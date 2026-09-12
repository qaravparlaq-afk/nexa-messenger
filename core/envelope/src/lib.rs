//! Canonical wire envelope for encrypted M messages.
//! Plaintext is never represented here.

#![forbid(unsafe_code)]

use nexa_protocol::{EncryptedMessage, ProtocolVersion, PROTOCOL_VERSION};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

const MAX_HEADER: usize = 256;
const MAX_CIPHERTEXT: usize = 1024 * 1024 * 16;
const AAD_DOMAIN: &[u8] = b"M/ENVELOPE-AAD/v1";

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
    pub sent_at_ms: u64,
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
            sent_at_ms: m.sent_at_ms,
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

    /// Canonical authenticated metadata. Ciphertext is deliberately excluded.
    pub fn aad(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate_metadata()?;
        let mut out = Vec::with_capacity(AAD_DOMAIN.len() + 2 + 16 * 4 + 4 + self.ratchet_header.len() + 8);
        out.extend_from_slice(AAD_DOMAIN);
        out.extend_from_slice(&self.version.0.to_be_bytes());
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.conversation_id);
        out.extend_from_slice(&self.sender_device_id);
        out.extend_from_slice(&self.recipient_device_id);
        let header_len = u32::try_from(self.ratchet_header.len()).map_err(|_| EnvelopeError::HeaderTooLarge)?;
        out.extend_from_slice(&header_len.to_be_bytes());
        out.extend_from_slice(&self.ratchet_header);
        out.extend_from_slice(&self.sent_at_ms.to_be_bytes());
        Ok(out)
    }

    fn validate_metadata(&self) -> Result<(), EnvelopeError> {
        if self.version.0 != PROTOCOL_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if self.ratchet_header.len() > MAX_HEADER {
            return Err(EnvelopeError::HeaderTooLarge);
        }
        if self.message_id == [0; 16] || self.conversation_id == [0; 16] {
            return Err(EnvelopeError::InvalidIds);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), EnvelopeError> {
        self.validate_metadata()?;
        if self.ciphertext.is_empty() || self.ciphertext.len() > MAX_CIPHERTEXT {
            return Err(EnvelopeError::CiphertextTooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexa_identity::{prekeys::publishable_signed_prekey, IdentityKey, SignedPrekey};
    use nexa_ratchet::{RatchetState, ReceiveRatchet};
    use nexa_session::{initiate, respond, InitiatorEphemeral};

    fn sample() -> WireEnvelope {
        WireEnvelope {
            version: ProtocolVersion(PROTOCOL_VERSION),
            message_id: [1; 16],
            conversation_id: [2; 16],
            sender_device_id: [3; 16],
            recipient_device_id: [4; 16],
            ratchet_header: vec![5, 6],
            ciphertext: vec![7, 8, 9],
            sent_at_ms: 123,
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

    #[test]
    fn session_ratchet_and_wire_envelope_round_trip_end_to_end() {
        let alice = IdentityKey::generate();
        let bob = IdentityKey::generate();
        let bob_spk = SignedPrekey::generate();
        let bob_record = publishable_signed_prekey(&bob, 1, &bob_spk);
        let bob_device = [7; 16];
        let alice_device = [8; 16];
        let bundle = nexa_protocol::PreKeyBundle {
            protocol_version: ProtocolVersion(PROTOCOL_VERSION),
            device_id: bob_device,
            identity_signing_key: bob.public_key().to_bytes(),
            identity_agreement_key: bob.agreement_public_key(),
            signed_prekey_id: bob_record.key_id,
            signed_prekey: bob_record.public_key,
            signed_prekey_signature: bob_record.signature,
            one_time_prekeys: vec![],
        };
        let ephemeral = InitiatorEphemeral::generate();
        let initiator = initiate(&alice, alice_device, &ephemeral, &bundle, &bob_record, None).unwrap();
        let responder = respond(&bob, &bob_spk, None, bob_device, alice_device, alice.agreement_public_key(), ephemeral.public_key).unwrap();
        assert_eq!(initiator.root.as_bytes(), responder.root.as_bytes());

        let root: [u8; 32] = (*initiator.root.as_bytes()).try_into().unwrap();
        let mut sender = RatchetState::from_root(root).unwrap();
        let mut receiver = ReceiveRatchet::from_root(root).unwrap();
        let mut envelope = WireEnvelope {
            version: ProtocolVersion(PROTOCOL_VERSION),
            message_id: [9; 16],
            conversation_id: [10; 16],
            sender_device_id: alice_device,
            recipient_device_id: bob_device,
            ratchet_header: sender.counter().to_be_bytes().to_vec(),
            ciphertext: vec![1],
            sent_at_ms: 1_000,
        };
        let aad = envelope.aad().unwrap();
        envelope.ciphertext = sender.encrypt(b"hello from M", &aad).unwrap();
        let wire = envelope.encode().unwrap();
        let decoded = WireEnvelope::decode(&wire).unwrap();
        let decoded_aad = decoded.aad().unwrap();
        let counter = u64::from_be_bytes(decoded.ratchet_header.as_slice().try_into().unwrap());
        let plaintext = receiver.decrypt(counter, &decoded.ciphertext, &decoded_aad).unwrap();
        assert_eq!(plaintext, b"hello from M");
        assert_eq!(receiver.expected_counter(), 1);

        let tampered_fields = [
            {
                let mut value = decoded.clone();
                value.message_id[0] ^= 1;
                value
            },
            {
                let mut value = decoded.clone();
                value.conversation_id[0] ^= 1;
                value
            },
            {
                let mut value = decoded.clone();
                value.sender_device_id[0] ^= 1;
                value
            },
            {
                let mut value = decoded.clone();
                value.recipient_device_id[0] ^= 1;
                value
            },
            {
                let mut value = decoded.clone();
                value.ratchet_header[0] ^= 1;
                value
            },
            {
                let mut value = decoded.clone();
                value.sent_at_ms ^= 1;
                value
            },
        ];

        for tampered in tampered_fields {
            let tampered_aad = tampered.aad().unwrap();
            assert!(receiver.decrypt(counter, &tampered.ciphertext, &tampered_aad).is_err());
            assert_eq!(receiver.expected_counter(), 1);
            assert_eq!(receiver.skipped_count(), 0);
        }
    }
}
