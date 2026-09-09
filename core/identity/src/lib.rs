//! Account/device identity and prekey primitives.
//!
//! Private identity and prekey material must remain on the device.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState {
    Unverified,
    Verified,
    Changed,
    Revoked,
}

pub struct IdentityKey {
    signing_key: SigningKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }
}

pub struct SignedPrekey {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl SignedPrekey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&X25519PublicKey::from(*peer_public))
            .to_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekeyRecord {
    pub key_id: u32,
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SignedPrekeyRecord {
    pub fn signing_bytes(key_id: u32, public_key: &[u8; 32]) -> Vec<u8> {
        let mut out = b"NEXA/SPK/v1".to_vec();
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(public_key);
        out
    }

    pub fn verify(&self, identity_public: &VerifyingKey) -> bool {
        let bytes = Self::signing_bytes(self.key_id, &self.public_key);
        identity_public
            .verify(&bytes, &Signature::from_bytes(&self.signature))
            .is_ok()
    }
}

/// A one-time X25519 prekey. Its private part is consumable and must never be
/// serialized into a server-facing bundle.
pub struct OneTimePrekey {
    pub key_id: u32,
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl OneTimePrekey {
    pub fn generate(key_id: u32) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { key_id, secret, public }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&X25519PublicKey::from(*peer_public))
            .to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_signature_verifies() {
        let identity = IdentityKey::generate();
        let payload = b"NEXA identity test";
        let signature = identity.sign(payload);
        assert!(identity.public_key().verify(payload, &signature).is_ok());
    }

    #[test]
    fn signed_prekey_binds_to_identity() {
        let identity = IdentityKey::generate();
        let spk = SignedPrekey::generate();
        let id = 7;
        let bytes = SignedPrekeyRecord::signing_bytes(id, &spk.public_key());
        let sig = identity.sign(&bytes);
        let record = SignedPrekeyRecord {
            key_id: id,
            public_key: spk.public_key(),
            signature: sig.to_bytes(),
        };
        assert!(record.verify(&identity.public_key()));
    }

    #[test]
    fn wrong_identity_rejects_signed_prekey() {
        let identity = IdentityKey::generate();
        let other = IdentityKey::generate();
        let spk = SignedPrekey::generate();
        let bytes = SignedPrekeyRecord::signing_bytes(1, &spk.public_key());
        let sig = identity.sign(&bytes);
        let record = SignedPrekeyRecord {
            key_id: 1,
            public_key: spk.public_key(),
            signature: sig.to_bytes(),
        };
        assert!(!record.verify(&other.public_key()));
    }

    #[test]
    fn one_time_prekey_has_public_component() {
        let key = OneTimePrekey::generate(42);
        assert_eq!(key.key_id, 42);
        assert_eq!(key.public_key().len(), 32);
    }
}
