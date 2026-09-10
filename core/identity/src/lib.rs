//! Account/device identity and prekey primitives.

#![forbid(unsafe_code)]

pub mod prekeys;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState { Unverified, Verified, Changed, Revoked }

pub struct IdentityKey {
    signing_key: SigningKey,
    agreement_secret: Zeroizing<[u8; 32]>,
    agreement_public: X25519PublicKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let agreement_secret = StaticSecret::random_from_rng(OsRng);
        let agreement_public = X25519PublicKey::from(&agreement_secret);
        Self { signing_key, agreement_secret: Zeroizing::new(agreement_secret.to_bytes()), agreement_public }
    }
    pub fn public_key(&self) -> VerifyingKey { self.signing_key.verifying_key() }
    pub fn sign(&self, message: &[u8]) -> Signature { self.signing_key.sign(message) }
    pub fn agreement_public_key(&self) -> [u8; 32] { self.agreement_public.to_bytes() }
    pub fn agreement_diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(*self.agreement_secret);
        secret.diffie_hellman(&X25519PublicKey::from(*peer_public)).to_bytes()
    }
}

pub struct SignedPrekey { secret: StaticSecret, public: X25519PublicKey }
impl SignedPrekey {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }
    pub fn public_key(&self) -> [u8; 32] { self.public.to_bytes() }
    pub fn diffie_hellman(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        self.secret.diffie_hellman(&X25519PublicKey::from(*peer_public)).to_bytes()
    }
}

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
    pub fn public_key(&self) -> [u8; 32] { self.public.to_bytes() }
    pub fn diffie_hellman(self, peer_public: &[u8; 32]) -> [u8; 32] {
        self.secret.diffie_hellman(&X25519PublicKey::from(*peer_public)).to_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrekeyRecord {
    pub key_id: u32,
    pub public_key: [u8; 32],
    pub agreement_public_key: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}
impl SignedPrekeyRecord {
    pub fn signing_bytes(key_id: u32, public_key: &[u8; 32], agreement_public_key: &[u8; 32]) -> Vec<u8> {
        let mut out = b"NEXA/SPK/v2".to_vec();
        out.extend_from_slice(&key_id.to_be_bytes());
        out.extend_from_slice(public_key);
        out.extend_from_slice(agreement_public_key);
        out
    }
    pub fn verify(&self, identity_public: &VerifyingKey) -> bool {
        let bytes = Self::signing_bytes(self.key_id, &self.public_key, &self.agreement_public_key);
        identity_public.verify(&bytes, &Signature::from_bytes(&self.signature)).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn identity_signature_verifies() {
        let identity = IdentityKey::generate();
        let payload = b"NEXA identity test";
        assert!(identity.public_key().verify(payload, &identity.sign(payload)).is_ok());
    }
    #[test] fn signed_prekey_binds_to_identity_and_agreement_key() {
        let identity = IdentityKey::generate();
        let spk = SignedPrekey::generate();
        let bytes = SignedPrekeyRecord::signing_bytes(7, &spk.public_key(), &identity.agreement_public_key());
        let record = SignedPrekeyRecord { key_id: 7, public_key: spk.public_key(), agreement_public_key: identity.agreement_public_key(), signature: identity.sign(&bytes).to_bytes() };
        assert!(record.verify(&identity.public_key()));
    }
    #[test] fn wrong_identity_rejects_signed_prekey() {
        let identity = IdentityKey::generate();
        let other = IdentityKey::generate();
        let spk = SignedPrekey::generate();
        let bytes = SignedPrekeyRecord::signing_bytes(1, &spk.public_key(), &identity.agreement_public_key());
        let record = SignedPrekeyRecord { key_id: 1, public_key: spk.public_key(), agreement_public_key: identity.agreement_public_key(), signature: identity.sign(&bytes).to_bytes() };
        assert!(!record.verify(&other.public_key()));
    }
    #[test] fn one_time_prekey_is_consumed_by_ownership() {
        let key = OneTimePrekey::generate(42);
        let peer = SignedPrekey::generate();
        assert_ne!(key.diffie_hellman(&peer.public_key()), [0u8; 32]);
    }
    #[test] fn agreement_key_is_stable_and_private() {
        let identity = IdentityKey::generate();
        let peer = IdentityKey::generate();
        assert_ne!(identity.agreement_public_key(), [0u8; 32]);
        assert_eq!(identity.agreement_diffie_hellman(&peer.agreement_public_key()), peer.agreement_diffie_hellman(&identity.agreement_public_key()));
    }
}
