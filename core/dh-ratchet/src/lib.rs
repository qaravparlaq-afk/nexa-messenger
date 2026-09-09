//! Staged DH-ratchet state transition.
//!
//! This module intentionally exposes only the key-transition primitive. The
//! complete production session still needs authenticated ratchet headers,
//! transcript binding, durable state transactions, and a complete receive
//! state machine.

#![forbid(unsafe_code)]

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const ROOT_DOMAIN: &[u8] = b"NEXA/DH-RATCHET/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhRatchetError {
    InvalidPeerKey,
    Kdf,
}

pub struct DhRatchetState {
    root_key: Zeroizing<[u8; 32]>,
    private: StaticSecret,
    pub public: [u8; 32],
}

impl DhRatchetState {
    pub fn new(root_key: [u8; 32]) -> Self {
        let private = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&private).to_bytes();
        Self {
            root_key: Zeroizing::new(root_key),
            private,
            public,
        }
    }

    pub fn root_key(&self) -> &[u8; 32] {
        &self.root_key
    }

    /// Performs one authenticated-at-a-higher-layer DH transition and returns
    /// the new root plus a fresh chain seed.
    pub fn ratchet(&mut self, peer_public: [u8; 32]) -> Result<([u8; 32], [u8; 32]), DhRatchetError> {
        let peer = PublicKey::from(peer_public);
        let dh = self.private.diffie_hellman(&peer);
        if dh.as_bytes().iter().all(|b| *b == 0) {
            return Err(DhRatchetError::InvalidPeerKey);
        }

        let hk = Hkdf::<Sha256>::new(Some(ROOT_DOMAIN), &*self.root_key);
        let mut ikm = Zeroizing::new([0u8; 64]);
        ikm[..32].copy_from_slice(dh.as_bytes());
        ikm[32..].copy_from_slice(&self.root_key[..]);

        let mut expanded = Zeroizing::new([0u8; 64]);
        hk.expand(&ikm[..], expanded.as_mut()).map_err(|_| DhRatchetError::Kdf)?;

        let mut next_root = [0u8; 32];
        let mut chain = [0u8; 32];
        next_root.copy_from_slice(&expanded[..32]);
        chain.copy_from_slice(&expanded[32..]);

        self.root_key = Zeroizing::new(next_root);

        self.private = StaticSecret::random_from_rng(rand_core::OsRng);
        self.public = PublicKey::from(&self.private).to_bytes();

        Ok((next_root, chain))
    }
}

impl Drop for DhRatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_derive_same_transition() {
        let root = [11u8; 32];
        let mut a = DhRatchetState::new(root);
        let mut b = DhRatchetState::new(root);

        let a_old = a.public;
        let b_old = b.public;

        let (_, a_chain) = a.ratchet(b_old).unwrap();
        let (_, b_chain) = b.ratchet(a_old).unwrap();

        assert_eq!(a.root_key(), b.root_key());
        assert_eq!(a_chain, b_chain);
        assert_ne!(a.public, a_old);
        assert_ne!(b.public, b_old);
    }

    #[test]
    fn zero_shared_secret_is_rejected() {
        let mut state = DhRatchetState::new([1u8; 32]);
        assert!(matches!(
            state.ratchet([0u8; 32]),
            Err(DhRatchetError::InvalidPeerKey)
        ));
    }
}
