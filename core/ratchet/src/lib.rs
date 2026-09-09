//! NEXA staged symmetric ratchet.
//!
//! Each successful step derives a fresh message key and advances the chain.
//! This is a building block for the complete messaging protocol, not a claim
//! of full Double Ratchet compatibility.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const CHAIN_DOMAIN: &[u8] = b"NEXA/CHAIN/v1";
const MESSAGE_DOMAIN: &[u8] = b"NEXA/MESSAGE/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    Kdf,
    Encryption,
    Decryption,
    InvalidNonce,
}

#[derive(Clone)]
pub struct RatchetState {
    chain_key: Zeroizing<[u8; 32]>,
    next_counter: u64,
}

impl RatchetState {
    pub fn from_root(root: [u8; 32]) -> Result<Self, RatchetError> {
        let hk = Hkdf::<Sha256>::new(Some(CHAIN_DOMAIN), &root);
        let mut chain = Zeroizing::new([0u8; 32]);
        hk.expand(b"initial-chain", chain.as_mut())
            .map_err(|_| RatchetError::Kdf)?;
        Ok(Self { chain_key: chain, next_counter: 0 })
    }

    pub fn counter(&self) -> u64 {
        self.next_counter
    }

    /// Derives a one-use message key and advances the sending chain.
    pub fn next_message_key(&mut self) -> Result<Zeroizing<[u8; 32]>, RatchetError> {
        let current = self.chain_key.clone();
        let hk = Hkdf::<Sha256>::new(Some(MESSAGE_DOMAIN), &*current);
        let mut message = Zeroizing::new([0u8; 32]);
        hk.expand(&self.next_counter.to_be_bytes(), message.as_mut())
            .map_err(|_| RatchetError::Kdf)?;

        let hk_next = Hkdf::<Sha256>::new(Some(CHAIN_DOMAIN), &*current);
        let mut next = Zeroizing::new([0u8; 32]);
        hk_next.expand(&self.next_counter.to_be_bytes(), next.as_mut())
            .map_err(|_| RatchetError::Kdf)?;

        self.chain_key = next;
        self.next_counter = self.next_counter.checked_add(1).ok_or(RatchetError::Kdf)?;
        Ok(message)
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, RatchetError> {
        let key = self.next_message_key()?;
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| RatchetError::Encryption)?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| RatchetError::Encryption)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_once(
        key: &[u8; 32],
        packet: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, RatchetError> {
        if packet.len() < 12 {
            return Err(RatchetError::InvalidNonce);
        }
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| RatchetError::Decryption)?;
        cipher
            .decrypt(
                Nonce::from_slice(&packet[..12]),
                Payload { msg: &packet[12..], aad },
            )
            .map_err(|_| RatchetError::Decryption)
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_keys_advance() {
        let root = [7u8; 32];
        let mut a = RatchetState::from_root(root).unwrap();
        let k1 = a.next_message_key().unwrap();
        let k2 = a.next_message_key().unwrap();
        assert_ne!(k1.as_ref(), k2.as_ref());
        assert_eq!(a.counter(), 2);
    }

    #[test]
    fn encryption_authenticates_aad() {
        let root = [9u8; 32];
        let mut sender = RatchetState::from_root(root).unwrap();
        let packet = sender.encrypt(b"hello", b"NEXA/aad/v1").unwrap();
        let key = {
            let mut probe = RatchetState::from_root(root).unwrap();
            probe.next_message_key().unwrap()
        };
        assert_eq!(
            RatchetState::decrypt_once(&key, &packet, b"NEXA/aad/v1").unwrap(),
            b"hello"
        );
        assert!(RatchetState::decrypt_once(&key, &packet, b"wrong").is_err());
    }

    #[test]
    fn tampering_fails() {
        let root = [3u8; 32];
        let mut sender = RatchetState::from_root(root).unwrap();
        let mut packet = sender.encrypt(b"secret", b"aad").unwrap();
        *packet.last_mut().unwrap() ^= 1;
        let mut probe = RatchetState::from_root(root).unwrap();
        let key = probe.next_message_key().unwrap();
        assert!(RatchetState::decrypt_once(&key, &packet, b"aad").is_err());
    }
}

mod receive;
pub use receive::{ReceiveError, ReceiveRatchet};
