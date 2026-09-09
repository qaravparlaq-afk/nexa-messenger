//! NEXA cryptographic boundary.
//!
//! This is a small local AEAD primitive built from maintained cryptographic
//! libraries. It is NOT the complete NEXA messaging protocol.
//!
//! The protocol still needs authenticated key agreement, identity binding,
//! ratcheting, replay protection, device verification and key lifecycle rules.

#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::RngCore;
use zeroize::Zeroize;

pub const API_VERSION: u32 = 1;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub nonce: [u8; NONCE_LEN],
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

pub fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut key);
    key
}

/// Encrypt local content with ChaCha20-Poly1305 and a fresh random nonce.
pub fn seal(key_bytes: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Ciphertext, CryptoError> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let body = cipher.encrypt(nonce, plaintext).map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(Ciphertext { nonce: nonce_bytes, body })
}

/// Decrypt and authenticate local ciphertext.
pub fn open(key_bytes: &[u8; KEY_LEN], ciphertext: &Ciphertext) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&ciphertext.nonce);
    cipher.decrypt(nonce, ciphertext.body.as_ref()).map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let encrypted = seal(&key, b"NEXA local plaintext").expect("encrypt");
        let decrypted = open(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, b"NEXA local plaintext");
    }

    #[test]
    fn tampering_is_rejected() {
        let key = generate_key();
        let mut encrypted = seal(&key, b"secret").expect("encrypt");
        encrypted.body[0] ^= 1;
        assert!(open(&key, &encrypted).is_err());
    }
}
