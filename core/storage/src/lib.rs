//! Local encrypted-storage boundary.
//!
//! This crate defines a versioned encrypted record format. It intentionally
//! does not own filesystem I/O or key derivation: the platform layer supplies
//! the storage key, and established AEAD primitives from `nexa-crypto` provide
//! confidentiality and integrity.

#![forbid(unsafe_code)]

use nexa_crypto::{open, seal, Ciphertext, CryptoError, KEY_LEN, NONCE_LEN};

pub const STORAGE_FORMAT_VERSION: u16 = 1;
pub const RECORD_HEADER_LEN: usize = 2;
pub const AEAD_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFormatVersion(pub u16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    InvalidVersion,
    Truncated,
    InvalidCiphertext,
    Crypto(CryptoError),
}

impl From<CryptoError> for StorageError {
    fn from(value: CryptoError) -> Self { Self::Crypto(value) }
}

/// Canonical encrypted record: version (u16 BE) || nonce (12 bytes) || AEAD body.
/// The body is authenticated by ChaCha20-Poly1305; malformed framing is rejected
/// before decryption.
pub fn seal_record(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    let encrypted = seal(key, plaintext)?;
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + NONCE_LEN + encrypted.body.len());
    out.extend_from_slice(&STORAGE_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&encrypted.nonce);
    out.extend_from_slice(&encrypted.body);
    Ok(out)
}

pub fn open_record(key: &[u8; KEY_LEN], record: &[u8]) -> Result<Vec<u8>, StorageError> {
    let minimum = RECORD_HEADER_LEN + NONCE_LEN + AEAD_TAG_LEN;
    if record.len() < minimum { return Err(StorageError::Truncated); }

    let version = u16::from_be_bytes([record[0], record[1]]);
    if version != STORAGE_FORMAT_VERSION { return Err(StorageError::InvalidVersion); }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&record[RECORD_HEADER_LEN..RECORD_HEADER_LEN + NONCE_LEN]);
    let body = record[RECORD_HEADER_LEN + NONCE_LEN..].to_vec();
    open(key, &Ciphertext { nonce, body }).map_err(StorageError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexa_crypto::generate_key;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let record = seal_record(&key, b"ratchet-state").unwrap();
        assert_eq!(open_record(&key, &record).unwrap(), b"ratchet-state");
    }

    #[test]
    fn tampering_is_rejected() {
        let key = generate_key();
        let mut record = seal_record(&key, b"secret-state").unwrap();
        let last = record.len() - 1;
        record[last] ^= 1;
        assert!(matches!(open_record(&key, &record), Err(StorageError::Crypto(CryptoError::DecryptionFailed))));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = generate_key();
        let other = generate_key();
        let record = seal_record(&key, b"secret-state").unwrap();
        assert!(open_record(&other, &record).is_err());
    }

    #[test]
    fn version_and_truncation_are_checked_before_decrypt() {
        let key = generate_key();
        assert!(matches!(open_record(&key, &[0]), Err(StorageError::Truncated)));

        let mut record = seal_record(&key, b"state").unwrap();
        record[0] = 0;
        record[1] = 2;
        assert!(matches!(open_record(&key, &record), Err(StorageError::InvalidVersion)));

        let short_ciphertext = [0u8; RECORD_HEADER_LEN + NONCE_LEN];
        assert!(matches!(open_record(&key, &short_ciphertext), Err(StorageError::Truncated)));

        let too_short_for_tag = [0u8; RECORD_HEADER_LEN + NONCE_LEN + AEAD_TAG_LEN - 1];
        assert!(matches!(open_record(&key, &too_short_for_tag), Err(StorageError::Truncated)));
    }

    #[test]
    fn repeated_seals_use_fresh_nonces() {
        let key = generate_key();
        let a = seal_record(&key, b"same").unwrap();
        let b = seal_record(&key, b"same").unwrap();
        assert_ne!(&a[RECORD_HEADER_LEN..RECORD_HEADER_LEN + NONCE_LEN], &b[RECORD_HEADER_LEN..RECORD_HEADER_LEN + NONCE_LEN]);
        assert_ne!(a, b);
    }
}
