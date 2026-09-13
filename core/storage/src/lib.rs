//! Local encrypted-storage boundary.
//!
//! This crate defines a versioned encrypted record format and a crash-safe
//! append-only persistence primitive. It intentionally does not own key
//! derivation: the platform layer supplies the storage key.

#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use nexa_crypto::{open, seal, Ciphertext, CryptoError, KEY_LEN, NONCE_LEN};

pub const STORAGE_FORMAT_VERSION: u16 = 1;
pub const RECORD_HEADER_LEN: usize = 2;
pub const AEAD_TAG_LEN: usize = 16;
const JOURNAL_MAGIC: &[u8; 4] = b"MJR1";
const JOURNAL_HEADER_LEN: usize = 4 + 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFormatVersion(pub u16);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    InvalidVersion,
    Truncated,
    InvalidCiphertext,
    InvalidJournalRecord,
    NoValidRecord,
    GenerationOverflow,
    Io,
    Crypto(CryptoError),
}

impl From<CryptoError> for StorageError {
    fn from(value: CryptoError) -> Self { Self::Crypto(value) }
}

impl From<io::Error> for StorageError {
    fn from(_: io::Error) -> Self { Self::Io }
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

/// Crash-safe encrypted journal.
///
/// Every save creates a new uniquely named temporary file, flushes it to the
/// filesystem, and atomically renames it to its final generation name. A crash
/// before rename leaves only a temporary file; the previous committed record
/// remains intact. Records are authenticated before they are considered during
/// recovery. Old records are intentionally retained; compaction is a separate
/// operation so cleanup can never destroy the last known-good state before a
/// new state is committed.
pub struct EncryptedJournal {
    directory: PathBuf,
    prefix: String,
}

impl EncryptedJournal {
    pub fn new(directory: impl AsRef<Path>, prefix: impl Into<String>) -> Result<Self, StorageError> {
        let prefix = prefix.into();
        if prefix.is_empty() || prefix.contains('/') || prefix.contains('\\') || prefix.contains("..") {
            return Err(StorageError::InvalidJournalRecord);
        }
        fs::create_dir_all(directory.as_ref())?;
        Ok(Self { directory: directory.as_ref().to_path_buf(), prefix })
    }

    fn final_path(&self, generation: u64) -> PathBuf {
        self.directory.join(format!("{}-{}.bin", self.prefix, generation))
    }

    fn temp_path(&self, generation: u64) -> PathBuf {
        self.directory.join(format!("{}-{}.tmp", self.prefix, generation))
    }

    fn parse_generation(&self, path: &Path) -> Option<u64> {
        let name = path.file_name()?.to_str()?;
        let stem = name.strip_prefix(&format!("{}-", self.prefix))?.strip_suffix(".bin")?;
        stem.parse().ok()
    }

    fn generations(&self) -> Result<Vec<u64>, StorageError> {
        let mut generations = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let path = entry?.path();
            if let Some(generation) = self.parse_generation(&path) {
                generations.push(generation);
            }
        }
        generations.sort_unstable();
        Ok(generations)
    }

    fn encode_journal(generation: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(JOURNAL_HEADER_LEN + plaintext.len());
        payload.extend_from_slice(JOURNAL_MAGIC);
        payload.extend_from_slice(&generation.to_be_bytes());
        payload.extend_from_slice(plaintext);
        payload
    }

    fn decode_journal(record: &[u8], expected_generation: u64) -> Result<Vec<u8>, StorageError> {
        if record.len() < JOURNAL_HEADER_LEN { return Err(StorageError::Truncated); }
        if &record[..4] != JOURNAL_MAGIC { return Err(StorageError::InvalidJournalRecord); }
        let generation = u64::from_be_bytes(record[4..12].try_into().map_err(|_| StorageError::Truncated)?);
        if generation != expected_generation { return Err(StorageError::InvalidJournalRecord); }
        Ok(record[JOURNAL_HEADER_LEN..].to_vec())
    }

    pub fn save(&self, key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<u64, StorageError> {
        let generations = self.generations()?;
        let generation = match generations.into_iter().max() {
            Some(current) => current.checked_add(1).ok_or(StorageError::GenerationOverflow)?,
            None => 0,
        };
        let journal_plaintext = Self::encode_journal(generation, plaintext);
        let encrypted = seal_record(key, &journal_plaintext)?;
        let temp = self.temp_path(generation);
        let final_path = self.final_path(generation);

        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&temp, &final_path)?;
        sync_directory(&self.directory);
        Ok(generation)
    }

    /// Returns the newest authenticated record. A corrupt newest record is
    /// ignored so that an older committed record can recover the session.
    pub fn load(&self, key: &[u8; KEY_LEN]) -> Result<(u64, Vec<u8>), StorageError> {
        let generations = self.generations()?;
        for generation in generations.into_iter().rev() {
            let path = self.final_path(generation);
            let mut bytes = Vec::new();
            if File::open(&path).and_then(|mut f| f.read_to_end(&mut bytes)).is_err() { continue; }
            let plaintext = match open_record(key, &bytes) { Ok(value) => value, Err(_) => continue };
            match Self::decode_journal(&plaintext, generation) {
                Ok(state) => return Ok((generation, state)),
                Err(_) => continue,
            }
        }
        Err(StorageError::NoValidRecord)
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) {
    if let Ok(dir) = File::open(directory) { let _ = dir.sync_all(); }
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use nexa_crypto::generate_key;
    use nexa_protocol::RatchetHeader;
    use nexa_ratchet::{ReceiveError, ReceiveRatchet, RatchetState};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("m-storage-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

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
        record[0] = 0; record[1] = 2;
        assert!(matches!(open_record(&key, &record), Err(StorageError::InvalidVersion)));
        let short_ciphertext = [0u8; RECORD_HEADER_LEN + NONCE_LEN];
        assert!(matches!(open_record(&key, &short_ciphertext), Err(StorageError::Truncated)));
    }

    #[test]
    fn repeated_seals_use_fresh_nonces() {
        let key = generate_key();
        let a = seal_record(&key, b"same").unwrap();
        let b = seal_record(&key, b"same").unwrap();
        assert_ne!(&a[RECORD_HEADER_LEN..RECORD_HEADER_LEN + NONCE_LEN], &b[RECORD_HEADER_LEN..RECORD_HEADER_LEN + NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn journal_recovers_after_a_corrupt_newest_record() {
        let dir = temp_dir("recovery");
        let journal = EncryptedJournal::new(&dir, "ratchet").unwrap();
        let key = generate_key();
        assert_eq!(journal.save(&key, b"state-0").unwrap(), 0);
        assert_eq!(journal.save(&key, b"state-1").unwrap(), 1);
        let newest = journal.final_path(1);
        let mut bytes = fs::read(&newest).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(newest, bytes).unwrap();
        let (generation, state) = journal.load(&key).unwrap();
        assert_eq!(generation, 0);
        assert_eq!(state, b"state-0");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn journal_ignores_orphaned_temp_file() {
        let dir = temp_dir("orphan");
        let journal = EncryptedJournal::new(&dir, "ratchet").unwrap();
        let key = generate_key();
        journal.save(&key, b"stable").unwrap();
        fs::write(journal.temp_path(99), b"partial").unwrap();
        let (generation, state) = journal.load(&key).unwrap();
        assert_eq!(generation, 0);
        assert_eq!(state, b"stable");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn journal_rejects_wrong_key_and_corrupts_to_no_valid_record() {
        let dir = temp_dir("invalid");
        let journal = EncryptedJournal::new(&dir, "ratchet").unwrap();
        let key = generate_key();
        let wrong = generate_key();
        journal.save(&key, b"secret").unwrap();
        assert!(matches!(journal.load(&wrong), Err(StorageError::NoValidRecord)));
        let path = journal.final_path(0);
        fs::write(path, b"broken").unwrap();
        assert!(matches!(journal.load(&key), Err(StorageError::NoValidRecord)));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ratchet_snapshot_survives_encrypted_restart_and_preserves_replay_protection() {
        let root = [42u8; 32];
        let storage_key = generate_key();
        let dir = temp_dir("ratchet-restart");
        let journal = EncryptedJournal::new(&dir, "receive").unwrap();

        let mut sender = RatchetState::from_root(root).unwrap();
        let packet0 = sender.encrypt(b"zero", b"aad").unwrap();
        let packet1 = sender.encrypt(b"one", b"aad").unwrap();
        let packet2 = sender.encrypt(b"two", b"aad").unwrap();

        let mut receiver = ReceiveRatchet::from_root(root).unwrap();
        assert_eq!(receiver.decrypt_with_header(&RatchetHeader::new(1).encode(), &packet1, b"aad").unwrap(), b"one");
        let snapshot = receiver.snapshot().unwrap();
        let generation = journal.save(&storage_key, &snapshot).unwrap();
        assert_eq!(generation, 0);
        drop(receiver);

        let (_, restored_snapshot) = journal.load(&storage_key).unwrap();
        let mut restored = ReceiveRatchet::from_snapshot(&restored_snapshot).unwrap();
        assert_eq!(restored.decrypt_with_header(&RatchetHeader::new(0).encode(), &packet0, b"aad").unwrap(), b"zero");
        assert_eq!(restored.decrypt_with_header(&RatchetHeader::new(2).encode(), &packet2, b"aad").unwrap(), b"two");
        assert!(matches!(restored.decrypt_with_header(&RatchetHeader::new(1).encode(), &packet1, b"aad"), Err(ReceiveError::Replay)));
        assert_eq!(restored.expected_counter(), 3);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn tampered_or_wrong_key_snapshot_cannot_restore() {
        let root = [43u8; 32];
        let key = generate_key();
        let wrong = generate_key();
        let dir = temp_dir("ratchet-auth");
        let journal = EncryptedJournal::new(&dir, "receive").unwrap();
        let receiver = ReceiveRatchet::from_root(root).unwrap();
        let snapshot = receiver.snapshot().unwrap();
        journal.save(&key, &snapshot).unwrap();
        assert!(matches!(journal.load(&wrong), Err(StorageError::NoValidRecord)));

        let path = journal.final_path(0);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(matches!(journal.load(&key), Err(StorageError::NoValidRecord)));
        let _ = fs::remove_dir_all(dir);
    }
}
