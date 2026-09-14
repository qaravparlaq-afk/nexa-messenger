//! Helpers for publishing and safely rotating prekeys.

use crate::{IdentityKey, OneTimePrekey, SignedPrekey, SignedPrekeyRecord};
use std::collections::BTreeMap;
use std::sync::Mutex;

pub const DEFAULT_SIGNED_PREKEY_ROTATION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const DEFAULT_SIGNED_PREKEY_GRACE_MS: u64 = 24 * 60 * 60 * 1000;

pub fn publishable_signed_prekey(
    identity: &IdentityKey,
    key_id: u32,
    prekey: &SignedPrekey,
) -> SignedPrekeyRecord {
    let public_key = prekey.public_key();
    let agreement_public_key = identity.agreement_public_key();
    let bytes = SignedPrekeyRecord::signing_bytes(key_id, &public_key, &agreement_public_key);
    let signature = identity.sign(&bytes);
    SignedPrekeyRecord { key_id, public_key, agreement_public_key, signature: signature.to_bytes() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedPrekeyStoreError {
    DuplicateKeyId,
    NotFound,
    InvalidTime,
    GenerationOverflow,
    Poisoned,
}

struct SignedPrekeyEntry {
    key_id: u32,
    created_at_ms: u64,
    expires_at_ms: Option<u64>,
    key: SignedPrekey,
    record: SignedPrekeyRecord,
}

struct SignedPrekeyState {
    current: SignedPrekeyEntry,
    retired: BTreeMap<u32, SignedPrekeyEntry>,
}

/// Holds the active signed prekey and a bounded grace-period set of retired keys.
/// Retired keys remain available so sessions created from a recently published
/// bundle can still complete after rotation. Expired keys are removed explicitly
/// by `prune` and are never returned by `with_key`.
pub struct SignedPrekeyStore {
    state: Mutex<SignedPrekeyState>,
}

impl SignedPrekeyStore {
    pub fn new(identity: &IdentityKey, key_id: u32, now_ms: u64) -> Self {
        let key = SignedPrekey::generate(key_id);
        let record = publishable_signed_prekey(identity, key_id, &key);
        Self {
            state: Mutex::new(SignedPrekeyState {
                current: SignedPrekeyEntry { key_id, created_at_ms: now_ms, expires_at_ms: None, key, record },
                retired: BTreeMap::new(),
            }),
        }
    }

    pub fn current_record(&self) -> Result<SignedPrekeyRecord, SignedPrekeyStoreError> {
        let state = self.state.lock().map_err(|_| SignedPrekeyStoreError::Poisoned)?;
        Ok(state.current.record.clone())
    }

    pub fn current_key_id(&self) -> Result<u32, SignedPrekeyStoreError> {
        Ok(self.state.lock().map_err(|_| SignedPrekeyStoreError::Poisoned)?.current.key_id)
    }

    /// Returns the private signed prekey for a published key id while keeping it in storage.
    /// The closure should perform only the work needed to establish the session.
    pub fn with_key<R, F>(&self, key_id: u32, now_ms: u64, operation: F) -> Result<R, SignedPrekeyStoreError>
    where
        F: FnOnce(&SignedPrekey) -> R,
    {
        let state = self.state.lock().map_err(|_| SignedPrekeyStoreError::Poisoned)?;
        if state.current.key_id == key_id {
            return Ok(operation(&state.current.key));
        }
        let entry = state.retired.get(&key_id).ok_or(SignedPrekeyStoreError::NotFound)?;
        if entry.expires_at_ms.is_some_and(|expires| now_ms >= expires) {
            return Err(SignedPrekeyStoreError::NotFound);
        }
        Ok(operation(&entry.key))
    }

    /// Rotates to a fresh signed prekey. The old key is retained only for `grace_ms`.
    /// Key ids may never be reused while the old entry remains in the store.
    pub fn rotate(
        &self,
        identity: &IdentityKey,
        new_key_id: u32,
        now_ms: u64,
        grace_ms: u64,
    ) -> Result<SignedPrekeyRecord, SignedPrekeyStoreError> {
        let mut state = self.state.lock().map_err(|_| SignedPrekeyStoreError::Poisoned)?;
        if new_key_id == state.current.key_id || state.retired.contains_key(&new_key_id) {
            return Err(SignedPrekeyStoreError::DuplicateKeyId);
        }
        if now_ms < state.current.created_at_ms {
            return Err(SignedPrekeyStoreError::InvalidTime);
        }
        let expires_at_ms = now_ms.checked_add(grace_ms).ok_or(SignedPrekeyStoreError::GenerationOverflow)?;
        let old = std::mem::replace(&mut state.current, {
            let key = SignedPrekey::generate(new_key_id);
            let record = publishable_signed_prekey(identity, new_key_id, &key);
            SignedPrekeyEntry { key_id: new_key_id, created_at_ms: now_ms, expires_at_ms: None, key, record }
        });
        state.retired.insert(old.key_id, SignedPrekeyEntry { expires_at_ms: Some(expires_at_ms), ..old });
        Ok(state.current.record.clone())
    }

    /// Removes retired keys whose grace period has ended.
    pub fn prune(&self, now_ms: u64) -> Result<usize, SignedPrekeyStoreError> {
        let mut state = self.state.lock().map_err(|_| SignedPrekeyStoreError::Poisoned)?;
        let before = state.retired.len();
        state.retired.retain(|_, entry| entry.expires_at_ms.is_none_or(|expires| now_ms < expires));
        Ok(before - state.retired.len())
    }

    pub fn retired_len(&self) -> Result<usize, SignedPrekeyStoreError> {
        Ok(self.state.lock().map_err(|_| SignedPrekeyStoreError::Poisoned)?.retired.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreKeyStoreError {
    DuplicateKeyId,
    NotFound,
    PublicKeyMismatch,
    Poisoned,
}

pub struct OneTimePrekeyStore {
    keys: Mutex<BTreeMap<u32, OneTimePrekey>>,
}

impl OneTimePrekeyStore {
    pub fn new() -> Self { Self { keys: Mutex::new(BTreeMap::new()) } }

    pub fn insert(&self, key: OneTimePrekey) -> Result<(), PreKeyStoreError> {
        let mut keys = self.keys.lock().map_err(|_| PreKeyStoreError::Poisoned)?;
        if keys.contains_key(&key.key_id) { return Err(PreKeyStoreError::DuplicateKeyId); }
        keys.insert(key.key_id, key);
        Ok(())
    }

    pub fn take(&self, key_id: u32) -> Result<OneTimePrekey, PreKeyStoreError> {
        let mut keys = self.keys.lock().map_err(|_| PreKeyStoreError::Poisoned)?;
        keys.remove(&key_id).ok_or(PreKeyStoreError::NotFound)
    }

    /// Atomically verifies the advertised public key and consumes the OPK only on a match.
    pub fn take_matching(&self, key_id: u32, expected_public: &[u8; 32]) -> Result<OneTimePrekey, PreKeyStoreError> {
        let mut keys = self.keys.lock().map_err(|_| PreKeyStoreError::Poisoned)?;
        let key = keys.get(&key_id).ok_or(PreKeyStoreError::NotFound)?;
        if key.public_key() != *expected_public { return Err(PreKeyStoreError::PublicKeyMismatch); }
        keys.remove(&key_id).ok_or(PreKeyStoreError::NotFound)
    }

    /// Runs a session operation while retaining the OPK until the operation succeeds.
    /// This makes OPK consumption transactional: an establishment failure does not burn a key.
    pub fn with_matching<R, E, F>(&self, key_id: u32, expected_public: &[u8; 32], operation: F) -> Result<R, E>
    where
        F: FnOnce(&OneTimePrekey) -> Result<R, E>,
        E: From<PreKeyStoreError>,
    {
        let mut keys = self.keys.lock().map_err(|_| E::from(PreKeyStoreError::Poisoned))?;
        let key = keys.get(&key_id).ok_or_else(|| E::from(PreKeyStoreError::NotFound))?;
        if key.public_key() != *expected_public { return Err(E::from(PreKeyStoreError::PublicKeyMismatch)); }
        let result = operation(key)?;
        keys.remove(&key_id).ok_or_else(|| E::from(PreKeyStoreError::NotFound))?;
        Ok(result)
    }

    pub fn len(&self) -> Result<usize, PreKeyStoreError> {
        Ok(self.keys.lock().map_err(|_| PreKeyStoreError::Poisoned)?.len())
    }

    pub fn is_empty(&self) -> Result<bool, PreKeyStoreError> { Ok(self.len()? == 0) }
}

impl Default for OneTimePrekeyStore { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn signed_prekey_rotation_keeps_old_key_during_grace() {
        let identity = IdentityKey::generate();
        let store = SignedPrekeyStore::new(&identity, 1, 1_000);
        let old = store.current_record().unwrap();
        let fresh = store.rotate(&identity, 2, 2_000, 500).unwrap();
        assert_eq!(fresh.key_id, 2);
        assert_eq!(store.current_key_id().unwrap(), 2);
        assert_eq!(store.retired_len().unwrap(), 1);
        assert!(store.with_key(old.key_id, 2_499, |_| ()).is_ok());
        assert!(matches!(store.with_key(old.key_id, 2_500, |_| ()), Err(SignedPrekeyStoreError::NotFound)));
        assert_eq!(store.prune(2_500).unwrap(), 1);
        assert_eq!(store.retired_len().unwrap(), 0);
    }

    #[test]
    fn signed_prekey_rotation_rejects_id_reuse_and_time_rollback() {
        let identity = IdentityKey::generate();
        let store = SignedPrekeyStore::new(&identity, 4, 10_000);
        assert!(matches!(store.rotate(&identity, 4, 11_000, 1), Err(SignedPrekeyStoreError::DuplicateKeyId)));
        assert!(matches!(store.rotate(&identity, 5, 9_999, 1), Err(SignedPrekeyStoreError::InvalidTime)));
        store.rotate(&identity, 5, 11_000, 10).unwrap();
        assert!(matches!(store.rotate(&identity, 4, 12_000, 10), Err(SignedPrekeyStoreError::DuplicateKeyId)));
    }

    #[test]
    fn signed_prekey_record_stays_bound_after_rotation() {
        let identity = IdentityKey::generate();
        let store = SignedPrekeyStore::new(&identity, 7, 100);
        let record = store.current_record().unwrap();
        assert!(record.verify(&identity.public_key()));
        let _ = store.rotate(&identity, 8, 200, DEFAULT_SIGNED_PREKEY_GRACE_MS).unwrap();
        assert!(store.with_key(record.key_id, 200, |key| assert_eq!(key.public_key(), record.public_key)).is_ok());
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let store = OneTimePrekeyStore::new();
        store.insert(OneTimePrekey::generate(7)).unwrap();
        assert!(matches!(store.insert(OneTimePrekey::generate(7)), Err(PreKeyStoreError::DuplicateKeyId)));
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn take_is_single_use() {
        let store = OneTimePrekeyStore::new();
        store.insert(OneTimePrekey::generate(8)).unwrap();
        let first = store.take(8).unwrap();
        assert_eq!(first.key_id, 8);
        assert!(matches!(store.take(8), Err(PreKeyStoreError::NotFound)));
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn mismatched_public_key_does_not_consume_prekey() {
        let store = OneTimePrekeyStore::new();
        let key = OneTimePrekey::generate(10);
        let public = key.public_key();
        store.insert(key).unwrap();
        assert!(matches!(store.take_matching(10, &[1u8; 32]), Err(PreKeyStoreError::PublicKeyMismatch)));
        assert_eq!(store.len().unwrap(), 1);
        let consumed = store.take_matching(10, &public).unwrap();
        assert_eq!(consumed.key_id, 10);
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn transactional_operation_restores_on_error() {
        let store = OneTimePrekeyStore::new();
        let key = OneTimePrekey::generate(13);
        let public = key.public_key();
        store.insert(key).unwrap();
        let failed: Result<(), PreKeyStoreError> = store.with_matching(13, &public, |_key| Err(PreKeyStoreError::PublicKeyMismatch));
        assert!(matches!(failed, Err(PreKeyStoreError::PublicKeyMismatch)));
        assert_eq!(store.len().unwrap(), 1);
        let ok: Result<u8, PreKeyStoreError> = store.with_matching(13, &public, |_key| Ok(1));
        assert_eq!(ok.unwrap(), 1);
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn concurrent_take_allows_exactly_one_consumer() {
        let store = Arc::new(OneTimePrekeyStore::new());
        let key = OneTimePrekey::generate(9);
        let public = key.public_key();
        store.insert(key).unwrap();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || store.take_matching(9, &public).is_ok()));
        }
        let mut winners = 0;
        for handle in handles {
            if handle.join().unwrap() { winners += 1; }
        }
        assert_eq!(winners, 1);
        assert_eq!(store.len().unwrap(), 0);
    }
}
