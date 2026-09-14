//! Helpers for publishing and atomically consuming prekeys.

use crate::{IdentityKey, OneTimePrekey, SignedPrekey, SignedPrekeyRecord};
use std::collections::BTreeMap;
use std::sync::Mutex;

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
