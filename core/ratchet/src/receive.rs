use std::collections::BTreeMap;
use zeroize::Zeroizing;
use nexa_protocol::{RatchetHeader, RatchetHeaderError};

const MAX_SKIP: u64 = 256;
const SNAPSHOT_VERSION: u16 = 1;
const SNAPSHOT_MAGIC: &[u8; 4] = b"MRS1";
const SNAPSHOT_HEADER_LEN: usize = 4 + 2 + 8 + 2;
const SNAPSHOT_ENTRY_LEN: usize = 8 + 32;
const MAX_SNAPSHOT_SKIPPED: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError { TooFarAhead, Replay, Decryption, InvalidHeader(RatchetHeaderError) }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveSnapshotError {
    Truncated,
    InvalidMagic,
    InvalidVersion,
    InvalidLength,
    TooManySkipped,
    DuplicateCounter,
}

pub struct ReceiveRatchet {
    state: crate::RatchetState,
    skipped: BTreeMap<u64, Zeroizing<[u8; 32]>>,
}

impl ReceiveRatchet {
    pub fn from_root(root: [u8; 32]) -> Result<Self, crate::RatchetError> {
        Ok(Self { state: crate::RatchetState::from_root(root)?, skipped: BTreeMap::new() })
    }
    pub fn expected_counter(&self) -> u64 { self.state.counter() }
    pub fn skipped_count(&self) -> usize { self.skipped.len() }

    /// Canonical plaintext snapshot for encrypted platform storage.
    /// The storage layer is responsible for AEAD encryption of these bytes.
    pub fn snapshot(&self) -> Result<Vec<u8>, ReceiveSnapshotError> {
        if self.skipped.len() > MAX_SNAPSHOT_SKIPPED { return Err(ReceiveSnapshotError::TooManySkipped); }
        let mut out = Vec::with_capacity(SNAPSHOT_HEADER_LEN + self.skipped.len() * SNAPSHOT_ENTRY_LEN + 32);
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_be_bytes());
        out.extend_from_slice(&self.state.counter().to_be_bytes());
        out.extend_from_slice(&(self.skipped.len() as u16).to_be_bytes());
        // RatchetState intentionally exposes no raw chain key publicly. The
        // snapshot API is therefore added at the state boundary below.
        out.extend_from_slice(self.state.snapshot_chain_key());
        for (counter, key) in &self.skipped {
            out.extend_from_slice(&counter.to_be_bytes());
            out.extend_from_slice(key.as_ref());
        }
        Ok(out)
    }

    pub fn from_snapshot(snapshot: &[u8]) -> Result<Self, ReceiveSnapshotError> {
        if snapshot.len() < SNAPSHOT_HEADER_LEN + 32 { return Err(ReceiveSnapshotError::Truncated); }
        if &snapshot[..4] != SNAPSHOT_MAGIC { return Err(ReceiveSnapshotError::InvalidMagic); }
        let version = u16::from_be_bytes([snapshot[4], snapshot[5]]);
        if version != SNAPSHOT_VERSION { return Err(ReceiveSnapshotError::InvalidVersion); }
        let counter = u64::from_be_bytes(snapshot[6..14].try_into().unwrap());
        let count = u16::from_be_bytes([snapshot[14], snapshot[15]]) as usize;
        if count > MAX_SNAPSHOT_SKIPPED { return Err(ReceiveSnapshotError::TooManySkipped); }
        let expected = SNAPSHOT_HEADER_LEN + 32 + count * SNAPSHOT_ENTRY_LEN;
        if snapshot.len() != expected { return Err(ReceiveSnapshotError::InvalidLength); }
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&snapshot[16..48]);
        let mut skipped = BTreeMap::new();
        let mut offset = 48;
        for _ in 0..count {
            let key_end = offset + SNAPSHOT_ENTRY_LEN;
            let entry = &snapshot[offset..key_end];
            let entry_counter = u64::from_be_bytes(entry[..8].try_into().unwrap());
            if skipped.insert(entry_counter, Zeroizing::new(entry[8..40].try_into().unwrap())).is_some() {
                return Err(ReceiveSnapshotError::DuplicateCounter);
            }
            offset = key_end;
        }
        let state = crate::RatchetState::from_snapshot_parts(chain, counter)
            .map_err(|_| ReceiveSnapshotError::InvalidLength)?;
        Ok(Self { state, skipped })
    }

    fn key_for(&mut self, target: u64) -> Result<Zeroizing<[u8; 32]>, ReceiveError> {
        let expected = self.state.counter();
        if target < expected { return self.skipped.remove(&target).ok_or(ReceiveError::Replay); }
        if target - expected > MAX_SKIP { return Err(ReceiveError::TooFarAhead); }
        let mut target_key = None;
        while self.state.counter() <= target {
            let counter = self.state.counter();
            let key = self.state.next_message_key().map_err(|_| ReceiveError::Decryption)?;
            if counter == target { target_key = Some(key); } else { self.skipped.insert(counter, key); }
        }
        target_key.ok_or(ReceiveError::Decryption)
    }

    pub fn decrypt_with_header(&mut self, header_bytes: &[u8], packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, ReceiveError> {
        let header = RatchetHeader::decode(header_bytes).map_err(ReceiveError::InvalidHeader)?;
        self.decrypt(header.message_counter, packet, aad)
    }

    pub fn decrypt(&mut self, counter: u64, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, ReceiveError> {
        let mut candidate = Self { state: self.state.clone(), skipped: self.skipped.clone() };
        let key = candidate.key_for(counter)?;
        let plaintext = crate::RatchetState::decrypt_once(&key, packet, aad).map_err(|_| ReceiveError::Decryption)?;
        *self = candidate;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_then_replay_is_rejected() {
        let root=[7u8;32]; let mut sender=crate::RatchetState::from_root(root).unwrap();
        let p0=sender.encrypt(b"zero",b"aad").unwrap(); let p1=sender.encrypt(b"one",b"aad").unwrap();
        let mut receiver=ReceiveRatchet::from_root(root).unwrap();
        assert_eq!(receiver.decrypt_with_header(&RatchetHeader::new(1).encode(),&p1,b"aad").unwrap(),b"one");
        assert_eq!(receiver.decrypt_with_header(&RatchetHeader::new(0).encode(),&p0,b"aad").unwrap(),b"zero");
        assert!(matches!(receiver.decrypt_with_header(&RatchetHeader::new(0).encode(),&p0,b"aad"),Err(ReceiveError::Replay)));
    }

    #[test]
    fn excessive_skip_is_rejected() {
        let mut receiver=ReceiveRatchet::from_root([8u8;32]).unwrap();
        assert!(matches!(receiver.key_for(MAX_SKIP+1),Err(ReceiveError::TooFarAhead)));
    }

    #[test]
    fn malformed_header_does_not_consume_receive_state() {
        let mut receiver=ReceiveRatchet::from_root([9u8;32]).unwrap();
        let valid = RatchetHeader::new(0).encode();
        let mut invalid_version = valid.to_vec(); invalid_version[1] ^= 1;
        assert!(matches!(receiver.decrypt_with_header(&invalid_version,b"bad",b"aad"),Err(ReceiveError::InvalidHeader(RatchetHeaderError::InvalidVersion))));
        assert_eq!(receiver.expected_counter(),0); assert_eq!(receiver.skipped_count(),0);
        let mut trailing = valid.to_vec(); trailing.push(0);
        assert!(matches!(receiver.decrypt_with_header(&trailing,b"bad",b"aad"),Err(ReceiveError::InvalidHeader(RatchetHeaderError::TrailingBytes))));
        assert_eq!(receiver.expected_counter(),0); assert_eq!(receiver.skipped_count(),0);
    }

    #[test]
    fn failed_decryption_does_not_consume_receive_state() {
        let root = [11u8; 32];
        let mut sender = crate::RatchetState::from_root(root).unwrap();
        let valid = sender.encrypt(b"message", b"aad").unwrap();
        let mut tampered = valid.clone(); *tampered.last_mut().unwrap() ^= 1;
        let mut receiver = ReceiveRatchet::from_root(root).unwrap();
        assert!(matches!(receiver.decrypt_with_header(&RatchetHeader::new(0).encode(), &tampered, b"aad"), Err(ReceiveError::Decryption)));
        assert_eq!(receiver.expected_counter(), 0); assert_eq!(receiver.skipped_count(), 0);
        assert_eq!(receiver.decrypt_with_header(&RatchetHeader::new(0).encode(), &valid, b"aad").unwrap(), b"message");
    }

    #[test]
    fn snapshot_round_trip_preserves_skipped_keys() {
        let root = [21u8; 32];
        let mut sender = crate::RatchetState::from_root(root).unwrap();
        let p0 = sender.encrypt(b"zero", b"aad").unwrap();
        let p1 = sender.encrypt(b"one", b"aad").unwrap();
        let mut receiver = ReceiveRatchet::from_root(root).unwrap();
        receiver.decrypt_with_header(&RatchetHeader::new(1).encode(), &p1, b"aad").unwrap();
        let snapshot = receiver.snapshot().unwrap();
        let mut restored = ReceiveRatchet::from_snapshot(&snapshot).unwrap();
        assert_eq!(restored.expected_counter(), receiver.expected_counter());
        assert_eq!(restored.skipped_count(), 1);
        assert_eq!(restored.decrypt_with_header(&RatchetHeader::new(0).encode(), &p0, b"aad").unwrap(), b"zero");
    }

    #[test]
    fn snapshot_rejects_trailing_duplicate_and_wrong_version() {
        let mut receiver = ReceiveRatchet::from_root([22u8; 32]).unwrap();
        let snapshot = receiver.snapshot().unwrap();
        let mut trailing = snapshot.clone(); trailing.push(1);
        assert!(matches!(ReceiveRatchet::from_snapshot(&trailing), Err(ReceiveSnapshotError::InvalidLength)));
        let mut wrong = snapshot.clone(); wrong[5] = 2;
        assert!(matches!(ReceiveRatchet::from_snapshot(&wrong), Err(ReceiveSnapshotError::InvalidVersion)));

        let mut duplicate = receiver.snapshot().unwrap();
        duplicate[14] = 0; duplicate[15] = 2;
        duplicate.extend_from_slice(&0u64.to_be_bytes()); duplicate.extend_from_slice(&[1u8;32]);
        duplicate.extend_from_slice(&0u64.to_be_bytes()); duplicate.extend_from_slice(&[2u8;32]);
        assert!(matches!(ReceiveRatchet::from_snapshot(&duplicate), Err(ReceiveSnapshotError::DuplicateCounter)));
    }
}
