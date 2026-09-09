use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MAX_SKIP: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveError { TooFarAhead, Replay, Decryption }

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

    fn key_for(&mut self, target: u64) -> Result<Zeroizing<[u8; 32]>, ReceiveError> {
        let expected = self.state.counter();
        if target < expected {
            return self.skipped.remove(&target).ok_or(ReceiveError::Replay);
        }
        if target - expected > MAX_SKIP { return Err(ReceiveError::TooFarAhead); }
        let mut target_key = None;
        while self.state.counter() <= target {
            let counter = self.state.counter();
            let key = self.state.next_message_key().map_err(|_| ReceiveError::Decryption)?;
            if counter == target { target_key = Some(key); }
            else { self.skipped.insert(counter, key); }
        }
        target_key.ok_or(ReceiveError::Decryption)
    }

    pub fn decrypt(&mut self, counter: u64, packet: &[u8], aad: &[u8]) -> Result<Vec<u8>, ReceiveError> {
        let key = self.key_for(counter)?;
        crate::RatchetState::decrypt_once(&key, packet, aad).map_err(|_| ReceiveError::Decryption)
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
        assert_eq!(receiver.decrypt(1,&p1,b"aad").unwrap(),b"one");
        assert_eq!(receiver.decrypt(0,&p0,b"aad").unwrap(),b"zero");
        assert!(matches!(receiver.decrypt(0,&p0,b"aad"),Err(ReceiveError::Replay)));
    }
    #[test]
    fn excessive_skip_is_rejected() {
        let mut receiver=ReceiveRatchet::from_root([8u8;32]).unwrap();
        assert!(matches!(receiver.key_for(MAX_SKIP+1),Err(ReceiveError::TooFarAhead)));
    }
}
