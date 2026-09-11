use std::{collections::{HashMap, VecDeque}, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use nexa_protocol::{EncryptedMessage, ProtocolVersion, PROTOCOL_VERSION};
use tokio::sync::Mutex;

const MAX_PER_DEVICE: usize = 256;
const MAX_TOTAL_MESSAGES: usize = 65_536;
const MAX_TOTAL_BYTES: usize = 512 * 1024 * 1024;
const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;
const MAX_RATCHET_HEADER: usize = 16 * 1024;
const OFFLINE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult { Accepted, Duplicate, Invalid, Full }

#[derive(Debug, Clone)]
struct StoredMessage {
    message: EncryptedMessage,
    expires_at_ms: u64,
    accounted_bytes: usize,
}

#[derive(Clone, Default)]
pub struct RelayStore { inner: Arc<Mutex<RelayInner>> }

#[derive(Default)]
struct RelayInner {
    queues: HashMap<[u8; 16], VecDeque<StoredMessage>>,
    total_messages: usize,
    total_bytes: usize,
}

impl RelayStore {
    pub async fn push(&self, message: EncryptedMessage) -> PushResult {
        if !valid_message(&message) { return PushResult::Invalid; }
        let now = now_ms();
        if message.sent_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
            || now.saturating_sub(message.sent_at_ms) > OFFLINE_TTL_MS
        { return PushResult::Invalid; }

        let accounted_bytes = message_size(&message);
        let expires_at_ms = now.saturating_add(OFFLINE_TTL_MS);
        let mut guard = self.inner.lock().await;
        let device_id = message.recipient_device_id;

        if let Some(mut queue) = guard.queues.remove(&device_id) {
            let (removed_messages, removed_bytes) = remove_expired(&mut queue, now);
            guard.total_messages = guard.total_messages.saturating_sub(removed_messages);
            guard.total_bytes = guard.total_bytes.saturating_sub(removed_bytes);

            if queue.iter().any(|stored| stored.message.message_id == message.message_id) {
                guard.queues.insert(device_id, queue);
                return PushResult::Duplicate;
            }
            if queue.len() >= MAX_PER_DEVICE {
                guard.queues.insert(device_id, queue);
                return PushResult::Full;
            }
            guard.queues.insert(device_id, queue);
        }

        if guard.total_messages >= MAX_TOTAL_MESSAGES
            || guard.total_bytes.saturating_add(accounted_bytes) > MAX_TOTAL_BYTES
        { return PushResult::Full; }

        guard.queues.entry(device_id).or_default().push_back(StoredMessage {
            message, expires_at_ms, accounted_bytes,
        });
        guard.total_messages += 1;
        guard.total_bytes += accounted_bytes;
        PushResult::Accepted
    }

    pub async fn pull(&self, device_id: [u8; 16]) -> Vec<EncryptedMessage> {
        let now = now_ms();
        let mut guard = self.inner.lock().await;
        let Some(mut queue) = guard.queues.remove(&device_id) else { return Vec::new(); };
        let (removed_messages, removed_bytes) = remove_expired(&mut queue, now);
        guard.total_messages = guard.total_messages.saturating_sub(removed_messages);
        guard.total_bytes = guard.total_bytes.saturating_sub(removed_bytes);
        let messages = queue.iter().map(|stored| stored.message.clone()).collect();
        if !queue.is_empty() { guard.queues.insert(device_id, queue); }
        messages
    }

    pub async fn ack(&self, device_id: [u8; 16], message_id: [u8; 16]) -> bool {
        let mut guard = self.inner.lock().await;
        let Some(mut queue) = guard.queues.remove(&device_id) else { return false; };
        let mut removed_bytes = 0usize;
        let before = queue.len();
        queue.retain(|stored| {
            if stored.message.message_id == message_id {
                removed_bytes = stored.accounted_bytes;
                false
            } else { true }
        });
        let removed = queue.len() != before;
        if removed {
            guard.total_messages = guard.total_messages.saturating_sub(1);
            guard.total_bytes = guard.total_bytes.saturating_sub(removed_bytes);
        }
        if !queue.is_empty() { guard.queues.insert(device_id, queue); }
        removed
    }
}

fn remove_expired(queue: &mut VecDeque<StoredMessage>, now: u64) -> (usize, usize) {
    let mut removed_messages = 0usize;
    let mut removed_bytes = 0usize;
    queue.retain(|stored| {
        if stored.expires_at_ms <= now {
            removed_messages += 1;
            removed_bytes = removed_bytes.saturating_add(stored.accounted_bytes);
            false
        } else { true }
    });
    (removed_messages, removed_bytes)
}

fn message_size(message: &EncryptedMessage) -> usize {
    2usize.saturating_add(16).saturating_add(16).saturating_add(16).saturating_add(16)
        .saturating_add(4).saturating_add(message.ratchet_header.len())
        .saturating_add(4).saturating_add(message.ciphertext.len()).saturating_add(8)
}

fn valid_message(message: &EncryptedMessage) -> bool {
    message.version == ProtocolVersion(PROTOCOL_VERSION)
        && message.message_id != [0; 16]
        && message.conversation_id != [0; 16]
        && message.sender_device_id != [0; 16]
        && message.recipient_device_id != [0; 16]
        && !message.ratchet_header.is_empty()
        && message.ratchet_header.len() <= MAX_RATCHET_HEADER
        && !message.ciphertext.is_empty()
        && message.ciphertext.len() <= MAX_CIPHERTEXT
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: u8) -> EncryptedMessage {
        EncryptedMessage::new([id; 16], [2; 16], [3; 16], [4; 16], vec![5], vec![6], now_ms())
    }

    #[tokio::test]
    async fn duplicate_message_is_not_queued_twice() {
        let store = RelayStore::default();
        assert_eq!(store.push(message(1)).await, PushResult::Accepted);
        assert_eq!(store.push(message(1)).await, PushResult::Duplicate);
        assert_eq!(store.pull([4; 16]).await.len(), 1);
    }

    #[tokio::test]
    async fn ack_removes_only_matching_message() {
        let store = RelayStore::default();
        store.push(message(1)).await;
        store.push(message(2)).await;
        assert!(!store.ack([4; 16], [9; 16]).await);
        assert!(store.ack([4; 16], [1; 16]).await);
        assert_eq!(store.pull([4; 16]).await.len(), 1);
    }

    #[tokio::test]
    async fn invalid_messages_are_rejected() {
        let store = RelayStore::default();
        let mut msg = message(1);
        msg.ciphertext.clear();
        assert_eq!(store.push(msg).await, PushResult::Invalid);
    }

    #[tokio::test]
    async fn pull_does_not_delete_before_ack() {
        let store = RelayStore::default();
        store.push(message(1)).await;
        assert_eq!(store.pull([4; 16]).await.len(), 1);
        assert_eq!(store.pull([4; 16]).await.len(), 1);
    }

    #[tokio::test]
    async fn per_device_limit_is_enforced() {
        let store = RelayStore::default();
        for id in 1u16..=(MAX_PER_DEVICE as u16) {
            let mut msg = message((id & 0xff) as u8);
            msg.message_id = (id as u128).to_be_bytes();
            assert_eq!(store.push(msg).await, PushResult::Accepted);
        }
        let mut extra = message(0);
        extra.message_id = (257u128).to_be_bytes();
        assert_eq!(store.push(extra).await, PushResult::Full);
    }

    #[tokio::test]
    async fn global_message_limit_is_enforced_without_unbounded_growth() {
        let store = RelayStore::default();
        for id in 1..=MAX_TOTAL_MESSAGES {
            let mut msg = message((id % 255 + 1) as u8);
            msg.recipient_device_id = (id as u128).to_be_bytes();
            msg.message_id = (id as u128).to_be_bytes();
            assert_eq!(store.push(msg).await, PushResult::Accepted);
        }
        let mut extra = message(1);
        extra.message_id = (MAX_TOTAL_MESSAGES as u128 + 1).to_be_bytes();
        extra.recipient_device_id = (MAX_TOTAL_MESSAGES as u128 + 1).to_be_bytes();
        assert_eq!(store.push(extra).await, PushResult::Full);
    }
}
