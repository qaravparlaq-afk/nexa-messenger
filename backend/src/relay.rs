use std::{collections::{HashMap, VecDeque}, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

use nexa_protocol::{EncryptedMessage, ProtocolVersion, PROTOCOL_VERSION};
use tokio::sync::Mutex;

const MAX_PER_DEVICE: usize = 256;
const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;
const MAX_RATCHET_HEADER: usize = 16 * 1024;
const OFFLINE_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushResult {
    Accepted,
    Duplicate,
    Invalid,
    Full,
}

#[derive(Debug, Clone)]
struct StoredMessage {
    message: EncryptedMessage,
    expires_at_ms: u64,
}

#[derive(Clone, Default)]
pub struct RelayStore {
    inner: Arc<Mutex<HashMap<[u8; 16], VecDeque<StoredMessage>>>>,
}

impl RelayStore {
    pub async fn push(&self, message: EncryptedMessage) -> PushResult {
        if !valid_message(&message) {
            return PushResult::Invalid;
        }

        let now = now_ms();
        if message.sent_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
            || now.saturating_sub(message.sent_at_ms) > OFFLINE_TTL_MS
        {
            return PushResult::Invalid;
        }

        let expires_at_ms = now.saturating_add(OFFLINE_TTL_MS);
        let mut guard = self.inner.lock().await;
        let queue = guard.entry(message.recipient_device_id).or_default();

        queue.retain(|stored| stored.expires_at_ms > now);

        if queue.iter().any(|stored| stored.message.message_id == message.message_id) {
            return PushResult::Duplicate;
        }
        if queue.len() >= MAX_PER_DEVICE {
            return PushResult::Full;
        }

        queue.push_back(StoredMessage { message, expires_at_ms });
        PushResult::Accepted
    }

    pub async fn pull(&self, device_id: [u8; 16]) -> Vec<EncryptedMessage> {
        let now = now_ms();
        let mut guard = self.inner.lock().await;
        let Some(queue) = guard.get_mut(&device_id) else {
            return Vec::new();
        };

        queue.retain(|stored| stored.expires_at_ms > now);
        queue.iter().map(|stored| stored.message.clone()).collect()
    }

    pub async fn ack(&self, device_id: [u8; 16], message_id: [u8; 16]) -> bool {
        let mut guard = self.inner.lock().await;
        let Some(queue) = guard.get_mut(&device_id) else {
            return false;
        };

        let before = queue.len();
        queue.retain(|stored| stored.message.message_id != message_id);
        let removed = queue.len() != before;

        if queue.is_empty() {
            guard.remove(&device_id);
        }
        removed
    }
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: u8) -> EncryptedMessage {
        EncryptedMessage::new(
            [id; 16], [2; 16], [3; 16], [4; 16], vec![5], vec![6], now_ms(),
        )
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
}
