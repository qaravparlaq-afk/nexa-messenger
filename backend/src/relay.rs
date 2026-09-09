use std::{collections::{HashMap, VecDeque}, sync::Arc};

use tokio::sync::Mutex;
use nexa_protocol::EncryptedMessage;

const MAX_PER_DEVICE: usize = 256;

#[derive(Clone, Default)]
pub struct RelayStore {
    inner: Arc<Mutex<HashMap<[u8; 16], VecDeque<EncryptedMessage>>>>,
}

impl RelayStore {
    pub async fn push(&self, message: EncryptedMessage) {
        let mut guard = self.inner.lock().await;
        let queue = guard.entry(message.recipient_device_id).or_default();
        if queue.len() >= MAX_PER_DEVICE {
            queue.pop_front();
        }
        queue.push_back(message);
    }

    pub async fn drain(&self, device_id: [u8; 16]) -> Vec<EncryptedMessage> {
        let mut guard = self.inner.lock().await;
        guard.remove(&device_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }
}
