use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use nexa_protocol::{PreKeyBundle, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::Mutex;

const PUBLICATION_DOMAIN: &[u8] = b"M/PREKEY-PUBLICATION/v1";
const MAX_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyPublication {
    pub bundle: PreKeyBundle,
    pub generation: u64,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationError { InvalidBundle, InvalidVersion, InvalidTime, Expired, TooLong, InvalidSignature, WrongDevice, StaleGeneration, NotFound, AlreadyRevoked, Poisoned }

impl PreKeyPublication {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let b = &self.bundle;
        let mut out = Vec::with_capacity(256 + b.one_time_prekeys.len() * 36);
        out.extend_from_slice(PUBLICATION_DOMAIN);
        out.extend_from_slice(&b.protocol_version.0.to_be_bytes());
        out.extend_from_slice(&b.device_id);
        out.extend_from_slice(&b.identity_signing_key);
        out.extend_from_slice(&b.identity_agreement_key);
        out.extend_from_slice(&b.signed_prekey_id.to_be_bytes());
        out.extend_from_slice(&b.signed_prekey);
        out.extend_from_slice(&b.signed_prekey_signature);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&(b.one_time_prekeys.len() as u32).to_be_bytes());
        for key in &b.one_time_prekeys {
            out.extend_from_slice(&key.key_id.to_be_bytes());
            out.extend_from_slice(&key.public_key);
        }
        out
    }

    pub fn verify_signature(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.bundle.identity_signing_key) else { return false; };
        key.verify(&self.signing_bytes(), &Signature::from_bytes(&self.signature)).is_ok()
    }

    pub fn validate(&self, expected_device: [u8; 16], now_ms: u64) -> Result<(), PublicationError> {
        self.bundle.validate().map_err(|_| PublicationError::InvalidBundle)?;
        if self.bundle.protocol_version.0 != PROTOCOL_VERSION { return Err(PublicationError::InvalidVersion); }
        if self.bundle.device_id != expected_device { return Err(PublicationError::WrongDevice); }
        if self.issued_at_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) || self.expires_at_ms <= self.issued_at_ms { return Err(PublicationError::InvalidTime); }
        if self.expires_at_ms.saturating_sub(self.issued_at_ms) > MAX_LIFETIME_MS { return Err(PublicationError::TooLong); }
        if self.expires_at_ms <= now_ms { return Err(PublicationError::Expired); }
        if !self.verify_signature() || !verify_signed_prekey(&self.bundle) { return Err(PublicationError::InvalidSignature); }
        Ok(())
    }
}

fn verify_signed_prekey(bundle: &PreKeyBundle) -> bool {
    let Ok(identity) = VerifyingKey::from_bytes(&bundle.identity_signing_key) else { return false; };
    let mut bytes = b"NEXA/SPK/v2".to_vec();
    bytes.extend_from_slice(&bundle.signed_prekey_id.to_be_bytes());
    bytes.extend_from_slice(&bundle.signed_prekey);
    bytes.extend_from_slice(&bundle.identity_agreement_key);
    identity.verify(&bytes, &Signature::from_bytes(&bundle.signed_prekey_signature)).is_ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Revocation { generation: u64, revoked_at_ms: u64 }

#[derive(Default)]
struct RegistryState {
    publications: HashMap<[u8; 16], PreKeyPublication>,
    revocations: HashMap<[u8; 16], Revocation>,
}

#[derive(Clone, Default)]
pub struct PreKeyRegistry { inner: Arc<Mutex<RegistryState>> }

impl PreKeyRegistry {
    pub async fn publish(&self, publication: PreKeyPublication, now_ms: u64) -> Result<(), PublicationError> {
        let device = publication.bundle.device_id;
        publication.validate(device, now_ms)?;
        let mut guard = self.inner.lock().await;
        if guard.revocations.contains_key(&device) { return Err(PublicationError::AlreadyRevoked); }
        if let Some(current) = guard.publications.get(&device) {
            if publication.generation <= current.generation { return Err(PublicationError::StaleGeneration); }
        }
        guard.publications.insert(device, publication);
        Ok(())
    }

    pub async fn get(&self, device: [u8; 16]) -> Option<PreKeyPublication> {
        self.inner.lock().await.publications.get(&device).cloned()
    }

    pub async fn is_revoked(&self, device: [u8; 16]) -> bool {
        self.inner.lock().await.revocations.contains_key(&device)
    }

    pub async fn revoke(&self, device: [u8; 16], generation: u64, now_ms: u64) -> Result<(), PublicationError> {
        let mut guard = self.inner.lock().await;
        let current = guard.publications.get(&device).ok_or(PublicationError::NotFound)?;
        if current.generation != generation { return Err(PublicationError::StaleGeneration); }
        if guard.revocations.contains_key(&device) { return Err(PublicationError::AlreadyRevoked); }
        guard.revocations.insert(device, Revocation { generation, revoked_at_ms: now_ms });
        Ok(())
    }

    pub async fn get_active(&self, device: [u8; 16], now_ms: u64) -> Option<PreKeyPublication> {
        let guard = self.inner.lock().await;
        if guard.revocations.contains_key(&device) { return None; }
        let publication = guard.publications.get(&device)?;
        (publication.expires_at_ms > now_ms).then_some(publication.clone())
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use nexa_protocol::{OneTimePrekeyPublic, ProtocolVersion};

    fn publication(key: &SigningKey, generation: u64) -> PreKeyPublication {
        let public = key.verifying_key().to_bytes();
        let device = crate::auth::device_id_from_public_key(&public);
        let agreement = [3u8; 32];
        let spk = [4u8; 32];
        let mut sb = b"NEXA/SPK/v2".to_vec();
        sb.extend_from_slice(&7u32.to_be_bytes());
        sb.extend_from_slice(&spk);
        sb.extend_from_slice(&agreement);
        let bundle = PreKeyBundle {
            protocol_version: ProtocolVersion(PROTOCOL_VERSION), device_id: device,
            identity_signing_key: public, identity_agreement_key: agreement,
            signed_prekey_id: 7, signed_prekey: spk,
            signed_prekey_signature: key.sign(&sb).to_bytes(),
            one_time_prekeys: vec![OneTimePrekeyPublic { key_id: 9, public_key: [5; 32] }],
        };
        let now = now_ms();
        let mut p = PreKeyPublication { bundle, generation, issued_at_ms: now, expires_at_ms: now + 60_000, signature: [0; 64] };
        p.signature = key.sign(&p.signing_bytes()).to_bytes();
        p
    }

    #[tokio::test]
    async fn publication_is_signed_and_monotonic() {
        let key = SigningKey::from_bytes(&[42; 32]); let r = PreKeyRegistry::default(); let p1 = publication(&key, 1); let d = p1.bundle.device_id;
        assert!(r.publish(p1.clone(), now_ms()).await.is_ok());
        assert!(matches!(r.publish(p1, now_ms()).await, Err(PublicationError::StaleGeneration)));
        let p2 = publication(&key, 2); assert!(r.publish(p2, now_ms()).await.is_ok()); assert_eq!(r.get(d).await.unwrap().generation, 2);
    }

    #[tokio::test]
    async fn tampering_is_rejected() {
        let key = SigningKey::from_bytes(&[43; 32]); let r = PreKeyRegistry::default(); let mut p = publication(&key, 1);
        p.bundle.signed_prekey[0] ^= 1; assert!(matches!(r.publish(p, now_ms()).await, Err(PublicationError::InvalidSignature)));
        let mut p = publication(&key, 1); p.signature[0] ^= 1; assert!(matches!(r.publish(p, now_ms()).await, Err(PublicationError::InvalidSignature)));
    }

    #[tokio::test]
    async fn revocation_blocks_republish_without_invalidating_publication_signature() {
        let key = SigningKey::from_bytes(&[44; 32]); let r = PreKeyRegistry::default(); let p = publication(&key, 5); let d = p.bundle.device_id;
        r.publish(p, now_ms()).await.unwrap(); r.revoke(d, 5, now_ms()).await.unwrap();
        assert!(r.is_revoked(d).await); assert!(r.get(d).await.unwrap().verify_signature()); assert!(r.get_active(d, now_ms()).await.is_none());
        assert!(matches!(r.publish(publication(&key, 6), now_ms()).await, Err(PublicationError::AlreadyRevoked)));
    }
}
