use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use nexa_protocol::{PreKeyBundle, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
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
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationError {
    InvalidBundle, InvalidVersion, InvalidTime, Expired, TooLong, InvalidSignature,
    WrongDevice, StaleGeneration, NotFound, AlreadyRevoked, AlreadyClaimed,
    InvalidRequest, Poisoned,
}

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
        if self.issued_at_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
            || self.expires_at_ms <= self.issued_at_ms { return Err(PublicationError::InvalidTime); }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpkClaimRequest {
    pub request_id: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpkClaim {
    pub request_id: [u8; 16],
    pub claimant_device: [u8; 16],
    pub recipient_device: [u8; 16],
    pub generation: u64,
    pub key_id: u32,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ClaimKey { device: [u8; 16], generation: u64, key_id: u32 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct RequestKey { claimant: [u8; 16], request_id: [u8; 16] }

#[derive(Default)]
struct RegistryState {
    publications: HashMap<[u8; 16], PreKeyPublication>,
    revoked: HashMap<[u8; 16], u64>,
    claims: HashMap<ClaimKey, OpkClaim>,
    requests: HashMap<RequestKey, ClaimKey>,
}

#[derive(Clone, Default)]
pub struct PreKeyRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

impl PreKeyRegistry {
    pub async fn publish(&self, expected_device: [u8; 16], publication: PreKeyPublication, now_ms: u64) -> Result<(), PublicationError> {
        let device = publication.bundle.device_id;
        publication.validate(expected_device, now_ms)?;
        let mut guard = self.inner.lock().await;
        if guard.revoked.contains_key(&device) { return Err(PublicationError::AlreadyRevoked); }
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
        self.inner.lock().await.revoked.contains_key(&device)
    }

    pub async fn revoke(&self, device: [u8; 16], generation: u64, now_ms: u64) -> Result<(), PublicationError> {
        let mut guard = self.inner.lock().await;
        let current = guard.publications.get(&device).ok_or(PublicationError::NotFound)?;
        if current.generation != generation { return Err(PublicationError::StaleGeneration); }
        if guard.revoked.contains_key(&device) { return Err(PublicationError::AlreadyRevoked); }
        guard.revoked.insert(device, now_ms);
        Ok(())
    }

    pub async fn get_active(&self, device: [u8; 16], now_ms: u64) -> Option<PreKeyPublication> {
        let guard = self.inner.lock().await;
        if guard.revoked.contains_key(&device) { return None; }
        let publication = guard.publications.get(&device)?;
        (publication.expires_at_ms > now_ms).then_some(publication.clone())
    }

    pub async fn claim_opk(
        &self, recipient: [u8; 16], generation: u64, key_id: u32,
        claimant: [u8; 16], request_id: [u8; 16], now_ms: u64,
    ) -> Result<OpkClaim, PublicationError> {
        if request_id == [0; 16] { return Err(PublicationError::InvalidRequest); }
        let mut guard = self.inner.lock().await;
        if guard.revoked.contains_key(&recipient) { return Err(PublicationError::NotFound); }
        let publication = guard.publications.get(&recipient).ok_or(PublicationError::NotFound)?;
        if publication.expires_at_ms <= now_ms { return Err(PublicationError::NotFound); }
        if publication.generation != generation { return Err(PublicationError::StaleGeneration); }

        let claim_key = ClaimKey { device: recipient, generation, key_id };
        if let Some(existing) = guard.claims.get(&claim_key) {
            if existing.claimant_device == claimant && existing.request_id == request_id { return Ok(*existing); }
            return Err(PublicationError::AlreadyClaimed);
        }

        let request_key = RequestKey { claimant, request_id };
        if guard.requests.contains_key(&request_key) { return Err(PublicationError::InvalidRequest); }

        let public_key = publication.bundle.one_time_prekeys.iter()
            .find(|key| key.key_id == key_id)
            .map(|key| key.public_key)
            .ok_or(PublicationError::NotFound)?;

        let claim = OpkClaim {
            request_id, claimant_device: claimant, recipient_device: recipient,
            generation, key_id, public_key,
        };
        guard.claims.insert(claim_key, claim);
        guard.requests.insert(request_key, claim_key);
        Ok(claim)
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
        let agreement = [3u8; 32]; let spk = [4u8; 32];
        let mut sb = b"NEXA/SPK/v2".to_vec();
        sb.extend_from_slice(&7u32.to_be_bytes()); sb.extend_from_slice(&spk); sb.extend_from_slice(&agreement);
        let bundle = PreKeyBundle {
            protocol_version: ProtocolVersion(PROTOCOL_VERSION), device_id: device,
            identity_signing_key: public, identity_agreement_key: agreement,
            signed_prekey_id: 7, signed_prekey: spk,
            signed_prekey_signature: key.sign(&sb).to_bytes(),
            one_time_prekeys: vec![OneTimePrekeyPublic { key_id: 9, public_key: [5; 32] }],
        };
        let now = now_ms();
        let mut p = PreKeyPublication { bundle, generation, issued_at_ms: now, expires_at_ms: now + 60_000, signature: [0; 64] };
        p.signature = key.sign(&p.signing_bytes()).to_bytes(); p
    }

    #[tokio::test]
    async fn publication_is_signed_and_monotonic() {
        let key = SigningKey::from_bytes(&[42; 32]); let r = PreKeyRegistry::default();
        let p1 = publication(&key, 1); let d = p1.bundle.device_id;
        assert!(r.publish(p1.clone(), now_ms()).await.is_ok());
        assert!(matches!(r.publish(p1, now_ms()).await, Err(PublicationError::StaleGeneration)));
        let p2 = publication(&key, 2); assert!(r.publish(p2, now_ms()).await.is_ok());
        assert_eq!(r.get(d).await.unwrap().generation, 2);
    }

    #[tokio::test]
    async fn tampering_is_rejected() {
        let key = SigningKey::from_bytes(&[43; 32]); let r = PreKeyRegistry::default(); let mut p = publication(&key, 1);
        p.bundle.signed_prekey[0] ^= 1; assert!(matches!(r.publish(p.bundle.device_id, p, now_ms()).await, Err(PublicationError::InvalidSignature)));
        let mut p = publication(&key, 1); p.signature[0] ^= 1;
        assert!(matches!(r.publish(p.bundle.device_id, p, now_ms()).await, Err(PublicationError::InvalidSignature)));
    }

    #[tokio::test]
    async fn revocation_blocks_republish_without_invalidating_publication_signature() {
        let key = SigningKey::from_bytes(&[44; 32]); let r = PreKeyRegistry::default();
        let p = publication(&key, 5); let d = p.bundle.device_id; r.publish(p.bundle.device_id, p, now_ms()).await.unwrap();
        r.revoke(d, 5, now_ms()).await.unwrap();
        assert!(r.is_revoked(d).await); assert!(r.get(d).await.unwrap().verify_signature());
        assert!(r.get_active(d, now_ms()).await.is_none());
        assert!(matches!(r.publish(publication(&key, 6), now_ms()).await, Err(PublicationError::AlreadyRevoked)));
    }

    #[tokio::test]
    async fn opk_claim_is_atomic_and_idempotent() {
        let key = SigningKey::from_bytes(&[45; 32]); let r = PreKeyRegistry::default();
        let p = publication(&key, 7); let recipient = p.bundle.device_id; r.publish(p.bundle.device_id, p, now_ms()).await.unwrap();
        let claimant = [8u8; 16]; let request = [9u8; 16];
        let first = r.claim_opk(recipient, 7, 9, claimant, request, now_ms()).await.unwrap();
        let retry = r.claim_opk(recipient, 7, 9, claimant, request, now_ms()).await.unwrap();
        assert_eq!(first, retry);
        assert!(matches!(r.claim_opk(recipient, 7, 9, [10;16], [11;16], now_ms()).await, Err(PublicationError::AlreadyClaimed)));
        assert!(matches!(r.claim_opk(recipient, 6, 9, [10;16], [12;16], now_ms()).await, Err(PublicationError::StaleGeneration)));
        assert!(matches!(r.claim_opk(recipient, 7, 99, [10;16], [13;16], now_ms()).await, Err(PublicationError::NotFound)));
    }

    #[tokio::test]
    async fn concurrent_opk_claim_has_exactly_one_winner() {
        let key = SigningKey::from_bytes(&[46; 32]); let r = PreKeyRegistry::default();
        let p = publication(&key, 8); let recipient = p.bundle.device_id; r.publish(p.bundle.device_id, p, now_ms()).await.unwrap();
        let mut tasks = Vec::new();
        for i in 0u8..16 {
            let registry = r.clone();
            tasks.push(tokio::spawn(async move {
                registry.claim_opk(recipient, 8, 9, [i + 1;16], [i + 33;16], now_ms()).await
            }));
        }
        let mut winners = 0;
        for task in tasks { if task.await.unwrap().is_ok() { winners += 1; } }
        assert_eq!(winners, 1);
    }
}
