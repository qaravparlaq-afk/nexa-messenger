use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use nexa_protocol::{PreKeyBundle, ProtocolVersion, PROTOCOL_VERSION};
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
    pub revoked: bool,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationError { InvalidBundle, InvalidVersion, InvalidTime, Expired, TooLong, InvalidSignature, WrongDevice, StaleGeneration, NotFound, Poisoned }

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
        out.push(self.revoked as u8);
        out.extend_from_slice(&(b.one_time_prekeys.len() as u32).to_be_bytes());
        for key in &b.one_time_prekeys { out.extend_from_slice(&key.key_id.to_be_bytes()); out.extend_from_slice(&key.public_key); }
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
        if !self.verify_signature() { return Err(PublicationError::InvalidSignature); }
        let spk = nexa_identity_record(&self.bundle);
        if !spk { return Err(PublicationError::InvalidSignature); }
        Ok(())
    }
}

fn nexa_identity_record(bundle: &PreKeyBundle) -> bool {
    let Ok(identity) = VerifyingKey::from_bytes(&bundle.identity_signing_key) else { return false; };
    let bytes = {
        let mut out = b"NEXA/SPK/v2".to_vec();
        out.extend_from_slice(&bundle.signed_prekey_id.to_be_bytes());
        out.extend_from_slice(&bundle.signed_prekey);
        out.extend_from_slice(&bundle.identity_agreement_key);
        out
    };
    identity.verify(&bytes, &Signature::from_bytes(&bundle.signed_prekey_signature)).is_ok()
}

#[derive(Clone, Default)]
pub struct PreKeyRegistry { inner: Arc<Mutex<HashMap<[u8; 16], PreKeyPublication>>> }

impl PreKeyRegistry {
    pub async fn publish(&self, publication: PreKeyPublication, now_ms: u64) -> Result<(), PublicationError> {
        let device = publication.bundle.device_id;
        publication.validate(device, now_ms)?;
        let mut guard = self.inner.lock().await;
        if let Some(current) = guard.get(&device) {
            if publication.generation <= current.generation { return Err(PublicationError::StaleGeneration); }
        }
        guard.insert(device, publication);
        Ok(())
    }
    pub async fn get(&self, device: [u8; 16]) -> Option<PreKeyPublication> { self.inner.lock().await.get(&device).cloned() }
    pub async fn revoke(&self, device: [u8; 16], generation: u64, now_ms: u64) -> Result<(), PublicationError> {
        let mut guard = self.inner.lock().await;
        let current = guard.get_mut(&device).ok_or(PublicationError::NotFound)?;
        if current.generation != generation { return Err(PublicationError::StaleGeneration); }
        current.revoked = true;
        current.expires_at_ms = current.expires_at_ms.min(now_ms);
        Ok(())
    }
}

pub fn now_ms() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use nexa_protocol::{OneTimePrekeyPublic, ProtocolVersion, PROTOCOL_VERSION};

    fn publication(key: &SigningKey, generation: u64) -> PreKeyPublication {
        let public = key.verifying_key().to_bytes();
        let device = crate::auth::device_id_from_public_key(&public);
        let agreement = [3u8; 32];
        let spk = [4u8; 32];
        let mut spk_bytes = b"NEXA/SPK/v2".to_vec(); spk_bytes.extend_from_slice(&7u32.to_be_bytes()); spk_bytes.extend_from_slice(&spk); spk_bytes.extend_from_slice(&agreement);
        let bundle = PreKeyBundle { protocol_version: ProtocolVersion(PROTOCOL_VERSION), device_id: device, identity_signing_key: public, identity_agreement_key: agreement, signed_prekey_id: 7, signed_prekey: spk, signed_prekey_signature: key.sign(&spk_bytes).to_bytes(), one_time_prekeys: vec![OneTimePrekeyPublic { key_id: 9, public_key: [5; 32] }] };
        let mut p = PreKeyPublication { bundle, generation, issued_at_ms: now_ms(), expires_at_ms: now_ms() + 60_000, revoked: false, signature: [0; 64] };
        p.signature = key.sign(&p.signing_bytes()).to_bytes(); p
    }

    #[tokio::test]
    async fn publication_is_signed_and_monotonic() { let key=SigningKey::from_bytes(&[42;32]); let registry=PreKeyRegistry::default(); let p1=publication(&key,1); let device=p1.bundle.device_id; assert!(registry.publish(p1.clone(),now_ms()).await.is_ok()); assert!(matches!(registry.publish(p1,now_ms()),Err(PublicationError::StaleGeneration))); let mut p2=publication(&key,2); p2.bundle.one_time_prekeys[0].public_key=[6;32]; p2.signature=key.sign(&p2.signing_bytes()).to_bytes(); assert!(registry.publish(p2,now_ms()).await.is_ok()); assert_eq!(registry.get(device).await.unwrap().generation,2); }

    #[tokio::test]
    async fn tampering_signature_or_spk_is_rejected() { let key=SigningKey::from_bytes(&[43;32]); let mut p=publication(&key,1); let device=p.bundle.device_id; p.bundle.signed_prekey[0]^=1; let registry=PreKeyRegistry::default(); assert!(matches!(registry.publish(p,now_ms()).await,Err(PublicationError::InvalidSignature))); let mut p=publication(&key,1); p.signature[0]^=1; assert!(matches!(registry.publish(p,now_ms()).await,Err(PublicationError::InvalidSignature))); assert!(registry.get(device).await.is_none()); }

    #[tokio::test]
    async fn revoked_generation_is_persisted_and_stale_cannot_replace() { let key=SigningKey::from_bytes(&[44;32]); let registry=PreKeyRegistry::default(); let p=publication(&key,5); let device=p.bundle.device_id; registry.publish(p,now_ms()).await.unwrap(); registry.revoke(device,5,now_ms()).await.unwrap(); let current=registry.get(device).await.unwrap(); assert!(current.revoked); assert!(current.expires_at_ms <= now_ms()); let p6=publication(&key,6); assert!(registry.publish(p6,now_ms()).await.is_ok()); }
}
