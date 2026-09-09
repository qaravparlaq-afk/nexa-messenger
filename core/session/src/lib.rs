//! NEXA v1 session-establishment primitive.
//!
//! This module derives a session root from fresh X25519 material and an
//! authenticated prekey. It intentionally does NOT claim to be a complete
//! Double Ratchet implementation yet.

#![forbid(unsafe_code)]

use hkdf::Hkdf;
use nexa_identity::{IdentityKey, OneTimePrekey, SignedPrekey, SignedPrekeyRecord};
use nexa_protocol::{PreKeyBundle, ProtocolVersion, PROTOCOL_VERSION};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const DOMAIN: &[u8] = b"NEXA/SESSION/v1";
const ROOT_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    ProtocolVersion,
    InvalidSignedPrekey,
    InvalidPeerIdentity,
    InvalidSharedSecret,
    KeyDerivation,
}

#[derive(Clone, Copy)]
pub struct InitiatorEphemeral {
    secret: [u8; 32],
    pub public_key: [u8; 32],
}

impl InitiatorEphemeral {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self { secret: secret.to_bytes(), public_key }
    }
}

impl Drop for InitiatorEphemeral {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The private result is zeroized when dropped.
pub struct SessionRoot(Zeroizing<[u8; ROOT_LEN]>);

impl SessionRoot {
    pub fn as_bytes(&self) -> &[u8; ROOT_LEN] {
        &self.0
    }
}

pub struct InitiatorSession {
    pub root: SessionRoot,
    pub peer_device_id: [u8; 16],
    pub used_one_time_prekey_id: Option<u32>,
}

pub struct ResponderSession {
    pub root: SessionRoot,
    pub peer_device_id: [u8; 16],
    pub used_one_time_prekey_id: Option<u32>,
}

/// Initiator side: authenticate the bundle and derive the same root as the
/// responder from the signed prekey and optional one-time prekey.
pub fn initiate(
    identity: &IdentityKey,
    own_ephemeral: InitiatorEphemeral,
    bundle: &PreKeyBundle,
    signed_prekey_record: &SignedPrekeyRecord,
    one_time_prekey_public: Option<(u32, [u8; 32])>,
) -> Result<InitiatorSession, SessionError> {
    if bundle.protocol_version.0 != PROTOCOL_VERSION {
        return Err(SessionError::ProtocolVersion);
    }

    let peer_identity = ed25519_dalek::VerifyingKey::from_bytes(&bundle.identity_signing_key)
        .map_err(|_| SessionError::InvalidPeerIdentity)?;

    if !signed_prekey_record.verify(&peer_identity)
        || signed_prekey_record.key_id != bundle.signed_prekey_id
        || signed_prekey_record.public_key != bundle.signed_prekey
    {
        return Err(SessionError::InvalidSignedPrekey);
    }

    let signed_public = PublicKey::from(bundle.signed_prekey);
    let own_secret = StaticSecret::from(own_ephemeral.secret);

    let mut dh1 = own_secret.diffie_hellman(&signed_public).to_bytes();
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&dh1);

    let used_id = if let Some((id, public)) = one_time_prekey_public {
        let mut dh2 = own_secret.diffie_hellman(&PublicKey::from(public)).to_bytes();
        ikm.extend_from_slice(&dh2);
        dh2.zeroize();
        Some(id)
    } else {
        None
    };

    let root = derive_root(&ikm, &bundle.device_id, &own_ephemeral.public_key)
        .ok_or(SessionError::KeyDerivation)?;
    dh1.zeroize();
    ikm.zeroize();

    let _ = identity; // Reserved for future transcript authentication binding.
    Ok(InitiatorSession {
        root,
        peer_device_id: bundle.device_id,
        used_one_time_prekey_id: used_id,
    })
}

/// Responder side counterpart. The caller supplies the private signed prekey
/// and, when selected, consumes the one-time prekey by ownership.
pub fn respond(
    own_signed_prekey: &SignedPrekey,
    own_one_time_prekey: Option<(u32, OneTimePrekey)>,
    own_device_id: [u8; 16],
    peer_device_id: [u8; 16],
    peer_ephemeral_public: [u8; 32],
) -> Result<ResponderSession, SessionError> {
    let peer = PublicKey::from(peer_ephemeral_public);
    let mut dh1 = own_signed_prekey.diffie_hellman(&peer);
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(&dh1);

    let (used_id, mut dh2) = if let Some((id, otp)) = own_one_time_prekey {
        (Some(id), otp.diffie_hellman(&peer))
    } else {
        (None, [0u8; 32])
    };
    if used_id.is_some() {
        ikm.extend_from_slice(&dh2);
    }

    let root = derive_root(&ikm, &own_device_id, &peer_ephemeral_public)
        .ok_or(SessionError::KeyDerivation)?;

    dh1.zeroize();
    dh2.zeroize();
    ikm.zeroize();

    Ok(ResponderSession {
        root,
        peer_device_id,
        used_one_time_prekey_id: used_id,
    })
}

fn derive_root(
    ikm: &[u8],
    device_id: &[u8; 16],
    ephemeral_public: &[u8; 32],
) -> Option<SessionRoot> {
    if ikm.iter().all(|b| *b == 0) {
        return None;
    }
    let hk = Hkdf::<Sha256>::new(Some(DOMAIN), ikm);
    let mut info = Vec::with_capacity(2 + 16 + 32);
    info.extend_from_slice(&ProtocolVersion(PROTOCOL_VERSION).0.to_be_bytes());
    info.extend_from_slice(device_id);
    info.extend_from_slice(ephemeral_public);
    let mut out = Zeroizing::new([0u8; ROOT_LEN]);
    hk.expand(&info, out.as_mut()).ok()?;
    Some(SessionRoot(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexa_identity::{prekeys::publishable_signed_prekey, IdentityKey};

    #[test]
    fn initiator_and_responder_derive_same_root() {
        let peer_identity = IdentityKey::generate();
        let peer_spk = SignedPrekey::generate();
        let record = publishable_signed_prekey(&peer_identity, 1, &peer_spk);
        let eph = InitiatorEphemeral::generate();

        let bundle = PreKeyBundle {
            protocol_version: ProtocolVersion(PROTOCOL_VERSION),
            device_id: [7; 16],
            identity_signing_key: peer_identity.public_key().to_bytes(),
            signed_prekey_id: 1,
            signed_prekey: peer_spk.public_key(),
            signed_prekey_signature: record.signature,
            one_time_prekeys: vec![],
        };

        let initiator = initiate(
            &IdentityKey::generate(),
            eph,
            &bundle,
            &record,
            None,
        ).expect("initiate");

        let responder = respond(
            &peer_spk,
            None,
            [7; 16],
            [8; 16],
            eph.public_key,
        ).expect("respond");

        assert_eq!(initiator.root.as_bytes(), responder.root.as_bytes());
    }
}
