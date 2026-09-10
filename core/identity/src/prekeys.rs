//! Helpers for constructing public prekey material.

use crate::{IdentityKey, SignedPrekey, SignedPrekeyRecord};

pub fn publishable_signed_prekey(
    identity: &IdentityKey,
    key_id: u32,
    prekey: &SignedPrekey,
) -> SignedPrekeyRecord {
    let public_key = prekey.public_key();
    let bytes = SignedPrekeyRecord::signing_bytes(key_id, &public_key);
    let signature = identity.sign(&bytes);
    SignedPrekeyRecord {
        key_id,
        public_key,
        signature: signature.to_bytes(),
    }
}
