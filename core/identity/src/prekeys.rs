//! Prekey lifecycle helpers kept separate from the identity key implementation.

use crate::{IdentityKey, SignedPrekey};

/// Build the signed-prekey record published to the server.
pub fn publishable_signed_prekey(identity: &IdentityKey, key_id: u32, prekey: &SignedPrekey) -> crate::SignedPrekeyRecord {
    let public_key = prekey.public_key();
    let bytes = crate::SignedPrekeyRecord::signing_bytes(key_id, &public_key);
    let signature = identity.sign(&bytes);
    crate::SignedPrekeyRecord {
        key_id,
        public_key,
        signature: signature.to_bytes(),
    }
}
