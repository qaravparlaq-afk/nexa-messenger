//! Account/device identity primitives.
//! Private signing keys must be kept in platform secure storage by clients.

#![forbid(unsafe_code)]

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationState {
    Unverified,
    Verified,
    Changed,
    Revoked,
}

pub struct IdentityKey {
    signing_key: SigningKey,
}

impl IdentityKey {
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_has_public_key() {
        let identity = IdentityKey::generate();
        assert_eq!(identity.public_key().as_bytes().len(), 32);
    }
}
