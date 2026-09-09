//! NEXA cryptographic boundary.
//! No proprietary cryptographic primitives belong here.
//! Concrete algorithms must be selected from established, reviewed libraries
//! after protocol review.

#![forbid(unsafe_code)]

pub const API_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoApiVersion(pub u32);

pub fn api_version() -> CryptoApiVersion {
    CryptoApiVersion(API_VERSION)
}
