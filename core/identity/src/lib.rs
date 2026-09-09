//! Identity/device lifecycle boundary.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationState {
    Unverified,
    Verified,
    Changed,
    Revoked,
}
