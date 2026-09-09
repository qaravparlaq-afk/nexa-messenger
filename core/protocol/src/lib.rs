//! Versioned protocol types.
//! Plaintext message content must remain outside the server-facing protocol layer.

#![forbid(unsafe_code)]

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion(pub u16);

pub fn version() -> ProtocolVersion {
    ProtocolVersion(PROTOCOL_VERSION)
}
