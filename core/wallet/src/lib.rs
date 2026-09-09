//! Non-custodial wallet boundary.
//! Private key material must never cross into a server-side service.

#![forbid(unsafe_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletMode {
    NonCustodial,
}
