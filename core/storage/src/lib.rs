//! Local encrypted-storage boundary.

#![forbid(unsafe_code)]

pub const STORAGE_FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFormatVersion(pub u16);
