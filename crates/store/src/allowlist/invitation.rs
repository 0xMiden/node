use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;

/// A nonempty invitation code represented by its SHA-256 digest.
///
/// The digest permits code matching without storing a code that an attacker can redeem after a database leak.
/// Construction does not retain the original text. Debug output hides the digest.
/// Callers must use random invitation codes with enough entropy to resist guessing.
#[derive(Clone, PartialEq, Eq)]
pub struct InvitationCode([u8; 32]);

impl InvitationCode {
    /// Computes a digest of the exact UTF-8 text without trimming or normalization.
    pub fn new(code: &str) -> Result<Self, InvalidInvitationCode> {
        if code.is_empty() {
            return Err(InvalidInvitationCode);
        }
        Ok(Self(Sha256::digest(code.as_bytes()).into()))
    }

    /// Uses a caller-computed SHA-256 digest without hashing it again. The caller must compute the
    /// digest from a nonempty invitation code.
    pub fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Parses a SHA-256 digest from 64 hexadecimal characters without a prefix. This method does
    /// not hash the digest again.
    pub fn from_hex_digest(value: &str) -> Result<Self, hex::FromHexError> {
        let mut digest = [0; 32];
        hex::decode_to_slice(value, &mut digest)?;
        Ok(Self::from_digest(digest))
    }

    pub(crate) fn digest(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for InvitationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationCode([REDACTED])")
    }
}

/// An invitation code must not be empty.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invitation code must not be empty")]
pub struct InvalidInvitationCode;
