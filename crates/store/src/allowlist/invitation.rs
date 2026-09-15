use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;

/// A nonempty invitation code represented by its SHA-256 digest.
///
/// The digest permits code matching without storing a code that an attacker can redeem after a database leak.
/// Construction does not retain the original bytes. Debug output hides the digest.
/// Callers must use random invitation codes with enough entropy to resist guessing.
#[derive(Clone, PartialEq, Eq)]
pub struct InvitationCode([u8; 32]);

impl InvitationCode {
    /// Computes a digest of the exact invitation code bytes without text normalization.
    pub fn new(bytes: &[u8]) -> Result<Self, InvalidInvitationCode> {
        if bytes.is_empty() {
            return Err(InvalidInvitationCode);
        }
        Ok(Self(Sha256::digest(bytes).into()))
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

/// An invitation code must contain at least one byte.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invitation code must not be empty")]
pub struct InvalidInvitationCode;
