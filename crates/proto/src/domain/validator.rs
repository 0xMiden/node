use miden_protobuf::{BuildUnchecked, ConversionError, ConversionResultExt, Verify};
use miden_protocol::Word;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};

use crate::generated as proto;

/// A single validator's response to a `sign_block` request.
#[derive(Debug, Clone)]
pub struct SignBlockResponse {
    pub signature: Signature,
    pub block_commitment: Word,
    pub public_key: PublicKey,
}

impl BuildUnchecked for proto::validator::DecodedSignBlockResponse {
    type Output = SignBlockResponse;
    type Error = ConversionError;

    /// Decode the signature and key without authenticating the response. The caller must match the
    /// commitment to its proposed block and verify the signature against the trusted parent
    /// validator set.
    fn build_unchecked(self) -> Result<Self::Output, Self::Error> {
        Ok(SignBlockResponse {
            signature: self.signature.verify().context("signature")?,
            block_commitment: self.block_commitment,
            public_key: self.public_key.verify().context("public_key")?,
        })
    }
}
