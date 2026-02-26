use core::convert::Infallible;
use core::error;

use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, SecretKey, Signature};

// BLOCK SIGNER
// ================================================================================================

/// Trait which abstracts the signing of block headers with ECDSA signatures.
///
/// Production-level implementations will involve some sort of secure remote backend. The trait also
/// allows for testing with local and ephemeral signers.
pub trait BlockSigner {
    type Error: error::Error + Send + Sync + 'static;
    fn sign(
        &self,
        header: &BlockHeader,
    ) -> impl Future<Output = Result<Signature, Self::Error>> + Send;
    fn public_key(&self) -> PublicKey;
}

// SECRET KEY BLOCK SIGNER
// ================================================================================================

impl BlockSigner for SecretKey {
    type Error = Infallible;

    async fn sign(&self, header: &BlockHeader) -> Result<Signature, Self::Error> {
        Ok(self.sign(header.commitment()))
    }

    fn public_key(&self) -> PublicKey {
        self.public_key()
    }
}
