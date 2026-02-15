use aws_sdk_kms::types::SigningAlgorithmSpec;
use miden_protocol::block::{BlockHeader, BlockSigner};
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_tx::utils::Serializable;

pub struct KmsSigner {
    key_id: String,
    client: aws_sdk_kms::Client,
}

impl KmsSigner {
    pub async fn new(key_id: impl Into<String>) -> Self {
        let version = aws_config::BehaviorVersion::v2026_01_12();
        let config = aws_config::load_defaults(version).await;
        let client = aws_sdk_kms::Client::new(&config);
        Self { key_id: key_id.into(), client }
    }
}

impl BlockSigner for KmsSigner {
    fn sign(&self, header: &BlockHeader) -> Signature {
        let s = tokio::runtime::Handle::current().block_on(async {
            self.client
                .sign()
                .key_id(&self.key_id)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .message(header.commitment().to_bytes().into())
                .send()
                .await
        });
    }

    fn public_key(&self) -> PublicKey {
        self.public_key()
    }
}
