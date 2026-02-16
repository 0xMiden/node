use aws_sdk_kms::types::SigningAlgorithmSpec;
use miden_node_utils::signer::BlockSigner;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};
use miden_tx::utils::{Deserializable, Serializable};

pub struct KmsSigner {
    key_id: String,
    pub_key: PublicKey,
    client: aws_sdk_kms::Client,
}

impl KmsSigner {
    pub async fn new(key_id: impl Into<String>) -> anyhow::Result<Self> {
        let version = aws_config::BehaviorVersion::v2026_01_12();
        let config = aws_config::load_defaults(version).await;
        let client = aws_sdk_kms::Client::new(&config);
        let key_id = key_id.into();

        // Retrieve public key.
        let pub_key_output = client.get_public_key().key_id(key_id.clone()).send().await?;

        if let Some(pub_key) = pub_key_output.public_key() {
            let pub_key = PublicKey::read_from_bytes(&pub_key.clone().into_inner())?;
            Ok(Self { key_id, pub_key, client })
        } else {
            anyhow::bail!("failed to retrieve public key");
        }
    }
}

#[async_trait::async_trait]
impl BlockSigner for KmsSigner {
    type Error = aws_sdk_kms::Error;
    async fn sign(&self, header: &BlockHeader) -> Result<Signature, Self::Error> {
        let sign_output = tokio::runtime::Handle::current().block_on(async {
            self.client
                .sign()
                .key_id(&self.key_id)
                .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                .message(header.commitment().to_bytes().into())
                .send()
                .await
                .expect("todo get updated trait from base next")
        });
        let sig = sign_output.signature().expect("todo get updated trait from base next");
        let sig = sig.clone().into_inner(); // todo no clone?
        Ok(Signature::read_from_bytes(&sig).expect("todo get updated trait from base next"))
    }

    fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }
}
