use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use miden_node_proto::domain::encryption::{
    TransactionInputsSealer,
    TrustedTransactionEncryptionState,
    verify_transaction_encryption_key,
};
use miden_node_proto::generated as proto;
use miden_node_proto::generated::rpc::api_server::Api;
use miden_node_rpc::RpcService;
use miden_protocol::Word;
use miden_protocol::block::BlockHeader;
use miden_protocol::crypto::dsa::ecdsa_k256_keccak::PublicKey;
use miden_protocol::transaction::{ProvenTransaction, TransactionInputs};
use miden_protocol::utils::serde::Serializable;
use tonic::{Request, Response};

pub(crate) struct CollectionRpc {
    api: Arc<RpcService>,
    request_timeout: Duration,
    genesis: Word,
    validator_keys: Vec<PublicKey>,
}

impl CollectionRpc {
    pub(crate) fn new(
        api: Arc<RpcService>,
        genesis: &BlockHeader,
        request_timeout: Duration,
    ) -> Self {
        Self {
            api,
            request_timeout,
            genesis: genesis.commitment(),
            validator_keys: genesis.validator_config().keys().to_vec(),
        }
    }

    pub(super) async fn submit(
        &self,
        tx: &ProvenTransaction,
        inputs: &TransactionInputs,
    ) -> anyhow::Result<()> {
        let key = self.request(self.api.get_transaction_encryption_key(Request::new(()))).await?;
        let verified = verify_transaction_encryption_key(
            key,
            TrustedTransactionEncryptionState::new(self.genesis, &self.validator_keys),
        )?;
        let sealed = TransactionInputsSealer::new(verified).seal(tx.id(), &inputs.to_bytes())?;
        self.request(self.api.submit_proven_tx(Request::new(
            proto::submission::ProvenTransactionSubmission {
                transaction: Some(tx.into()),
                sealed_transaction_inputs: Some(sealed),
            },
        )))
        .await?;
        Ok(())
    }

    async fn request<T>(
        &self,
        call: impl Future<Output = tonic::Result<Response<T>>>,
    ) -> anyhow::Result<T> {
        tokio::time::timeout(self.request_timeout, call)
            .await
            .context("batch fee collection RPC request timed out")?
            .map(Response::into_inner)
            .map_err(Into::into)
    }
}
