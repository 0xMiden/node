use std::collections::HashSet;

use miden_node_proto::generated as proto;
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamAccountIdLimit;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use proto::miden::node::v2;
use tonic::Status;

use super::get_account::get_account_error_to_status;
use super::get_account_infos::{account_id, required_height};
use super::{RpcService, check};

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::GetAccountWitnesses for RpcService {
    type Input = (BlockNumber, Vec<AccountId>);
    type Output = v2::GetAccountWitnessesResponse;

    fn decode(request: v2::GetAccountWitnessesRequest) -> tonic::Result<Self::Input> {
        let target = required_height(request.block_num)?;
        check::<QueryParamAccountIdLimit>(request.account_ids.len())?;
        let ids = request
            .account_ids
            .into_iter()
            .map(|raw| account_id(Some(raw)))
            .collect::<Result<Vec<_>, _>>()?;
        if ids.is_empty() || ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            return Err(Status::invalid_argument("expected one or more distinct account IDs"));
        }
        Ok((target, ids))
    }

    fn encode(output: Self::Output) -> tonic::Result<v2::GetAccountWitnessesResponse> {
        Ok(output)
    }

    #[instrument(name = "get_account_witnesses", err)]
    async fn handle(
        &self,
        (target, ids): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(
            block.number = target,
            account.count = ids.len(),
            account.ids = super::trace_sample(&ids),
        );

        let proof = self
            .state
            .view()
            .account_tree_witnesses(target, &ids)
            .map_err(get_account_error_to_status)?;
        Ok(v2::GetAccountWitnessesResponse {
            block_num: target.as_u32(),
            account_tree: Some(proof.into()),
        })
    }
}
