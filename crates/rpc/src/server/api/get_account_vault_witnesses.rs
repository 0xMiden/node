use miden_node_proto::domain::account::{
    AccountDetailRequest,
    AccountStorageRequest,
    AccountVaultDetails,
    AccountVaultRequest,
    GetAccountRequest,
};
use miden_node_proto::{DecodeMessageExt, generated as proto};
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamVaultAssetLimit;
use miden_protocol::account::AccountId;
use miden_protocol::asset::AssetId;
use miden_protocol::block::BlockNumber;
use proto::miden::node::v2;
use tonic::Status;

use super::get_account::get_account_error_to_status;
use super::get_account_infos::{account_id, required_height};
use super::{RpcService, check};

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::GetAccountVaultWitnesses for RpcService {
    type Input = (AccountId, BlockNumber, Vec<AssetId>);
    type Output = v2::GetAccountVaultWitnessesResponse;

    fn decode(request: v2::GetAccountVaultWitnessesRequest) -> tonic::Result<Self::Input> {
        let target = required_height(request.block_num)?;
        let account = account_id(request.account_id)?;
        if !account.is_public() {
            return Err(Status::invalid_argument("public account required"));
        }
        check::<QueryParamVaultAssetLimit>(request.asset_ids.len())?;
        let entries = request
            .asset_ids
            .into_iter()
            .map(|asset| {
                asset
                    .decode_and_verify()
                    .map_err(|err| Status::invalid_argument(err.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok((account, target, entries))
    }

    fn encode(output: Self::Output) -> tonic::Result<v2::GetAccountVaultWitnessesResponse> {
        Ok(output)
    }

    #[instrument(name = "get_account_vault_witnesses", err)]
    async fn handle(
        &self,
        (account, target, entries): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        miden_span_record!(
            block.number = target,
            account.id = account,
            asset.count = entries.len(),
            asset.ids = super::trace_sample(&entries),
        );

        let details = self
            .state
            .view()
            .get_account(GetAccountRequest {
                account_id: account,
                block_num: Some(target),
                details: Some(AccountDetailRequest {
                    code_commitment: None,
                    vault_request: AccountVaultRequest::Assets(entries),
                    storage_request: AccountStorageRequest::None,
                }),
            })
            .await
            .map_err(get_account_error_to_status)?
            .details
            .ok_or_else(|| {
                super::error_codes::internal_error("missing requested account details")
            })?;
        let AccountVaultDetails::Partial { vault, .. } = details.vault_details else {
            return Err(super::error_codes::internal_error("missing requested vault proof"));
        };
        Ok(v2::GetAccountVaultWitnessesResponse {
            block_num: target.as_u32(),
            vault: Some(vault.partial_smt().clone().into()),
        })
    }
}
