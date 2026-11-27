use std::collections::HashSet;

use miden_node_proto::{DecodeMessage, Verify, generated as proto};
use miden_node_store::DatabaseError;
use miden_node_tracing::{instrument, miden_span_record};
use miden_node_utils::limiter::QueryParamAccountIdLimit;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use proto::miden::node::v2::get_account_infos_response::AccountInfo;
use proto::miden::node::v2::get_account_infos_response::account_info::Result as Info;
use proto::miden::node::v2::{self};
use tonic::Status;

use super::{RpcService, check, database_error_to_status};

pub(super) fn required_height(height: Option<u32>) -> tonic::Result<BlockNumber> {
    height
        .map(Into::into)
        .ok_or_else(|| Status::invalid_argument("block_num is required"))
}

pub(super) fn account_id(raw: Option<proto::account::AccountId>) -> tonic::Result<AccountId> {
    raw.ok_or_else(|| Status::invalid_argument("account_id is required"))?
        .decode_fields()
        .map_err(|err| Status::invalid_argument(err.to_string()))?
        .verify()
        .map_err(|err| Status::invalid_argument(err.to_string()))
}

#[tonic::async_trait]
impl proto::server::miden_node_v2_node_service::GetAccountInfos for RpcService {
    type Input = (BlockNumber, Vec<(AccountId, Option<Word>)>);
    type Output = v2::GetAccountInfosResponse;

    fn decode(request: v2::GetAccountInfosRequest) -> tonic::Result<Self::Input> {
        let target = required_height(request.block_num)?;
        check::<QueryParamAccountIdLimit>(request.accounts.len())?;
        let mut seen = HashSet::new();
        let accounts = request
            .accounts
            .into_iter()
            .map(|query| {
                let id = account_id(query.account_id)?;
                if !id.is_public() || !seen.insert(id) {
                    return Err(Status::invalid_argument("expected distinct public account IDs"));
                }
                let known = query
                    .known_commitment
                    .map(DecodeMessage::decode_fields)
                    .transpose()
                    .map_err(|err| Status::invalid_argument(err.to_string()))?;
                Ok((id, known))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((target, accounts))
    }

    fn encode(output: Self::Output) -> tonic::Result<v2::GetAccountInfosResponse> {
        Ok(output)
    }

    #[instrument(name = "get_account_infos", err)]
    async fn handle(
        &self,
        (target, accounts): Self::Input,
        _metadata: &tonic::metadata::MetadataMap,
        _extensions: &tonic::codegen::http::Extensions,
    ) -> tonic::Result<Self::Output> {
        if miden_node_tracing::enabled!(tracing::Level::INFO) {
            miden_span_record!(
                block.number = target,
                account.count = accounts.len(),
                account.queries = format!("{:?}", super::trace_sample(&accounts)) #[nonstandard],
            );
        }

        let accounts = self
            .state
            .read(move |view| {
                let range = view.snapshot.scope_range(target..=target)?;
                view.tx.check_account_history_target(range.scoped_end())?;
                accounts
                    .into_iter()
                    .map(|(id, known)| {
                        let result = match view.tx.account_headers(id, range.scoped_end()) {
                            Ok((header, _)) if Some(header.to_commitment()) == known => {
                                Info::Unchanged(())
                            },
                            Ok((account, storage)) => Info::Headers(v2::AccountHeaders {
                                account_header: Some(account.into()),
                                storage_header: Some(storage.into()),
                            }),
                            Err(DatabaseError::AccountNotFoundInDb(_)) => Info::NotFound(()),
                            Err(err) => return Err(err),
                        };
                        Ok(AccountInfo {
                            account_id: Some(id.into()),
                            result: Some(result),
                        })
                    })
                    .collect::<Result<Vec<_>, DatabaseError>>()
            })
            .await
            .map_err(|err| database_error_to_status(&err))?;

        Ok(v2::GetAccountInfosResponse { block_num: target.as_u32(), accounts })
    }
}
