//! Transaction-scoped log reads bounded by the published snapshot.

use miden_node_proto::domain::transaction_logs::{
    GetTransactionLogsRequest,
    GetTransactionLogsResponse,
};
use miden_node_tracing::instrument;

use super::StateView;
use crate::errors::DatabaseError;

impl StateView {
    /// Returns logs and their stored commitment for a transaction under its native account.
    #[instrument(level = "debug", err(level = "debug"))]
    pub async fn get_transaction_logs(
        &self,
        request: GetTransactionLogsRequest,
    ) -> Result<Option<GetTransactionLogsResponse>, DatabaseError> {
        self.db
            .select_transaction_logs(request.native_account_id, request.transaction_id, self.tip())
            .await
    }
}
