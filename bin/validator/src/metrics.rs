/// The chain height and transaction count read when the validator starts.
#[derive(Clone, Copy, Default)]
pub(crate) struct InitialMetrics {
    /// Block number of the chain tip, or zero if the database holds no block header.
    pub chain_tip: u32,
    /// Total number of validated transactions.
    pub validated_transactions: u64,
}
