/// The persisted state the validator server's in-memory counters are seeded with on startup.
#[derive(Clone, Copy, Default)]
pub(crate) struct InitialMetrics {
    /// Block number of the chain tip, or zero if the database holds no block header.
    pub chain_tip: u32,
    /// Total number of validated transactions.
    pub validated_transactions: u64,
}
