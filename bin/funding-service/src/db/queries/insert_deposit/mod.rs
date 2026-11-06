use anyhow::Context;
use miden_node_db::sqlite::WriteTx;
use miden_node_utils::usdcx_p2id::UsdcxP2Id;

/// Stores an unspent deposit under its nullifier. Storing a known deposit again has no effect.
pub fn insert_deposit(tx: &WriteTx<'_>, deposit: &UsdcxP2Id) -> anyhow::Result<()> {
    tx.execute(
        include_str!("insert_deposit.sql"),
        &[
            &deposit.nullifier(),
            &i64::try_from(deposit.amount()).context("deposit amount exceeds i64")?,
            deposit.note(),
        ],
    )?;
    Ok(())
}
