//! Top-up of the funding account.

use std::num::NonZeroU16;
use std::time::Duration;

use anyhow::{Context, Result};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_node_tracing::{info, warn};
use miden_node_utils::shutdown::CancellationToken;
use miden_protocol::Word;
use miden_protocol::account::AccountId;
use miden_protocol::block::BlockNumber;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{Note, NoteTag, NoteType};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{ExecutedTransaction, InputNote, InputNotes, TransactionArgs};
use miden_protocol::utils::serde::Serializable;
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::note::{P2idNote, P2idNoteStorage};
use miden_standards::tx_script::ExpirationTransactionScript;
use miden_tx::TransactionExecutor;
use miden_tx::auth::BasicAuthenticator;

use crate::LOG_TARGET;
use crate::account::FunderKey;
use crate::data_store::InMemoryDataStore;
use crate::node::RpcNodeClient;
use crate::prover::Prover;
use crate::tx::ExecutionInputs;

// DEPOSIT COLLECTION
// ================================================================================================

/// Finds deposits addressed to the funding account and consumes them.
pub struct TopUp {
    node: RpcNodeClient,
    prover: Prover,
    key: FunderKey,
    protocol_config: ProtocolConfig,
    expiration_delta: NonZeroU16,
    interval: Duration,
    /// The block the next scan starts at.
    next_block: BlockNumber,
    rng: RandomCoin,
}

impl TopUp {
    pub fn new(
        node: RpcNodeClient,
        prover: Prover,
        key: FunderKey,
        protocol_config: ProtocolConfig,
        expiration_delta: NonZeroU16,
        interval: Duration,
    ) -> Self {
        Self {
            node,
            prover,
            key,
            protocol_config,
            expiration_delta,
            interval,
            next_block: BlockNumber::GENESIS,
            rng: RandomCoin::new(Word::from(rand::random::<[u32; 4]>())),
        }
    }

    /// The faucet which issues the chain's fee asset.
    fn fee_faucet_id(&self) -> AccountId {
        self.protocol_config.fee_asset_id().faucet_id()
    }

    /// Collects deposits until the service shuts down.
    pub async fn run(mut self, shutdown: CancellationToken) -> Result<()> {
        loop {
            tokio::select! {
                () = tokio::time::sleep(self.interval) => {},
                () = shutdown.cancelled() => return Ok(()),
            }

            if let Err(err) = self.collect().await {
                warn!(
                    &err,
                    target: LOG_TARGET,
                    "Failed to collect deposits for the funding account"
                );
            }
        }
    }

    /// Runs one collection: find the deposits, and consume them if there are any.
    async fn collect(&mut self) -> Result<()> {
        let deposits = self.find_deposits().await?;
        if deposits.is_empty() {
            return Ok(());
        }

        let total: u64 =
            deposits.iter().map(|note| native_amount(note, self.fee_faucet_id())).sum();
        info!(
            target: LOG_TARGET,
            "Collecting deposits for the funding account",
            account.id = self.key.account_id(),
            note.count = deposits.len(),
            asset.amount = total
        );

        // Boxed because the transaction the future builds is large enough for the `large_futures`
        // lint to reject it on the enclosing future's stack.
        Box::pin(self.consume(deposits)).await
    }

    /// Returns the deposits which the funding account can consume.
    async fn find_deposits(&mut self) -> Result<Vec<Note>> {
        let tag = NoteTag::with_account_target(self.key.account_id());
        let synced = self.node.sync_note_ids(tag, self.next_block).await?;

        if synced.note_ids.is_empty() {
            self.next_block = synced.last_checked_block + 1;
            return Ok(Vec::new());
        }

        let candidates: Vec<Note> = self
            .node
            .public_notes(&synced.note_ids)
            .await?
            .into_iter()
            .filter(|note| is_deposit(note, self.key.account_id(), self.fee_faucet_id()))
            .collect();

        if candidates.is_empty() {
            self.next_block = synced.last_checked_block + 1;
            return Ok(Vec::new());
        }

        // A rescan sees deposits which an earlier collection already consumed. Consuming one twice
        // the transaction, so the spent ones are dropped here.
        let nullifiers: Vec<_> = candidates.iter().map(Note::nullifier).collect();
        let spent = self.node.spent_nullifiers(&nullifiers).await?;
        let unspent: Vec<Note> = candidates
            .into_iter()
            .filter(|note| !spent.contains(&note.nullifier()))
            .collect();

        // The cursor only advances once the notes of that range have been collected, so a failure
        // to read them does not skip a deposit.
        self.next_block = synced.last_checked_block + 1;

        Ok(unspent)
    }

    /// Consumes the deposits in one transaction.
    async fn consume(&mut self, deposits: Vec<Note>) -> Result<()> {
        let (reference_header, blockchain) = self.node.tip_chain_state().await?;
        let reference_block = reference_header.block_num();
        let account_id = self.key.account_id();

        let (funder, _witness) = self.node.public_account(account_id, reference_block).await?;
        let fee_faucet = self.node.public_account(self.fee_faucet_id(), reference_block).await?;

        let inputs = ExecutionInputs {
            funder,
            secret_key: self.key.secret_key().clone(),
            fee_faucet,
            protocol_config: self.protocol_config.clone(),
            reference_header,
            blockchain,
            expiration_delta: self.expiration_delta,
        };

        // Boxed because the transaction execution the future holds is large enough for the
        // `large_futures` lint to reject it on the enclosing future's stack.
        let executed_tx = Box::pin(execute_deposit_tx(inputs, deposits, &mut self.rng))
            .await
            .context("failed to execute the deposit transaction")?;
        let transaction_inputs = executed_tx.tx_inputs().to_bytes();

        let proven_tx = self
            .prover
            .prove(executed_tx)
            .await
            .context("failed to prove the deposit transaction")?;
        let transaction_id = proven_tx.id();

        self.node
            .submit(&proven_tx, &transaction_inputs)
            .await
            .context("failed to submit the deposit transaction")?;

        info!(
            target: LOG_TARGET,
            "Submitted a deposit transaction",
            transaction.id = transaction_id,
            block.number = reference_block
        );

        Ok(())
    }
}

// TRANSACTION
// ================================================================================================

/// Executes the transaction which consumes `deposits`.
///
/// The transaction pays its own fee. That works even when the funding account's balance is zero,
/// because the assets of an input note land before the kernel withdraws the fee, which is exactly
/// the case this collection has to recover from.
pub async fn execute_deposit_tx(
    inputs: ExecutionInputs,
    deposits: Vec<Note>,
    rng: &mut RandomCoin,
) -> Result<ExecutedTransaction> {
    let ExecutionInputs {
        funder,
        secret_key,
        fee_faucet,
        protocol_config,
        reference_header,
        blockchain,
        expiration_delta,
    } = inputs;

    let account_id = funder.id();
    let reference_block = reference_header.block_num();
    let fee_faucet_id = protocol_config.fee_asset_id().faucet_id();
    let tx_args = build_tx_args(fee_faucet_id, expiration_delta, rng);

    let input_notes =
        InputNotes::new(deposits.into_iter().map(InputNote::unauthenticated).collect())
            .context("failed to build the deposit input notes")?;

    spawn_blocking_in_current_span(move || {
        let mut data_store = InMemoryDataStore::new(reference_header, blockchain, protocol_config);
        data_store.add_account(funder);
        let (faucet_account, faucet_witness) = fee_faucet;
        data_store.add_foreign_account(faucet_account, faucet_witness);

        let authenticator = BasicAuthenticator::new(&[secret_key]);
        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        futures::executor::block_on(executor.execute_transaction(
            account_id,
            reference_block,
            input_notes,
            tx_args,
        ))
        .context("failed to execute the deposit transaction")
    })
    .await
    .context("the deposit transaction task failed")?
}

/// Builds the arguments of the deposit transaction.
///
/// The transaction runs no script of its own: consuming a note runs the note's script. The
/// expiration script is attached so the transaction cannot sit in the mempool indefinitely, and the
/// auth args tell the account's auth procedure how to convert the fee.
fn build_tx_args(
    fee_faucet_id: AccountId,
    expiration_delta: NonZeroU16,
    rng: &mut RandomCoin,
) -> TransactionArgs {
    let script = ExpirationTransactionScript::new(expiration_delta);
    let script_args = script.tx_script_args();
    let mut tx_args =
        TransactionArgs::default().with_tx_script_and_args(script.into(), script_args);

    let (auth_args, conversion_info_preimage) =
        commit_fee_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id), rng.draw_word());
    tx_args = tx_args.with_auth_args(auth_args);
    tx_args.extend_advice_map([(auth_args, conversion_info_preimage)]);

    tx_args
}

// DEPOSIT FILTER
// ================================================================================================

/// Returns `true` when the note is a deposit which `funder` can consume.
///
/// A deposit is a public pay-to-ID note which targets `funder` and holds nothing but the native
/// asset. Only the native asset is collected, because a note holding anything else would put an
/// asset the service cannot spend into the vault.
fn is_deposit(note: &Note, funder: AccountId, fee_faucet_id: AccountId) -> bool {
    if note.metadata().note_type() != NoteType::Public {
        return false;
    }
    if note.recipient().script().root() != P2idNote::script_root() {
        return false;
    }

    let targets_funder =
        P2idNoteStorage::try_from(note.recipient().storage().to_elements().as_slice())
            .is_ok_and(|storage| storage.target() == funder);
    if !targets_funder {
        return false;
    }

    note.assets().num_assets() == 1 && native_amount(note, fee_faucet_id) > 0
}

/// The amount of the native asset the note holds.
fn native_amount(note: &Note, fee_faucet_id: AccountId) -> u64 {
    note.assets()
        .iter()
        .filter_map(|asset| {
            asset
                .as_fungible()
                .filter(|asset| asset.faucet_id() == fee_faucet_id)
                .map(|asset| asset.amount().as_u64())
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use miden_protocol::asset::{AssetId, FungibleAsset};

    use super::*;
    use crate::test_utils::{Fixture, TEST_BASE_FEE, genesis_style_wallet};

    const EXPIRATION: NonZeroU16 = NonZeroU16::new(20).expect("literal is non-zero");

    /// Builds a public P2ID note which holds `amount` of `faucet_id` and targets `target`.
    fn deposit_note(
        target: AccountId,
        faucet_id: AccountId,
        amount: u64,
        serial: u32,
        note_type: NoteType,
    ) -> Note {
        P2idNote::builder()
            .sender(target)
            .target(target)
            .asset(FungibleAsset::new(faucet_id, amount).expect("valid asset"))
            .note_type(note_type)
            .serial_number(Word::from([serial; 4]))
            .build()
            .expect("the note should build")
            .into()
    }

    /// A public P2ID note holding the native asset and targeting the funder is a deposit.
    #[test]
    fn a_native_asset_note_for_the_funder_is_a_deposit() {
        let funder = FungibleAsset::mock_issuer();
        let note = deposit_note(funder, funder, 5_000, 1, NoteType::Public);

        assert!(is_deposit(&note, funder, funder));
        assert_eq!(native_amount(&note, funder), 5_000);
    }

    /// Only the native asset is collected: anything else would leave an asset in the vault which
    /// the service cannot spend.
    #[test]
    fn a_note_holding_another_asset_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let (other, _) = genesis_style_wallet(funder, 0, [3; 32]).expect("wallet should build");
        let note = deposit_note(funder, other.id(), 5_000, 2, NoteType::Public);

        assert!(!is_deposit(&note, funder, funder));
        assert_eq!(native_amount(&note, funder), 0);
    }

    /// The note tag only encodes the leading bits of an account ID, so notes for other accounts
    /// reach the collection and must be filtered by their target.
    #[test]
    fn a_note_for_another_account_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let (other, _) = genesis_style_wallet(funder, 0, [5; 32]).expect("wallet should build");
        let note = deposit_note(other.id(), funder, 5_000, 3, NoteType::Public);

        assert!(!is_deposit(&note, funder, funder));
    }

    /// The node stores no details for a private note, so it cannot be consumed.
    #[test]
    fn a_private_note_is_skipped() {
        let funder = FungibleAsset::mock_issuer();
        let note = deposit_note(funder, funder, 5_000, 4, NoteType::Private);

        assert!(!is_deposit(&note, funder, funder));
    }

    /// The deposit transaction pays its own fee from the assets the deposit brings in, so it works
    /// at a zero balance. That is the state the collection exists to recover from.
    #[tokio::test]
    async fn a_deposit_is_consumed_at_a_zero_balance() -> Result<()> {
        let fixture = Fixture::new(0, TEST_BASE_FEE)?;
        let mut rng = RandomCoin::new(Word::from([29u32; 4]));
        let deposit = deposit_note(
            fixture.funder.id(),
            fixture.fee_faucet_id,
            5_000_000,
            7,
            NoteType::Public,
        );

        let inputs = {
            let chain = fixture.chain.lock().await;
            let reference_header = chain.latest_block_header();
            let witness = chain
                .account_witnesses([fixture.fee_faucet_id])
                .remove(&fixture.fee_faucet_id)
                .context("a witness was requested for the faucet")?;

            ExecutionInputs {
                funder: chain.committed_account(fixture.funder.id())?.clone(),
                secret_key: fixture.funder_key.secret_key().clone(),
                fee_faucet: (chain.committed_account(fixture.fee_faucet_id)?.clone(), witness),
                protocol_config: chain.protocol_config().clone(),
                reference_header,
                blockchain: chain.latest_partial_blockchain(),
                expiration_delta: EXPIRATION,
            }
        };

        let executed_tx = execute_deposit_tx(inputs, vec![deposit], &mut rng).await?;

        // The deposit's assets land in the vault, less the fee the transaction pays from them.
        let mut updated = fixture.funder.clone();
        updated.apply_patch(executed_tx.account_patch())?;
        let balance = updated
            .vault()
            .get_balance(AssetId::new_fungible(fixture.fee_faucet_id))?
            .as_u64();

        assert!(balance > 0, "the deposit must raise the balance above zero");
        assert!(balance < 5_000_000, "the transaction must pay its fee from the deposit");

        Ok(())
    }
}
