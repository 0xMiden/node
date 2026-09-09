//! Building and execution of the funding transaction.

use std::num::NonZeroU16;

use anyhow::{Context, Result};
use miden_node_tracing::spawn::spawn_blocking_in_current_span;
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::account::{Account, AccountId};
use miden_protocol::asset::FungibleAsset;
use miden_protocol::block::BlockHeader;
use miden_protocol::block::account_tree::AccountWitness;
use miden_protocol::crypto::rand::{FeltRng, RandomCoin};
use miden_protocol::note::{Note, NoteType, PartialNote};
use miden_protocol::protocol_config::ProtocolConfig;
use miden_protocol::transaction::{
    ExecutedTransaction,
    InputNotes,
    PartialBlockchain,
    RawOutputNote,
    TransactionArgs,
};
use miden_standards::account::auth::{FeeConversionInfo, commit_fee_conversion_info};
use miden_standards::note::P2idNote;
use miden_standards::tx_script::SendNotesTransactionScript;
use miden_tx::TransactionExecutor;
use miden_tx::auth::BasicAuthenticator;

use crate::data_store::InMemoryDataStore;

// NOTE CREATION
// ================================================================================================

/// Builds one private P2ID note per target which holds `amount` base units of the fee asset.
pub fn build_funding_notes(
    sender: AccountId,
    fee_faucet_id: AccountId,
    targets: &[(AccountId, u64)],
    rng: &mut RandomCoin,
) -> Result<Vec<Note>> {
    targets
        .iter()
        .map(|&(target, amount)| {
            let asset = FungibleAsset::new(fee_faucet_id, amount)
                .context("failed to build the funding asset")?;
            let note: Note = P2idNote::builder()
                .sender(sender)
                .target(target)
                .asset(asset)
                .note_type(NoteType::Private)
                .generate_serial_number(rng)
                .build()
                .context("failed to build the funding note")?
                .into();
            Ok(note)
        })
        .collect()
}

// TRANSACTION EXECUTION
// ================================================================================================

/// Everything one funding transaction needs besides the notes it creates.
pub struct ExecutionInputs {
    /// The funding account, in the state committed in `reference_header`.
    pub funder: Account,
    /// The signing key of the funding account.
    pub secret_key: AuthSecretKey,
    /// The faucet which issues the fee asset, together with its account-tree witness.
    pub fee_faucet: (Account, AccountWitness),
    /// The protocol configuration of the chain, which names the fee asset.
    pub protocol_config: ProtocolConfig,
    /// The reference block of the transaction.
    pub reference_header: BlockHeader,
    /// A partial blockchain which proves the reference block.
    pub blockchain: PartialBlockchain,
    /// How many blocks after the reference block the transaction expires.
    pub expiration_delta: NonZeroU16,
}

/// Executes the transaction which creates `notes`.
pub async fn execute(
    inputs: ExecutionInputs,
    notes: Vec<Note>,
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

    let fee_faucet_id = protocol_config.fee_asset_id().faucet_id();
    let account_id = funder.id();
    let reference_block = reference_header.block_num();
    let expected_expiration = reference_block + u32::from(expiration_delta.get());
    let tx_args = build_tx_args(&funder, fee_faucet_id, &notes, expiration_delta, rng)?;

    let executed_tx = spawn_blocking_in_current_span(move || {
        let mut data_store = InMemoryDataStore::new(reference_header, blockchain, protocol_config);
        data_store.add_account(funder);
        let (faucet_account, faucet_witness) = fee_faucet;
        data_store.add_foreign_account(faucet_account, faucet_witness);

        let authenticator = BasicAuthenticator::new(&[secret_key]);
        let executor = TransactionExecutor::new(&data_store).with_authenticator(&authenticator);

        futures::executor::block_on(executor.execute_transaction(
            account_id,
            reference_block,
            InputNotes::default(),
            tx_args,
        ))
        .context("failed to execute the funding transaction")
    })
    .await
    .context("the funding transaction task failed")??;

    // The notes and the expiration are what the caller promises to the requester, so a mismatch
    // must fail here instead of after the transaction is submitted.
    let output_note_ids: Vec<_> =
        executed_tx.output_notes().iter().map(RawOutputNote::id).collect();
    for note in &notes {
        anyhow::ensure!(
            output_note_ids.contains(&note.id()),
            "the executed transaction does not create note {}",
            note.id(),
        );
    }
    anyhow::ensure!(
        executed_tx.expiration_block_num() == expected_expiration,
        "the executed transaction expires at block {} instead of {expected_expiration}",
        executed_tx.expiration_block_num(),
    );

    Ok(executed_tx)
}

/// Builds the transaction arguments which emit `notes` and pay the fee from the funder's vault.
fn build_tx_args(
    funder: &Account,
    fee_faucet_id: AccountId,
    notes: &[Note],
    expiration_delta: NonZeroU16,
    rng: &mut RandomCoin,
) -> Result<TransactionArgs> {
    let partial_notes: Vec<PartialNote> = notes.iter().map(|note| note.clone().into()).collect();
    let code_interface = funder.code_interface();
    let script = SendNotesTransactionScript::with_expiration_delta(
        &code_interface,
        &partial_notes,
        expiration_delta,
    )
    .context("failed to build the send-notes transaction script")?;

    let mut tx_args = TransactionArgs::default()
        .with_tx_script_and_args(script.tx_script().clone(), script.tx_script_args());

    // A private note's recipient is not derivable from the note ID, so the executor needs it to
    // build the output note.
    for note in notes {
        tx_args.add_output_note_recipient(Box::new(note.recipient().clone()));
    }

    let (auth_args, conversion_info_preimage) =
        commit_fee_conversion_info(FeeConversionInfo::one_to_one(fee_faucet_id), rng.draw_word());
    tx_args = tx_args.with_auth_args(auth_args);
    tx_args.extend_advice_map([(auth_args, conversion_info_preimage)]);

    Ok(tx_args)
}

#[cfg(test)]
mod tests {
    use miden_protocol::Word;
    use miden_protocol::asset::AssetId;
    use miden_standards::note::TxFeeNote;

    use super::*;
    use crate::test_utils::{
        Fixture,
        TEST_BASE_FEE,
        genesis_style_native_faucet,
        genesis_style_wallet,
    };

    const BALANCE: u64 = 1_000_000;

    /// Builds the execution inputs for the fixture's funding account at the chain tip.
    async fn execution_inputs(
        fixture: &Fixture,
        expiration_delta: NonZeroU16,
    ) -> Result<ExecutionInputs> {
        let chain = fixture.chain.lock().await;
        let reference_header = chain.latest_block_header();
        let blockchain = chain.latest_partial_blockchain();
        let funder = chain.committed_account(fixture.funder.id())?.clone();
        let faucet = chain.committed_account(fixture.fee_faucet_id)?.clone();
        let witness = chain
            .account_witnesses([fixture.fee_faucet_id])
            .remove(&fixture.fee_faucet_id)
            .context("a witness was requested for the faucet")?;

        Ok(ExecutionInputs {
            funder,
            secret_key: fixture.funder_key.secret_key().clone(),
            fee_faucet: (faucet, witness),
            protocol_config: chain.protocol_config().clone(),
            reference_header,
            blockchain,
            expiration_delta,
        })
    }

    /// One transaction must create every requested note, pay its own fee, and expire at the
    /// configured delta.
    #[tokio::test]
    async fn one_transaction_creates_every_note_and_pays_the_fee() -> Result<()> {
        let expiration_delta = NonZeroU16::new(20).unwrap();
        let fixture = Fixture::new(BALANCE, TEST_BASE_FEE)?;
        let mut rng = RandomCoin::new(Word::from([11u32; 4]));

        let targets: Vec<(AccountId, u64)> = (0u8..3)
            .map(|index| {
                let (account, _) =
                    genesis_style_wallet(fixture.fee_faucet_id, 0, [index + 20; 32])?;
                Ok((account.id(), 100 * (u64::from(index) + 1)))
            })
            .collect::<Result<_>>()?;
        let requested: u64 = targets.iter().map(|(_, amount)| amount).sum();

        let notes =
            build_funding_notes(fixture.funder.id(), fixture.fee_faucet_id, &targets, &mut rng)?;
        let reference_block = {
            let chain = fixture.chain.lock().await;
            chain.latest_block_header().block_num()
        };

        let inputs = execution_inputs(&fixture, expiration_delta).await?;
        let executed_tx = execute(inputs, notes.clone(), &mut rng).await?;

        // Three funding notes plus the fee note the kernel emits.
        assert_eq!(executed_tx.output_notes().num_notes(), 4);
        let fee_notes = executed_tx
            .output_notes()
            .iter()
            .filter(|note| {
                note.recipient()
                    .is_some_and(|recipient| recipient.script().root() == TxFeeNote::script_root())
            })
            .count();
        assert_eq!(fee_notes, 1, "the transaction must emit exactly one fee note");

        assert_eq!(
            executed_tx.expiration_block_num(),
            reference_block + u32::from(expiration_delta.get())
        );

        // The vault pays both the notes and the fee, so it loses more than the requested amount.
        // The funding account exists on chain, so its patch is a delta and is applied.
        let mut updated = fixture.funder.clone();
        updated.apply_patch(executed_tx.account_patch())?;
        let remaining = updated
            .vault()
            .get_balance(AssetId::new_fungible(fixture.fee_faucet_id))?
            .as_u64();
        assert!(
            remaining < BALANCE - requested,
            "the fee must be paid on top of the notes: {remaining} vs {}",
            BALANCE - requested
        );

        // Every note must be a private note the requester can consume.
        for note in &notes {
            assert_eq!(note.metadata().note_type(), NoteType::Private);
            assert_eq!(note.assets().num_assets(), 1);
        }

        Ok(())
    }

    /// The native asset is callback-enabled, so moving it loads the issuing faucet in a foreign
    /// context. Without the faucet the kernel cannot start that context.
    #[tokio::test]
    async fn execution_requires_the_fee_faucet_as_a_foreign_account() -> Result<()> {
        let fixture = Fixture::new(BALANCE, TEST_BASE_FEE)?;
        let mut rng = RandomCoin::new(Word::from([17u32; 4]));
        let (target, _) = genesis_style_wallet(fixture.fee_faucet_id, 0, [41; 32])?;

        let notes = build_funding_notes(
            fixture.funder.id(),
            fixture.fee_faucet_id,
            &[(target.id(), 100)],
            &mut rng,
        )?;

        // Substitute an unrelated account for the faucet, which leaves the real faucet absent from
        // the data store.
        let mut inputs = execution_inputs(&fixture, NonZeroU16::new(20).unwrap()).await?;
        let (unrelated, _) = genesis_style_wallet(fixture.fee_faucet_id, 0, [51; 32])?;
        let unrelated_witness = {
            let chain = fixture.chain.lock().await;
            chain
                .account_witnesses([fixture.funder.id()])
                .remove(&fixture.funder.id())
                .context("a witness was requested")?
        };
        inputs.fee_faucet = (unrelated, unrelated_witness);

        let err = execute(inputs, notes, &mut rng)
            .await
            .expect_err("moving a callback-enabled asset requires the issuing faucet");
        assert!(
            format!("{err:#}").contains("account"),
            "expected an account failure, got: {err:#}"
        );

        Ok(())
    }

    /// A funding amount which the asset type cannot express must fail while the notes are built.
    #[tokio::test]
    async fn an_invalid_amount_fails_while_building_the_notes() -> Result<()> {
        let mut rng = RandomCoin::new(Word::from([23u32; 4]));
        let (owner, _) = genesis_style_wallet(FungibleAsset::mock_issuer(), 0, [71; 32])?;
        let faucet = genesis_style_native_faucet(owner.id(), [77; 32])?;

        let err = build_funding_notes(owner.id(), faucet.id(), &[(owner.id(), u64::MAX)], &mut rng)
            .expect_err("an amount above the asset maximum must be rejected");
        assert!(format!("{err:#}").contains("asset"), "unexpected error: {err:#}");

        Ok(())
    }
}
