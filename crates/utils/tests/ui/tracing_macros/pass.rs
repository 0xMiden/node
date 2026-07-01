use miden_node_utils::tracing::{miden_instrument, miden_span_record};

#[miden_instrument(
    target = "miden-node-utils-test",
    name = "records_fields",
    skip_all,
)]
fn records_fields() {
    let display_value = "display";
    let debug_value = vec![1, 2, 3];
    let plain_value = 7;

    miden_span_record!(
        transaction.id = %display_value,
        transactions.ids = ?debug_value,
        block.number = plain_value,
    );
}

#[miden_instrument]
fn records_with_default_instrument_args() {
    let value = 1;

    miden_span_record!(block.number = value);
}

#[miden_instrument(
    skip_all,
)]
fn records_same_field_more_than_once() {
    let value = 1;
    let updated = 2;

    miden_span_record!(block.number = value);
    miden_span_record!(block.number = updated);
}

#[miden_instrument(
    skip_all,
)]
fn records_allowed_canonical_fields() {
    let tx_id = "0x1234";
    let account_id = "0xabcd";
    let block_number = 12u32;
    let transaction_ids = ["0x1", "0x2"];
    let transaction_count = transaction_ids.len();
    let size = 1024u64;

    miden_span_record!(
        transaction.id = %tx_id,
        transaction.expires_at = block_number,
        transaction.reference_block.number = block_number,
        transaction.reference_block.commitment = %tx_id,
        tip.number = block_number,
        transaction.input_notes.count = transaction_count,
        transaction.output_notes.count = transaction_count,
        account.id = %account_id,
        account.id.network_prefix = %account_id,
        account.updated = true,
        block.number = block_number,
        block.from = block_number,
        block.commitment = %tx_id,
        block.sub_commitment = %tx_id,
        block.prev_block_commitment = %tx_id,
        block.timestamp = block_number,
        block.protocol.version = block_number,
        block.batch.ids = ?transaction_ids,
        block.batches.count = transaction_count,
        block.batches.output_notes.count = transaction_count,
        block.transactions.ids = ?transaction_ids,
        block.updated_accounts.count = transaction_count,
        block.erased_note_proofs.count = transaction_count,
        block.nullifiers.count = transaction_count,
        block.output_notes.count = transaction_count,
        block.erased_notes.count = transaction_count,
        block.commitments.kernel = %tx_id,
        block.commitments.nullifier = %tx_id,
        block.commitments.account = %tx_id,
        block.commitments.chain = %tx_id,
        block.commitments.note = %tx_id,
        block.commitments.transaction = %tx_id,
        block_range.from = block_number,
        block_range.to = block_number,
        transactions.ids = ?transaction_ids,
        transactions.count = transaction_count,
        transactions.input_notes.count = transaction_count,
        transactions.output_notes.count = transaction_count,
        transactions.unauthenticated_notes.count = transaction_count,
        block.transactions.count = transaction_count,
        batch.expires_at = block_number,
        batch.expiration_height = block_number,
        batch.reference_block.number = block_number,
        batch.reference_block.commitment = %tx_id,
        batch.account_updates.count = transaction_count,
        batch.input_notes.count = transaction_count,
        batch.output_notes.count = transaction_count,
        script.root = %tx_id,
        note.id = %tx_id,
        notes.count = transaction_count,
        reference_block.number = block_number,
        request.kind = "block",
        workers.count = transaction_count,
        workers.active = transaction_count,
        workers.capacity = transaction_count,
        prover.kind = "local",
        failure_rate = 0.0,
        dice_roll = 0.5,
        mempool.transactions.uncommitted = transaction_count,
        mempool.transactions.unbatched = transaction_count,
        mempool.batches.proposed = transaction_count,
        mempool.batches.proven = transaction_count,
        mempool.accounts = transaction_count,
        mempool.nullifiers = transaction_count,
        mempool.output_notes = transaction_count,
        db.sqlite.size = size,
        db.sqlite.wal.size = size,
        db.block_store.size = size,
        db.account_tree.size = size,
        db.nullifier_tree.size = size,
        db.account_state_forest.size = size,
    );
}

fn main() {
    records_fields();
    records_with_default_instrument_args();
    records_same_field_more_than_once();
    records_allowed_canonical_fields();
}
