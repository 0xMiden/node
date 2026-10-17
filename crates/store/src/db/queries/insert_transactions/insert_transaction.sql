-- Records a transaction included in a block.
--
-- `size_in_bytes` is the estimated size of the sync record this transaction produces; it lets the
-- transaction-record queries stop before they exceed the response payload limit without having to
-- deserialize each row.
INSERT INTO transactions (
    transaction_id,
    account_id,
    block_num,
    initial_state_commitment,
    final_state_commitment,
    input_notes,
    output_notes,
    size_in_bytes
)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
