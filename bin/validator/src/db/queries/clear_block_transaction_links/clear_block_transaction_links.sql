-- Unlinks every validated transaction currently linked to the given block height.
UPDATE validated_transactions
SET block_num = NULL,
    block_tx_index = NULL
WHERE block_num = ?1;
