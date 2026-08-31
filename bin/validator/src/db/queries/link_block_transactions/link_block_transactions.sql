-- Links one validated transaction to its position in a signed block.
UPDATE validated_transactions
SET block_num = ?1,
    block_tx_index = ?2
WHERE id = ?3;
