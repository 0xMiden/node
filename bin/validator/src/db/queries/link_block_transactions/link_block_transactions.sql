-- Links one validated transaction to its position in a signed block.
INSERT INTO block_transactions (block_num, block_tx_index, transaction_id)
VALUES (?1, ?2, ?3);
