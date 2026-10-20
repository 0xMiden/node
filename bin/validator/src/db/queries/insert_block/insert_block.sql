-- Inserts a block at a height that must not already hold one.
INSERT INTO blocks (block_num, block_header, block_data, proving_inputs)
VALUES (?1, ?2, ?3, ?4);
