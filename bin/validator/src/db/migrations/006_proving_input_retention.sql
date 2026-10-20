CREATE INDEX idx_blocks_proving_inputs
ON blocks(block_num) WHERE proving_inputs IS NOT NULL;
