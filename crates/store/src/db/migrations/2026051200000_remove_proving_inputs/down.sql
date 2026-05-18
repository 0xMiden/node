-- Restore proving_inputs and proven_in_sequence columns (data is not recovered).
ALTER TABLE block_headers ADD COLUMN proving_inputs BLOB;
ALTER TABLE block_headers ADD COLUMN proven_in_sequence BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX block_headers_proven_desc ON block_headers(block_num DESC) WHERE proving_inputs IS NULL;
CREATE INDEX block_headers_proven_in_sequence ON block_headers(block_num DESC) WHERE proven_in_sequence = TRUE;
