-- Move proving inputs out of the database.
--
-- Proving inputs are large BLOBs that only serve the proof scheduler; they now live as
-- `inputs_<block_num>.dat` files in the block store alongside block data and proofs.
-- The proven-in-sequence tip is tracked by a small `proven_tip` file in the data directory.
--
-- Drop indexes that reference the columns being removed first (required by SQLite before DROP
-- COLUMN can succeed for indexed columns).
DROP INDEX block_headers_proven_desc;
DROP INDEX block_headers_proven_in_sequence;
ALTER TABLE block_headers DROP COLUMN proving_inputs;
ALTER TABLE block_headers DROP COLUMN proven_in_sequence;
