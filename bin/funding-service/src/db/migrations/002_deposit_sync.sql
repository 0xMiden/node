-- The first block to include in the next deposit scan. The initial value starts discovery at
-- genesis.
CREATE TABLE deposit_sync (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sync_block INTEGER NOT NULL CHECK (next_sync_block BETWEEN 0 AND 4294967295)
) STRICT;

INSERT INTO deposit_sync (singleton, next_sync_block) VALUES (1, 0);

-- Deposits discovered before next_sync_block with no spend known when they were discovered. This
-- table is the deposit pool: rows are added as discovery advances and removed when the service
-- consumes or discards them.
--
-- The amount duplicates the note's asset so selection can order deposits without decoding notes.
CREATE TABLE deposits (
    nullifier BLOB PRIMARY KEY CHECK (length(nullifier) = 32),
    amount INTEGER NOT NULL CHECK (amount > 0),
    note BLOB NOT NULL,
    -- The transaction attempt consuming the deposit. The link is cleared when the attempt is
    -- released, which returns the deposit to the pool.
    attempt_id BLOB REFERENCES transaction_attempt(transaction_id) ON DELETE SET NULL
) STRICT;

CREATE INDEX idx_available_deposits ON deposits(amount DESC, nullifier) WHERE attempt_id IS NULL;
CREATE INDEX idx_attempt_deposits ON deposits(attempt_id) WHERE attempt_id IS NOT NULL;

-- A transaction can consume several deposits, which now link to their attempt. An attempt recorded
-- before this migration loses its deposit link. Its deposit is not stored yet either: the first
-- scan from genesis runs after the attempt is resolved and stores the deposit only if it is unspent.
ALTER TABLE transaction_attempt DROP COLUMN deposit_nullifier;
