-- The first block to include in the next deposit scan. The initial value starts discovery at
-- genesis.
CREATE TABLE deposit_sync (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sync_block INTEGER NOT NULL CHECK (next_sync_block BETWEEN 0 AND 4294967295)
) STRICT;

INSERT INTO deposit_sync (singleton, next_sync_block) VALUES (1, 0);

-- Deposits discovered before next_sync_block with no spend known when they were discovered. This
-- table is the deposit pool: rows are added as discovery advances and removed one by one when the
-- service consumes or discards them. The amount duplicates the note's asset so selection can order
-- deposits without decoding notes.
CREATE TABLE deposits (
    nullifier BLOB PRIMARY KEY CHECK (length(nullifier) = 32),
    amount INTEGER NOT NULL CHECK (amount > 0),
    note BLOB NOT NULL
) STRICT;

CREATE INDEX idx_deposits_by_amount ON deposits(amount DESC, nullifier);
