-- The first block to include in the next deposit scan. The initial value starts discovery at
-- genesis.
CREATE TABLE deposit_sync (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_sync_block INTEGER NOT NULL CHECK (next_sync_block BETWEEN 0 AND 4294967295)
) STRICT;

INSERT INTO deposit_sync (singleton, next_sync_block) VALUES (1, 0);

-- Deposits discovered before next_sync_block with no known spend before that block. Deposits
-- consumed or discarded by the service are removed.
CREATE TABLE deposits (
    nullifier BLOB PRIMARY KEY CHECK (length(nullifier) = 32),
    note BLOB NOT NULL
) STRICT;
