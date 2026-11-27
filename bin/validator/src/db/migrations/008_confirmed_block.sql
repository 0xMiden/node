-- The referenced block row supplies both the height and the authenticated header commitment.
CREATE TABLE recovery_confirmation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    block_num INTEGER NOT NULL REFERENCES blocks(block_num) ON DELETE RESTRICT
);
