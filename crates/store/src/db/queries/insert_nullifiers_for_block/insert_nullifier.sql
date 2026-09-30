-- Records a nullifier created by a block. The prefix column is indexed so nullifier lookups by
-- prefix never have to scan the full nullifier.
INSERT INTO nullifiers (nullifier, nullifier_prefix, block_num)
VALUES (?1, ?2, ?3)
