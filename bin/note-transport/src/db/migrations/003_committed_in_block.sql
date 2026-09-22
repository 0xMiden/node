-- Keep existing block hints unverified because their proof status is unknown.
ALTER TABLE notes ADD COLUMN committed_in_block INTEGER
    CHECK (committed_in_block BETWEEN 0 AND 4294967295)
    CHECK (committed_in_block IS NULL OR after_block_num IS NULL);
