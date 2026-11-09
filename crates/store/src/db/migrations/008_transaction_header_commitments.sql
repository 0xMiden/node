ALTER TABLE transactions ADD COLUMN logs_commitment BLOB NOT NULL CHECK (length(logs_commitment) = 32);
ALTER TABLE transactions ADD COLUMN code_patch_commitment BLOB NOT NULL CHECK (length(code_patch_commitment) = 32);
