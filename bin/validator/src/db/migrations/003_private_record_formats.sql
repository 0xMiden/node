-- Constrain format_version to the range of a u32 instead of a fixed set of versions, so that a
-- new record format needs no migration. SQLite cannot alter a CHECK constraint, so the table is
-- rebuilt. Existing rows hold format 1 and keep that value.
CREATE TABLE validated_transactions_new (
    -- Rowid-backed local insertion order used by the private administration API.
    insertion_sequence    INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Transaction ID, unique within this validator's database.
    id                    BLOB NOT NULL UNIQUE,
    -- Signing public key of the validator that produced this record.
    validator_id          BLOB NOT NULL,
    -- Genesis commitment of the network that produced the transaction.
    chain_id              BLOB NOT NULL,
    -- Operator-chosen epoch of the Golden storage key.
    key_epoch             BLOB NOT NULL,
    -- Identifier of the Golden DKG setup needed to combine shares.
    setup_context_id      BLOB NOT NULL,
    -- Format of the encrypted record. Version 1 holds the serialized transaction inputs.
    -- Version 2 holds the protobuf transaction effects. Both use XChaCha20-Poly1305.
    -- The validator rejects a version it does not support when it reads the row.
    format_version        BIGINT NOT NULL,
    -- XChaCha20-Poly1305 nonce.
    cipher_nonce          BLOB NOT NULL,
    -- Authenticated encryption of the record named by format_version.
    encrypted_record      BLOB NOT NULL,
    -- Golden EHTDH1 encryption of the key for encrypted_record.
    encrypted_record_key  BLOB NOT NULL,
    CHECK (length(id) = 32),
    CHECK (length(validator_id) = 33),
    CHECK (length(chain_id) = 32),
    CHECK (length(key_epoch) = 32),
    CHECK (length(setup_context_id) = 32),
    CHECK (format_version BETWEEN 1 AND 0xFFFFFFFF),
    CHECK (length(cipher_nonce) = 24),
    CHECK (length(encrypted_record) >= 16),
    CHECK (length(encrypted_record_key) > 0)
);

INSERT INTO validated_transactions_new (
    insertion_sequence,
    id,
    validator_id,
    chain_id,
    key_epoch,
    setup_context_id,
    format_version,
    cipher_nonce,
    encrypted_record,
    encrypted_record_key
)
SELECT
    insertion_sequence,
    id,
    validator_id,
    chain_id,
    key_epoch,
    setup_context_id,
    format_version,
    cipher_nonce,
    encrypted_record,
    encrypted_record_key
FROM validated_transactions
ORDER BY insertion_sequence;

DROP TABLE validated_transactions;

ALTER TABLE validated_transactions_new RENAME TO validated_transactions;

CREATE INDEX idx_validated_transactions_key_epoch
ON validated_transactions(key_epoch);

CREATE INDEX idx_validated_transactions_setup_context_id
ON validated_transactions(setup_context_id);
