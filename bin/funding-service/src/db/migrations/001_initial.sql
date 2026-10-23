CREATE TABLE database_identity (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    genesis_commitment BLOB NOT NULL CHECK (length(genesis_commitment) = 32),
    funding_account_id BLOB NOT NULL CHECK (length(funding_account_id) = 15),
    fee_faucet_id BLOB NOT NULL CHECK (length(fee_faucet_id) = 15)
) STRICT;

-- One transaction can be waiting for confirmation at a time.
CREATE TABLE transaction_attempt (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    transaction_id BLOB NOT NULL UNIQUE CHECK (length(transaction_id) = 32),
    reference_block INTEGER NOT NULL CHECK (reference_block BETWEEN 0 AND 4294967295),
    expiration_block INTEGER NOT NULL CHECK (expiration_block BETWEEN 0 AND 4294967295),
    deposit_nullifier BLOB CHECK (length(deposit_nullifier) = 32),
    CHECK (expiration_block > reference_block)
) STRICT;

CREATE TABLE requests (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT CHECK (sequence > 0),
    note_id BLOB NOT NULL UNIQUE CHECK (length(note_id) = 32),
    note BLOB NOT NULL,
    -- Local time when the service accepted the request, in microseconds since the Unix epoch.
    accepted_at INTEGER NOT NULL CHECK (accepted_at >= 0),
    transaction_id BLOB CHECK (length(transaction_id) = 32),
    committed_in_block INTEGER CHECK (committed_in_block BETWEEN 0 AND 4294967295),
    -- Local time when the service recorded commitment, in microseconds since the Unix epoch.
    -- NULL until delivery is confirmed.
    confirmed_at INTEGER CHECK (confirmed_at >= 0),
    -- Requests are kept after their attempt is removed.
    attempt_id BLOB REFERENCES transaction_attempt(transaction_id) ON DELETE SET NULL,
    CHECK (
        (transaction_id IS NULL AND committed_in_block IS NULL AND confirmed_at IS NULL)
        OR
        (transaction_id IS NOT NULL AND committed_in_block IS NOT NULL AND confirmed_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_pending_requests ON requests(sequence) WHERE transaction_id IS NULL;
CREATE INDEX idx_attempt_requests ON requests(attempt_id) WHERE attempt_id IS NOT NULL;
