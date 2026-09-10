CREATE TABLE account_allowlist (
    id                INTEGER PRIMARY KEY,
    account_id        BLOB UNIQUE,
    invitation_digest BLOB UNIQUE,
    allowlisted_at    BIGINT NOT NULL,
    CHECK (account_id IS NOT NULL OR invitation_digest IS NOT NULL),
    CHECK (length(invitation_digest) = 32)
);
