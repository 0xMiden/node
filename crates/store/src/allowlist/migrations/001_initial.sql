CREATE TABLE account_allowlist (
    id                INTEGER PRIMARY KEY,
    account_id        BLOB,
    invitation_digest BLOB,
    allowlisted_at    BIGINT NOT NULL,
    CHECK (account_id IS NOT NULL OR invitation_digest IS NOT NULL),
    CHECK (length(invitation_digest) = 32)
);

CREATE UNIQUE INDEX idx_account_allowlist_account_id ON account_allowlist(account_id);
CREATE UNIQUE INDEX idx_account_allowlist_invitation_digest ON account_allowlist(invitation_digest);
