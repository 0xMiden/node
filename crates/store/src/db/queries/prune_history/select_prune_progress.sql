-- Returns the cutoff through which account-code pruning has completed, if any prune has run under
-- this schema. The table holds at most one row, pinned to `id = 0`.
SELECT codes_cutoff FROM prune_progress
