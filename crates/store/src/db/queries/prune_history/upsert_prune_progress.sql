-- Records the cutoff through which account-code pruning has completed. Written in the same
-- transaction as the prune itself, so the marker is exact and crash-consistent.
INSERT INTO prune_progress (id, codes_cutoff)
VALUES (0, ?1)
ON CONFLICT(id) DO UPDATE SET codes_cutoff = excluded.codes_cutoff
