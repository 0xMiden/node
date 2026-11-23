-- Index consumed notes by the block that consumed them.
--
-- Consumed notes are deleted once they are older than the retention window. The deletion runs on
-- every committed block, and these partial indexes let it remove a range instead of scanning the
-- tables.
CREATE INDEX idx_notes_committed_at ON notes(committed_at) WHERE committed_at IS NOT NULL;
CREATE INDEX idx_sponsorship_notes_committed_at ON sponsorship_notes(committed_at)
    WHERE committed_at IS NOT NULL;
