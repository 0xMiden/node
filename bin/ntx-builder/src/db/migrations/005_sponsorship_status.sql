-- Index every FEE_SPONSORSHIP note by its feature note, including consumed notes. The note status
-- endpoint reports consumed sponsorships too, and the partial index does not cover them. The
-- selection-time join (`feature_note_id = ? AND committed_at IS NULL`) also uses this index.
DROP INDEX idx_sponsorship_notes_feature;
CREATE INDEX idx_sponsorship_notes_feature ON sponsorship_notes(feature_note_id);

-- Latest failure of the FEE_SPONSORSHIP note itself, for status reporting. The feature note keeps
-- the attempt count and the backoff.
--
-- Block number of the last failed attempt. NULL if the sponsorship never failed.
ALTER TABLE sponsorship_notes ADD COLUMN last_attempt BIGINT
    CONSTRAINT sponsorship_notes_last_attempt_is_u32 CHECK (last_attempt BETWEEN 0 AND 0xFFFFFFFF);
-- Latest execution error message. NULL if no error recorded.
ALTER TABLE sponsorship_notes ADD COLUMN last_error TEXT;
