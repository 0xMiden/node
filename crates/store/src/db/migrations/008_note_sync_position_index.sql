-- Orders each tag range by the complete note position. This supports partial-block cursors.
DROP INDEX idx_notes_tag;
CREATE INDEX idx_notes_tag_position
    ON notes(tag, committed_at, batch_index, note_index);
