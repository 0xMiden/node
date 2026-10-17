-- Inserts a note script, keyed by its root. Scripts are shared across notes, so re-inserting a
-- known root is a no-op rather than a constraint violation.
INSERT OR IGNORE INTO note_scripts (script_root, script)
VALUES (?1, ?2)
