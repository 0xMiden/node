-- Note IDs are bound as one array parameter so the statement text is independent of the list size.
SELECT note_id
FROM notes
WHERE note_id IN (SELECT value FROM rarray(?1))
