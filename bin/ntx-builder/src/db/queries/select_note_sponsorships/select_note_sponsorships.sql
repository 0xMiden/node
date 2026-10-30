-- Selects every FEE_SPONSORSHIP note bound to the given feature note, including consumed notes.
SELECT note_data, committed_at, last_attempt, last_error
FROM sponsorship_notes
WHERE feature_note_id = ?1
ORDER BY note_id
