-- Reads what the new eligibility block of a failing note depends on: its current attempt count and
-- its execution hint (carried by the serialized note).
SELECT attempt_count, note_data FROM notes WHERE nullifier = ?1
