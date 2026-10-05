-- Returns the note script stored under the given root.
SELECT script
FROM note_scripts
WHERE script_root = ?1
