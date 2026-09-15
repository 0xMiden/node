DELETE FROM notes
WHERE seq IN (SELECT value FROM rarray(?1));
