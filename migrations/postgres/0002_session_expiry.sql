-- 0002_session_expiry: expire console sessions after 30 days.
ALTER TABLE sessions ADD COLUMN expires_at BIGINT;
UPDATE sessions SET expires_at = created_at + 2592000 WHERE expires_at IS NULL;
ALTER TABLE sessions ALTER COLUMN expires_at SET NOT NULL;
