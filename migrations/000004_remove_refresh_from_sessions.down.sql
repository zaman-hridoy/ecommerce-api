ALTER TABLE sessions
ADD COLUMN refresh_token_hash TEXT,
ADD COLUMN refresh_expires_at TIMESTAMPTZ;