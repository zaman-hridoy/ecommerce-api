
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL
            REFERENCES users(id)
            ON DELETE CASCADE,

    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,

    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,

    device_name TEXT,
    device_type TEXT,


    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_use_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id
ON sessions(user_id);

CREATE INDEX idx_sessions_access_expires_at
ON sessions(access_expires_at);

CREATE INDEX idx_sessions_refresh_expires_at
ON sessions(refresh_expires_at);