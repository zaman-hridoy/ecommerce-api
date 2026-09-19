CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    session_id UUID NOT NULL
        REFERENCES sessions(id)
        ON DELETE CASCADE,
    
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    used_at    TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    replaced_by UUID
        REFERENCES refresh_tokens(id)
        ON DELETE SET NULL
);


CREATE INDEX idx_refresh_tokens_session_id
ON refresh_tokens(session_id);

CREATE INDEX idx_refresh_tokens_expires_at
ON refresh_tokens(expires_at);