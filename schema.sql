-- SealedArena schema version 1. Keep this file at the project root. No migration folder is needed.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    source VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_started_at TIMESTAMPTZ,
    last_error TEXT,
    legacy_import BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS events_status_due_idx
    ON events (status, next_attempt_at, id);
CREATE INDEX IF NOT EXISTS events_received_at_idx
    ON events (received_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS analyses (
    event_id BIGINT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS analyses_severity_idx
    ON analyses ((result->>'severity'));
