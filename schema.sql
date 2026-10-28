-- SealedArena schema version 2. Statements are safe to reapply at startup.
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scenario_runs (
    run_id TEXT PRIMARY KEY,
    scenario_key VARCHAR(64) NOT NULL,
    name VARCHAR(160) NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0)
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    source VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    scenario_run_id TEXT REFERENCES scenario_runs(run_id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_started_at TIMESTAMPTZ,
    last_error TEXT,
    legacy_import BOOLEAN NOT NULL DEFAULT false
);

ALTER TABLE events ADD COLUMN IF NOT EXISTS scenario_run_id TEXT
    REFERENCES scenario_runs(run_id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS events_status_due_idx
    ON events (status, next_attempt_at, id);
CREATE INDEX IF NOT EXISTS events_received_at_idx
    ON events (received_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS events_scenario_run_idx
    ON events (scenario_run_id, id);

CREATE TABLE IF NOT EXISTS analyses (
    event_id BIGINT PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
    result JSONB NOT NULL CHECK (jsonb_typeof(result) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS analyses_severity_idx
    ON analyses ((result->>'severity'));

CREATE TABLE IF NOT EXISTS cases (
    id BIGSERIAL PRIMARY KEY,
    case_key TEXT NOT NULL UNIQUE,
    scenario_run_id TEXT REFERENCES scenario_runs(run_id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical', 'unknown')),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'resolved')),
    verdict TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (verdict IN ('unreviewed', 'true_positive', 'false_positive', 'needs_more_info')),
    assigned_to VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS cases_status_updated_idx ON cases (status, updated_at DESC);
CREATE INDEX IF NOT EXISTS cases_severity_idx ON cases (severity);

CREATE TABLE IF NOT EXISTS case_events (
    case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, event_id)
);

CREATE TABLE IF NOT EXISTS case_activity (
    id BIGSERIAL PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor VARCHAR(100) NOT NULL,
    action VARCHAR(64) NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS case_activity_case_idx ON case_activity (case_id, created_at DESC);
