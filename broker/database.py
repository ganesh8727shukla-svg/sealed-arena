"""PostgreSQL persistence for Broker events and their analysis results."""

from datetime import datetime, timezone
from pathlib import Path
import json
import os
import time

import psycopg
from psycopg.rows import dict_row

from contracts import ALLOWED_STATUSES, normalize_analysis, retry_delay_seconds, validate_event_payload
from contracts import ALLOWED_SEVERITIES


MAX_ATTEMPTS = 5
PROCESSING_LEASE_SECONDS = 120


def enabled():
    return bool(os.environ.get("DB_HOST"))


def connect():
    return psycopg.connect(
        host=os.environ.get("DB_HOST", "postgres"),
        port=int(os.environ.get("DB_PORT", "5432")),
        dbname=os.environ.get("DB_NAME", "sealed_arena"),
        user=os.environ.get("DB_USER", "sealed_arena"),
        password=os.environ.get("DB_PASSWORD", ""),
        connect_timeout=3,
        row_factory=dict_row,
    )


def _iso(value):
    return value.isoformat() if value is not None else None


def _event_dict(row):
    if row is None:
        return None
    event = dict(row)
    for key in ("received_at", "next_attempt_at", "processing_started_at"):
        if key in event:
            event[key] = _iso(event[key])
    return event


def initialize_storage():
    """Apply idempotent schema statements and import the pre-DB event snapshot."""
    schema_path = Path(os.environ.get("SCHEMA_FILE", "/app/schema.sql"))
    schema_text = schema_path.read_text(encoding="utf-8")
    with connect() as connection:
        for statement in schema_text.split(";"):
            statement = statement.strip()
            if statement:
                connection.execute(statement)
        connection.execute(
            """INSERT INTO schema_migrations (version, description)
               VALUES (1, 'events and analysis baseline')
               ON CONFLICT (version) DO NOTHING"""
        )

    legacy_path = Path(os.environ.get("LEGACY_EVENTS_FILE", "/app/legacy_events.json"))
    imported = 0
    if legacy_path.exists():
        legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
        legacy_events = legacy.get("events", []) if isinstance(legacy, dict) else []
        with connect() as connection:
            for event in legacy_events:
                if (not isinstance(event, dict) or isinstance(event.get("id"), bool)
                        or not isinstance(event.get("id"), int) or event["id"] < 1):
                    continue
                payload = event.get("payload")
                try:
                    validate_event_payload(payload)
                except ValueError:
                    continue
                received_at = event.get("received_at")
                try:
                    timestamp = datetime.fromisoformat(str(received_at).replace("Z", "+00:00"))
                except ValueError:
                    timestamp = datetime.now(timezone.utc)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                cursor = connection.execute(
                    """INSERT INTO events
                       (id, received_at, source, event_type, payload, status, legacy_import)
                       VALUES (%s, %s, %s, %s, %s::jsonb, 'completed', true)
                       ON CONFLICT (id) DO NOTHING
                       RETURNING id""",
                    (
                        event["id"],
                        timestamp,
                        payload["source"].strip(),
                        payload["type"].strip(),
                        json.dumps(payload),
                    ),
                )
                imported += int(cursor.fetchone() is not None)
            connection.execute(
                """SELECT setval(
                     pg_get_serial_sequence('events', 'id'),
                     GREATEST(COALESCE((SELECT MAX(id) FROM events), 0) + 1, 1),
                     false
                   )"""
            )
    return imported


def check_database():
    with connect() as connection:
        connection.execute("SELECT 1").fetchone()
    return True


def create_event(payload, idempotency_key=None):
    validate_event_payload(payload)
    with connect() as connection:
        row = connection.execute(
            """INSERT INTO events
                 (idempotency_key, source, event_type, payload, status)
               VALUES (%s, %s, %s, %s::jsonb, 'pending')
               ON CONFLICT (idempotency_key) DO UPDATE
                 SET idempotency_key = EXCLUDED.idempotency_key
               RETURNING id, source, event_type AS type, received_at, payload,
                         status, attempts, next_attempt_at, processing_started_at,
                         last_error, legacy_import""",
            (
                idempotency_key,
                payload["source"].strip(),
                payload["type"].strip(),
                json.dumps(payload),
            ),
        ).fetchone()
    return _event_dict(row)


def list_events(limit=25, offset=0, status=None, severity=None, query=None):
    if status and status not in ALLOWED_STATUSES:
        raise ValueError("status must be pending, processing, completed, or failed")
    if severity and severity.lower() not in ALLOWED_SEVERITIES:
        raise ValueError("severity must be informational, low, medium, high, critical, or unknown")
    limit = max(1, min(int(limit), 100))
    offset = max(0, min(int(offset), 100000))
    clauses = []
    parameters = []
    if status:
        clauses.append("e.status = %s")
        parameters.append(status)
    if severity:
        clauses.append("a.result->>'severity' = %s")
        parameters.append(severity.lower())
    if query:
        clauses.append("e.payload::text ILIKE %s")
        parameters.append(f"%{query[:100]}%")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as connection:
        total = connection.execute(
            "SELECT COUNT(*) AS total FROM events e LEFT JOIN analyses a ON a.event_id=e.id" + where,
            parameters,
        ).fetchone()["total"]
        rows = connection.execute(
            """SELECT e.id, e.source, e.event_type AS type, e.received_at, e.payload,
                      e.status, e.attempts, e.next_attempt_at, e.last_error,
                      e.legacy_import, a.result AS analysis
               FROM events e LEFT JOIN analyses a ON a.event_id=e.id"""
            + where
            + " ORDER BY e.id DESC LIMIT %s OFFSET %s",
            parameters + [limit, offset],
        ).fetchall()
    return [_event_dict(row) for row in rows], total


def claim_event():
    with connect() as connection:
        connection.execute(
            """UPDATE events
               SET status='failed', processing_started_at=NULL,
                   last_error=COALESCE(last_error, 'Processing lease expired after maximum attempts')
               WHERE status='processing'
                 AND processing_started_at < now() - (%s * interval '1 second')
                 AND attempts >= %s""",
            (PROCESSING_LEASE_SECONDS, MAX_ATTEMPTS),
        )
        row = connection.execute(
            """WITH candidate AS (
                 SELECT id FROM events
                 WHERE source='red' AND attempts < %s
                   AND ((status='pending' AND next_attempt_at <= now())
                     OR (status='processing'
                         AND processing_started_at < now() - (%s * interval '1 second')))
                 ORDER BY id
                 LIMIT 1 FOR UPDATE SKIP LOCKED
               )
               UPDATE events AS e
               SET status='processing', attempts=e.attempts+1,
                   processing_started_at=now(), last_error=NULL
               FROM candidate
               WHERE e.id=candidate.id
               RETURNING e.id, e.source, e.event_type AS type, e.received_at,
                         e.payload, e.status, e.attempts, e.next_attempt_at,
                         e.processing_started_at, e.last_error, e.legacy_import""",
            (MAX_ATTEMPTS, PROCESSING_LEASE_SECONDS),
        ).fetchone()
    return _event_dict(row)


def save_analysis(event_id, analysis):
    normalized = normalize_analysis(analysis)
    with connect() as connection:
        exists = connection.execute("SELECT 1 FROM events WHERE id=%s", (event_id,)).fetchone()
        if exists is None:
            raise KeyError("event not found")
        inserted = connection.execute(
            """INSERT INTO analyses (event_id, result)
               VALUES (%s, %s::jsonb)
               ON CONFLICT (event_id) DO NOTHING
               RETURNING event_id""",
            (event_id, json.dumps(normalized)),
        ).fetchone() is not None
        connection.execute(
            """UPDATE events SET status='completed', processing_started_at=NULL,
                      next_attempt_at=now(), last_error=NULL
               WHERE id=%s""",
            (event_id,),
        )
    return {"event_id": event_id, "created": inserted, "analysis": normalized}


def record_failure(event_id, error):
    safe_error = str(error).replace("\x00", "")[:1000] or "Analysis failed"
    with connect() as connection:
        row = connection.execute(
            "SELECT attempts, status FROM events WHERE id=%s FOR UPDATE", (event_id,)
        ).fetchone()
        if row is None:
            raise KeyError("event not found")
        if row["status"] != "processing":
            return {"event_id": event_id, "status": row["status"], "attempts": row["attempts"]}
        attempts = row["attempts"]
        if attempts >= MAX_ATTEMPTS:
            status = "failed"
            delay = 0
        else:
            status = "pending"
            delay = retry_delay_seconds(attempts)
        connection.execute(
            """UPDATE events
               SET status=%s, processing_started_at=NULL, last_error=%s,
                   next_attempt_at=now() + (%s * interval '1 second')
               WHERE id=%s""",
            (status, safe_error, delay, event_id),
        )
    return {"event_id": event_id, "status": status, "attempts": attempts, "retry_in_seconds": delay}


def retry_event(event_id):
    with connect() as connection:
        row = connection.execute(
            """UPDATE events
               SET status='pending', attempts=0, next_attempt_at=now(),
                   processing_started_at=NULL, last_error=NULL
               WHERE id=%s AND status='failed'
               RETURNING id, status""",
            (event_id,),
        ).fetchone()
        if row is None:
            exists = connection.execute("SELECT status FROM events WHERE id=%s", (event_id,)).fetchone()
            if exists is None:
                raise KeyError("event not found")
            return {"event_id": event_id, "status": exists["status"], "retried": False}
    return {"event_id": event_id, "status": "pending", "retried": True}


def status_counts():
    with connect() as connection:
        rows = connection.execute(
            "SELECT status, COUNT(*) AS total FROM events GROUP BY status"
        ).fetchall()
    counts = {status: 0 for status in ALLOWED_STATUSES}
    counts.update({row["status"]: row["total"] for row in rows})
    return counts
