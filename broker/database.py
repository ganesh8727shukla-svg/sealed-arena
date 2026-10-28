"""PostgreSQL persistence for Broker events and their analysis results."""

from datetime import datetime, timezone
from pathlib import Path
import json
import os
import time

import psycopg
from psycopg.rows import dict_row

from contracts import (
    ALLOWED_CASE_STATUSES,
    ALLOWED_CASE_VERDICTS,
    ALLOWED_SEVERITIES,
    ALLOWED_STATUSES,
    normalize_analysis,
    retry_delay_seconds,
    validate_event_payload,
)


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
    for key in ("received_at", "next_attempt_at", "processing_started_at", "occurred_at"):
        if key in event:
            event[key] = _iso(event[key])
    return event


def _dated_dict(row):
    if row is None:
        return None
    result = dict(row)
    for key in ("created_at", "updated_at", "started_at", "completed_at", "linked_at", "received_at"):
        if key in result:
            result[key] = _iso(result[key])
    return result


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
        connection.execute(
            """INSERT INTO schema_migrations (version, description)
               VALUES (2, 'scenarios, evidence-based detections, and analyst cases')
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
                 (idempotency_key, source, event_type, payload, scenario_run_id, status)
               VALUES (%s, %s, %s, %s::jsonb, %s, 'pending')
               ON CONFLICT (idempotency_key) DO UPDATE
                 SET idempotency_key = EXCLUDED.idempotency_key
               RETURNING id, source, event_type AS type, received_at, payload,
                         status, attempts, next_attempt_at, processing_started_at,
                         last_error, legacy_import, scenario_run_id""",
            (
                idempotency_key,
                payload["source"].strip(),
                payload["type"].strip(),
                json.dumps(payload),
                (payload.get("scenario_run_id") or "").strip() or None,
            ),
        ).fetchone()
    return _event_dict(row)


def list_events(limit=25, offset=0, status=None, severity=None, query=None,
                scenario_run_id=None, source=None, asset=None):
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
    if scenario_run_id:
        clauses.append("e.scenario_run_id = %s")
        parameters.append(scenario_run_id[:64])
    if source:
        clauses.append("e.source ILIKE %s")
        parameters.append(f"%{source[:64]}%")
    if asset:
        clauses.append("(e.payload->>'device_id' ILIKE %s OR e.payload->>'actor_user' ILIKE %s)")
        value = f"%{asset[:100]}%"
        parameters.extend([value, value])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as connection:
        total = connection.execute(
            "SELECT COUNT(*) AS total FROM events e LEFT JOIN analyses a ON a.event_id=e.id" + where,
            parameters,
        ).fetchone()["total"]
        rows = connection.execute(
            """SELECT e.id, e.source, e.event_type AS type, e.received_at, e.payload,
                      e.scenario_run_id,
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
                 SELECT e.id FROM events e
                 LEFT JOIN scenario_runs sr ON sr.run_id=e.scenario_run_id
                 WHERE e.attempts < %s
                   AND (e.scenario_run_id IS NULL OR sr.status <> 'running')
                   AND ((e.status='pending' AND e.next_attempt_at <= now())
                     OR (e.status='processing'
                         AND e.processing_started_at < now() - (%s * interval '1 second')))
                 ORDER BY e.id
                 LIMIT 1 FOR UPDATE OF e SKIP LOCKED
               )
               UPDATE events AS e
               SET status='processing', attempts=e.attempts+1,
                   processing_started_at=now(), last_error=NULL
               FROM candidate
               WHERE e.id=candidate.id
               RETURNING e.id, e.source, e.event_type AS type, e.received_at,
                         e.payload, e.status, e.attempts, e.next_attempt_at,
                         e.scenario_run_id,
                         e.processing_started_at, e.last_error, e.legacy_import""",
            (MAX_ATTEMPTS, PROCESSING_LEASE_SECONDS),
        ).fetchone()
    return _event_dict(row)


def save_analysis(event_id, analysis):
    normalized = normalize_analysis(analysis)
    with connect() as connection:
        event = connection.execute(
            "SELECT id, scenario_run_id FROM events WHERE id=%s", (event_id,)
        ).fetchone()
        if event is None:
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
        for detection in normalized["detections"]:
            run_id = event["scenario_run_id"]
            case_key = (
                f"run:{run_id}:{detection['rule_id']}" if run_id
                else f"event:{event_id}:{detection['rule_id']}"
            )
            case = connection.execute(
                """INSERT INTO cases (case_key, scenario_run_id, title, severity)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (case_key) DO UPDATE
                     SET updated_at=now()
                   RETURNING id""",
                (case_key, run_id, detection["title"], detection["severity"]),
            ).fetchone()
            case_id = case["id"]
            linked = connection.execute(
                """INSERT INTO case_events (case_id, event_id)
                   VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING event_id""",
                (case_id, event_id),
            ).fetchone()
            if linked is not None:
                connection.execute(
                    """INSERT INTO case_activity (case_id, actor, action, detail)
                       VALUES (%s, 'system', 'evidence_linked', %s::jsonb)""",
                    (case_id, json.dumps({"event_id": event_id, "rule_id": detection["rule_id"]})),
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


def system_metrics():
    with connect() as connection:
        event_rows = connection.execute("SELECT status, COUNT(*) AS total FROM events GROUP BY status").fetchall()
        case_rows = connection.execute("SELECT status, COUNT(*) AS total FROM cases GROUP BY status").fetchall()
        runs = connection.execute("SELECT COUNT(*) AS total FROM scenario_runs").fetchone()["total"]
    event_counts = {status: 0 for status in ALLOWED_STATUSES}
    event_counts.update({row["status"]: row["total"] for row in event_rows})
    case_counts = {status: 0 for status in ALLOWED_CASE_STATUSES}
    case_counts.update({row["status"]: row["total"] for row in case_rows})
    return {"events": event_counts, "cases": case_counts, "scenario_runs": runs}


def create_scenario_run(run_id, scenario_key, name):
    if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 64:
        raise ValueError("run_id must be a non-empty string of at most 64 characters")
    if not isinstance(scenario_key, str) or not scenario_key.strip() or len(scenario_key) > 64:
        raise ValueError("scenario_key must be a non-empty string of at most 64 characters")
    if not isinstance(name, str) or not name.strip() or len(name) > 160:
        raise ValueError("name must be a non-empty string of at most 160 characters")
    with connect() as connection:
        row = connection.execute(
            """INSERT INTO scenario_runs (run_id, scenario_key, name)
               VALUES (%s, %s, %s)
               RETURNING run_id, scenario_key, name, status, started_at,
                         completed_at, event_count""",
            (run_id.strip(), scenario_key.strip(), name.strip()),
        ).fetchone()
    return _dated_dict(row)


def complete_scenario_run(run_id, status="completed", event_count=0):
    if not isinstance(status, str) or status not in {"completed", "failed"}:
        raise ValueError("scenario run status must be completed or failed")
    if isinstance(event_count, bool) or not isinstance(event_count, int) or not 0 <= event_count <= 1000:
        raise ValueError("event_count must be an integer from 0 to 1000")
    with connect() as connection:
        row = connection.execute(
            """UPDATE scenario_runs
               SET status=%s, event_count=%s, completed_at=now()
               WHERE run_id=%s
               RETURNING run_id, scenario_key, name, status, started_at,
                         completed_at, event_count""",
            (status, event_count, run_id),
        ).fetchone()
    if row is None:
        raise KeyError("scenario run not found")
    return _dated_dict(row)


def list_scenario_runs(limit=10):
    limit = max(1, min(int(limit), 50))
    with connect() as connection:
        rows = connection.execute(
            """SELECT run_id, scenario_key, name, status, started_at, completed_at, event_count
               FROM scenario_runs ORDER BY started_at DESC LIMIT %s""",
            (limit,),
        ).fetchall()
    return [_dated_dict(row) for row in rows]


def event_context(event_id, window_seconds=600):
    window_seconds = max(1, min(int(window_seconds), 86400))
    with connect() as connection:
        target = connection.execute(
            "SELECT id, source, received_at, payload, scenario_run_id FROM events WHERE id=%s",
            (event_id,),
        ).fetchone()
        if target is None:
            raise KeyError("event not found")
        actor = target["payload"].get("actor_user")
        source_ip = target["payload"].get("source_ip")
        if not isinstance(actor, str) or not actor or not isinstance(source_ip, str) or not source_ip:
            rows = [target]
        else:
            rows = connection.execute(
                """SELECT e.id, e.source, e.received_at, e.payload, e.scenario_run_id
                   FROM events e
                   WHERE e.source=%s
                     AND e.payload->>'actor_user'=%s
                     AND e.payload->>'source_ip'=%s
                     AND e.received_at BETWEEN %s - (%s * interval '1 second')
                                            AND %s + (%s * interval '1 second')
                   ORDER BY e.received_at, e.id LIMIT 200""",
                (target["source"], actor, source_ip, target["received_at"], window_seconds,
                 target["received_at"], window_seconds),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["received_at"] = _iso(item["received_at"])
            result.append(item)
    return {"event_id": event_id, "window_seconds": window_seconds, "events": result}


def list_cases(limit=25, offset=0, status=None, severity=None, query=None):
    if status and status not in ALLOWED_CASE_STATUSES:
        raise ValueError("status must be new, investigating, or resolved")
    if severity and severity.lower() not in ALLOWED_SEVERITIES:
        raise ValueError("invalid severity")
    limit = max(1, min(int(limit), 100))
    offset = max(0, min(int(offset), 100000))
    clauses, parameters = [], []
    if status:
        clauses.append("c.status=%s")
        parameters.append(status)
    if severity:
        clauses.append("c.severity=%s")
        parameters.append(severity.lower())
    if query:
        clauses.append("(c.title ILIKE %s OR c.case_key ILIKE %s OR c.assigned_to ILIKE %s)")
        value = f"%{query[:100]}%"
        parameters.extend([value, value, value])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as connection:
        total = connection.execute("SELECT COUNT(*) AS total FROM cases c" + where, parameters).fetchone()["total"]
        rows = connection.execute(
            """SELECT c.id, c.case_key, c.scenario_run_id, c.title, c.severity,
                      c.status, c.verdict, c.assigned_to, c.created_at, c.updated_at,
                      COUNT(ce.event_id) AS event_count,
                      COALESCE(jsonb_agg(jsonb_build_object(
                        'id', e.id, 'source', e.source, 'type', e.event_type,
                        'received_at', e.received_at, 'payload', e.payload,
                        'detections', a.result->'detections'
                      ) ORDER BY e.received_at, e.id) FILTER (WHERE e.id IS NOT NULL), '[]'::jsonb) AS events,
                      (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                         'actor', recent.actor, 'action', recent.action,
                         'detail', recent.detail, 'created_at', recent.created_at
                       ) ORDER BY recent.created_at DESC), '[]'::jsonb)
                       FROM (SELECT actor, action, detail, created_at FROM case_activity
                             WHERE case_id=c.id ORDER BY created_at DESC, id DESC LIMIT 3) recent) AS recent_activity
               FROM cases c
               LEFT JOIN case_events ce ON ce.case_id=c.id
               LEFT JOIN events e ON e.id=ce.event_id
               LEFT JOIN analyses a ON a.event_id=e.id"""
            + where
            + " GROUP BY c.id ORDER BY c.updated_at DESC, c.id DESC LIMIT %s OFFSET %s",
            parameters + [limit, offset],
        ).fetchall()
    return [_dated_dict(row) for row in rows], total


def get_case(case_id):
    with connect() as connection:
        row = connection.execute(
            """SELECT id, case_key, scenario_run_id, title, severity, status, verdict,
                      assigned_to, created_at, updated_at
               FROM cases WHERE id=%s""",
            (case_id,),
        ).fetchone()
        if row is None:
            raise KeyError("case not found")
        events = connection.execute(
            """SELECT e.id, e.source, e.event_type AS type, e.received_at,
                      e.payload, e.status, a.result AS analysis
               FROM case_events ce JOIN events e ON e.id=ce.event_id
               LEFT JOIN analyses a ON a.event_id=e.id
               WHERE ce.case_id=%s ORDER BY e.received_at, e.id""",
            (case_id,),
        ).fetchall()
        activity = connection.execute(
            """SELECT actor, action, detail, created_at FROM case_activity
               WHERE case_id=%s ORDER BY created_at DESC, id DESC LIMIT 100""",
            (case_id,),
        ).fetchall()
    case = _dated_dict(row)
    case["events"] = [_dated_dict(item) for item in events]
    case["activity"] = [_dated_dict(item) for item in activity]
    return case


def update_case(case_id, data, actor="local-analyst"):
    allowed = {"status", "verdict", "assigned_to"}
    unknown = set(data) - allowed - {"note"}
    if unknown:
        raise ValueError("unsupported case fields: " + ", ".join(sorted(unknown)))
    updates = {}
    if "status" in data:
        if not isinstance(data["status"], str) or data["status"] not in ALLOWED_CASE_STATUSES:
            raise ValueError("status must be new, investigating, or resolved")
        updates["status"] = data["status"]
    if "verdict" in data:
        if not isinstance(data["verdict"], str) or data["verdict"] not in ALLOWED_CASE_VERDICTS:
            raise ValueError("invalid case verdict")
        updates["verdict"] = data["verdict"]
    if "assigned_to" in data:
        assigned = data["assigned_to"]
        if assigned is not None and (not isinstance(assigned, str) or len(assigned) > 100):
            raise ValueError("assigned_to must be a string of at most 100 characters")
        updates["assigned_to"] = assigned.strip() or None if assigned else None
    note = data.get("note", "")
    if not isinstance(note, str) or len(note) > 2000:
        raise ValueError("note must be a string of at most 2000 characters")
    if not updates and not note.strip():
        raise ValueError("provide a case change or a note")

    with connect() as connection:
        existing = connection.execute("SELECT id FROM cases WHERE id=%s FOR UPDATE", (case_id,)).fetchone()
        if existing is None:
            raise KeyError("case not found")
        if updates:
            assignments = ", ".join(f"{field}=%s" for field in updates)
            values = list(updates.values())
            connection.execute(
                f"UPDATE cases SET {assignments}, updated_at=now() WHERE id=%s",
                values + [case_id],
            )
            for field, value in updates.items():
                connection.execute(
                    """INSERT INTO case_activity (case_id, actor, action, detail)
                       VALUES (%s, %s, %s, %s::jsonb)""",
                    (case_id, actor, field + "_changed", json.dumps({field: value})),
                )
        if note.strip():
            connection.execute(
                """INSERT INTO case_activity (case_id, actor, action, detail)
                   VALUES (%s, %s, 'note_added', %s::jsonb)""",
                (case_id, actor, json.dumps({"note": note.strip()})),
            )
    return get_case(case_id)


def clear_scenario_data():
    with connect() as connection:
        case_count = connection.execute(
            """SELECT COUNT(DISTINCT ce.case_id) AS total FROM case_events ce
               JOIN events e ON e.id=ce.event_id WHERE e.scenario_run_id IS NOT NULL"""
        ).fetchone()["total"]
        event_count = connection.execute(
            "SELECT COUNT(*) AS total FROM events WHERE scenario_run_id IS NOT NULL"
        ).fetchone()["total"]
        run_count = connection.execute("SELECT COUNT(*) AS total FROM scenario_runs").fetchone()["total"]
        connection.execute(
            """DELETE FROM cases WHERE id IN (
                 SELECT DISTINCT ce.case_id FROM case_events ce
                 JOIN events e ON e.id=ce.event_id WHERE e.scenario_run_id IS NOT NULL
               )"""
        )
        connection.execute("DELETE FROM events WHERE scenario_run_id IS NOT NULL")
        connection.execute("DELETE FROM scenario_runs")
    return {"cases_deleted": case_count, "events_deleted": event_count, "runs_deleted": run_count}
