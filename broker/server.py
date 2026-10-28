
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
import json

from database import (
    check_database,
    claim_event,
    clear_scenario_data,
    complete_scenario_run,
    create_scenario_run,
    create_event,
    enabled as database_enabled,
    event_context,
    get_case,
    initialize_storage,
    list_cases,
    list_events,
    list_scenario_runs,
    record_failure,
    retry_event,
    save_analysis,
    status_counts,
    system_metrics,
    update_case,
)

events = []
MAX_EVENTS = 200


def log_record(stage, **fields):
    print(json.dumps({"service": "broker", "stage": stage, **fields}, ensure_ascii=False), flush=True)


class BrokerHandler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if database_enabled():
            database_get(self)
            return

        if self.path == "/health":
            self.send_json(200, {
                "service": "broker",
                "status": "healthy"
            })
        elif self.path == "/ready":
            self.send_json(200, {
                "service": "broker",
                "status": "healthy",
                "storage": "memory"
            })
        elif self.path == "/events":
            self.send_json(200, {"events": events})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if database_enabled():
            database_post(self)
            return

        if self.path != "/message":
            self.send_json(404, {"error": "Not found"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                self.send_json(400, {"error": "Invalid body size"})
                return

            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                self.send_json(400, {"error": "JSON object required"})
                return

            event = {
                "id": events[-1]["id"] + 1 if events else 1,
                "received_at": datetime.now(timezone.utc).isoformat(),
                "payload": payload
            }
            events.append(event)

            if len(events) > MAX_EVENTS:
                del events[:-MAX_EVENTS]

            log_record(
                "event_received",
                event_id=event["id"],
                source=payload.get("source"),
                event_type=payload.get("type"),
                storage="memory",
            )
            self.send_json(200, {
                "status": "received",
                "broker": "sealed-broker",
                "event_id": event["id"]
            })

        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON"})


def read_database_request(handler):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        handler.send_json(400, {"error": "Invalid Content-Length"})
        return None
    if length <= 0 or length > 65536:
        handler.send_json(400, {"error": "Invalid body size"})
        return None
    try:
        body = json.loads(handler.rfile.read(length))
    except (ValueError, json.JSONDecodeError):
        handler.send_json(400, {"error": "Invalid JSON"})
        return None
    if not isinstance(body, dict):
        handler.send_json(400, {"error": "JSON object required"})
        return None
    return body


def database_get(handler):
    path = urlsplit(handler.path).path
    if path == "/health":
        # Liveness answers whether Broker's process is serving HTTP. Keep this
        # independent from PostgreSQL so orchestrators do not restart a live
        # Broker during a temporary database outage.
        handler.send_json(200, {
            "service": "broker",
            "status": "healthy",
            "storage": "postgresql",
        })
        return

    if path in ("/ready", "/db-health"):
        try:
            check_database()
            service = "postgres" if path == "/db-health" else "broker"
            response = {"service": service, "status": "healthy"}
            if path != "/db-health":
                response["storage"] = "postgresql"
            handler.send_json(200, response)
        except Exception as error:
            log_record("database_health", status="unavailable", error_type=type(error).__name__)
            service = "postgres" if path == "/db-health" else "broker"
            response = {"service": service, "status": "unavailable"}
            if path != "/db-health":
                response["storage"] = "postgresql"
            handler.send_json(503, response)
        return

    if path == "/events":
        params = parse_qs(urlsplit(handler.path).query)
        try:
            limit = int(params.get("limit", [25])[0])
            offset = int(params.get("offset", [0])[0])
            status = params.get("status", [None])[0]
            severity = params.get("severity", [None])[0]
            query = params.get("q", [None])[0]
            scenario_run_id = params.get("scenario_run_id", [None])[0]
            source = params.get("source", [None])[0]
            asset = params.get("asset", [None])[0]
            rows, total = list_events(limit, offset, status, severity, query, scenario_run_id, source, asset)
            handler.send_json(200, {
                "events": rows,
                "total": total,
                "limit": max(1, min(limit, 100)),
                "offset": max(0, min(offset, 100000)),
            })
        except ValueError as error:
            handler.send_json(400, {"error": str(error)})
        except Exception as error:
            log_record("events_query", status="failed", error_type=type(error).__name__)
            handler.send_json(503, {"error": "Event storage is temporarily unavailable"})
        return

    if path == "/event-context":
        params = parse_qs(urlsplit(handler.path).query)
        try:
            event_id = int(params.get("event_id", [""])[0])
            window_seconds = int(params.get("window_seconds", [600])[0])
            if event_id < 1:
                raise ValueError("event_id must be positive")
            handler.send_json(200, event_context(event_id, window_seconds))
        except ValueError as error:
            handler.send_json(400, {"error": str(error)})
        except KeyError:
            handler.send_json(404, {"error": "Event not found"})
        except Exception as error:
            log_record("event_context", status="failed", error_type=type(error).__name__)
            handler.send_json(503, {"error": "Event context is temporarily unavailable"})
        return

    if path == "/scenario-runs":
        params = parse_qs(urlsplit(handler.path).query)
        try:
            handler.send_json(200, {"runs": list_scenario_runs(int(params.get("limit", [10])[0]))})
        except ValueError as error:
            handler.send_json(400, {"error": str(error)})
        return

    if path == "/cases":
        params = parse_qs(urlsplit(handler.path).query)
        try:
            limit = int(params.get("limit", [25])[0])
            offset = int(params.get("offset", [0])[0])
            rows, total = list_cases(
                limit, offset,
                params.get("status", [None])[0],
                params.get("severity", [None])[0],
                params.get("q", [None])[0],
            )
            handler.send_json(200, {"cases": rows, "total": total, "limit": limit, "offset": offset})
        except ValueError as error:
            handler.send_json(400, {"error": str(error)})
        except Exception as error:
            log_record("cases_query", status="failed", error_type=type(error).__name__)
            handler.send_json(503, {"error": "Case storage is temporarily unavailable"})
        return

    if path.startswith("/cases/"):
        try:
            case_id = int(path.rsplit("/", 1)[1])
            if case_id < 1:
                raise ValueError
            handler.send_json(200, get_case(case_id))
        except ValueError:
            handler.send_json(400, {"error": "case ID must be a positive integer"})
        except KeyError:
            handler.send_json(404, {"error": "Case not found"})
        except Exception as error:
            log_record("case_detail", status="failed", error_type=type(error).__name__)
            handler.send_json(503, {"error": "Case detail is temporarily unavailable"})
        return

    if path == "/stats":
        try:
            handler.send_json(200, {"statuses": status_counts(), "metrics": system_metrics()})
        except Exception as error:
            log_record("status_query", status="failed", error_type=type(error).__name__)
            handler.send_json(503, {"error": "Event storage is temporarily unavailable"})
        return

    handler.send_json(404, {"error": "Not found"})


def database_post(handler):
    path = urlsplit(handler.path).path
    if path not in (
        "/message", "/events/claim", "/analysis", "/events/fail", "/events/retry",
        "/scenario-runs", "/scenario-runs/complete", "/scenario-runs/reset", "/cases/update",
    ):
        handler.send_json(404, {"error": "Not found"})
        return
    body = read_database_request(handler)
    if body is None:
        return

    try:
        if path == "/message":
            key = handler.headers.get("Idempotency-Key", "").strip()
            if len(key) > 128:
                handler.send_json(400, {"error": "Idempotency-Key is too long"})
                return
            event = create_event(body, key or None)
            log_record(
                "event_received",
                event_id=event["id"],
                source=event["source"],
                event_type=event["type"],
                status=event["status"],
                storage="postgresql",
            )
            handler.send_json(200, {
                "status": "received",
                "broker": "sealed-broker",
                "event_id": event["id"],
                "event_status": event["status"],
                "scenario_run_id": event.get("scenario_run_id"),
            })
        elif path == "/scenario-runs":
            row = create_scenario_run(body.get("run_id"), body.get("scenario_key"), body.get("name"))
            handler.send_json(201, row)
        elif path == "/scenario-runs/complete":
            run_id = body.get("run_id")
            if not isinstance(run_id, str) or not run_id.strip():
                handler.send_json(400, {"error": "run_id is required"})
                return
            row = complete_scenario_run(run_id, body.get("status", "completed"), body.get("event_count", 0))
            handler.send_json(200, row)
        elif path == "/scenario-runs/reset":
            handler.send_json(200, clear_scenario_data())
        elif path == "/cases/update":
            case_id = body.get("case_id")
            if isinstance(case_id, bool) or not isinstance(case_id, int) or case_id < 1:
                handler.send_json(400, {"error": "case_id must be a positive integer"})
                return
            data = {key: value for key, value in body.items() if key not in {"case_id", "actor"}}
            actor = body.get("actor", "local-analyst")
            if not isinstance(actor, str) or not actor.strip() or len(actor) > 100:
                handler.send_json(400, {"error": "actor must be a non-empty string of at most 100 characters"})
                return
            handler.send_json(200, update_case(case_id, data, actor.strip()))
        elif path == "/events/claim":
            event = claim_event()
            handler.send_json(200, {"event": event})
        elif path == "/analysis":
            event_id = body.get("event_id")
            if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
                handler.send_json(400, {"error": "event_id must be a positive integer"})
                return
            result = body.get("analysis")
            saved = save_analysis(event_id, result)
            handler.send_json(201 if saved["created"] else 200, saved)
        elif path == "/events/fail":
            event_id = body.get("event_id")
            reason = body.get("error")
            if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
                handler.send_json(400, {"error": "event_id must be a positive integer"})
                return
            if not isinstance(reason, str) or not reason.strip():
                handler.send_json(400, {"error": "error must be a non-empty string"})
                return
            handler.send_json(200, record_failure(event_id, reason))
        elif path == "/events/retry":
            event_id = body.get("event_id")
            if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1:
                handler.send_json(400, {"error": "event_id must be a positive integer"})
                return
            handler.send_json(200, retry_event(event_id))
    except KeyError:
        handler.send_json(404, {"error": "Event not found"})
    except ValueError as error:
        handler.send_json(400, {"error": str(error)})
    except Exception as error:
        log_record("database_write", route=path, status="failed", error_type=type(error).__name__)
        handler.send_json(503, {"error": "Event storage is temporarily unavailable"})


if database_enabled():
    imported = initialize_storage()
    log_record("database_ready", status="healthy", imported_legacy_events=imported)

server = ThreadingHTTPServer(("0.0.0.0", 8000), BrokerHandler)
log_record("server_start", port=8000, storage="postgresql" if database_enabled() else "memory")
server.serve_forever()
