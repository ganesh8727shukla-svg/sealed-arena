
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
from threading import Thread
import json
import os
import time

from rules import build_analysis, evaluate_detections, sanitize_for_llm

def service_url(name, default):
    value = os.environ.get(name, default).strip().rstrip("/")
    return value if "://" in value else "http://" + value


BROKER_BASE_URL = service_url("BROKER_URL", "http://broker:8000")
BROKER_URL = BROKER_BASE_URL + "/events"
BROKER_READY_URL = BROKER_BASE_URL + "/ready"
BROKER_CLAIM_URL = BROKER_BASE_URL + "/events/claim"
BROKER_ANALYSIS_URL = BROKER_BASE_URL + "/analysis"
BROKER_FAILURE_URL = BROKER_BASE_URL + "/events/fail"
LLM_URL = service_url("LLM_URL", "http://llm:8001") + "/analyze"
BROKER_CONTEXT_URL = BROKER_BASE_URL + "/event-context"

seen_ids = set()


def log_record(stage, **fields):
    print(json.dumps({"service": "blue", "stage": stage, **fields}, ensure_ascii=False), flush=True)


class BlueHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = json.dumps({
                "service": "blue",
                "status": "healthy"
            }).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/ready":
            try:
                with urlopen(BROKER_READY_URL, timeout=2):
                    pass
                body = json.dumps({"service": "blue", "status": "healthy"}).encode()
                status = 200
            except Exception as error:
                body = json.dumps({
                    "service": "blue",
                    "status": "unavailable",
                    "dependency_error": type(error).__name__,
                }).encode()
                status = 503
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return


def analyze_event(event):
    event_id = event.get("id")
    context_url = BROKER_CONTEXT_URL + "?" + urlencode({"event_id": str(event_id)})
    with urlopen(context_url, timeout=5) as response:
        context = json.loads(response.read().decode("utf-8"))
    payload = dict(event.get("payload", {}))
    payload["id"] = event_id
    detections = evaluate_detections(payload, context.get("events", []))
    request_body = {
        "event_id": event_id,
        "event": sanitize_for_llm(event.get("payload", {})),
    }

    request = Request(
        LLM_URL,
        data=json.dumps(request_body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urlopen(request, timeout=35) as response:
            model_result = json.loads(response.read().decode())
        if not isinstance(model_result, dict):
            raise ValueError("LLM returned a non-object response")
        model_available = True
    except (URLError, HTTPError, TimeoutError, ValueError, KeyError, TypeError) as error:
        log_record("llm_advisory_unavailable", event_id=event_id, error_type=type(error).__name__)
        model_result = {
            "provider": "unavailable",
            "model": "unavailable",
            "severity": "unknown",
            "explanation": "LLM advisory is unavailable; deterministic rule results remain active.",
            "recommendation": "Review the event and any rule evidence manually.",
            "confidence": None,
        }
        model_available = False
    return build_analysis(detections, model_result, model_available)


def monitor_broker():
    log_record("worker_start", status="claiming_pending_events")

    while True:
        try:
            claim = post_json(BROKER_CLAIM_URL, {})
            event = claim.get("event")
            if event is None:
                time.sleep(2)
                continue

            event_id = event["id"]
            log_record("event_processing", event_id=event_id, attempt=event.get("attempts"))
            processing_started = time.monotonic()
            try:
                analysis = analyze_event(event)
                post_json(BROKER_ANALYSIS_URL, {"event_id": event_id, "analysis": analysis})
                log_record(
                    "analysis_stored",
                    event_id=event_id,
                    severity=analysis.get("severity", "unknown"),
                    provider=analysis.get("provider"),
                    model=analysis.get("model"),
                    duration_ms=round((time.monotonic() - processing_started) * 1000),
                )
            except (URLError, HTTPError, TimeoutError, ValueError, KeyError, TypeError) as error:
                try:
                    result = post_json(BROKER_FAILURE_URL, {
                        "event_id": event_id,
                        "error": type(error).__name__,
                    })
                    log_record(
                        "analysis_failed",
                        event_id=event_id,
                        status=result.get("status"),
                        attempt=result.get("attempts"),
                        retry_in_seconds=result.get("retry_in_seconds"),
                        error_type=type(error).__name__,
                    )
                except Exception as broker_error:
                    # The broker will reclaim this event when the processing lease expires.
                    log_record(
                        "failure_report_unavailable",
                        event_id=event_id,
                        error_type=type(broker_error).__name__,
                    )
        except Exception as error:
            log_record("worker_error", error_type=type(error).__name__)
            time.sleep(3)


def post_json(url, data):
    request = Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


Thread(target=monitor_broker, daemon=True).start()

server = ThreadingHTTPServer(("0.0.0.0", 8002), BlueHandler)

log_record("server_start", port=8002)
server.serve_forever()
