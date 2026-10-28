"""HTTP API for launching safe synthetic Red-team scenarios."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import json
import os
import uuid

from scenarios import generate_scenario_events, list_scenarios


def service_url(name, default):
    value = os.environ.get(name, default).strip().rstrip("/")
    return value if "://" in value else "http://" + value


BROKER_URL = service_url("BROKER_URL", "http://broker:8000")


def broker_json(path, data=None, headers=None):
    body = None if data is None else json.dumps(data).encode("utf-8")
    request = Request(
        BROKER_URL + path,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="GET" if data is None else "POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def log_record(stage, **fields):
    print(json.dumps({"service": "red", "stage": stage, **fields}), flush=True)


class RedHandler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"service": "red", "status": "healthy"})
        elif self.path == "/ready":
            try:
                broker_json("/ready")
                self.send_json(200, {"service": "red", "status": "healthy"})
            except Exception as error:
                self.send_json(503, {
                    "service": "red",
                    "status": "unavailable",
                    "dependency_error": type(error).__name__,
                })
        elif self.path == "/scenarios":
            self.send_json(200, {"scenarios": list_scenarios()})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/scenarios/run":
            self.send_json(404, {"error": "Not found"})
            return
        run_id = None
        event_ids = []
        run_registered = False
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4096:
                self.send_json(400, {"error": "Invalid body size"})
                return
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or not isinstance(data.get("scenario_id"), str):
                self.send_json(400, {"error": "scenario_id is required"})
                return
            scenario_id = data["scenario_id"].strip()
            scenario = next((item for item in list_scenarios() if item["id"] == scenario_id), None)
            if scenario is None:
                self.send_json(400, {"error": "Unknown scenario_id"})
                return

            run_id = str(uuid.uuid4())
            events = generate_scenario_events(scenario_id, run_id)
            broker_json("/scenario-runs", {
                "run_id": run_id,
                "scenario_key": scenario_id,
                "name": scenario["title"],
            })
            run_registered = True
            for index, event in enumerate(events, start=1):
                result = broker_json(
                    "/message",
                    event,
                    {"Idempotency-Key": f"{run_id}:{index}"},
                )
                event_ids.append(result["event_id"])
            broker_json("/scenario-runs/complete", {
                "run_id": run_id,
                "status": "completed",
                "event_count": len(event_ids),
            })
            log_record("scenario_submitted", run_id=run_id, scenario_id=scenario_id, event_count=len(event_ids))
            self.send_json(201, {
                "run_id": run_id,
                "scenario_id": scenario_id,
                "scenario_name": scenario["title"],
                "event_count": len(event_ids),
                "event_ids": event_ids,
                "status": "completed",
            })
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
        except (HTTPError, URLError, TimeoutError, OSError, KeyError) as error:
            if run_registered and run_id:
                try:
                    broker_json("/scenario-runs/complete", {
                        "run_id": run_id,
                        "status": "failed",
                        "event_count": len(event_ids),
                    })
                except Exception:
                    pass
            log_record("scenario_failed", error_type=type(error).__name__)
            try:
                self.send_json(503, {"error": "Scenario could not be submitted to Broker"})
            except OSError:
                pass

    def log_message(self, format_string, *args):
        log_record("http_request", client=self.address_string(), route=self.path.split("?", 1)[0])


server = ThreadingHTTPServer(("0.0.0.0", 8003), RedHandler)
server.daemon_threads = True
log_record("server_start", port=8003)
server.serve_forever()
