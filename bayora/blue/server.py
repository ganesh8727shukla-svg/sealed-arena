"""Private Blue policy and post-run scoring service."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hashlib
import hmac
import json
import os

from logic import POLICIES, score_run


INTERNAL_TOKEN = os.environ.get("BAYORA_BLUE_INTERNAL_TOKEN", "local-blue-service-token")
ARTIFACT_PATH = Path(__file__).with_name("private") / "defense-plan.json"
ARTIFACT_READ_COUNT = 0


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global ARTIFACT_READ_COUNT
        if self.path in ("/health", "/ready"):
            self.send_json(200, {"service": "bayora-blue", "status": "healthy"})
        elif self.path == "/policies":
            self.send_json(200, {"policies": POLICIES})
        elif self.path in {"/internal/artifacts/metadata", "/internal/artifacts/defense-plan"}:
            supplied = self.headers.get("X-Bayora-Blue-Token", "")
            if not hmac.compare_digest(supplied, INTERNAL_TOKEN):
                self.send_json(403, {"error": "Blue private artifact access requires the controller service credential"})
                return
            try:
                artifact_bytes = ARTIFACT_PATH.read_bytes()
                artifact = json.loads(artifact_bytes)
            except (OSError, json.JSONDecodeError):
                self.send_json(503, {"error": "Protected artifact is unavailable"})
                return
            if self.path.endswith("/metadata"):
                self.send_json(200, {
                    "artifact_id": artifact["artifact_id"],
                    "title": artifact["title"],
                    "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
                    "read_count": ARTIFACT_READ_COUNT,
                })
            else:
                ARTIFACT_READ_COUNT += 1
                self.send_json(200, artifact)
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/score":
            self.send_json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 262144:
                self.send_json(400, {"error": "Invalid body size"})
                return
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                self.send_json(400, {"error": "JSON object required"})
                return
            report = score_run(
                body.get("run_id"), body.get("policy_profile"), body.get("results"),
                body.get("policy_title"),
            )
            self.send_json(200, report)
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})

    def log_message(self, format_string, *args):
        # Keep raw test prompts and responses out of Blue's container logs.
        return


PORT = int(os.environ.get("PORT", "8100"))
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.daemon_threads = True
print(json.dumps({"service": "bayora-blue", "stage": "ready", "port": PORT}), flush=True)
server.serve_forever()
