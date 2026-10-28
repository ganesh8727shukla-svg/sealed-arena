"""Private Red test-pack service. It is reachable only by the controller."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from urllib.parse import urlsplit, parse_qs

from catalog import get_test_cases


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
        path = urlsplit(self.path).path
        if path in ("/health", "/ready"):
            self.send_json(200, {"service": "bayora-red", "status": "healthy"})
        elif path == "/test-cases":
            params = parse_qs(urlsplit(self.path).query)
            pack_id = params.get("pack_id", ["safe_prompt_boundary_v1"])[0]
            try:
                cases = get_test_cases(pack_id)
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
                return
            self.send_json(200, {"pack_id": pack_id, "cases": cases})
        else:
            self.send_json(404, {"error": "Not found"})

    def log_message(self, format_string, *args):
        return


PORT = int(os.environ.get("PORT", "8100"))
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.daemon_threads = True
print(json.dumps({"service": "bayora-red", "stage": "ready", "port": PORT}), flush=True)
server.serve_forever()
