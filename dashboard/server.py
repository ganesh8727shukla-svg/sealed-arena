
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen
import json
import os

PAGE = b"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SealedArena</title>
<style>
body{font:16px system-ui;max-width:850px;margin:40px auto;padding:0 18px;background:#101827;color:#edf2f7}
h1{color:#7dd3fc}
.card{background:#1e293b;padding:18px;border-radius:12px;margin:16px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere}
</style>
</head>
<body>
<h1>SealedArena</h1>
<p>Local multi-service prototype</p>
<div class="card"><h2>Broker status</h2><pre id="health">Checking...</pre></div>
<div class="card"><h2>Recent events</h2><pre id="events">Loading...</pre></div>
<script>
async function refresh(){
  try {
    const h = await fetch('/api/health');
    document.getElementById('health').textContent =
      JSON.stringify(await h.json(), null, 2);
    const e = await fetch('/api/events');
    document.getElementById('events').textContent =
      JSON.stringify(await e.json(), null, 2);
  } catch(err) {
    document.getElementById('health').textContent = String(err);
  }
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""


BROKER_URL = os.environ.get("BROKER_URL", "http://broker:8000").strip().rstrip("/")
if "://" not in BROKER_URL:
    BROKER_URL = "http://" + BROKER_URL
PORT = int(os.environ.get("PORT", "8081"))


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(PAGE)))
            self.end_headers()
            self.wfile.write(PAGE)
            return

        endpoint = {
            "/api/health": "/health",
            "/api/events": "/events"
        }.get(self.path)

        if endpoint:
            try:
                with urlopen(BROKER_URL + endpoint, timeout=3) as r:
                    body = r.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as error:
                body = json.dumps({"error": str(error)}).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()


server = ThreadingHTTPServer(("0.0.0.0", PORT), DashboardHandler)
print(f"[DASHBOARD] Listening on port {PORT}", flush=True)
server.serve_forever()
