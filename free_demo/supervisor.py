"""Run the synthetic SealedArena + Bayora preview in one Render free web service."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_PORT = int(os.environ.get("PORT", "10000"))
SOC_BASE = "http://127.0.0.1:8082"
BAYORA_BASE = "http://127.0.0.1:8083"
SHUTDOWN = Event()
CHILDREN = []


def child_environment(overrides=None):
    result = os.environ.copy()
    result.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"})
    if overrides:
        result.update({key: str(value) for key, value in overrides.items()})
    return result


def start_child(name, directory, script, overrides=None):
    process = subprocess.Popen(
        [sys.executable, "-u", script],
        cwd=ROOT / directory,
        env=child_environment(overrides),
    )
    CHILDREN.append((name, process))
    print(json.dumps({"service": "free-demo", "stage": "child_started", "name": name, "pid": process.pid}), flush=True)
    return process


def wait_for_database(timeout=75):
    host = os.environ.get("DB_HOST", "").strip()
    if not host:
        raise RuntimeError("Render Postgres host is required for the free demo")
    port = int(os.environ.get("DB_PORT", "5432"))
    end = time.monotonic() + timeout
    while time.monotonic() < end and not SHUTDOWN.is_set():
        try:
            with socket.create_connection((host, port), timeout=2):
                print(json.dumps({"service": "free-demo", "stage": "database_reachable"}), flush=True)
                return
        except OSError:
            time.sleep(2)
    raise RuntimeError("Render Postgres did not become reachable before startup timed out")


def boot_services():
    wait_for_database()
    broker_env = {
        "SCHEMA_FILE": str(ROOT / "schema.sql"),
        "LEGACY_EVENTS_FILE": str(ROOT / "legacy_events.json"),
    }
    start_child("broker", "broker", "server.py", broker_env)
    start_child("llm", "llm", "server.py", {"PORT": 8001, "LLM_PROVIDER": "mock"})
    start_child("red", "red", "server.py", {"BROKER_URL": "http://127.0.0.1:8000"})
    start_child("blue", "blue", "server.py", {
        "BROKER_URL": "http://127.0.0.1:8000", "LLM_URL": "http://127.0.0.1:8001",
    })
    start_child("dashboard", "dashboard", "server.py", {
        "PORT": 8081, "BROKER_URL": "http://127.0.0.1:8000",
    })
    start_child("soc-dashboard", "dashboard_addon", "server.py", {
        "PORT": 8082,
        "BROKER_URL": "http://127.0.0.1:8000",
        "RED_URL": "http://127.0.0.1:8003",
        "BLUE_URL": "http://127.0.0.1:8002",
        "LLM_URL": "http://127.0.0.1:8001",
        "DASHBOARD_URL": "http://127.0.0.1:8081",
        "BAYORA_PUBLIC_URL": "",
    })

    blue_token = secrets.token_urlsafe(32)
    witness_token = secrets.token_urlsafe(32)
    bayora_workers = [
        ("bayora-red", "bayora/red", "server.py", {"PORT": 8101}),
        ("bayora-model", "bayora/model", "server.py", {"PORT": 8102, "BAYORA_MODEL_PROVIDER": "mock"}),
        ("bayora-blue", "bayora/blue", "server.py", {"PORT": 8103, "BAYORA_BLUE_INTERNAL_TOKEN": blue_token}),
        ("bayora-witness", "bayora/witness", "server.py", {
            "PORT": 8104, "WITNESS_DB_PATH": "/data/witness.sqlite3",
            "BAYORA_WITNESS_TOKEN": witness_token,
        }),
    ]
    for name, directory, script, overrides in bayora_workers:
        start_child(name, directory, script, overrides)
    start_child("bayora-controller", "bayora/controller", "server.py", {
        "PORT": 8083,
        "BAYORA_DB_PATH": "/data/bayora.sqlite3",
        "BAYORA_RED_URL": "http://127.0.0.1:8101",
        "BAYORA_MODEL_URL": "http://127.0.0.1:8102",
        "BAYORA_BLUE_URL": "http://127.0.0.1:8103",
        "BAYORA_WITNESS_URL": "http://127.0.0.1:8104",
        "BAYORA_BLUE_INTERNAL_TOKEN": blue_token,
        "BAYORA_WITNESS_TOKEN": witness_token,
        "SEALED_ARENA_PUBLIC_URL": "/soc",
    })


def service_json(url, timeout=2):
    with urlopen(url, timeout=timeout) as response:
        return json.loads(response.read(65537).decode("utf-8"))


def route_target(request_target):
    """Map /soc routes to the SOC app and all other app routes to Bayora."""
    parts = urlsplit(request_target)
    if parts.path == "/soc":
        backend_path = "/"
        service = SOC_BASE
    elif parts.path.startswith("/soc/"):
        backend_path = parts.path[4:]
        service = SOC_BASE
    else:
        backend_path = parts.path or "/"
        service = BAYORA_BASE
    if parts.query:
        backend_path += "?" + parts.query
    return service, backend_path, service == SOC_BASE and backend_path.split("?", 1)[0] == "/"


def rewrite_soc_home(content):
    return content.replace(b"fetch('/api/", b"fetch('/soc/api/")


class PublicHandler(BaseHTTPRequestHandler):
    def reply_json(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/health":
            self.reply_json(200, {"service": "sealedarena-free-demo", "status": "healthy"})
            return
        if path == "/ready":
            try:
                bayora = service_json(BAYORA_BASE + "/ready")
                soc = service_json(SOC_BASE + "/ready", timeout=5)
                ready = bayora.get("status") == "healthy" and soc.get("status") == "healthy"
                self.reply_json(200 if ready else 503, {
                    "service": "sealedarena-free-demo",
                    "status": "healthy" if ready else "unavailable",
                    "bayora": bayora,
                    "soc": soc,
                })
            except (OSError, URLError, ValueError, json.JSONDecodeError):
                self.reply_json(503, {"service": "sealedarena-free-demo", "status": "starting"})
            return
        self.proxy("GET")

    def do_POST(self):
        self.proxy("POST")

    def proxy(self, method):
        base, backend_path, is_soc_home = route_target(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_048_576:
            self.reply_json(413, {"error": "Request body is too large"})
            return
        body = self.rfile.read(length) if method == "POST" and length else None
        headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in {"host", "content-length", "connection", "accept-encoding"}
        }
        request = Request(base + backend_path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=60) as response:
                status = response.status
                content_type = response.headers.get("Content-Type", "application/octet-stream")
                cache_control = response.headers.get("Cache-Control", "no-store")
                www_authenticate = response.headers.get("WWW-Authenticate")
                content = response.read(4_194_305)
        except HTTPError as error:
            status = error.code
            content_type = error.headers.get("Content-Type", "application/json; charset=utf-8")
            cache_control = error.headers.get("Cache-Control", "no-store")
            www_authenticate = error.headers.get("WWW-Authenticate")
            content = error.read(4_194_305)
        except (URLError, TimeoutError, OSError):
            self.reply_json(503, {"error": "The demo service is starting or unavailable"})
            return
        if len(content) > 4_194_304:
            self.reply_json(502, {"error": "The demo response is too large"})
            return
        if is_soc_home and content_type.startswith("text/html"):
            content = rewrite_soc_home(content)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", cache_control)
        if www_authenticate:
            self.send_header("WWW-Authenticate", www_authenticate)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format_string, *args):
        print(json.dumps({
            "service": "free-demo", "stage": "http_request",
            "route": urlsplit(self.path).path,
        }), flush=True)


def stop_children():
    for _, process in CHILDREN:
        if process.poll() is None:
            process.terminate()
    for _, process in CHILDREN:
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()


def main():
    boot_services()
    server = ThreadingHTTPServer(("0.0.0.0", PUBLIC_PORT), PublicHandler)
    server.daemon_threads = True
    server.timeout = 0.5
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: SHUTDOWN.set())
    print(json.dumps({"service": "free-demo", "stage": "ready", "port": PUBLIC_PORT}), flush=True)
    failed = False
    try:
        while not SHUTDOWN.wait(1):
            stopped = [(name, process.returncode) for name, process in CHILDREN if process.poll() is not None]
            if stopped:
                print(json.dumps({"service": "free-demo", "stage": "child_exited", "children": stopped}), flush=True)
                failed = True
                break
            server.handle_request()
    finally:
        server.server_close()
        stop_children()
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
