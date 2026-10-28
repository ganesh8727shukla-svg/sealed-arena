"""Independent local checkpoint witness for Bayora's append-only event chain."""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import hmac
import json
import os
import sqlite3
import threading

from audit import GENESIS_HASH, hash_entry


DB_PATH = os.environ.get("WITNESS_DB_PATH", "/data/witness.sqlite3")
INGEST_TOKEN = os.environ.get("BAYORA_WITNESS_TOKEN", "local-witness-ingest-token")
ALLOWED_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.environ.get(
        "BAYORA_ALLOWED_ORIGINS",
        "http://localhost:8083,http://127.0.0.1:8083",
    ).split(",")
    if origin.strip()
}
DB_LOCK = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    connection = connect_db()
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS checkpoint_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                sequence INTEGER NOT NULL,
                root_hash TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT OR IGNORE INTO checkpoint_state VALUES (1,0,?,?)",
            (GENESIS_HASH, now_iso()),
        )
        connection.commit()
    finally:
        connection.close()


def read_checkpoint():
    connection = connect_db()
    try:
        row = connection.execute("SELECT * FROM checkpoint_state WHERE singleton=1").fetchone()
    finally:
        connection.close()
    return {"sequence": row["sequence"], "root_hash": row["root_hash"], "updated_at": row["updated_at"]}


def advance(entries):
    if not isinstance(entries, list) or len(entries) > 5000:
        raise ValueError("entries must be a list of at most 5000 records")
    with DB_LOCK:
        connection = connect_db()
        try:
            connection.execute("BEGIN IMMEDIATE")
            state = connection.execute(
                "SELECT sequence,root_hash FROM checkpoint_state WHERE singleton=1"
            ).fetchone()
            sequence = state["sequence"]
            root_hash = state["root_hash"]
            for entry in entries:
                expected_sequence = sequence + 1
                if not isinstance(entry, dict) or entry.get("sequence") != expected_sequence:
                    raise ValueError("checkpoint sequence is not contiguous")
                if entry.get("previous_hash") != root_hash:
                    raise ValueError("checkpoint does not extend the witnessed root")
                expected_hash = hash_entry(root_hash, entry.get("body"))
                if entry.get("entry_hash") != expected_hash:
                    raise ValueError("event hash does not match its body")
                sequence = expected_sequence
                root_hash = expected_hash
            if sequence != state["sequence"]:
                connection.execute(
                    "UPDATE checkpoint_state SET sequence=?,root_hash=?,updated_at=? WHERE singleton=1",
                    (sequence, root_hash, now_iso()),
                )
            connection.commit()
            return read_checkpoint()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status, value):
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        self.send_response(204)
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Vary", "Origin")
        self.end_headers()

    def do_GET(self):
        if self.path in {"/health", "/ready"}:
            self.send_json(200, {"service": "bayora-witness", "status": "healthy"})
        elif self.path in {"/head", "/checkpoint"}:
            self.send_json(200, {"service": "bayora-witness", **read_checkpoint()})
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        if self.path != "/checkpoint":
            self.send_json(404, {"error": "Not found"})
            return
        supplied = self.headers.get("X-Bayora-Witness-Token", "")
        if not hmac.compare_digest(supplied, INGEST_TOKEN):
            self.send_json(403, {"error": "Checkpoint ingestion is restricted to the controller"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                self.send_json(400, {"error": "Invalid body size"})
                return
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                self.send_json(400, {"error": "JSON object required"})
                return
            checkpoint = advance(body.get("entries"))
            self.send_json(200, {"service": "bayora-witness", **checkpoint})
        except (ValueError, json.JSONDecodeError) as error:
            self.send_json(409, {"error": str(error)})

    def log_message(self, format_string, *args):
        return


initialize_db()
PORT = int(os.environ.get("PORT", "8100"))
server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
server.daemon_threads = True
print(json.dumps({"service": "bayora-witness", "stage": "ready", "port": PORT}), flush=True)
server.serve_forever()
