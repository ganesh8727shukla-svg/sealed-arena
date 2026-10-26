"""Compose integration check. Run only after starting the full stack."""

from datetime import datetime, timezone
import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import sys
from pathlib import Path


ROOT = str(Path(__file__).resolve().parents[1])
BROKER = "http://localhost:8000"
DASHBOARD = "http://localhost:8082"


def request_json(url, data=None, headers=None, timeout=5):
    body = None if data is None else json.dumps(data).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="GET" if data is None else "POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def find_event(event_id, query_text):
    query = urllib.parse.urlencode({"q": query_text, "limit": 10})
    result = request_json(BROKER + "/events?" + query)
    return next((item for item in result["events"] if item["id"] == event_id), None)


def wait_until_complete(event_id, query_text, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            event = find_event(event_id, query_text)
            if event and event["status"] in {"completed", "failed"}:
                return event
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    return None


def compose(*args):
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.addon.yml", *args],
        cwd=ROOT,
        check=True,
    )


def main():
    try:
        request_json(BROKER + "/message", {"source": "red"})
    except urllib.error.HTTPError as error:
        if error.code != 400:
            raise AssertionError(f"Invalid event returned HTTP {error.code}, expected 400")
    else:
        raise AssertionError("Invalid event payload was accepted")

    key = "integration-" + str(uuid.uuid4())
    payload = {
        "source": "red",
        "type": "integration-test",
        "message": "SealedArena integration check " + datetime.now(timezone.utc).isoformat(),
    }
    first = request_json(BROKER + "/message", payload, {"Idempotency-Key": key})
    duplicate = request_json(BROKER + "/message", payload, {"Idempotency-Key": key})
    if first["event_id"] != duplicate["event_id"]:
        raise AssertionError("Idempotent duplicate created a second event")

    event_id = first["event_id"]
    event = wait_until_complete(event_id, payload["message"], timeout=90)
    if not event:
        raise AssertionError("Event was not returned by Broker")
    if event["status"] != "completed" or not isinstance(event.get("analysis"), dict):
        raise AssertionError(f"Event did not complete with a stored analysis: {event}")

    dashboard_query = urllib.parse.urlencode({"q": payload["message"], "limit": 10})
    snapshot = request_json(DASHBOARD + "/api/dashboard?" + dashboard_query)
    dashboard_event = next((item for item in snapshot["events"] if item["id"] == event_id), None)
    if not dashboard_event or not dashboard_event.get("analysis"):
        raise AssertionError("Dashboard did not return the event analysis")

    if "--exercise-timeout" in sys.argv:
        timeout_message = "SealedArena timeout recovery check " + str(uuid.uuid4())
        timeout_payload = {"source": "red", "type": "timeout-integration-test", "message": timeout_message}
        subprocess.run(["docker", "pause", "sealed-llm"], check=True)
        timeout_event_id = None
        try:
            submitted = request_json(BROKER + "/message", timeout_payload)
            timeout_event_id = submitted["event_id"]
            deadline = time.time() + 50
            timed_out = None
            while time.time() < deadline:
                timed_out = find_event(timeout_event_id, timeout_message)
                if timed_out and timed_out.get("attempts", 0) >= 1 and timed_out["status"] == "pending":
                    break
                time.sleep(1)
            if not timed_out or timed_out.get("attempts", 0) < 1 or timed_out["status"] != "pending":
                raise AssertionError("A timed-out LLM request was not scheduled for retry")
        finally:
            subprocess.run(["docker", "unpause", "sealed-llm"], check=True)
        recovered = wait_until_complete(timeout_event_id, timeout_message, timeout=60)
        if not recovered or recovered["status"] != "completed" or not recovered.get("analysis"):
            raise AssertionError("Event did not complete after the timed-out LLM recovered")
        print("PASS: LLM request timeout was retried and completed after recovery")

    if "--restart-broker" in sys.argv:
        compose("restart", "broker")
        deadline = time.time() + 60
        persisted = None
        while time.time() < deadline:
            try:
                persisted = find_event(event_id, payload["message"])
                if persisted:
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(2)
        if not persisted or persisted.get("status") != "completed" or not persisted.get("analysis"):
            raise AssertionError("Event and analysis did not survive Broker restart")

    if "--restart-postgres" in sys.argv:
        compose("restart", "postgres")
        persisted = wait_until_complete(event_id, payload["message"], timeout=60)
        if not persisted or persisted.get("status") != "completed" or not persisted.get("analysis"):
            raise AssertionError("Event and analysis did not survive PostgreSQL restart")
        print("PASS: stored event and analysis survived PostgreSQL restart")

    print(f"PASS: event #{event_id} is idempotent, analyzed, and visible in the dashboard")
    if "--restart-broker" in sys.argv:
        print("PASS: stored event and analysis survived Broker restart")


if __name__ == "__main__":
    main()
