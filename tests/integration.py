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


def wait_for_scenario(run_id, expected_count=5, timeout=90):
    deadline = time.time() + timeout
    query = urllib.parse.urlencode({"scenario_run_id": run_id, "limit": 100})
    while time.time() < deadline:
        try:
            result = request_json(BROKER + "/events?" + query)
            events = result.get("events", [])
            if len(events) == expected_count and all(event["status"] == "completed" for event in events):
                return events
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    return None


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

    other_source_payload = {
        "source": "demo-sensor",
        "type": "health_check",
        "message": "Non-Red event-source processing check " + str(uuid.uuid4()),
    }
    other_source = request_json(BROKER + "/message", other_source_payload)
    other_source_event = wait_until_complete(other_source["event_id"], other_source_payload["message"], timeout=60)
    if not other_source_event or other_source_event["status"] != "completed":
        raise AssertionError("Broker did not dispatch an event from a non-Red source")

    scenario = request_json(
        DASHBOARD + "/api/scenarios/run", {"scenario_id": "brute_force_login"}, timeout=15
    )
    scenario_events = wait_for_scenario(scenario["run_id"], timeout=90)
    if not scenario_events:
        raise AssertionError("Synthetic sign-in scenario did not finish processing")
    if not all(
        any(item.get("rule_id") == "auth.repeated_login_failures"
            for item in (event.get("analysis") or {}).get("detections", []))
        for event in scenario_events
    ):
        raise AssertionError("Brute-force scenario did not produce the expected evidence-based finding")

    scenario_query = urllib.parse.urlencode({"scenario_run_id": scenario["run_id"], "limit": 20})
    scenario_dashboard = request_json(DASHBOARD + "/api/dashboard?" + scenario_query)
    if len(scenario_dashboard.get("events", [])) != 5:
        raise AssertionError("Dashboard did not show all events for the scenario run")
    if not any(item.get("case_key") == f"run:{scenario['run_id']}:auth.repeated_login_failures"
               for item in scenario_dashboard.get("cases", [])):
        raise AssertionError("Dashboard did not show the generated analyst case")

    cases = request_json(BROKER + "/cases?limit=100").get("cases", [])
    case = next((item for item in cases if item["case_key"] == f"run:{scenario['run_id']}:auth.repeated_login_failures"), None)
    if not case or case["event_count"] != 5:
        raise AssertionError("Detection case did not link all five scenario events")
    updated_case = request_json(DASHBOARD + "/api/cases/update", {
        "case_id": case["id"],
        "status": "investigating",
        "verdict": "true_positive",
        "assigned_to": "integration-test",
        "note": "Integration workflow check",
    })
    if updated_case["status"] != "investigating" or updated_case["verdict"] != "true_positive":
        raise AssertionError("Analyst case update was not persisted")
    if not any(item["action"] == "note_added" for item in updated_case["activity"]):
        raise AssertionError("Case note was not recorded in the activity history")

    normal_scenario = request_json(
        DASHBOARD + "/api/scenarios/run", {"scenario_id": "normal_login"}, timeout=15
    )
    normal_events = wait_for_scenario(normal_scenario["run_id"], expected_count=1, timeout=90)
    if not normal_events or (normal_events[0].get("analysis") or {}).get("detections") != []:
        raise AssertionError("Normal sign-in scenario did not complete without a detection")
    normal_cases = request_json(BROKER + "/cases?limit=100&q=" + normal_scenario["run_id"])
    if normal_cases.get("cases"):
        raise AssertionError("Normal sign-in scenario unexpectedly created an analyst case")

    if "--exercise-timeout" in sys.argv:
        timeout_message = "SealedArena timeout recovery check " + str(uuid.uuid4())
        timeout_payload = {"source": "red", "type": "timeout-integration-test", "message": timeout_message}
        subprocess.run(["docker", "pause", "sealed-llm"], check=True)
        timeout_event_id = None
        try:
            submitted = request_json(BROKER + "/message", timeout_payload)
            timeout_event_id = submitted["event_id"]
            deadline = time.time() + 65
            timed_out = None
            while time.time() < deadline:
                timed_out = find_event(timeout_event_id, timeout_message)
                if timed_out and timed_out["status"] in {"completed", "failed"}:
                    break
                time.sleep(1)
            if (not timed_out or timed_out["status"] != "completed"
                    or (timed_out.get("analysis") or {}).get("analysis_mode") != "rules-only"):
                raise AssertionError("A timed-out LLM request blocked deterministic event processing")
        finally:
            subprocess.run(["docker", "unpause", "sealed-llm"], check=True)
        print("PASS: event completed with rules-only analysis while the LLM was unavailable")

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
    print(f"PASS: event #{other_source['event_id']} from a non-Red source was processed")
    print(f"PASS: scenario run {scenario['run_id']} created an evidence-linked analyst case")
    print(f"PASS: case #{case['id']} review, verdict, assignment, and note were recorded")
    print(f"PASS: normal scenario {normal_scenario['run_id']} completed without creating a case")
    if "--restart-broker" in sys.argv:
        print("PASS: stored event and analysis survived Broker restart")


if __name__ == "__main__":
    main()
