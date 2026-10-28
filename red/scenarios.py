"""Deterministic, synthetic security telemetry scenarios for local practice."""

from datetime import datetime, timedelta, timezone


_SCENARIOS = (
    {
        "id": "normal_login",
        "title": "Normal sign-in",
        "description": "A routine sign-in that should not create an incident.",
        "events": 1,
    },
    {
        "id": "brute_force_login",
        "title": "Repeated sign-in failures",
        "description": "Five failed sign-ins from one address in a short window.",
        "events": 5,
    },
    {
        "id": "unusual_location",
        "title": "Sign-in from a new location",
        "description": "A successful sign-in marked as coming from a new location.",
        "events": 1,
    },
    {
        "id": "suspicious_process",
        "title": "Unsigned process from a document app",
        "description": "Synthetic process telemetry with an unsigned child process.",
        "events": 1,
    },
)


def list_scenarios():
    return [dict(item) for item in _SCENARIOS]


def generate_scenario_events(scenario_id, run_id, started_at=None):
    """Return safe synthetic event payloads; no attack code or real targets."""
    if scenario_id not in {item["id"] for item in _SCENARIOS}:
        raise ValueError("Unknown scenario")
    started_at = started_at or datetime.now(timezone.utc)
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)

    common = {
        "source": "red",
        "type": "security_telemetry",
        "schema_version": "1.0",
        "scenario_key": scenario_id,
        "scenario_run_id": run_id,
    }

    if scenario_id == "normal_login":
        records = [{
            "event_type": "authentication.login_success",
            "actor_user": "alex.morgan",
            "source_ip": "203.0.113.10",
            "device_id": "demo-laptop-01",
            "new_location": False,
            "message": "Routine sign-in from a known location.",
        }]
    elif scenario_id == "brute_force_login":
        records = [
            {
                "event_type": "authentication.login_failed",
                "actor_user": "jordan.lee",
                "source_ip": "198.51.100.77",
                "device_id": "demo-laptop-02",
                "attempt_number": attempt,
                "message": f"Synthetic failed sign-in attempt {attempt}.",
            }
            for attempt in range(1, 6)
        ]
    elif scenario_id == "unusual_location":
        records = [{
            "event_type": "authentication.login_success",
            "actor_user": "sam.taylor",
            "source_ip": "203.0.113.88",
            "device_id": "demo-laptop-03",
            "new_location": True,
            "message": "Successful sign-in from a location not seen in this demo profile.",
        }]
    else:
        records = [{
            "event_type": "process.execution",
            "actor_user": "alex.morgan",
            "source_ip": "203.0.113.10",
            "device_id": "demo-laptop-01",
            "process_name": "invoice_viewer_demo.exe",
            "parent_process": "word",
            "signed": False,
            "message": "Synthetic unsigned child process event for analyst training.",
        }]

    payloads = []
    for index, record in enumerate(records):
        payload = {
            **common,
            "occurred_at": (started_at + timedelta(seconds=index)).isoformat(),
            **record,
        }
        payloads.append(payload)
    return payloads
