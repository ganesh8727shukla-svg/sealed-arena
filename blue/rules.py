"""Small, deterministic rules for the synthetic SealedArena scenarios."""

import re


BRUTE_FORCE_THRESHOLD = 5
CORRELATION_WINDOW_SECONDS = 600


def evaluate_detections(payload, context_events):
    """Evaluate structured fields and return findings with event-linked evidence."""
    event_type = payload.get("event_type")
    detections = []

    if event_type == "authentication.login_failed":
        actor = payload.get("actor_user")
        source_ip = payload.get("source_ip")
        matching = [
            event for event in context_events
            if isinstance(event, dict)
            and isinstance(event.get("payload"), dict)
            and event["payload"].get("event_type") == "authentication.login_failed"
            and event["payload"].get("actor_user") == actor
            and event["payload"].get("source_ip") == source_ip
        ]
        if len(matching) >= BRUTE_FORCE_THRESHOLD:
            evidence = [
                {
                    "event_id": event.get("id"),
                    "field": "attempt_number",
                    "value": str(event["payload"].get("attempt_number", "not supplied")),
                }
                for event in matching[:20]
            ]
            detections.append({
                "rule_id": "auth.repeated_login_failures",
                "title": "Repeated sign-in failures",
                "severity": "high",
                "summary": (
                    f"{len(matching)} failed sign-ins for the same account and source address "
                    f"were received within {CORRELATION_WINDOW_SECONDS // 60} minutes."
                ),
                "window_seconds": CORRELATION_WINDOW_SECONDS,
                "evidence": evidence,
            })

    if event_type == "authentication.login_success" and payload.get("new_location") is True:
        detections.append({
            "rule_id": "auth.success_from_new_location",
            "title": "Successful sign-in from a new location",
            "severity": "medium",
            "summary": "The sign-in succeeded and the source marked its location as new for this account.",
            "window_seconds": 0,
            "evidence": [
                {"event_id": payload.get("id"), "field": "event_type", "value": event_type},
                {"event_id": payload.get("id"), "field": "new_location", "value": "true"},
            ],
        })

    parent = payload.get("parent_process")
    if (event_type == "process.execution" and payload.get("signed") is False
            and isinstance(parent, str) and parent.lower() in {"word", "excel", "powerpoint", "libreoffice"}):
        detections.append({
            "rule_id": "endpoint.unsigned_document_child",
            "title": "Unsigned process started by a document application",
            "severity": "high",
            "summary": "An unsigned process was reported as a child of a document application.",
            "window_seconds": 0,
            "evidence": [
                {"event_id": payload.get("id"), "field": "event_type", "value": event_type},
                {"event_id": payload.get("id"), "field": "parent_process", "value": parent},
                {"event_id": payload.get("id"), "field": "signed", "value": "false"},
            ],
        })
    return detections


def build_analysis(detections, model_result, model_available=True):
    """Keep rules authoritative while allowing the LLM advisory to be optional."""
    if detections:
        analysis = dict(model_result)
        analysis["severity"] = max(
            detections,
            key=lambda item: {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[item["severity"]],
        )["severity"]
        analysis["explanation"] = " ".join(item["summary"] for item in detections)
        analysis["recommendation"] = (
            "Review the linked synthetic events and validate them with the relevant owner. "
            "No response action is performed automatically."
        )
        analysis["ai_summary"] = model_result.get("explanation", "") if model_available else ""
        analysis["ai_recommendation"] = model_result.get("recommendation", "") if model_available else ""
        analysis["ai_suggested_severity"] = model_result.get("severity", "unknown")
        analysis["analysis_mode"] = (
            "rules+" + str(model_result.get("provider", "model")) if model_available else "rules-only"
        )
        analysis["detections"] = detections
        return analysis

    analysis = dict(model_result)
    analysis["explanation"] = (
        model_result.get("explanation", "") if model_available
        else "No deterministic detection rule matched. Review the event manually."
    )
    analysis["ai_suggested_severity"] = model_result.get("severity", "unknown")
    analysis["severity"] = "unknown"
    analysis["recommendation"] = (
        "No deterministic detection rule matched. Review the event manually; any model suggestion is unverified."
    )
    analysis["analysis_mode"] = str(model_result.get("provider", "model")) if model_available else "rules-only"
    analysis["detections"] = []
    analysis["ai_summary"] = model_result.get("explanation", "") if model_available else ""
    analysis["ai_recommendation"] = model_result.get("recommendation", "") if model_available else ""
    return analysis


_PRIVATE_KEY_PARTS = (
    "password", "secret", "token", "api_key", "authorization", "cookie",
    "email", "phone", "address", "source_ip", "actor_user", "username",
    "account", "device_id", "hostname",
)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key|authorization)\b(\s*[:=]\s*)[^\s,;]+"
)


def sanitize_for_llm(value):
    """Redact common credentials and identifiers before sending event data out."""
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(part in key_text for part in _PRIVATE_KEY_PARTS):
                result[key] = "[REDACTED]"
            else:
                result[key] = sanitize_for_llm(item)
        return result
    if isinstance(value, list):
        return [sanitize_for_llm(item) for item in value]
    if isinstance(value, str):
        value = _EMAIL.sub("[REDACTED_EMAIL]", value)
        return _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
    return value
