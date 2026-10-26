"""Shared validation rules for Broker event and analysis records."""

from datetime import datetime, timezone
import math


ALLOWED_SEVERITIES = {"informational", "low", "medium", "high", "critical", "unknown"}
ALLOWED_STATUSES = {"pending", "processing", "completed", "failed"}
MAX_SOURCE_LENGTH = 64
MAX_TYPE_LENGTH = 64
MAX_EXPLANATION_LENGTH = 4000
MAX_RECOMMENDATION_LENGTH = 2000


def validate_event_payload(payload):
    if not isinstance(payload, dict):
        raise ValueError("event payload must be a JSON object")

    source = payload.get("source")
    event_type = payload.get("type")
    if not isinstance(source, str) or not source.strip() or len(source) > MAX_SOURCE_LENGTH:
        raise ValueError("source must be a non-empty string of at most 64 characters")
    if not isinstance(event_type, str) or not event_type.strip() or len(event_type) > MAX_TYPE_LENGTH:
        raise ValueError("type must be a non-empty string of at most 64 characters")
    if "message" in payload and not isinstance(payload["message"], str):
        raise ValueError("message must be a string when provided")
    if isinstance(payload.get("message"), str) and len(payload["message"]) > 32768:
        raise ValueError("message must be at most 32768 characters")
    return payload


def normalize_analysis(value, provider_default="mock", model_default="fake-llm"):
    if not isinstance(value, dict):
        raise ValueError("analysis must be a JSON object")

    severity = value.get("severity", "unknown")
    if not isinstance(severity, str) or severity.lower() not in ALLOWED_SEVERITIES:
        raise ValueError("severity must be informational, low, medium, high, critical, or unknown")

    explanation = value.get("explanation")
    recommendation = value.get("recommendation")
    if not isinstance(explanation, str) or not explanation.strip() or len(explanation) > MAX_EXPLANATION_LENGTH:
        raise ValueError("explanation must be a non-empty string of at most 4000 characters")
    if not isinstance(recommendation, str) or not recommendation.strip() or len(recommendation) > MAX_RECOMMENDATION_LENGTH:
        raise ValueError("recommendation must be a non-empty string of at most 2000 characters")

    confidence = value.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("confidence must be a number from 0 to 1 or null")
        confidence = float(confidence)
        if not math.isfinite(confidence) or confidence < 0 or confidence > 1:
            raise ValueError("confidence must be a number from 0 to 1 or null")

    provider = value.get("provider", provider_default)
    model = value.get("model", model_default)
    prompt_version = value.get("prompt_version", "sealedarena-analysis-v1")
    for name, field, maximum in (
        ("provider", provider, 100),
        ("model", model, 200),
        ("prompt_version", prompt_version, 100),
    ):
        if not isinstance(field, str) or not field.strip() or len(field) > maximum:
            raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters")

    analyzed_at = value.get("analyzed_at")
    if analyzed_at is None:
        analyzed_at = datetime.now(timezone.utc).isoformat()
    elif isinstance(analyzed_at, str):
        try:
            parsed = datetime.fromisoformat(analyzed_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("analyzed_at must be an ISO 8601 timestamp") from error
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        analyzed_at = parsed.astimezone(timezone.utc).isoformat()
    else:
        raise ValueError("analyzed_at must be an ISO 8601 timestamp")

    return {
        "provider": provider.strip(),
        "model": model.strip(),
        "severity": severity.lower(),
        "explanation": explanation.strip(),
        "confidence": confidence,
        "recommendation": recommendation.strip(),
        "prompt_version": prompt_version.strip(),
        "analyzed_at": analyzed_at,
    }


def retry_delay_seconds(attempt):
    """Bounded exponential backoff: 5, 10, 20... up to 300 seconds."""
    attempt = max(1, int(attempt))
    return min(5 * (2 ** (attempt - 1)), 300)
