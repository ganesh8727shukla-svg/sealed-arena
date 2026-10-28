"""Shared validation rules for Broker event and analysis records."""

from datetime import datetime, timezone
import math


ALLOWED_SEVERITIES = {"informational", "low", "medium", "high", "critical", "unknown"}
ALLOWED_STATUSES = {"pending", "processing", "completed", "failed"}
ALLOWED_CASE_STATUSES = {"new", "investigating", "resolved"}
ALLOWED_CASE_VERDICTS = {"unreviewed", "true_positive", "false_positive", "needs_more_info"}
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
    for name, maximum in (("scenario_run_id", 64), ("scenario_key", 64), ("event_type", 128),
                          ("schema_version", 32)):
        value = payload.get(name)
        if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > maximum):
            raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters")
    occurred_at = payload.get("occurred_at")
    if occurred_at is not None:
        if not isinstance(occurred_at, str):
            raise ValueError("occurred_at must be an ISO 8601 timestamp")
        try:
            parsed = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("occurred_at must be an ISO 8601 timestamp") from error
        if parsed.tzinfo is None:
            raise ValueError("occurred_at must include a timezone")
    return payload


def normalize_detections(value):
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError("detections must be a list of at most 20 items")
    detections = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("each detection must be a JSON object")
        rule_id = item.get("rule_id")
        title = item.get("title")
        severity = item.get("severity")
        summary = item.get("summary")
        if not isinstance(rule_id, str) or not rule_id.strip() or len(rule_id) > 100:
            raise ValueError("detection rule_id must be a non-empty string of at most 100 characters")
        if not isinstance(title, str) or not title.strip() or len(title) > 200:
            raise ValueError("detection title must be a non-empty string of at most 200 characters")
        if not isinstance(severity, str) or severity.lower() not in ALLOWED_SEVERITIES - {"unknown"}:
            raise ValueError("detection severity must be informational, low, medium, high, or critical")
        if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_EXPLANATION_LENGTH:
            raise ValueError("detection summary must be a non-empty string of at most 4000 characters")
        window_seconds = item.get("window_seconds", 0)
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or not 0 <= window_seconds <= 86400:
            raise ValueError("detection window_seconds must be an integer from 0 to 86400")
        evidence = item.get("evidence", [])
        if not isinstance(evidence, list) or len(evidence) > 50:
            raise ValueError("detection evidence must be a list of at most 50 items")
        normalized_evidence = []
        for entry in evidence:
            if not isinstance(entry, dict):
                raise ValueError("each evidence item must be a JSON object")
            event_id = entry.get("event_id")
            field = entry.get("field")
            value_text = entry.get("value")
            if event_id is not None and (isinstance(event_id, bool) or not isinstance(event_id, int) or event_id < 1):
                raise ValueError("evidence event_id must be a positive integer or null")
            if not isinstance(field, str) or not field.strip() or len(field) > 100:
                raise ValueError("evidence field must be a non-empty string of at most 100 characters")
            if not isinstance(value_text, str) or len(value_text) > 500:
                raise ValueError("evidence value must be a string of at most 500 characters")
            normalized_evidence.append({"event_id": event_id, "field": field.strip(), "value": value_text})
        detections.append({
            "rule_id": rule_id.strip(),
            "title": title.strip(),
            "severity": severity.lower(),
            "summary": summary.strip(),
            "window_seconds": window_seconds,
            "evidence": normalized_evidence,
        })
    return detections


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

    analysis_mode = value.get("analysis_mode", "llm")
    if not isinstance(analysis_mode, str) or not analysis_mode.strip() or len(analysis_mode) > 100:
        raise ValueError("analysis_mode must be a non-empty string of at most 100 characters")
    ai_summary = value.get("ai_summary", "")
    ai_recommendation = value.get("ai_recommendation", "")
    if not isinstance(ai_summary, str) or len(ai_summary) > MAX_EXPLANATION_LENGTH:
        raise ValueError("ai_summary must be a string of at most 4000 characters")
    if not isinstance(ai_recommendation, str) or len(ai_recommendation) > MAX_RECOMMENDATION_LENGTH:
        raise ValueError("ai_recommendation must be a string of at most 2000 characters")
    ai_suggested_severity = value.get("ai_suggested_severity", "unknown")
    if not isinstance(ai_suggested_severity, str) or ai_suggested_severity.lower() not in ALLOWED_SEVERITIES:
        raise ValueError("ai_suggested_severity must be a supported severity")

    return {
        "provider": provider.strip(),
        "model": model.strip(),
        "severity": severity.lower(),
        "explanation": explanation.strip(),
        "confidence": confidence,
        "recommendation": recommendation.strip(),
        "prompt_version": prompt_version.strip(),
        "analyzed_at": analyzed_at,
        "analysis_mode": analysis_mode.strip(),
        "detections": normalize_detections(value.get("detections")),
        "ai_summary": ai_summary,
        "ai_recommendation": ai_recommendation,
        "ai_suggested_severity": ai_suggested_severity.lower(),
    }


def retry_delay_seconds(attempt):
    """Bounded exponential backoff: 5, 10, 20... up to 300 seconds."""
    attempt = max(1, int(attempt))
    return min(5 * (2 ** (attempt - 1)), 300)
