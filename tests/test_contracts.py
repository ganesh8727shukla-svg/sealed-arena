import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "broker"))

from contracts import normalize_analysis, retry_delay_seconds, validate_event_payload


class EventContractTests(unittest.TestCase):
    def test_accepts_existing_red_payload_shape(self):
        payload = {"source": "red", "type": "test", "message": "hello"}
        self.assertIs(validate_event_payload(payload), payload)

    def test_rejects_missing_source_or_type(self):
        with self.assertRaises(ValueError):
            validate_event_payload({"type": "test"})
        with self.assertRaises(ValueError):
            validate_event_payload({"source": "red"})

    def test_rejects_non_string_message(self):
        with self.assertRaises(ValueError):
            validate_event_payload({"source": "red", "type": "test", "message": 12})


class AnalysisContractTests(unittest.TestCase):
    def valid_result(self):
        return {
            "severity": "medium",
            "explanation": "A test event was received.",
            "confidence": 0.7,
            "recommendation": "Review the event manually.",
        }

    def test_normalizes_analysis_fields(self):
        result = normalize_analysis(self.valid_result(), "mock", "fake-llm")
        self.assertEqual(result["severity"], "medium")
        self.assertEqual(result["provider"], "mock")
        self.assertTrue(result["analyzed_at"].endswith("+00:00"))

    def test_rejects_invalid_severity_and_confidence(self):
        value = self.valid_result()
        value["severity"] = "urgent"
        with self.assertRaises(ValueError):
            normalize_analysis(value)
        value = self.valid_result()
        value["confidence"] = 1.2
        with self.assertRaises(ValueError):
            normalize_analysis(value)

    def test_retry_backoff_is_bounded(self):
        self.assertEqual(retry_delay_seconds(1), 5)
        self.assertEqual(retry_delay_seconds(2), 10)
        self.assertEqual(retry_delay_seconds(3), 20)
        self.assertEqual(retry_delay_seconds(99), 300)


if __name__ == "__main__":
    unittest.main()
