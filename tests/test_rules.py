import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "blue"))

from rules import build_analysis, evaluate_detections, sanitize_for_llm


class DetectionRuleTests(unittest.TestCase):
    def failed_login(self, event_id, actor="jordan.lee", source_ip="198.51.100.77"):
        return {
            "id": event_id,
            "payload": {
                "event_type": "authentication.login_failed",
                "actor_user": actor,
                "source_ip": source_ip,
            },
        }

    def test_brute_force_rule_requires_five_matching_events_and_includes_evidence(self):
        events = [self.failed_login(event_id) for event_id in range(1, 6)]
        findings = evaluate_detections(events[-1]["payload"], events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "auth.repeated_login_failures")
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual([item["event_id"] for item in findings[0]["evidence"]], [1, 2, 3, 4, 5])
        self.assertEqual(evaluate_detections(events[0]["payload"], events[:4]), [])

    def test_brute_force_does_not_combine_different_accounts_or_addresses(self):
        target = self.failed_login(1)
        unrelated = [self.failed_login(index, actor=f"user{index}") for index in range(2, 8)]
        self.assertEqual(evaluate_detections(target["payload"], [target, *unrelated]), [])

    def test_normal_sign_in_does_not_create_a_detection(self):
        event = {"event_type": "authentication.login_success", "new_location": False}
        self.assertEqual(evaluate_detections(event, []), [])

    def test_unusual_location_rule(self):
        event = {"id": 8, "event_type": "authentication.login_success", "new_location": True}
        finding = evaluate_detections(event, [])[0]
        self.assertEqual(finding["rule_id"], "auth.success_from_new_location")
        self.assertEqual(finding["evidence"][1]["value"], "true")

    def test_unsigned_document_child_rule_requires_all_fields(self):
        event = {"id": 9, "event_type": "process.execution", "signed": False, "parent_process": "Word"}
        self.assertEqual(evaluate_detections(event, [])[0]["rule_id"], "endpoint.unsigned_document_child")
        event["signed"] = True
        self.assertEqual(evaluate_detections(event, []), [])

    def test_rule_finding_remains_authoritative_when_llm_is_unavailable(self):
        event = {"id": 8, "event_type": "authentication.login_success", "new_location": True}
        finding = evaluate_detections(event, [])[0]
        analysis = build_analysis([finding], {
            "provider": "unavailable", "model": "unavailable", "severity": "unknown",
            "explanation": "unavailable", "recommendation": "unavailable", "confidence": None,
        }, model_available=False)
        self.assertEqual(analysis["severity"], "medium")
        self.assertEqual(analysis["analysis_mode"], "rules-only")
        self.assertEqual(analysis["ai_summary"], "")
        self.assertEqual(len(analysis["detections"]), 1)

    def test_no_detection_stays_unknown_when_llm_is_unavailable(self):
        analysis = build_analysis([], {
            "provider": "unavailable", "model": "unavailable", "severity": "unknown",
            "explanation": "unavailable", "recommendation": "unavailable", "confidence": None,
        }, model_available=False)
        self.assertEqual(analysis["severity"], "unknown")
        self.assertEqual(analysis["analysis_mode"], "rules-only")
        self.assertEqual(analysis["ai_recommendation"], "")
        self.assertIn("No deterministic detection rule matched", analysis["explanation"])


class RedactionTests(unittest.TestCase):
    def test_redacts_private_fields_emails_and_secret_assignments(self):
        safe = sanitize_for_llm({
            "actor_user": "alex@example.com",
            "source_ip": "203.0.113.10",
            "message": "Contact alex@example.com; token=abc123",
            "event_type": "authentication.login_failed",
        })
        self.assertEqual(safe["actor_user"], "[REDACTED]")
        self.assertEqual(safe["source_ip"], "[REDACTED]")
        self.assertNotIn("alex@example.com", safe["message"])
        self.assertNotIn("abc123", safe["message"])
        self.assertEqual(safe["event_type"], "authentication.login_failed")


if __name__ == "__main__":
    unittest.main()
