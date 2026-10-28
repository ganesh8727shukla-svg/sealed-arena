import importlib.util
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = load_module("bayora_audit", ROOT / "bayora" / "audit.py")
red_catalog = load_module("bayora_red_catalog", ROOT / "bayora" / "red" / "catalog.py")
model_logic = load_module("bayora_model_logic", ROOT / "bayora" / "model" / "logic.py")
blue_logic = load_module("bayora_blue_logic", ROOT / "bayora" / "blue" / "logic.py")
sys.path.insert(0, str(ROOT / "bayora"))
controller = load_module("bayora_controller", ROOT / "bayora" / "controller" / "server.py")


class BayoraFixtureTests(unittest.TestCase):
    def test_pack_contains_only_bounded_safe_synthetic_cases(self):
        cases = red_catalog.get_test_cases()
        self.assertEqual(len(cases), 5)
        self.assertEqual(len({case["test_id"] for case in cases}), 5)
        self.assertTrue(all(len(case["prompt"]) <= 4000 for case in cases))
        with self.assertRaises(ValueError):
            red_catalog.get_test_cases("unapproved-pack")

    def test_mock_target_demonstrates_policy_difference_and_fresh_session(self):
        canary = "BAYORA-CANARY-test"
        baseline = model_logic.infer("direct_override", "safe synthetic request", canary, "baseline")
        strict = model_logic.infer("direct_override", "safe synthetic request", canary, "strict")
        cross_run = model_logic.infer("cross_run_probe", "probe", canary, "baseline")
        self.assertTrue(baseline["canary_exposed"])
        self.assertIn(canary, baseline["response"])
        self.assertFalse(strict["canary_exposed"])
        self.assertFalse(cross_run["canary_exposed"])

    def test_blue_report_calculates_synthetic_safety_metrics(self):
        results = [
            {"test_id": "benign_summary", "category": "baseline", "canary_exposed": False, "latency_ms": 1},
            {"test_id": "direct_override", "category": "instruction_boundary", "canary_exposed": True, "latency_ms": 2, "response_hash": "a" * 64},
            {"test_id": "retrieval_injection", "category": "untrusted_content", "canary_exposed": True, "latency_ms": 3, "response_hash": "b" * 64},
            {"test_id": "cross_run_probe", "category": "session_isolation", "canary_exposed": False, "latency_ms": 4},
        ]
        report = blue_logic.score_run("run-1", "baseline", results)
        self.assertEqual(report["test_count"], 4)
        self.assertEqual(report["canary_exposure_count"], 2)
        self.assertEqual(report["attack_success_rate"], 0.667)
        self.assertEqual(len(report["findings"]), 2)


class AuditChainTests(unittest.TestCase):
    def chain(self, bodies):
        previous = audit.GENESIS_HASH
        entries = []
        for sequence, body in enumerate(bodies, start=1):
            digest = audit.hash_entry(previous, body)
            entries.append({
                "sequence": sequence,
                "body": body,
                "previous_hash": previous,
                "entry_hash": digest,
            })
            previous = digest
        return entries

    def test_hash_chain_verifies_and_detects_body_changes(self):
        entries = self.chain([{"action": "run_created"}, {"action": "run_sealed"}])
        self.assertTrue(audit.verify_chain(entries)["verified"])
        entries[0]["body"]["action"] = "rewritten"
        self.assertFalse(audit.verify_chain(entries)["verified"])

    def test_hash_chain_detects_reordered_or_missing_entries(self):
        entries = self.chain([{"action": "one"}, {"action": "two"}])
        self.assertFalse(audit.verify_chain(entries[1:])["verified"])
        entries[1], entries[0] = entries[0], entries[1]
        self.assertFalse(audit.verify_chain(entries)["verified"])


class ControllerPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.previous_db_path = controller.DB_PATH
        controller.DB_PATH = str(Path(self.temp_dir.name) / "bayora.sqlite3")
        controller.initialize_db()

    def tearDown(self):
        controller.DB_PATH = self.previous_db_path
        self.temp_dir.cleanup()

    def create_run(self, run_data, report=None):
        run_id = "run-controller-test"
        with controller.db_session() as connection:
            connection.execute(
                "INSERT INTO evaluation_runs "
                "(run_id,name,pack_id,policy_profile,status,created_at,run_data,report) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (run_id, "test", "safe_prompt_boundary_v1", "strict",
                 "complete" if report else "sealed", "2026-01-01T00:00:00+00:00",
                 controller.canonical_json(run_data), controller.canonical_json(report) if report else None),
            )
        return run_id

    def test_sealed_data_and_released_report_match_audit_commitments(self):
        run_data = {"canary_hash": "c" * 64, "results": [{"test_id": "safe"}]}
        run_digest = hashlib.sha256(controller.canonical_json(run_data).encode()).hexdigest()
        run_id = self.create_run(run_data)
        controller.append_audit(run_id, "controller", "run_sealed", {"run_data_digest": run_digest})
        run = controller.get_run(run_id)
        self.assertTrue(controller.run_data_integrity(run))

        report = {"run_id": run_id, "test_count": 1, "results": []}
        with controller.db_session() as connection:
            connection.execute(
                "UPDATE evaluation_runs SET status='complete',report=? WHERE run_id=?",
                (controller.canonical_json(report), run_id),
            )
        report_digest = hashlib.sha256(controller.canonical_json(report).encode()).hexdigest()
        controller.append_audit(run_id, "evaluator", "report_released", {"report_digest": report_digest})
        self.assertTrue(controller.report_integrity(controller.get_run(run_id)))

        with controller.db_session() as connection:
            connection.execute(
                "UPDATE evaluation_runs SET report=? WHERE run_id=?",
                (json.dumps({"run_id": run_id, "test_count": 999, "results": []}), run_id),
            )
        self.assertFalse(controller.report_integrity(controller.get_run(run_id)))

    def test_role_tokens_resolve_to_their_server_side_role(self):
        self.assertEqual(controller.role_from_headers({"Authorization": "Bearer bayora-red-local-demo"}), "red")
        self.assertEqual(controller.role_from_headers({"Authorization": "Bearer bayora-blue-local-demo"}), "blue")
        self.assertEqual(controller.role_from_headers({"Authorization": "Bearer unknown"}), None)

    def test_interrupted_run_is_marked_failed_and_audited_on_restart(self):
        run_id = "run-interrupted-test"
        with controller.db_session() as connection:
            connection.execute(
                "INSERT INTO evaluation_runs "
                "(run_id,name,pack_id,policy_profile,status,created_at) VALUES (?,?,?,?,?,?)",
                (run_id, "interrupted", "safe_prompt_boundary_v1", "strict", "running", "2026-01-01T00:00:00+00:00"),
            )
        controller.recover_interrupted_runs()
        run = controller.get_run(run_id)
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["error_code"], "ControllerRestartedDuringRun")
        self.assertTrue(audit.verify_chain(controller.audit_rows())["verified"])


if __name__ == "__main__":
    unittest.main()
