import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "red"))

from scenarios import generate_scenario_events, list_scenarios


class ScenarioTests(unittest.TestCase):
    def test_catalog_scenarios_generate_expected_safe_event_shapes(self):
        expected = {
            "normal_login": (1, "authentication.login_success"),
            "brute_force_login": (5, "authentication.login_failed"),
            "unusual_location": (1, "authentication.login_success"),
            "suspicious_process": (1, "process.execution"),
        }
        catalog = {item["id"] for item in list_scenarios()}
        self.assertEqual(catalog, set(expected))
        for scenario_id, (count, event_type) in expected.items():
            events = generate_scenario_events(scenario_id, "run-test")
            self.assertEqual(len(events), count)
            self.assertTrue(all(item["scenario_run_id"] == "run-test" for item in events))
            self.assertTrue(all(item["schema_version"] == "1.0" for item in events))
            self.assertEqual(events[0]["event_type"], event_type)

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError):
            generate_scenario_events("run_real_attack", "run-test")


if __name__ == "__main__":
    unittest.main()
