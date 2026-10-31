"""Verify that cleanup certification cannot be inferred from an early failure."""
import copy
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location("suite", Path(__file__).with_name("run-lock-namespace-suite.py"))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)

class CleanupEvidenceTests(unittest.TestCase):
    def clean(self, stage="context"):
        return {"exit_code": 1, "report": {"process_reaped": True,
            "host_namespace_mountinfo_enforcing_unchanged": True,
            "loop_backings_unchanged": True, "namespace_released": True,
            "child": {"error": f"injected failure: {stage}", "cleanup": {"status": "passed"}}}}

    def test_reached_failure_with_complete_cleanup(self):
        self.assertEqual(suite.assess(self.clean(), "context"), "passed")

    def test_earlier_permission_denial_does_not_certify_later_failure(self):
        run = self.clean()
        run["report"]["child"]["error"] = "Operation not permitted (os error 1)"
        self.assertEqual(suite.assess(run, "context"), "blocked")

    def test_each_missing_cleanup_observation_prevents_success(self):
        base = self.clean()
        for key in ("process_reaped", "host_namespace_mountinfo_enforcing_unchanged", "loop_backings_unchanged", "namespace_released"):
            run = copy.deepcopy(base)
            del run["report"][key]
            self.assertEqual(suite.assess(run, "context"), "failed")
        base["report"]["child"]["cleanup"]["status"] = "failed"
        self.assertEqual(suite.assess(base, "context"), "failed")

    def test_abnormal_exit_needs_parent_observations(self):
        run = self.clean()
        run["report"]["child"] = {}
        run["report"]["child_exit_code"] = 86
        self.assertEqual(suite.assess(run, "abort"), "passed")
        run["report"]["namespace_released"] = False
        self.assertEqual(suite.assess(run, "abort"), "failed")

    def test_no_json_or_no_exit_code_cannot_pass(self):
        self.assertEqual(suite.assess({"exit_code": 1}), "failed")
        self.assertEqual(suite.assess({"exit_code": 1}, "abort"), "blocked")

if __name__ == "__main__":
    unittest.main()