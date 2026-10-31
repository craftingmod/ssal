"""Negative evidence for v5 comparisons and intentionally failed cleanup."""
import copy
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location("v5suite",Path(__file__).with_name("run-lock-mount-v5.py"))
suite=importlib.util.module_from_spec(spec);spec.loader.exec_module(suite)

class MountComparisonEvidenceTests(unittest.TestCase):
    def clean(self):
        return {"exit_code":1,"report":{"process_reaped":True,"host_namespace_mountinfo_enforcing_unchanged":True,
            "loop_backings_unchanged":True,"namespace_released":True,"status":"failed",
            "child":{"operation":"comparison_tmpfs_mount","mount_attempt":{"filesystem":"tmpfs"},"errno":13,
                     "cleanup":{"status":"passed"}}}}
    def test_context_eacces_is_a_denial_observation_not_success(self):
        run=self.clean()
        self.assertEqual(suite.assess(run,comparison=True),"observed_denial")
        self.assertEqual(suite.assess(run),"failed")
    def test_earlier_eacces_is_not_context_denial_evidence(self):
        run=self.clean();run["report"]["child"]["operation"]="unshare"
        self.assertEqual(suite.assess(run,comparison=True),"failed")
    def test_cleanup_error_stays_a_failed_probe(self):
        run=self.clean();run["report"]["child"]["cleanup"]["status"]="failed"
        self.assertEqual(suite.assess(run,"cleanup"),"detected_cleanup_failure")
        self.assertEqual(suite.assess(run,comparison=True),"failed")
        run["report"]["namespace_released"]=False
        self.assertEqual(suite.assess(run,"cleanup"),"failed")
    def test_missing_parent_observation_cannot_pass(self):
        base=self.clean()
        for key in ("process_reaped","namespace_released","loop_backings_unchanged","host_namespace_mountinfo_enforcing_unchanged"):
            run=copy.deepcopy(base);del run["report"][key]
            self.assertEqual(suite.assess(run,comparison=True),"failed")
    def test_temporary_relabel_denial_is_separate_from_mount_denial(self):
        run=self.clean();run["report"]["child"]["operation"]="namespace_temporary_file_fsetxattr"
        self.assertEqual(suite.assess(run,comparison=True),"observed_relabel_denial")
        self.assertEqual(suite.assess(run),"failed")

if __name__=="__main__":unittest.main()
