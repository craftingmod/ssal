import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('planner', Path(__file__).with_name('plan-selinux.py'))
planner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(planner)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def report(self, label):
        return {'live': {'invalid_contexts': [{'label': label, 'errno': 22}]},
                'inventory': {label: {'files': [], 'service_names': ['example']}}, 'offline': {}}

    def test_attributes_are_candidates_without_runtime_or_missing_type_claim(self):
        path = self.root / 'vendor/android_device_lineage_sepolicy/common/private/service.te'
        path.parent.mkdir(parents=True)
        path.write_text('type example, system_api_service, system_server_service, service_manager_type;\n')
        entry = planner.build_plan(self.report('u:object_r:example:s0'), self.root)['entries'][0]
        self.assertEqual(entry['proposed_attributes'], ['service_manager_type', 'system_api_service', 'system_server_service'])
        self.assertIn('unproven', entry['missing_type_in_loaded_policy'])
        self.assertEqual(entry['required_for_boot'], 'unknown')
        self.assertIsNone(entry['mapping_target'])
        self.assertEqual(entry['runtime_use'], 'unverified')
        self.assertEqual(entry['attribute_impact']['system_api_service']['member_count'], None)

    def test_contract_domain_requires_design(self):
        report = self.report('u:r:ssal_property:s0')
        report['inventory']['u:r:ssal_property:s0']['contract_service'] = 'property_service'
        entry = planner.build_plan(report, self.root)['entries'][0]
        self.assertEqual(entry['candidate_actions'], ['design_private_property_service_policy'])
        self.assertEqual(entry['ksu_declaration_candidates'], [])

    def test_generated_attributes_are_not_transplanted(self):
        path = self.root / 'guest.cil'
        path.write_text('(type example)\n(typeattributeset base_typeattr_123 (example))\n(typeattributeset service_manager_type (example))\n')
        report = self.report('u:object_r:example:s0')
        report['offline'] = {'guest': {'inputs': [{'path': str(path)}]}}
        entry = planner.build_plan(report, self.root)['entries'][0]
        self.assertIn('base_typeattr_123', entry['compiled_direct_attributes'])
        self.assertNotIn('base_typeattr_123', entry['proposed_attributes'])
        self.assertEqual(entry['proposed_attributes'], ['service_manager_type'])

    def test_artifacts_cannot_escape_workspace(self):
        with self.assertRaises(ValueError):
            planner.local_path('/src/../outside', self.root)

    def test_changed_export_is_rejected(self):
        path = self.root / 'changed.cil'
        path.write_text('(type example)\n')
        report = self.report('u:object_r:example:s0')
        report['offline'] = {'guest': {'inputs': [{'path': str(path), 'sha256': '0' * 64}]}}
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            planner.build_plan(report, self.root)

    def test_old_prebuilt_declarations_are_excluded(self):
        path = self.root / 'vendor/android_system_sepolicy/prebuilts/api/29.0/public/service.te'
        path.parent.mkdir(parents=True)
        path.write_text('type example, old_attribute;\n')
        entry = planner.build_plan(self.report('u:object_r:example:s0'), self.root)['entries'][0]
        self.assertEqual(entry['declarations'], [])
        self.assertEqual(entry['candidate_actions'], ['resolve_declaration_or_design'])


if __name__ == '__main__':
    unittest.main()
