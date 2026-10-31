"""Adversarial offline input tests, no Android device access."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("compat", Path(__file__).with_name("validate-guest-lock-compat.py"))
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)


class OfflineValidationTests(unittest.TestCase):
    def test_actual_xml(self):
        compat.validate_xml((compat.SOURCE / "ssal-lockscreen.xml").read_bytes())

    def test_wrong_feature_tag_and_extra_operations_fail(self):
        xml = (compat.SOURCE / "ssal-lockscreen.xml").read_text(encoding="utf-8")
        feature = '<unavailable-feature name="android.hardware.fingerprint" />'
        for text in (
            xml.replace(feature, '<feature name="android.hardware.fingerprint" />'),
            xml.replace(feature, '<unavailable-feature name="android.hardware.camera" />'),
            xml.replace(feature, ''),
            xml.replace(feature, feature + feature),
            xml.replace(feature, '<unavailable-feature name="android.hardware.fingerprint" extra="1" />'),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                compat.validate_xml(text)

    def test_arsc_policy_chunks_are_structural_not_string_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "target.apk"
            # Minimal table containing a package containing an overlayable chunk.
            child = struct.pack("<HHI", 0x204, 8, 8)
            package = struct.pack("<HHI", 0x200, 8, 16) + child
            table = struct.pack("<HHI", 2, 8, 24) + package
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("resources.arsc", table)
            self.assertEqual(compat.arsc_overlayable_count(apk), 1)

    def test_truncated_arsc_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "target.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("resources.arsc", struct.pack("<HHI", 2, 8, 99))
            with self.assertRaises(ValueError):
                compat.arsc_overlayable_count(apk)


if __name__ == "__main__":
    unittest.main()
