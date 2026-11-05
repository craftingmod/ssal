import unittest
from types import SimpleNamespace

from phase8b3a_policy_diff import _diff, _guest_attribute_membership, _rule_records


class Symbol:
    def __init__(self, name, members=()):
        self.name = name
        self.members = members or (self,)

    def expand(self):
        return self.members


class PolicyDiffTests(unittest.TestCase):
    def test_attribute_expansion_for_system_server(self):
        server = Symbol("system_server")
        zygote = Symbol("zygote")
        file_a = Symbol("system_file")
        file_b = Symbol("guest_file")
        source_attribute = Symbol("domain", (server, zygote))
        target_attribute = Symbol("readable_files", (file_a, file_b))
        rule = SimpleNamespace(
            source=source_attribute,
            target=target_attribute,
            tclass=SimpleNamespace(name="file"),
            perms={"getattr", "read"},
            extended=False,
        )

        self.assertEqual(
            _rule_records(rule, "source"),
            {
                ("system_server", "system_file", "file", "getattr"),
                ("system_server", "system_file", "file", "read"),
                ("system_server", "guest_file", "file", "getattr"),
                ("system_server", "guest_file", "file", "read"),
            },
        )

    def test_set_diff_and_comparable_coverage(self):
        host = {
            "types": ["system_server", "system_file"],
            "source_allow": {"active": [["system_server", "system_file", "file", "read"]]},
        }
        guest = {
            "types": ["system_server", "system_file", "guest_file"],
            "source_allow": {
                "active": [
                    ["system_server", "system_file", "file", "read"],
                    ["system_server", "system_file", "file", "write"],
                    ["system_server", "system_file", "file", "unsupported_permission"],
                    ["system_server", "guest_file", "file", "read"],
                ]
            },
        }

        result = _diff(host["source_allow"], guest["source_allow"], set(host["types"]), {"file": {"read", "write"}}, 1)
        self.assertEqual(result["common_count"], 1)
        self.assertEqual(result["guest_only_count"], 3)
        self.assertEqual(result["guest_only_types"], ["guest_file"])
        self.assertEqual(result["uncomparable_missing_class_or_permission_count"], 1)
        self.assertEqual(result["comparable_coverage"], 0.5)

    def test_guest_only_attribute_membership_on_server_targets(self):
        self.assertEqual(
            _guest_attribute_membership(
                {"sdcard_posix": ["sdcard_posix_contextmount_type", "file_type"], "system_file": ["file_type"]},
                {"sdcard_posix_contextmount_type", "unused_guest_attr"},
            ),
            {"sdcard_posix_contextmount_type": ["sdcard_posix"]},
        )


if __name__ == "__main__":
    unittest.main()
