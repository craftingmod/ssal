#!/usr/bin/env python3
"""Compare active system_server SELinux access vectors in two binary policies."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SYSTEM_SERVER = "system_server"
RULE_STATES = ("unconditional", "conditional_enabled", "conditional_disabled")


def _names(symbol):
    return {member.name for member in symbol.expand()}


def _state(rule, not_conditional):
    try:
        rule.conditional
    except not_conditional:
        return "unconditional"
    return "conditional_enabled" if rule.enabled else "conditional_disabled"


def _rule_records(rule, direction):
    sources = _names(rule.source)
    targets = _names(rule.target)
    if direction == "source":
        sources.intersection_update({SYSTEM_SERVER})
    else:
        targets.intersection_update({SYSTEM_SERVER})
    if not sources or not targets:
        return set()

    if rule.extended:
        tail = (str(rule.xperm_type), str(rule.perms))
    else:
        tail = None

    records = set()
    for source in sources:
        for target in targets:
            if tail is not None:
                records.add((source, target, rule.tclass.name, *tail))
            else:
                records.update(
                    (source, target, rule.tclass.name, str(permission))
                    for permission in rule.perms
                )
    return records


def _collect_rules(policy, rule_type, direction, not_conditional, attribute_names):
    from setools import TERuleQuery

    query = TERuleQuery(policy, ruletype=[rule_type], **{direction: SYSTEM_SERVER})
    state_records = {state: set() for state in RULE_STATES}
    state_rule_counts = {state: 0 for state in RULE_STATES}
    source_attributes = set()
    target_attributes = set()
    matched = direct = 0
    for rule in query.results():
        records = _rule_records(rule, direction)
        if not records:
            continue
        matched += 1
        symbol = rule.source if direction == "source" else rule.target
        direct += symbol.name == SYSTEM_SERVER
        if rule.source.name in attribute_names:
            source_attributes.add(rule.source.name)
        if rule.target.name in attribute_names:
            target_attributes.add(rule.target.name)
        state = _state(rule, not_conditional)
        state_rule_counts[state] += 1
        state_records[state].update(records)

    active = state_records["unconditional"] | state_records["conditional_enabled"]
    possible = active | state_records["conditional_disabled"]
    return {
        "matched_rule_count": matched,
        "direct_rule_count": direct,
        "attribute_rule_count": matched - direct,
        "state_rule_counts": state_rule_counts,
        "source_attribute_references": sorted(source_attributes),
        "target_attribute_references": sorted(target_attributes),
        "active_count": len(active),
        "possible_count": len(possible),
        "active": [list(record) for record in sorted(active)],
        "possible": [list(record) for record in sorted(possible)],
    }


def _collect_transitions(policy, focus, not_conditional, no_filename):
    from setools import TERuleQuery

    result = {}
    for rule_type in ("type_transition", "type_change", "type_member"):
        query = TERuleQuery(
            policy,
            ruletype=[rule_type],
            **({"source": SYSTEM_SERVER} if focus == "source" else {"default": SYSTEM_SERVER}),
        )
        records = set()
        direct = matched = 0
        state_rule_counts = {state: 0 for state in RULE_STATES}
        for rule in query.results():
            sources = _names(rule.source)
            targets = _names(rule.target)
            if focus == "source":
                if SYSTEM_SERVER not in sources:
                    continue
                sources = {SYSTEM_SERVER}
            elif rule.default.name != SYSTEM_SERVER:
                continue
            matched += 1
            direct += (rule.source.name == SYSTEM_SERVER) if focus == "source" else True
            state = _state(rule, not_conditional)
            state_rule_counts[state] += 1
            for source in sources:
                for target in targets:
                    try:
                        filename = rule.filename or ""
                    except no_filename:
                        filename = ""
                    records.add((source, target, rule.tclass.name, rule.default.name, filename, state))
        result[rule_type] = {
            "matched_rule_count": matched,
            "direct_rule_count": direct,
            "state_rule_counts": state_rule_counts,
            "expanded": [list(record) for record in sorted(records)],
        }
    return result


def _policy_info(path):
    import setools
    from setools import BoundsQuery, ConstraintQuery, ObjClassQuery, SELinuxPolicy
    from setools.exception import NoCommon, RuleNotConditional, TERuleNoFilename

    policy = SELinuxPolicy(str(path))
    types = {item.name for item in policy.types()}
    attributes = {item.name for item in policy.typeattributes()}
    class_permissions = {}
    for item in ObjClassQuery(policy).results():
        permissions = set(item.perms)
        try:
            permissions.update(item.common.perms)
        except NoCommon:
            pass
        class_permissions[item.name] = sorted(permissions)
    permissive = sorted(item.name for item in policy.types() if item.ispermissive)
    result = {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "setools_version": setools.__version__,
        "policy_version": policy.version,
        "type_count": len(types),
        "attribute_count": len(attributes),
        "permissive_types": permissive,
        "constraint_count": sum(1 for _ in ConstraintQuery(policy).results()),
        "typebounds_count": sum(1 for _ in BoundsQuery(policy).results()),
        "class_permissions": class_permissions,
        "types": sorted(types),
        "attributes": sorted(attributes),
        "source_allow": _collect_rules(policy, "allow", "source", RuleNotConditional, attributes),
        "target_allow": _collect_rules(policy, "allow", "target", RuleNotConditional, attributes),
        "source_allowxperm": _collect_rules(policy, "allowxperm", "source", RuleNotConditional, attributes),
        "target_allowxperm": _collect_rules(policy, "allowxperm", "target", RuleNotConditional, attributes),
        "source_dontaudit": _collect_rules(policy, "dontaudit", "source", RuleNotConditional, attributes),
        "target_dontaudit": _collect_rules(policy, "dontaudit", "target", RuleNotConditional, attributes),
        "transitions_from_system_server": _collect_transitions(policy, "source", RuleNotConditional, TERuleNoFilename),
        "transitions_to_system_server": _collect_transitions(policy, "default", RuleNotConditional, TERuleNoFilename),
    }
    type_by_name = {item.name: item for item in policy.types()}
    target_names = {row[1] for row in result["source_allow"]["active"]}
    result["system_server_target_attributes"] = {
        name: sorted(attribute.name for attribute in type_by_name[name].attributes())
        for name in target_names
        if name in type_by_name
    }
    return result


def _diff(host_group, guest_group, host_types, host_class_permissions, type_index):
    host_records = {tuple(row) for row in host_group["active"]}
    guest_records = {tuple(row) for row in guest_group["active"]}
    common = host_records & guest_records
    comparable = {
        row
        for row in guest_records
        if row[type_index] in host_types
        and row[2] in host_class_permissions
        and row[3] in host_class_permissions[row[2]]
    }
    missing_types = sorted({row[type_index] for row in guest_records if row[type_index] not in host_types})
    missing_class_or_permission = {
        row
        for row in guest_records
        if row[type_index] in host_types
        and (row[2] not in host_class_permissions or row[3] not in host_class_permissions.get(row[2], set()))
    }
    return {
        "host_effective_count": len(host_records),
        "guest_effective_count": len(guest_records),
        "common_count": len(common),
        "host_only_count": len(host_records - guest_records),
        "guest_only_count": len(guest_records - host_records),
        "comparable_guest_count": len(comparable),
        "comparable_common_count": len(common & comparable),
        "comparable_coverage": len(common & comparable) / len(comparable) if comparable else None,
        "guest_only_type_count": len(missing_types),
        "guest_only_types": missing_types,
        "uncomparable_guest_record_count": len(guest_records - comparable),
        "uncomparable_missing_class_or_permission_count": len(missing_class_or_permission),
        "common": [list(row) for row in sorted(common)],
        "host_only": [list(row) for row in sorted(host_records - guest_records)],
        "guest_only": [list(row) for row in sorted(guest_records - host_records)],
    }


def _guest_attribute_membership(type_attributes, guest_only_attributes):
    result = {
        attribute: sorted(type_name for type_name, attributes in type_attributes.items() if attribute in attributes)
        for attribute in sorted(guest_only_attributes)
    }
    return {attribute: types for attribute, types in result.items() if types}


def _compact_rules(group):
    return {key: value for key, value in group.items() if key not in ("active", "possible")}


def _compact_policy(policy):
    summary = {
        key: value
        for key, value in policy.items()
        if key not in ("types", "attributes", "system_server_target_attributes")
        and key != "class_permissions"
        and not key.startswith("transitions_")
        and key not in (
            "source_allow", "target_allow", "source_allowxperm", "target_allowxperm",
            "source_dontaudit", "target_dontaudit",
        )
    }
    for key in (
        "source_allow", "target_allow", "source_allowxperm", "target_allowxperm",
        "source_dontaudit", "target_dontaudit",
    ):
        summary[key] = _compact_rules(policy[key])
    for key in ("transitions_from_system_server", "transitions_to_system_server"):
        summary[key] = {
            rule_type: {name: value for name, value in rule.items() if name != "expanded"}
            for rule_type, rule in policy[key].items()
        }
    return summary


def _transition_diff(host, guest):
    result = {}
    for rule_type in host:
        host_records = {tuple(row) for row in host[rule_type]["expanded"]}
        guest_records = {tuple(row) for row in guest[rule_type]["expanded"]}
        result[rule_type] = {
            "host_count": len(host_records),
            "guest_count": len(guest_records),
            "common": [list(row) for row in sorted(host_records & guest_records)],
            "host_only": [list(row) for row in sorted(host_records - guest_records)],
            "guest_only": [list(row) for row in sorted(guest_records - host_records)],
        }
    return result


def _compare(host, guest):
    host_types = set(host["types"])
    host_class_permissions = {name: set(permissions) for name, permissions in host["class_permissions"].items()}
    guest_types = set(guest["types"])
    host_attributes = set(host["attributes"])
    guest_attributes = set(guest["attributes"])
    return {
        "source_allow": _diff(host["source_allow"], guest["source_allow"], host_types, host_class_permissions, 1),
        "source_allowxperm": _diff(host["source_allowxperm"], guest["source_allowxperm"], host_types, host_class_permissions, 1),
        "target_allow": _diff(host["target_allow"], guest["target_allow"], host_types, host_class_permissions, 0),
        "target_allowxperm": _diff(host["target_allowxperm"], guest["target_allowxperm"], host_types, host_class_permissions, 0),
        "transitions_from_system_server": _transition_diff(
            host["transitions_from_system_server"], guest["transitions_from_system_server"]
        ),
        "transitions_to_system_server": _transition_diff(
            host["transitions_to_system_server"], guest["transitions_to_system_server"]
        ),
        "dontaudit_counts": {
            side: {
                direction: _compact_rules(policy[key])
                for direction, key in (("source", "source_dontaudit"), ("target", "target_dontaudit"))
            }
            for side, policy in (("host", host), ("guest", guest))
        },
        "guest_only_types": sorted(guest_types - host_types),
        "host_only_types": sorted(host_types - guest_types),
        "guest_only_attributes": sorted(guest_attributes - host_attributes),
        "host_only_attributes": sorted(host_attributes - guest_attributes),
        "guest_only_system_server_rule_attributes": {
            "used_as_source": sorted(
                set(guest["source_allow"]["source_attribute_references"]) & (guest_attributes - host_attributes)
            ),
            "used_as_target": sorted(
                set(guest["source_allow"]["target_attribute_references"]) & (guest_attributes - host_attributes)
            ),
        },
        "guest_only_attribute_memberships_on_system_server_targets": _guest_attribute_membership(
            guest["system_server_target_attributes"], guest_attributes - host_attributes
        ),
        "unresolved_policy_symbols": [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host_policy", type=Path)
    parser.add_argument("guest_policy", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if not args.host_policy.is_file() or not args.guest_policy.is_file():
        parser.error("both policy paths must be files")

    host = _policy_info(args.host_policy)
    guest = _policy_info(args.guest_policy)
    report = {
        "schema": "phase8b3a-system-server-policy-diff-v1",
        "comparison_note": "Exact type/class/permission names only; equal labels do not prove equal object meaning.",
        "host": _compact_policy(host),
        "guest": _compact_policy(guest),
        "comparison": _compare(host, guest),
    }
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.output}")
    print(json.dumps({
        name: {key: value for key, value in result.items() if not isinstance(value, list)}
        for name, result in report["comparison"].items()
        if isinstance(result, dict) and "host_effective_count" in result
    }, indent=2))


if __name__ == "__main__":
    main()
