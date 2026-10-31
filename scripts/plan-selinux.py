#!/usr/bin/env python3
"""Build review-only SELinux plans from a saved diagnostic; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_path(value, root):
    if value.startswith('/src/'):
        path = root / value[5:]
    else:
        path = Path(value)
        if not path.is_absolute():
            path = root / path
    path = path.resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f'Artifact outside workspace: {value}')
    return path


def build_plan(report, root):
    invalid = report['live']['invalid_contexts']
    names = sorted({item['label'].split(':')[2] for item in invalid})
    declarations = {name: [] for name in names}
    references = {name: [] for name in names}
    cil_attrs = {name: set() for name in names}
    pattern = re.compile(r'\b(?:' + '|'.join(map(re.escape, names)) + r')\b') if names else re.compile(r'(?!)')
    files = set()
    for analysis in report.get('offline', {}).values():
        for item in analysis.get('inputs', []):
            path = local_path(item['path'], root)
            if path.is_file():
                if item.get('sha256') and sha(path) != item['sha256']:
                    raise ValueError(f'Exported input hash mismatch: {path}')
                files.add(path)
            else:
                raise ValueError(f'Exported policy input missing: {path}')
    for directory in ('vendor/android_system_sepolicy', 'vendor/android_device_lineage_sepolicy',
                      'vendor/device_phh_treble/sepolicy', 'module'):
        base = root / directory
        files.update(p for p in base.rglob('*') if p.is_file() and not p.is_symlink()
                     and not {'prebuilts', 'microdroid', 'tests', '.git'} & set(p.relative_to(base).parts)
                     and (p.suffix in ('.te', '.rule') or p.name.endswith('contexts')))
    sources = []
    for path in sorted(files):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(errors='replace')
        if not pattern.search(text):
            continue
        sources.append({'path': relative, 'sha256': sha(path)})
        for line_number, raw in enumerate(text.splitlines(), 1):
            line = raw.split('#', 1)[0].strip()
            for name in set(pattern.findall(line)):
                evidence = {'path': relative, 'line': line_number, 'text': line[:800]}
                references[name].append(evidence)
                match = re.match(r'type\s+' + re.escape(name) + r'\s*(?:,\s*([^;]+))?;', line)
                if match:
                    declarations[name].append({**evidence, 'format': 'te',
                        'attributes': [a.strip() for a in (match[1] or '').split(',') if a.strip()],
                        'conditional_build_context': 'unresolved'})
                if re.fullmatch(r'\(type\s+' + re.escape(name) + r'\)', line):
                    declarations[name].append({**evidence, 'format': 'cil', 'attributes': []})
                match = re.match(r'\(typeattributeset\s+(\w+)\s+\(([^()]*)\)\)', line)
                if match and name in match[2].split() and not set(match[2].split()) & {'not', 'and', 'or', 'xor', 'all'}:
                    cil_attrs[name].add(match[1])
    all_attrs = set()
    for name in names:
        all_attrs.update(a for d in declarations[name] for a in d['attributes'])
        all_attrs.update(a for a in cil_attrs[name] if not a.startswith('base_typeattr_'))
    impact = {a: {'baseline_attribute_present': None, 'member_count': None,
                  'retained_rule_reference_count': None, 'examples': [],
                  'source_reference_count': 0, 'source_references': []} for a in sorted(all_attrs)}
    attr_pattern = re.compile(r'\b(?:' + '|'.join(map(re.escape, sorted(all_attrs))) + r')\b') if all_attrs else re.compile(r'(?!)')
    recorded = {s['path'] for s in sources}
    for path in sorted(files):
        text = path.read_text(errors='replace')
        if not attr_pattern.search(text):
            continue
        relative = path.relative_to(root).as_posix()
        if relative not in recorded:
            sources.append({'path': relative, 'sha256': sha(path)})
            recorded.add(relative)
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.split('#', 1)[0].strip()
            for attr in set(attr_pattern.findall(line)):
                impact[attr]['source_reference_count'] += 1
                if len(impact[attr]['source_references']) < 12:
                    impact[attr]['source_references'].append({'path': relative, 'line': number, 'text': line[:800],
                        'interpretation': 'reference only; macro expansion and build conditions unresolved'})
    baseline = report.get('offline', {}).get('host_reconstructed', {}).get('device_compile', {}).get('init', {}).get('policy')
    baseline_error = None
    if baseline:
        try:
            import setools
            path = local_path(baseline['path'], root)
            if sha(path) != baseline['sha256']:
                raise ValueError('Reconstructed policy hash mismatch')
            policy = setools.SELinuxPolicy(str(path))
            attrs = {str(a): a for a in policy.typeattributes()}
            for name, item in impact.items():
                item['baseline_attribute_present'] = name in attrs
                item['member_count'] = len(list(attrs[name].expand())) if name in attrs else None
                item['retained_rule_reference_count'] = 0
            for rule in policy.terules():
                touched = {str(rule.source), str(rule.target)} & all_attrs
                for name in touched:
                    impact[name]['retained_rule_reference_count'] += 1
                    if len(impact[name]['examples']) < 3:
                        impact[name]['examples'].append(str(rule))
        except Exception as error:
            baseline_error = str(error)
    entries = []
    for item in invalid:
        label = item['label']
        name = label.split(':')[2]
        inventory = report['inventory'].get(label, {})
        attrs = sorted({a for d in declarations[name] for a in d['attributes']} |
                       {a for a in cil_attrs[name] if not a.startswith('base_typeattr_')})
        category = ('contract_domain' if inventory.get('contract_service') else
                    'app_domain' if label.startswith('u:r:') else
                    'service' if inventory.get('service_names') else
                    'property' if any('property_contexts' in p for p in inventory.get('files', [])) else 'file')
        bindings = []
        for value in inventory.get('files', []):
            path = local_path(value, root)
            if path.is_file():
                for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
                    if re.search(r'\b' + re.escape(name) + r'\b', line.split('#', 1)[0]):
                        bindings.append({'path': path.relative_to(root).as_posix(), 'line': number, 'text': line[:1000]})
        candidate = ['review_type_extension', 'review_guest_mapping_reuse'] if declarations[name] else ['resolve_declaration_or_design']
        if category == 'contract_domain':
            candidate = ['design_private_property_service_policy']
        entries.append({'context': label, 'type': name, 'category': category,
            'status': 'context_invalid', 'kernel_errno': item.get('errno'),
            'missing_type_in_loaded_policy': 'unproven; EINVAL alone is insufficient',
            'required_for_boot': 'unknown', 'runtime_use': 'unverified',
            'declarations': declarations[name], 'bindings': bindings,
            'service_names': inventory.get('service_names', []),
            'contract_service': inventory.get('contract_service'),
            'proposed_attributes': attrs, 'compiled_direct_attributes': sorted(cil_attrs[name]),
            'attribute_impact': {a: impact[a] for a in attrs},
            'source_references': references[name][:40], 'source_reference_count': len(references[name]),
            'candidate_actions': candidate, 'mapping_target': None,
            'ksu_declaration_candidates': ([f'type {name} ' + (attrs[0] if attrs else 'domain')] +
                [f'typeattribute {name} {a}' for a in attrs[1:]]) if declarations[name] and attrs else [],
            'candidate_validation': 'not_validated_with_installed_samsung_ksud',
            'host_security_impact': 'unassessed; attribute membership and type reuse can inherit global permissions',
            'action': 'review_before_apply'})
    return {'schema': 1, 'mode': 'review_only', 'policy_modified': False, 'device_access': False,
        'source_run': report.get('run'), 'sources': sources, 'entries': entries,
        'summary': {'invalid_contexts': len(entries), 'with_declaration_evidence': sum(bool(e['declarations']) for e in entries),
                    'unresolved': [e['type'] for e in entries if not e['declarations']]},
        'genfs_action': 'retain_host_genfscon; exclude conflicting Guest declarations from incremental transplantation',
        'genfs_conflicts': report.get('offline', {}).get('guest_with_host_vendor', {}).get('genfs_same_path_differences', []),
        'baseline_analysis_error': baseline_error,
        'validation_limits': ['Reconstructed policy is not an export of the loaded policy.',
            'Source references and context bindings do not prove runtime use or file existence.',
            'TE conditionals, macros, attribute complements and indirect memberships are not fully evaluated.',
            'Retained binary rule counts omit expanded/optimized rules; zero is not evidence of no impact.',
            'No allow rules or mapping replacements are inferred from denied AV queries.',
            'No runnable policy file is emitted. KSU syntax, role/MLS validity and live effect remain unverified.',
            'Host KeyMint/Gatekeeper/Weaver/FBE isolation remains a requirement, not a proven property.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = Path.cwd().resolve()
    path = local_path(str(args.report), root)
    report = json.loads(path.read_text())
    plan = build_plan(report, root)
    plan['input_report'] = {'path': path.relative_to(root).as_posix(), 'sha256': sha(path)}
    output = local_path(str(args.output or path.with_name('patch-plan.json')), root)
    if output == path:
        raise ValueError('Output must not overwrite input report')
    output.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'plan': str(output), **plan['summary']}, indent=2))


if __name__ == '__main__':
    main()
