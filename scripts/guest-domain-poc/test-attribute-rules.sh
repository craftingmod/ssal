#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 2 ]] || { echo 'usage: test-attribute-rules.sh TOOL POLICY' >&2; exit 2; }
tool=$1
policy=$2
output=$("$tool" "$policy" file_type)
grep -q $'^unconditional\tfile_type\ttmpfs\tfilesystem\t0x0001\t0x00000040\t associate$' <<<"$output"
grep -q $'^unconditional\tksu\tfile_type\tfile\t0x0001\t' <<<"$output"
if "$tool" "$policy" ssal_guest_probe >/dev/null 2>&1; then
  echo 'concrete type unexpectedly accepted as attribute' >&2
  exit 1
fi
if "$tool" "$policy" ssal_nonexistent_attribute >/dev/null 2>&1; then
  echo 'missing attribute unexpectedly accepted' >&2
  exit 1
fi
echo 'PASS: saved-policy attribute rules and invalid attribute checks'
