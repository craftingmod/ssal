#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 5 ]] || { echo 'usage: test-property-policy.sh AV_QUERY TRANSITION ORIGINAL ROUNDTRIP CANDIDATE' >&2; exit 2; }
query=$1 transition=$2 original=$3 roundtrip=$4 candidate=$5
guest=u:r:ssal_guest_probe:s0
dir=u:object_r:ssal_guest_property_dir:s0
area=u:object_r:ssal_guest_property_area:s0
tmpfs=u:object_r:tmpfs:s0
exec_type=u:object_r:ssal_guest_probe_exec:s0

compare() {
  local a b c
  a=$("$query" "$original" "$@" | tail -n 1)
  b=$("$query" "$roundtrip" "$@" | tail -n 1)
  c=$("$query" "$candidate" "$@" | tail -n 1)
  [[ "$a" == "$b" ]] || { echo "roundtrip decision differs: $*" >&2; exit 1; }
  [[ "$b" == "$c" ]] || { echo "candidate changed existing decision: $*" >&2; exit 1; }
}
expect() {
  local expected=$1
  shift
  local result
  result=$("$query" "$candidate" "$@" | tail -n 1)
  [[ "$result" == *"\"allowed\":$expected,"* ]] || { echo "unexpected candidate decision: $* $result" >&2; exit 1; }
}
compare "$guest" "$guest" dir search
compare "$guest" "$tmpfs" file write
compare "$exec_type" "$tmpfs" filesystem associate
compare u:r:init:s0 u:object_r:proc:s0 dir search
compare u:r:system_server:s0 u:object_r:property_info:s0 file read
compare u:r:zygote:s0 u:object_r:system_file:s0 file execute
[[ $("$transition" "$candidate" "$guest" "$dir" file | tail -n 1) == "$area" ]]
for permission in getattr search write add_name; do
  expect true "$guest" "$dir" dir "$permission"
done
for permission in create getattr open read write map relabelfrom relabelto; do
  expect true "$guest" "$area" file "$permission"
done
expect true "$dir" "$tmpfs" filesystem associate
expect true "$area" "$tmpfs" filesystem associate
expect false u:r:untrusted_app:s0 "$area" file read
expect false u:r:untrusted_app:s0 "$dir" dir search
echo 'PASS: sampled policy roundtrip, candidate transition, and AV decisions'
