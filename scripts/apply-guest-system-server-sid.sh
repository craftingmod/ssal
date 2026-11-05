#!/system/bin/sh
set -eu
stage=/dev/ssal-guest-system-server-sid-ksu
ksud=/data/adb/ksu/bin/ksud
test "$(getenforce)" = Enforcing
"$ksud" sepolicy check "$(cat "$stage/guest.rule")" > "$stage/policy-check.txt" 2>&1
"$ksud" sepolicy apply "$stage/guest.rule" > "$stage/policy-apply.txt" 2>&1
SSAL_SID_STAGE="$stage" sh "$stage/run.sh"
