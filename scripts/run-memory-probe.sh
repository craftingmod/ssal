#!/system/bin/sh
# Phase 7C: run only the disposable allocator, never the Guest launcher.
set -eu
bin=/data/local/tmp/ssal-phase7c
stage="$bin/run-$(date +%s)-$$"
mkdir -m 700 "$stage"
snapshot() {
    date '+%Y-%m-%dT%H:%M:%S%z'
    cat /proc/pressure/memory
    grep -E '^(MemAvailable|MemFree|SwapFree|Cached):' /proc/meminfo
    for path in /sys/fs/cgroup /sys/fs/cgroup/apps /sys/fs/cgroup/system; do
        for file in cgroup.controllers cgroup.subtree_control cgroup.type; do
            printf '%s/%s=' "$path" "$file"
            if test -f "$path/$file"; then cat "$path/$file"; else echo unavailable; fi
            echo
        done
    done
    getenforce
    cat /proc/sys/kernel/random/boot_id
    for name in init zygote64 zygote_next system_server servicemanager surfaceflinger netd lmkd installd tombstoned; do
        for pid in $(pidof "$name" || true); do
            printf 'core=%s ' "$name"
            awk '{print $1,$2,$22}' "/proc/$pid/stat"
            cat "/proc/$pid/attr/current" "/proc/$pid/cgroup"
        done
    done
    for key in init.svc.zygote init.svc.zygote_secondary init.svc.installd init.svc.artd sys.boot_completed; do
        echo "$key=$(getprop "$key")"
    done
}
stable() { sed '1,/^Enforcing$/ { /^Enforcing$/!d; }' "$1"; }
test "$(getenforce)" = Enforcing
snapshot > "$stage/before.txt"
logcat -b all -d -v epoch -t 1 > "$stage/log-start.txt" 2>&1 || true
set +e
"$bin/ssal-memory-probe" "$stage/phase7b" > "$stage/probe.log" 2>&1
status=$?
set -e
snapshot > "$stage/after.txt"
stable "$stage/before.txt" > "$stage/core-before.txt"
stable "$stage/after.txt" > "$stage/core-after.txt"
if ! cmp -s "$stage/core-before.txt" "$stage/core-after.txt"; then
    echo HOST_CORE_CHANGED
    diff -u "$stage/core-before.txt" "$stage/core-after.txt" || true
    status=1
fi
for path in /sys/fs/cgroup /sys/fs/cgroup/apps /sys/fs/cgroup/system; do
    test -z "$(cat "$path/cgroup.subtree_control")" || status=1
done
test "$(getenforce)" = Enforcing || status=1
echo "probe_exit=$status stage=$stage"
cat "$stage/probe.log"
exit "$status"
