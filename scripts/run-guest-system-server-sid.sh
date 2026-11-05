#!/system/bin/sh
set -eu
bin=${SSAL_SID_STAGE:-/dev/ssal-guest-system-server-sid}
snapshot() {
    echo "enforce=$(getenforce)"
    cat /sys/fs/selinux/enforce
    cat /proc/sys/kernel/random/boot_id
    sha256sum /data/adb/modules/ssal/sepolicy.rule /proc/1/mountinfo
    sha256sum /sys/fs/selinux/policy 2>/dev/null || echo ACTIVE_POLICY_HASH=UNAVAILABLE
    /data/adb/ksu/bin/ksud feature list
    for name in init zygote64 system_server servicemanager surfaceflinger adbd netd lmkd installd; do
        for pid in $(pidof "$name"); do
            echo "process=$name"
            awk '{print $1,$2,$22}' "/proc/$pid/stat"
            cat "/proc/$pid/attr/current" "/proc/$pid/cgroup"
            grep -E '^(Uid|Gid|Groups|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' "/proc/$pid/status"
        done
    done
}
test "$(getenforce)" = Enforcing
if test "${1:-}" = --snapshot; then snapshot; exit; fi
case "${1:-}" in ''|--boundary) ;; *) exit 2 ;; esac
snapshot > "$bin/before.txt"
date '+%Y-%m-%dT%H:%M:%S%z' > "$bin/probe.txt"
set +e
"$bin/probe" "$@" >> "$bin/probe.txt" 2>&1
status=$?
set -e
echo "probe_exit=$status" >> "$bin/probe.txt"
snapshot > "$bin/after.txt"
if cmp -s "$bin/before.txt" "$bin/after.txt"; then
    echo HOST_SAFETY_SNAPSHOT=UNCHANGED >> "$bin/probe.txt"
else
    echo HOST_SAFETY_SNAPSHOT=CHANGED >> "$bin/probe.txt"
    exit 4
fi
cat "$bin/probe.txt"
exit "$status"
