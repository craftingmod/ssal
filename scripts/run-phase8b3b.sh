#!/system/bin/sh
set -eu
bin=/dev/ssal-phase8b3b
system=/data/local/ssal/images/1793366406758-25627/system.img
userdata=/data/local/ssal/guests/phase5a-bringup-20261104/userdata.img
mode="${1:-noop}"
case "$mode" in baseline|noop) ;; *) exit 2 ;; esac
stage="$bin/$mode-$(date +%s)"
mkdir -p "$stage/worker/system" "$stage/worker/data"
snapshot() {
    sha256sum /sys/fs/selinux/policy 2>/dev/null || echo ACTIVE_POLICY_HASH=UNAVAILABLE
    sha256sum /data/adb/modules/ssal/sepolicy.rule
    for name in zygote64 system_server adbd netd; do
        for pid in $(pidof "$name"); do
            if grep -q ssal-zygote-selinux-noop "/proc/$pid/maps"; then echo "HOST_HOOK_LEAK=$pid"; fi
        done
    done
    echo "enforce=$(getenforce)"
    echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
    echo "mount_ns=$(readlink /proc/1/ns/mnt)"
    echo "net_ns=$(readlink /proc/1/ns/net)"
    sha256sum /proc/1/mountinfo
    getprop | sort
    stat -c '%n %d %i %a %u %g' /data /dev/__properties__ /dev/socket/property_service /dev/socket/zygote /dev/binder "$system" "$userdata"
    cat /sys/fs/cgroup/cgroup.subtree_control
    cat /sys/fs/cgroup/apps/cgroup.subtree_control
    losetup -a 2>/dev/null | sort
    for key in init.svc.adbd init.svc.netd init.svc.zygote init.svc.system_server init.svc.servicemanager; do
        echo "$key=$(getprop "$key")"
    done
    for name in init zygote64 system_server servicemanager surfaceflinger adbd netd lmkd installd artd; do
        for pid in $(pidof "$name" 2>/dev/null || true); do
            echo "host_process=$name"
            awk '{print $1,$2,$22}' "/proc/$pid/stat"
            cat "/proc/$pid/attr/current"
            grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' "/proc/$pid/status"
            readlink "/proc/$pid/root" || true
            readlink "/proc/$pid/exe" || true
            readlink "/proc/$pid/ns/mnt" || true
            readlink "/proc/$pid/ns/net" || true
        done
    done
}
test "$(getenforce)" = Enforcing
test -f "$system"
test -f "$userdata"
snapshot > "$stage/before.txt"
chmod 600 "$stage/before.txt"
if test "$mode" = noop; then export SSAL_PHASE8B3B_NOOP=1; else unset SSAL_PHASE8B3B_NOOP; fi
set +e
SSAL_PHASE7I_PROPERTIES=1 SSAL_PHASE7I_VERIFY_PERSIST=1 SSAL_PHASE7FB_FORK=1 SSAL_PHASE7FC_BYPASS_SETCONTEXT=1 \
    "$bin/ssald" --guest-zygote-7a-worker "$system" "$userdata" "$stage/worker" > "$stage/worker.log" 2>&1
status=$?
set -e
grep -nE 'PHASE7|guest_property_service_ready|SSAL_(PROPERTY|SETCONTEXT|ORIGINAL_CONTEXT|RESULT_CONTEXT|SELINUX|STARTUP|FINAL)|Guest fork|Guest Java|prepare worker:|error|Error|avc: denied' "$stage/worker.log" | tail -n 160 || true
snapshot > "$stage/after.txt"
chmod 600 "$stage/after.txt"
for maps in /proc/[0-9]*/maps; do
    if grep -q '/ssal-zygote-selinux-noop.so' "$maps" 2>/dev/null; then
        echo "CLEANUP_FAIL hook_mapping_remains=$maps"
        status=1
    fi
done
echo "worker_exit=$status stage=$stage"
if test -e /sys/fs/cgroup/apps/ssal_guest; then
    echo "CLEANUP_FAIL guest_cgroup_remains"
    status=1
fi
if grep -q "$stage/worker/rootfs" /proc/1/mountinfo; then
    echo "CLEANUP_FAIL guest_root_mount_remains"
    status=1
fi
if cmp -s "$stage/before.txt" "$stage/after.txt"; then
    echo HOST_SAFETY_SNAPSHOT=UNCHANGED
else
    echo HOST_SNAPSHOT_DIFF
    diff -u "$stage/before.txt" "$stage/after.txt" | sed -E 's/^([+-].*):.*/\1: [changed]/' || true
    status=1
fi
exit "$status"
