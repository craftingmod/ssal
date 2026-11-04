#!/system/bin/sh
set -eu
bin=/data/local/tmp/ssal-common-launcher
stage="$bin/run-$(date +%s)"
mkdir -p "$stage/worker/system" "$stage/worker/data"
snapshot() {
    getenforce
    cat /proc/sys/kernel/random/boot_id
    sha256sum /proc/1/mountinfo
    stat -c '%n %d %i %a %u %g' /data /dev/__properties__ /dev/socket/property_service /dev/binder
    for key in ro.build.version.sdk ro.boot.serialno init.svc.zygote init.svc.installd init.svc.artd; do
        echo "$key=$(getprop "$key")"
    done
    service check aidl_lazy_test_1
    for name in init zygote64 system_server servicemanager surfaceflinger adbd netd lmkd installd artd; do
        for pid in $(pidof "$name" || true); do
            echo "host_process=$name"
            awk '{print $1,$2,$22}' "/proc/$pid/stat"
            cat "/proc/$pid/attr/current"
            grep -E '^(Uid|Gid|Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Seccomp):' "/proc/$pid/status"
            readlink "/proc/$pid/root" "/proc/$pid/exe" "/proc/$pid/ns/mnt"
        done
    done
}
test "$(getenforce)" = Enforcing
snapshot > "$stage/before.txt"
set +e
"$bin/ssald" "${1:---guest-service-worker}" \
    /data/local/ssal/images/1793366406758-25627/system.img \
    /data/local/ssal/guests/phase5a-bringup-20261104/userdata \
    "$stage/worker" > "$stage/worker.log" 2>&1
status=$?
set -e
cat "$stage/worker.log"
snapshot > "$stage/after.txt"
echo "worker_exit=$status stage=$stage"
if cmp -s "$stage/before.txt" "$stage/after.txt"; then
    echo HOST_ENFORCING_CORE_PROCESSES_ENDPOINTS=UNCHANGED
else
    diff -u "$stage/before.txt" "$stage/after.txt" || true
    status=1
fi
exit "$status"
