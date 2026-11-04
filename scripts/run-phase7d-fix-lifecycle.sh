#!/system/bin/sh
set -eu
mode=${1:?expected INT, TERM, HUP, timeout, or leader}
case "$mode" in INT|TERM|HUP|timeout|leader) ;; *) exit 2;; esac
base=/data/local/tmp/ssal-7dfix
stage="$base/lifecycle-$mode-final"
mkdir -m 700 "$stage" "$stage/worker" "$stage/worker/system" "$stage/worker/data"
snapshot() {
    getenforce
    cat /proc/sys/kernel/random/boot_id
    for group in /sys/fs/cgroup /sys/fs/cgroup/apps; do echo "$group=$(cat "$group/cgroup.subtree_control")"; done
    for name in init zygote64 system_server servicemanager surfaceflinger adbd netd lmkd installd; do
        for pid in $(pidof "$name" || true); do
            echo "host=$name"
            awk '{print $1,$2,$22}' "/proc/$pid/stat"
            cat "/proc/$pid/attr/current" "/proc/$pid/cgroup"
        done
    done
}
test "$(getenforce)" = Enforcing
test -z "$(cat /sys/fs/cgroup/cgroup.subtree_control)"
test -z "$(cat /sys/fs/cgroup/apps/cgroup.subtree_control)"
test ! -e /sys/fs/cgroup/apps/ssal_guest
snapshot > "$stage/before.txt"
if test "$mode" = timeout; then
    export SSAL_PHASE7D_FIX_TIMEOUT=1
else
    export SSAL_PHASE7D_FIX_HOLD=1
fi
export SSAL_PHASE7D_FIX_HELPER="$base/helper-final"
"/dev/ssal-common-launcher/ssald" --guest-memory-worker \
    /data/local/ssal/images/1793366406758-25627/system.img \
    /data/local/ssal/guests/phase5a-bringup-20261104/userdata "$stage/worker" > "$stage/worker.log" 2>&1 &
worker=$!
trap 'if kill -0 "$worker" 2>/dev/null; then kill -TERM "$worker" 2>/dev/null || true; wait "$worker" 2>/dev/null || true; fi' EXIT
ready=0
for n in $(seq 1 800); do
    if grep -q GUEST_LIFECYCLE_WAIT "$stage/worker.log"; then ready=1; break; fi
    if ! kill -0 "$worker" 2>/dev/null; then break; fi
    sleep 0.05
done
if test "$ready" = 1; then
    group=/sys/fs/cgroup/apps/ssal_guest
    for name in cgroup.procs cgroup.events memory.current memory.peak memory.high memory.max memory.events memory.stat memory.pressure; do
        echo "--- $name" >> "$stage/memory.txt"
        cat "$group/$name" >> "$stage/memory.txt" 2>> "$stage/memory.txt" || echo unavailable >> "$stage/memory.txt"
    done
    for pid in $(sed -n 's/^GUEST_CHILD pid=\([0-9]*\).*/\1/p; s/^GUEST_MEMORY_PROBE pid=\([0-9]*\).*/\1/p' "$stage/worker.log"); do
        echo "PID=$pid" >> "$stage/processes.txt"
        cat "/proc/$pid/cgroup" >> "$stage/processes.txt"
        awk '{print $1,$22}' "/proc/$pid/stat" >> "$stage/identities.txt"
    done
    if test "$mode" = leader; then
        leader=$(sed -n 's/^GUEST_MEMORY_PROBE pid=\([0-9]*\).*/\1/p' "$stage/worker.log")
        grep -q '^0::/apps/ssal_guest/phase7d_fix$' "/proc/$leader/cgroup"
        kill -KILL "$leader"
        for n in $(seq 1 100); do
            state=$(awk '{print $3}' "/proc/$leader/stat" 2>/dev/null || true)
            test "$state" = Z && break
            sleep 0.02
        done
        test "$state" = Z
        echo LEADER_EXIT_OBSERVED
        kill -TERM "$worker"
    elif test "$mode" != timeout; then
        kill -s "$mode" "$worker"
    fi
else
    kill -TERM "$worker" 2>/dev/null || true
fi
set +e
wait "$worker"
status=$?
set -e
trap - EXIT
snapshot > "$stage/after.txt"
echo "ready=$ready worker_exit=$status"
tail -15 "$stage/worker.log"
test "$ready" = 1
test "$status" != 0
if test "$mode" = timeout; then grep -q 'Guest lifecycle test timeout' "$stage/worker.log"; else grep -q 'Guest worker interrupted' "$stage/worker.log"; fi
while read pid start; do
    if test -r "/proc/$pid/stat" && test "$(awk '{print $22}' "/proc/$pid/stat")" = "$start"; then echo "residual_pid=$pid"; exit 1; fi
done < "$stage/identities.txt"
test ! -e /sys/fs/cgroup/apps/ssal_guest
cmp "$stage/before.txt" "$stage/after.txt"
echo LIFECYCLE_PASS
