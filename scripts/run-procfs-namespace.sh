#!/system/bin/sh
set -eu
bin=/dev/ssal-phase8b4b2
stage="$bin/run-$(date +%s)"
mkdir -p "$stage"
snapshot() {
    cat /proc/1/mountinfo
    echo SUPERVISOR_MOUNTINFO
    cat /proc/self/mountinfo
    echo ENFORCING
    cat /sys/fs/selinux/enforce
    echo NAMESPACES
    readlink /proc/1/ns/mnt
    readlink /proc/self/ns/mnt
}
snapshot > "$stage/before.txt"
set +e
"$bin/ssal-procfs-namespace" > "$stage/probe.txt" 2>&1
result=$?
set -e
snapshot > "$stage/after.txt"
cat "$stage/probe.txt"
if cmp -s "$stage/before.txt" "$stage/after.txt"; then
    echo INDEPENDENT_HOST_SNAPSHOT=UNCHANGED
else
    echo INDEPENDENT_HOST_SNAPSHOT=FAIL
    result=4
fi
echo "stage=$stage exit=$result"
exit "$result"
