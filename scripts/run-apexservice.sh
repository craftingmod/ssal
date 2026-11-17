#!/system/bin/sh
# One registration check, then one SystemServer run. Keep evidence for review/cleanup.
set -eu
test "$#" = 4
bindir=$1
system=$2
profile=$3
stage=$4
userdata=$profile/.userdata-apexservice.img
test "$(getenforce)" = Enforcing
test "$(getprop sys.boot_completed)" = 1
test -s "$system"
test -s "$profile/userdata.img"
test -s "$profile/selinux/applied.json"
test ! -e "$userdata"
test ! -e "$stage/check"
test ! -e "$stage/boot"
snapshot() {
    getenforce
    cat /proc/sys/kernel/random/boot_id
    pidof system_server apexd
    sha256sum /proc/1/mountinfo /apex/apex-info-list.xml /sys/fs/selinux/policy
    getprop init.svc.apexd
    stat -c '%n %s %Y %i' "$profile/userdata.img" "$system"
}
mkdir -p "$stage"
snapshot > "$stage/host-before.txt"
cp -p "$profile/userdata.img" "$userdata"
cmp -s "$profile/userdata.img" "$userdata"
test "$(stat -c %i "$profile/userdata.img")" != "$(stat -c %i "$userdata")"
chcon u:object_r:ssal_userdata_image_file:s0 "$userdata"
mkdir -p "$stage/check/system" "$stage/check/data"
set +e
SSAL_GUEST_APEX_CHECK_ONLY=1 SSAL_MEMORY_HIGH=1073741824 SSAL_MEMORY_MAX=1610612736 \
    "$bindir/ssald" --guest-service-worker "$system" "$userdata" "$stage/check" > "$stage/check.log" 2>&1
rc=$?
set -e
echo "registration_exit=$rc" > "$stage/result.txt"
snapshot > "$stage/host-after-check.txt"
if [ "$rc" != 0 ] || ! grep -q 'guest_apex_aidl=PASS' "$stage/check.log"; then
    echo FIRST_BLOCKER=GUEST_BINDER_REGISTRATION_OR_QUERY >> "$stage/result.txt"
    exit 1
fi
cmp -s "$stage/host-before.txt" "$stage/host-after-check.txt"
mkdir -p "$stage/boot/system" "$stage/boot/data"
set +e
SSAL_CONTEXT_MAP_AVC_RESET=1 SSAL_CONTEXT_MAP_RAW_SETCON=1 SSAL_START_SYSTEM_SERVER=1 \
SSAL_MEMORY_HIGH=1073741824 SSAL_MEMORY_MAX=1610612736 \
    "$bindir/ssald" --guest-zygote-7a-worker "$system" "$userdata" "$stage/boot" > "$stage/boot.log" 2>&1
rc=$?
set -e
echo "boot_exit=$rc" >> "$stage/result.txt"
snapshot > "$stage/host-after-boot.txt"
cmp -s "$stage/host-before.txt" "$stage/host-after-boot.txt"
echo HOST_SNAPSHOT=UNCHANGED >> "$stage/result.txt"
exit "$rc"
