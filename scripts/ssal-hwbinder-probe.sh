#!/system/bin/sh
# The worker passes the identity of its private device after comparing it to Host.
set -eu

die() {
    echo "Guest HwBinder probe: $*" >&2
    exit 1
}

test "$#" = 2 || die 'expected MAJOR:MINOR and empty, live, allocator, or dead'
expected=$1
mode=$2
case "$mode" in empty|live|allocator|dead) ;; *) die "invalid mode: $mode" ;; esac

sid=$(id -Z)
test "$(id -u):$(id -g)" = 2000:2000 || die 'expected Guest shell credentials'
case "$sid" in u:r:ssal_*_shell:s0) ;; *) die "unexpected shell SID: $sid" ;; esac
test -c /dev/hwbinder || die '/dev/hwbinder is missing or not a character device'
hex=$(stat -Lc '%t:%T' /dev/hwbinder)
rdev=$(printf '%d:%d' "0x${hex%:*}" "0x${hex#*:}")
test "$rdev" = "$expected" || die "unexpected device $rdev, expected $expected"
for path in /dev/binder /dev/vndbinder /dev/binderfs/hwbinder /proc/1/root/dev/hwbinder; do
    if [ -e "$path" ] || [ -L "$path" ]; then die "unexpected endpoint $path"; fi
done
printf 'Guest HwBinder probe mode=%s rdev=%s sid=%s ready=%s\n' \
    "$mode" "$rdev" "$sid" "$(getprop hwservicemanager.ready)"

manager=android.hidl.manager@1.2::IServiceManager/default
token=android.hidl.token@1.0::ITokenManager/default
if [ "$mode" = empty ]; then
    rc=0
    timeout --foreground -k 1 2 /system/bin/lshal debug "$manager" || rc=$?
    test "$rc" = 124 || die "expected bounded wait in $mode mode, got $rc"
    printf 'guest_hwbinder_lookup_unavailable mode=%s exit=%s\n' "$mode" "$rc"
    exit 0
fi

test "$(getprop hwservicemanager.ready)" = true || die "expected readiness property in $mode mode"
if [ "$mode" = dead ]; then
    rc=0
    diagnostic=$(timeout --foreground -k 1 5 /system/bin/lshal debug "$manager" 2>&1 >/dev/null) || rc=$?
    printf '%s\n' "$diagnostic"
    test "$rc" != 124 || die "timed out waiting for DEAD_OBJECT"
    case "$diagnostic" in
        "Cannot get $manager: "*DEAD_OBJECT*) ;;
        *) die "expected DEAD_OBJECT on context-manager lookup" ;;
    esac
    echo 'guest_hwbinder_lookup_unavailable mode=dead status=DEAD_OBJECT'
    exit 0
fi

# lshal debug resolves the named object on handle 0 and invokes remote IBase::debug.
if [ "$mode" = allocator ]; then
    services='android.hidl.allocator@1.0::IAllocator/ashmem'
else
    services="$manager $token"
fi
for service in $services; do
    rc=0
    diagnostic=$(timeout --foreground -k 1 5 /system/bin/lshal debug "$service" 2>&1 >/dev/null) || rc=$?
    # lshal's transaction error flag can truncate to a zero process exit status.
    if [ "$rc" != 0 ] || [ -n "$diagnostic" ]; then
        die "HIDL lookup or debug failed for $service (exit $rc): $diagnostic"
    fi
    printf 'guest_hwbinder_hidl=PASS service=%s transaction=IBase::debug\n' "$service"
done
