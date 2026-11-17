#!/system/bin/sh
# Run as root on a device; binaries remain beside ssald and its property helper.
set -eu
bin=${1:-/data/adb/modules/ssal/bin/ssal}
profile=${2:-y702}
out=${3:-/data/local/tmp/ssal-shell-test}
mkdir -p "$out"
cat /proc/sys/kernel/random/boot_id > "$out/before.boot"
sha256sum /proc/1/mountinfo > "$out/before.mounts"
pidof system_server > "$out/before.systemserver"
"$bin" exec "$profile" -- /system/bin/sh -c 'id; echo SHELL_READY; sleep 45' > "$out/holder.stdout" 2> "$out/holder.stderr" &
holder=$!
ready=false
for _ in $(seq 1 600); do
    if grep -q SHELL_READY "$out/holder.stdout"; then ready=true; break; fi
    if ! kill -0 "$holder" 2>/dev/null; then break; fi
    sleep 1
done
if [ "$ready" != true ]; then
    wait "$holder" || true
    echo "FAIL: standalone Shell startup; see $out/holder.stderr"
    exit 1
fi
# shellcheck disable=SC2016
"$bin" exec "$profile" -- /system/bin/sh -c '
set -eu
test "$(id -u)" = 2000
test "$(id -g)" = 2000
test -w "$HOME"
printf scratch > "$TMPDIR/ssal-shell-test"
test "$(cat "$TMPDIR/ssal-shell-test")" = scratch
rm "$TMPDIR/ssal-shell-test"
id
cat /proc/self/attr/current
grep Cap /proc/self/status
test "$(grep CapBnd /proc/self/status | tr -dc 0-9)" = 0000000000000000
ls -l /proc/self/fd
test ! -e /dev/binder
test ! -e /dev/hwbinder
test ! -e /dev/socket/init
test ! -e /.ssal-old-root
test -z "$(getprop sys.boot_completed)"
getprop ro.build.version.sdk
if ls /proc/1/root >/dev/null 2>&1; then echo HOST_PROC_ROOT_EXPOSED; exit 1; fi
echo SHELL_ISOLATION_PASS
' > "$out/attached.stdout" 2> "$out/attached.stderr"
set +e
"$bin" exec "$profile" -- /system/bin/sh -c 'exit 37' > "$out/exit.stdout" 2> "$out/exit.stderr"
code=$?
set -e
test "$code" = 37
printf 'id\ngetprop ro.build.version.sdk\n' | "$bin" exec "$profile" -- /system/bin/sh > "$out/stdin.stdout" 2> "$out/stdin.stderr"
grep -q 'uid=2000' "$out/stdin.stdout"
grep -q '^36$' "$out/stdin.stdout"
# shellcheck disable=SC2016
"$bin" exec "$profile" -- /system/bin/sh -c 'sleep 60 & echo $!' > "$out/background.stdout" 2> "$out/background.stderr"
if [ ! -e /proc/self/ns/pid ]; then
    test ! -d "/proc/$(cat "$out/background.stdout")"
fi
echo "PASS: standalone, attach, UID/GID, FD, properties, proc boundary, exit status"
wait "$holder"
test ! -e "/data/local/ssal/guests/$profile/environment.json"
cat /proc/sys/kernel/random/boot_id > "$out/after.boot"
sha256sum /proc/1/mountinfo > "$out/after.mounts"
pidof system_server > "$out/after.systemserver"
cmp "$out/before.boot" "$out/after.boot"
cmp "$out/before.mounts" "$out/after.mounts"
cmp "$out/before.systemserver" "$out/after.systemserver"
test "$(cat /sys/fs/selinux/enforce)" = 1
echo "PASS: session cleanup, Host mount namespace, boot ID, SystemServer, Enforcing"
