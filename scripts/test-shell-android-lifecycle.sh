#!/system/bin/sh
# Device-only failure injection: signals only a process with this profile's mapped SID.
set -eu
bin=${1:?ssal binary required}
system=${2:?system image required}
userdata=${3:?userdata image required}
out=${4:?evidence directory required}
profile_dir=${userdata%/*}
profile=${profile_dir##*/}
id=$(sed -n 's/.*"selinux_id": "\([^"]*\)".*/\1/p' "$profile_dir/profile.json")
test -n "$id"
stage=/data/local/ssal/mnt/shell-lifecycle-$$
mkdir -p "$out" "$stage/system" "$stage/data"
cat /proc/sys/kernel/random/boot_id > "$out/before.boot"
sha256sum /proc/1/mountinfo > "$out/before.mounts"
pidof system_server > "$out/before.systemserver"
SSAL_START_SYSTEM_SERVER=1 "${bin%/*}/ssald" --guest-zygote-7a-worker "$system" "$userdata" "$stage" > "$out/android.log" 2>&1 &
android=$!
sleep 1
# shellcheck disable=SC2016
"$bin" exec "$profile" -- /system/bin/sh -c 'id; echo BOOTING_SHELL_READY; sleep 90; test "$(getprop ro.build.version.sdk)" = 36; echo SHELL_SURVIVED_ANDROID_FAILURE' > "$out/shell.stdout" 2> "$out/shell.stderr" &
shell=$!
ready=false
for _ in $(seq 1 600); do
    if grep -q BOOTING_SHELL_READY "$out/shell.stdout"; then ready=true; break; fi
    if ! kill -0 "$shell" 2>/dev/null; then break; fi
    sleep 1
done
if [ "$ready" != true ]; then
    echo "FAIL: Shell while Android booting; see $out"
    wait "$android" || true
    wait "$shell" || true
    exit 1
fi
injected=false
for _ in $(seq 1 60); do
        for pid in $(pidof system_server || true); do
            context=$(tr -d '\000' < "/proc/$pid/attr/current" 2>/dev/null || true)
            case "$context" in
                u:r:ssal_"$id"_system_server:s0|u:r:ssal_"$id"_system_server_startup:s0)
                    echo "Guest failure injection: pid=$pid sid=$context"
                    kill -KILL "$pid"
                    injected=true
                    break 2
                    ;;
            esac
        done
    sleep 1
done
if [ "$injected" != true ]; then
    for pid in $(pidof servicemanager || true); do
        context=$(tr -d '\000' < "/proc/$pid/attr/current" 2>/dev/null || true)
        if [ "$context" = "u:r:ssal_${id}_servicemanager:s0" ]; then
            echo "SystemServer not reached; Guest servicemanager failure injection: pid=$pid sid=$context"
            kill -KILL "$pid"
            injected=true
        fi
    done
fi
wait "$shell"
grep -q SHELL_SURVIVED_ANDROID_FAILURE "$out/shell.stdout"
set +e
wait "$android"
status=$?
set -e
echo "Android worker exit=$status injected=$injected stage=$stage"
test "$status" != 0
test ! -e "$profile_dir/environment.json"
test "$(cat /sys/fs/selinux/enforce)" = 1
cat /proc/sys/kernel/random/boot_id > "$out/after.boot"
sha256sum /proc/1/mountinfo > "$out/after.mounts"
pidof system_server > "$out/after.systemserver"
cmp "$out/before.boot" "$out/after.boot"
cmp "$out/before.mounts" "$out/after.mounts"
cmp "$out/before.systemserver" "$out/after.systemserver"
echo "PASS: Shell while booting, Shell after Android failure, cleanup and Host unchanged"
