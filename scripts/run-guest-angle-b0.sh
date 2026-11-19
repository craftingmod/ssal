#!/system/bin/sh
# Run as root in a new mount and network namespace with the staged GSI root.
set -eu
root=${1:?missing staged GSI root}
printf 'guest mount=%s network=%s context=' "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/net)"
cat /proc/self/attr/current | tr -d '\000'
printf '\n'
for path in vendor odm dev proc sys data linkerconfig; do
    if [ -e "$root/$path" ] || [ -L "$root/$path" ]; then
        echo "unexpected Guest root path: /$path" >&2
        exit 2
    fi
done
echo 'Guest /vendor /odm /dev /proc /sys /data /linkerconfig absent'

result=0
for backend in swiftshader vulkan; do
    rc=0
    timeout -k 3 25 env -i \
        LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/system/lib64 \
        /system/bin/chroot "$root" /apex/com.android.runtime/bin/linker64 /b0 "$backend" || rc=$?
    echo "exit $backend=$rc"
    if [ "$backend" = swiftshader ]; then
        result=$rc
    fi
done
exit "$result"
