#!/system/bin/sh
# Disposable diagnostic: invoke with unshare -m; no persistent policy rules.
set -eu
SOURCE=$1
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ]
/data/adb/ksu/bin/busybox mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /mnt
ALIAS_MOUNTED=0
BINDER_MOUNTED=0
cleanup() {
    if [ "$ALIAS_MOUNTED" = 1 ]; then umount /mnt/binder || exit 1; fi
    if [ "$BINDER_MOUNTED" = 1 ]; then umount /mnt/binderfs || exit 1; fi
    umount /mnt || exit 1
    echo CLEANUP_PASSED
}
trap cleanup EXIT
mkdir /mnt/binderfs
touch /mnt/binder
cp "$SOURCE" /mnt/ssal-binder-access
chmod 0755 /mnt/ssal-binder-access
chcon u:object_r:servicemanager_exec:s0 /mnt/ssal-binder-access
echo 'INITIAL_USER_NAMESPACES'
readlink /proc/self/ns/user /proc/1/ns/user || echo user_namespace_links_unavailable
echo 'ASSOCIATION_AV'
CLASS=$(cat /sys/fs/selinux/class/filesystem/index)
PERM=$(cat /sys/fs/selinux/class/filesystem/perms/associate)
MASK=$(printf '%x' "$((1 << (PERM - 1)))")
for FS in binder_device tmpfs binderfs; do
    exec 3<> /sys/fs/selinux/access
    printf 'u:object_r:binder_device:s0 u:object_r:%s:s0 %s %s' "$FS" "$CLASS" "$MASK" >&3
    echo "binder_device -> $FS"
    cat <&3
    echo
    exec 3>&-
done
for OPTIONS in max=4 max=4,context=u:object_r:binder_device:s0 max=4,context=u:object_r:binder_device:s0,fscontext=u:object_r:tmpfs:s0; do
    echo "MOUNT_CASE $OPTIONS"
    if /mnt/ssal-binder-access mount /mnt/binderfs "$OPTIONS"; then
        BINDER_MOUNTED=1
        ls -laZ /mnt/binderfs
        stat -c 'private %d %i %t:%T' /mnt/binderfs/binder
        chown 1000:1000 /mnt/binderfs/binder
        chmod 0600 /mnt/binderfs/binder
        MAJOR=$(stat -c %t /mnt/binderfs/binder)
        MINOR=$(stat -c %T /mnt/binderfs/binder)
        /data/adb/ksu/bin/busybox mount --bind /mnt/binderfs/binder /mnt/binder
        ALIAS_MOUNTED=1
        /data/adb/ksu/bin/busybox setuidgid 1000 runcon u:r:servicemanager:s0 /mnt/ssal-binder-access access /mnt/binder "$((0x$MAJOR))" "$((0x$MINOR))" || echo "TARGET_EXIT=$?"
        umount /mnt/binder
        ALIAS_MOUNTED=0
        umount /mnt/binderfs
        BINDER_MOUNTED=0
    fi
done
