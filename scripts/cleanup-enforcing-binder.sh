#!/system/bin/sh
# Cleanup only explicitly named disposable enforcing-probe directories.
set -eu
for ssal_base in "$@"; do
    case "$ssal_base" in
        /data/local/tmp/ssal-enforcing-*) ;;
        *) echo "refused cleanup path: $ssal_base" >&2; exit 40 ;;
    esac
    [ "$(readlink -f "$ssal_base")" = "$ssal_base" ] || exit 41
    [ -d "$ssal_base" ] && [ ! -L "$ssal_base" ] || exit 42
    if grep -F "$ssal_base" /proc/self/mountinfo; then exit 43; fi
    for ssal_backing in /sys/block/loop*/loop/backing_file; do
        [ -r "$ssal_backing" ] || continue
        if grep -F "$ssal_base" "$ssal_backing"; then exit 44; fi
    done
    for ssal_link in /proc/[0-9]*/exe; do
        ssal_target=$(readlink "$ssal_link" 2>/dev/null || true)
        case "$ssal_target" in
            "$ssal_base"|"$ssal_base"/*) echo "owned executable remains: $ssal_link $ssal_target"; exit 45 ;;
        esac
    done
    # Exact canonical path was checked above. No lazy unmount, daemon kill or
    # policy restoration command is hidden in scratch deletion.
    rm -rf -- "$ssal_base"
    [ ! -e "$ssal_base" ] || exit 46
    echo "CLEANUP_PASSED $ssal_base"
done
