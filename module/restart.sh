#!/system/bin/sh
MODDIR=${0%/*}
ROOT=/data/local/ssal
LOCK="$ROOT/run/restart.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
    echo 'restart already running or daemon directories unavailable' >&2
    exit 1
fi
trap 'rmdir "$LOCK"' EXIT
pid=$(pidof ssald)
if "$MODDIR/bin/ssal" status >/dev/null 2>&1; then
    "$MODDIR/bin/ssal" stop-for-restart || exit 1
    i=0
    while [ "$i" -lt 50 ] && pidof ssald >/dev/null 2>&1; do
        sleep 0.1
        i=$((i + 1))
    done
    if pidof ssald >/dev/null 2>&1; then echo 'daemon did not stop' >&2; exit 1; fi
elif [ -n "$pid" ]; then
    echo 'daemon is running but not responding' >&2
    exit 1
fi
"$MODDIR/bin/ssald" >> "$ROOT/logs/daemon.log" 2>&1 &
i=0
while [ "$i" -lt 50 ]; do
    if "$MODDIR/bin/ssal" status >/dev/null 2>&1; then exit 0; fi
    sleep 0.1
    i=$((i + 1))
done
echo 'daemon did not become ready; check daemon.log' >&2
exit 1
