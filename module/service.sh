#!/system/bin/sh
MODDIR=${0%/*}
"$MODDIR/bin/ssald" >> /data/local/ssal/logs/daemon.log 2>&1 &
