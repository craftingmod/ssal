#!/system/bin/sh
[ "$ARCH" = arm64 ] || abort "ssal currently requires arm64"
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
