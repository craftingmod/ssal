#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p out/phase8b3d/bin
cc="${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
"$cc" -Wall -Wextra -Werror -Os -shared -fPIC native/binder-probe/app-selinux-trace.c -ldl -o out/phase8b3d/bin/ssal-zygote-selinux-noop.so
"$cc" -Wall -Wextra -Werror -Os -DSSAL_APP_PROBE native/binder-probe/app-selinux-trace.c -ldl -o out/phase8b3d/bin/ssal-selinux-startup-probe
mkdir -p out/phase8b3d/fixed
"$cc" -Wall -Wextra -Werror -Os -DSSAL_APP_PROBE -DSSAL_APP_FIXED native/binder-probe/app-selinux-trace.c -ldl -o out/phase8b3d/fixed/ssal-selinux-startup-probe
python3 scripts/patch-app-selinux-same-context.py out/phase7fb/source/libselinux.so out/phase8b3d/fixed/ssal-libselinux-same-context.so > out/phase8b3d/patch-hashes.txt
# Staging-only names reuse the existing Guest runtime slots; never install as the default helper.
sed 's|/dev/ssal-phase8b3b|/dev/ssal-phase8b3d|; /set -eu/a export SSAL_PHASE8B3D_TRACE=1' scripts/run-phase8b3b.sh > out/phase8b3d/run.sh
