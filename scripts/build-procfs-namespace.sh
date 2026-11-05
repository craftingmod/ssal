#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dest=out/phase8b4b2/bin
mkdir -p "$dest"
cc="${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
"$cc" -O2 -Wall -Wextra -Werror native/binder-probe/procfs-namespace.c -ldl -o "$dest/ssal-procfs-namespace"
cc -O2 -Wall -Wextra -Werror native/binder-probe/procfs-namespace.c -ldl -o "$dest/self-test"
"$dest/self-test" --self-test
bash -n scripts/run-procfs-namespace.sh
sha256sum "$dest/ssal-procfs-namespace"
