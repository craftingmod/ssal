#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cc="${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
cxx="${cc}++"
mkdir -p out/phase8b4b1/bin
dest=out/phase8b4b1/bin
"$cc" -Os -Wall -Wextra -Werror -shared -fPIC native/binder-probe/system-server-gate.c -ldl -o "$dest/ssal-system-server-gate.so"
"$cc" -Os -Wall -Wextra -Werror -DSSAL_GATE_WRAPPER native/binder-probe/system-server-gate.c -o "$dest/ssal-system-server-wrapper"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(pwd)/target}"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$cc"
cargo build --locked --release --target aarch64-linux-android --bin ssal-system-server-gate-probe --bin ssal-system-server-boundary
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-system-server-gate-probe" "$dest/ssal-system-server-gate-probe"
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-system-server-boundary" "$dest/ssal-system-server-boundary"
"$cxx" -std=c++17 -O2 -fPIE -pie -fno-exceptions -fno-rtti -Wall -Wextra -Werror -nostdlib++ \
  native/processgroup-probe/system-server.cpp -Lout/phase5b-processgroup/image \
  -lprocessgroup -l:libc++.so -Wl,--allow-shlib-undefined -o "$dest/ssal-system-server-cgroup-probe"
sha256sum "$dest"/*
