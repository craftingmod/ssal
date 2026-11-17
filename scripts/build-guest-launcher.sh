#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
bash scripts/build-android.sh
cargo build --locked --release --manifest-path experiments/apexservice/Cargo.toml --target aarch64-linux-android
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-apexservice" out/bin/ssal-apexservice
cargo build --locked --release --manifest-path tools/rsbinder/Cargo.toml --target aarch64-linux-android
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/phase3-ipc" out/bin/phase3-ipc
# The established Guest-only logger is built by build-binder-probe.sh.
test -s out/bin/ssal-phase2-log.so
"${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -shared -fPIC -Os -Wall -Wextra -Werror native/binder-probe/zygote-diagnostics.c \
    -ldl -o out/bin/ssal-zygote-diag.so
"${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -shared -fPIC -Os -Wall -Wextra -Werror native/binder-probe/zygote-fd-reopen.c \
    -ldl -o out/bin/ssal-zygote-fd-reopen.so
"${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -shared -fPIC -Os -Wall -Wextra -Werror native/binder-probe/zygote-selinux-noop.c \
    -ldl -o out/bin/ssal-zygote-selinux-noop.so
"${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -Os -Wall -Wextra -Werror native/binder-probe/selinux-startup-probe.c \
    -ldl -o out/bin/ssal-selinux-startup-probe
"${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -O2 -Wall -Wextra -Werror native/binder-probe/system-server-stall.c \
    -o out/bin/ssal-system-server-stall
"${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -O2 -Wall -Wextra -Werror native/binder-probe/ashmem-probe.c -ldl \
    -o out/bin/ssal-ashmem-probe
