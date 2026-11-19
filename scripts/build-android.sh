#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
android_ndk="${ANDROID_NDK_HOME:-/opt/android-ndk}"
android_linker="$android_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
if [[ ! -x "$android_linker" ]]; then
    echo "Android NDK linker missing: $android_linker (set ANDROID_NDK_HOME)" >&2
    exit 1
fi
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_linker"
cargo build --locked --release --target aarch64-linux-android
cargo build --locked --release --manifest-path experiments/apexservice/Cargo.toml --target aarch64-linux-android
cargo build --locked --release --manifest-path experiments/system-suspend/Cargo.toml --target aarch64-linux-android
cargo build --locked --release --manifest-path experiments/health/Cargo.toml --target aarch64-linux-android
cargo build --locked --release --manifest-path experiments/virtual-composer/Cargo.toml --target aarch64-linux-android
mkdir -p out/bin
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-apexservice" out/bin/ssal-apexservice
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-system-suspend" out/bin/ssal-system-suspend
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-health" out/bin/ssal-health
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-virtual-composer" out/bin/ssal-virtual-composer
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal" out/bin/ssal
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssald" out/bin/ssald
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-sepolicy" out/bin/ssal-sepolicy
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-selinux-identity" out/bin/ssal-selinux-identity
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-guest-domain-poc" out/bin/ssal-guest-domain-poc
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-binder-access" out/bin/ssal-binder-access
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-enforcing-binder" out/bin/ssal-enforcing-binder
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-property-service" out/bin/ssal-property-service
install -m 755 scripts/ssal-hwbinder-probe.sh out/bin/ssal-hwbinder-probe.sh
if [[ -f .cache/android16-hwbinder-libs/libhidlbase.so ]]; then
    bash scripts/build-hwbinder-probe.sh .cache/android16-hwbinder-libs
fi
"$android_linker" -shared -fPIC -O2 -Wall -Wextra -Werror native/binder-probe/context-map.c -ldl -o out/bin/ssal-context-map.so
"$android_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
    -shared -fPIC -Os -Wall -Wextra -Werror native/binder-probe/log-to-stderr.c \
    -llog -o out/bin/ssal-phase2-log.so
