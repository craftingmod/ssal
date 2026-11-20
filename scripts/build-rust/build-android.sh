#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"
build_target="${1:-all}"
if [[ $# -gt 1 ]] || [[ ! "$build_target" =~ ^(all|src|services|native|clean)$ ]]; then
    echo 'Usage: bash scripts/build-rust/build-android.sh [all|src|services|native|clean]' >&2
    exit 2
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
android_ndk="${ANDROID_NDK_HOME:-/opt/android-ndk}"
android_linker="$android_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
if [[ ! -x "$android_linker" ]]; then
    echo "Android NDK linker missing: $android_linker (set ANDROID_NDK_HOME)" >&2
    exit 1
fi
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_linker"
if [[ "$build_target" == clean ]]; then
    cargo clean --release --target aarch64-linux-android
    cargo clean --release --manifest-path services/Cargo.toml --target aarch64-linux-android
    rm -f out/bin/ssal out/bin/ssald out/bin/ssal-sepolicy out/bin/ssal-selinux-identity \
        out/bin/ssal-guest-domain-poc out/bin/ssal-binder-access out/bin/ssal-enforcing-binder \
        out/bin/ssal-property-service out/bin/ssal-lmkd out/bin/ssal-art-exec-proc \
        out/bin/ssal-ashmem-probe out/bin/ssal-selinux-startup-probe out/bin/ssal-system-server-stall \
        out/bin/ssal-apexservice out/bin/ssal-system-suspend out/bin/ssal-health \
        out/bin/ssal-gatekeeper out/bin/ssal-keymint out/bin/ssal-virtual-composer \
        out/bin/ssal-vold out/bin/ssal-netd out/bin/ssal-hwbinder-probe.sh \
        out/bin/ssal-hwbinder-probe out/bin/ssal-virtual-audio out/bin/ssal-audio-host \
        out/bin/ssal-context-map.so out/bin/ssal-phase2-log.so \
        out/bin/ssal-binder-ipc out/bin/ssal-zygote-diag.so out/bin/ssal-zygote-fd-reopen.so \
        out/bin/ssal-zygote-selinux-noop.so out/bin/fork-probe.jar out/bin/input-injector.jar
    build_target=all
fi
mkdir -p out/bin
if [[ "$build_target" == all || "$build_target" == src ]]; then
    cargo build --locked --release --target aarch64-linux-android
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal" out/bin/ssal
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssald" out/bin/ssald
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-sepolicy" out/bin/ssal-sepolicy
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-selinux-identity" out/bin/ssal-selinux-identity
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-guest-domain-poc" out/bin/ssal-guest-domain-poc
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-binder-access" out/bin/ssal-binder-access
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-enforcing-binder" out/bin/ssal-enforcing-binder
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-property-service" out/bin/ssal-property-service
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-lmkd" out/bin/ssal-lmkd
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-art-exec-proc" out/bin/ssal-art-exec-proc
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-ashmem-probe" out/bin/ssal-ashmem-probe
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-selinux-startup-probe" out/bin/ssal-selinux-startup-probe
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-system-server-stall" out/bin/ssal-system-server-stall
fi
if [[ "$build_target" == all || "$build_target" == services ]]; then
    cargo build --locked --release --manifest-path services/Cargo.toml --workspace --target aarch64-linux-android
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-apexservice" out/bin/ssal-apexservice
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-system-suspend" out/bin/ssal-system-suspend
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-health" out/bin/ssal-health
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-gatekeeper" out/bin/ssal-gatekeeper
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-keymint" out/bin/ssal-keymint
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-virtual-composer" out/bin/ssal-virtual-composer
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-vold" out/bin/ssal-vold
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-netd" out/bin/ssal-netd
fi
if [[ "$build_target" == all || "$build_target" == native ]]; then
    install -m 755 scripts/ssal-hwbinder-probe.sh out/bin/ssal-hwbinder-probe.sh
    bash scripts/build-rust/build-hwbinder-probe.sh
    bash scripts/build-rust/build-virtual-audio.sh
    bash scripts/build-rust/build-jars.sh
    cargo build --locked --release --manifest-path tools/rsbinder/Cargo.toml --target aarch64-linux-android
    install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-binder-ipc" out/bin/ssal-binder-ipc
    android30_linker="$android_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
    for lib in zygote-diagnostics:ssal-zygote-diag zygote-fd-reopen:ssal-zygote-fd-reopen zygote-selinux-noop:ssal-zygote-selinux-noop; do
        "$android30_linker" -shared -fPIC -Os -Wall -Wextra -Werror "native/binder-probe/${lib%%:*}.c" \
            -ldl -o "out/bin/${lib##*:}.so"
    done
    "$android_linker" -shared -fPIC -O2 -Wall -Wextra -Werror native/binder-probe/context-map.c -ldl -o out/bin/ssal-context-map.so
    "$android_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
        -shared -fPIC -Os -Wall -Wextra -Werror native/binder-probe/log-to-stderr.c \
        -llog -o out/bin/ssal-phase2-log.so
fi
