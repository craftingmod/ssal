#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dest=out/phase8b4b2/bin
mkdir -p "$dest"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(pwd)/target}"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
cargo build --locked --release --target aarch64-linux-android --bin ssal-procfs-namespace
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-procfs-namespace" "$dest/ssal-procfs-namespace"
cargo test --locked --bin ssal-procfs-namespace
bash -n scripts/run-procfs-namespace.sh
sha256sum "$dest/ssal-procfs-namespace"
