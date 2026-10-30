#!/usr/bin/env bash
set -euo pipefail
cd /src
cargo build --locked --release --target aarch64-linux-android
mkdir -p out/bin
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal" out/bin/ssal
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssald" out/bin/ssald
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-selinux-identity" out/bin/ssal-selinux-identity
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-binder-access" out/bin/ssal-binder-access
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal-enforcing-binder" out/bin/ssal-enforcing-binder
