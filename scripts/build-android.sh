#!/usr/bin/env bash
set -euo pipefail
cd /src
cargo build --locked --release --target aarch64-linux-android
mkdir -p out/bin
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssal" out/bin/ssal
install -m 755 "$CARGO_TARGET_DIR/aarch64-linux-android/release/ssald" out/bin/ssald
python3 scripts/package-module.py
