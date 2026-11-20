#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
cc="${ANDROID_NDK_HOME:-/opt/android-ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
output="${1:-out/bin/ssal-graphics-buffer-probe}"
mkdir -p "$(dirname "$output")"
"$cc" -std=c11 -O2 -Wall -Wextra -Werror native/graphics-buffer-probe.c \
  -landroid -lEGL -lGLESv3 -o "$output"
