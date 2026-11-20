#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
# Link to the actual image library; never rebuild or replace libprocessgroup.
image="${1:-out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img}"
test -s "$image"
image_libs=out/phase5b-processgroup/image
mkdir -p "$image_libs"
for name in libprocessgroup.so libc++.so; do
  debugfs -R "dump /system/lib64/$name $image_libs/$name" "$image"
done
test -s "$image_libs/libprocessgroup.so"
test -s "$image_libs/libc++.so"
mkdir -p out/bin
/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++ \
  -std=c++17 -O2 -fPIE -pie -fno-exceptions -fno-rtti -Wall -Wextra -Werror \
  -nostdlib++ native/processgroup-probe/main.cpp -L"$image_libs" \
  -lprocessgroup -l:libc++.so -Wl,--allow-shlib-undefined \
  -o out/bin/ssal-processgroup-probe
sha256sum out/bin/ssal-processgroup-probe "$image_libs/libprocessgroup.so"
