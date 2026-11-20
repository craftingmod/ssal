#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 1 ]]; then
    echo 'Usage: bash scripts/build-rust/build-virtual-audio.sh GUEST_ANDROID16_LIB_DIR' >&2
    exit 2
fi
ssal_guest_libs=$(realpath "$1")
ssal_headers="$PWD/.cache/android16-binder"
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
for library in libhidlbase.so libutils.so libcutils.so libc++.so; do
    [[ -f "$ssal_guest_libs/$library" ]] || { echo "Missing guest library: $library" >&2; exit 1; }
done
mkdir -p out/bin
"$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++" \
    -std=c++17 -O2 -Wall -Wextra -Werror -fno-rtti -fno-exceptions -fPIE -pie \
    -I native/virtual-audio/shim \
    -I "$ssal_headers/system/libhidl/base/include" \
    -I "$ssal_headers/system/libhidl/transport/include" \
    -I "$ssal_headers/system/libhwbinder/include" \
    -I "$ssal_headers/system/libfmq/base" \
    -I "$ssal_headers/system/core/libutils/include" \
    -I "$ssal_headers/system/core/libcutils/include" \
    -I "$ssal_headers/system/core/libsystem/include" \
    -I "$ssal_headers/system/logging/liblog/include" \
    -I "$ssal_headers/system/libbase/include" \
    native/virtual-audio/main.cpp -L "$ssal_guest_libs" \
    -nostdlib++ -Wl,--allow-shlib-undefined -lhidlbase -lutils -lcutils -lc++ -llog -ldl \
    -o out/bin/ssal-virtual-audio
"$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++" \
    -std=c++17 -O2 -Wall -Wextra -Werror -static-libstdc++ \
    native/virtual-audio/host_bridge.cpp -laaudio -o out/bin/ssal-audio-host
