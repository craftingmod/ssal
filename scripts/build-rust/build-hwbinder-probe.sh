#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 1 ]]; then
    echo 'Usage: bash scripts/build-rust/build-hwbinder-probe.sh GUEST_ANDROID16_LIB_DIR' >&2
    exit 2
fi
ssal_guest_libs=$(realpath "$1")
ssal_headers="$PWD/.cache/android16-binder"
ssal_revision=android-16.0.0_r2
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
for library in libhidlbase.so libutils.so libc++.so; do
    [[ -f "$ssal_guest_libs/$library" ]] || { echo "Missing guest library: $library" >&2; exit 1; }
done
fetch_headers() {
    local repo=$1 subtree=$2
    local destination="$ssal_headers/$repo/$subtree"
    local archive="$ssal_headers/${repo//\//_}-${subtree//\//_}.tar.gz"
    if [[ ! -f "$destination/.ssal-source" ]]; then
        mkdir -p "$destination"
        curl -fsSL --retry 2 --connect-timeout 10 --max-time 60 \
            "https://android.googlesource.com/platform/$repo/+archive/$ssal_revision/$subtree.tar.gz" -o "$archive"
        tar --warning=no-timestamp -xzf "$archive" -C "$destination"
        printf '%s\n' "$ssal_revision" > "$destination/.ssal-source"
    fi
}
fetch_headers system/libhidl base/include
fetch_headers system/libhidl transport/include
fetch_headers system/libhwbinder include
fetch_headers system/libfmq base
fetch_headers system/core libutils/include
fetch_headers system/core libcutils/include
fetch_headers system/core libsystem/include
fetch_headers system/logging liblog/include
fetch_headers system/libbase include
mkdir -p out/bin
"$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++" \
    -std=c++17 -O2 -Wall -Wextra -Werror -fno-rtti -fno-exceptions -fPIE -pie \
    -I "$ssal_headers/system/libhidl/base/include" \
    -I "$ssal_headers/system/libhidl/transport/include" \
    -I "$ssal_headers/system/libhwbinder/include" \
    -I "$ssal_headers/system/core/libutils/include" \
    -I "$ssal_headers/system/core/libcutils/include" \
    -I "$ssal_headers/system/core/libsystem/include" \
    -I "$ssal_headers/system/logging/liblog/include" \
    -I "$ssal_headers/system/libbase/include" \
    native/hwbinder-probe/main.cpp -L "$ssal_guest_libs" \
    -nostdlib++ -Wl,--allow-shlib-undefined -lhidlbase -lutils -lc++ -llog -ldl -o out/bin/ssal-hwbinder-probe
