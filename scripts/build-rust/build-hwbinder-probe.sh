#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 0 ]]; then
    echo 'Usage: bash scripts/build-rust/build-hwbinder-probe.sh' >&2
    exit 2
fi
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
mkdir -p out/bin
"$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++" \
    -std=c++17 -O2 -Wall -Wextra -Werror -fno-rtti -fno-exceptions \
    -static-libstdc++ -fPIE -pie native/hwbinder/hwbinder.cpp \
    native/hwbinder-probe/main.cpp -o out/bin/ssal-hwbinder-probe
