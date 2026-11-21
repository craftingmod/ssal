#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 0 ]]; then
    echo 'Usage: bash scripts/build-rust/build-sensor-host.sh' >&2
    exit 2
fi
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
ssal_cxx="$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++"
mkdir -p out/bin
"$ssal_cxx" -std=c++17 -O2 -Wall -Wextra -Werror -static-libstdc++ \
    native/sensor-host/main.cpp -landroid -o out/bin/ssal-sensor-host
