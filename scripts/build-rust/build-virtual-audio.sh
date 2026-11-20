#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $# != 0 ]]; then
    echo 'Usage: bash scripts/build-rust/build-virtual-audio.sh' >&2
    exit 2
fi
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
ssal_cxx="$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++"
mkdir -p out/bin
"$ssal_cxx" -std=c++17 -O2 -Wall -Wextra -Werror -fno-rtti -fno-exceptions \
    -static-libstdc++ -fPIE -pie native/hwbinder/hwbinder.cpp \
    native/virtual-audio/fmq.cpp native/virtual-audio/main.cpp -o out/bin/ssal-virtual-audio
"$ssal_cxx" -std=c++17 -O2 -Wall -Wextra -Werror -static-libstdc++ \
    native/virtual-audio/host_bridge.cpp -laaudio -o out/bin/ssal-audio-host
