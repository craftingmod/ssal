#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p out
"${CXX:-g++}" -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=undefined -pthread \
    native/hwbinder/hwbinder.cpp native/virtual-audio/fmq.cpp native/hwbinder/test.cpp \
    -o out/hwbinder-selfcheck
out/hwbinder-selfcheck
"${CXX:-g++}" -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=undefined -pthread \
    native/hwbinder/hwbinder.cpp native/virtual-audio/fmq.cpp native/virtual-audio/test.cpp \
    -o out/audio-selfcheck
out/audio-selfcheck
bash scripts/build-rust/build-hwbinder-probe.sh
bash scripts/build-rust/build-virtual-audio.sh
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
for helper in ssal-hwbinder-probe ssal-virtual-audio ssal-audio-host; do
    dependencies=$("$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf" \
        -d "out/bin/$helper" | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p')
    while IFS= read -r library; do
        case "$library" in
            libc.so|libm.so|libdl.so) ;;
            libaaudio.so) [[ "$helper" == ssal-audio-host ]] ;;
            *) echo "Unexpected $helper dependency: $library" >&2; exit 1 ;;
        esac
    done <<< "$dependencies"
    printf '%s: NDK-only dependencies verified\n' "$helper"
done
