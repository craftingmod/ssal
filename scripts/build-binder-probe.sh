#!/usr/bin/env bash
set -euo pipefail
cd /src
if [[ $# != 1 ]]; then
    echo 'Usage: bash scripts/build-binder-probe.sh GUEST_ANDROID16_LIB_DIR' >&2
    exit 2
fi
ssal_guest_libs=$(realpath "$1")
ssal_headers=/src/.cache/android16-binder
ssal_revision=android-16.0.0_r2
ssal_ndk=${ANDROID_NDK_HOME:-/opt/android-ndk}
for library in libbinder.so libutils.so libc++.so; do
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
fetch_headers frameworks/native libs/binder/include
fetch_headers system/core libutils/include
fetch_headers system/core libutils/binder/include
fetch_headers system/core libcutils/include
fetch_headers system/core libsystem/include
fetch_headers system/logging liblog/include
fetch_headers system/libbase include
mkdir -p out/bin
"$ssal_ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++" \
    -std=c++17 -Wall -Wextra -Werror -fno-rtti -fno-exceptions -fPIE -pie \
    -I "$ssal_headers/frameworks/native/libs/binder/include" \
    -I "$ssal_headers/system/core/libutils/include" \
    -I "$ssal_headers/system/core/libutils/binder/include" \
    -I "$ssal_headers/system/core/libcutils/include" \
    -I "$ssal_headers/system/core/libsystem/include" \
    -I "$ssal_headers/system/logging/liblog/include" \
    -I "$ssal_headers/system/libbase/include" \
    native/binder-probe/main.cpp -L "$ssal_guest_libs" \
    -nostdlib++ -Wl,--allow-shlib-undefined -lbinder -lutils -lc++ -llog -o out/bin/ssal-binder-probe
# Only the helper is packaged; linked platform libraries stay in the guest image.
SSAL_GUEST_LIBS="$ssal_guest_libs" SSAL_REVISION="$ssal_revision" python3 - <<'PY'
import hashlib, json, os, pathlib
libs = pathlib.Path(os.environ['SSAL_GUEST_LIBS'])
metadata = {
    'header_revision': os.environ['SSAL_REVISION'],
    'helper_sha256': hashlib.sha256(pathlib.Path('out/bin/ssal-binder-probe').read_bytes()).hexdigest(),
    'source_sha256': hashlib.sha256(pathlib.Path('native/binder-probe/main.cpp').read_bytes()).hexdigest(),
    'build_script_sha256': hashlib.sha256(pathlib.Path('scripts/build-binder-probe.sh').read_bytes()).hexdigest(),
    'guest_library_sha256': {name: hashlib.sha256((libs / name).read_bytes()).hexdigest()
                             for name in ('libbinder.so', 'libutils.so', 'libc++.so')},
    'abi_scope': 'Android 16 platform C++ ABI; runtime private IPC test still required',
}
pathlib.Path('out/bin/ssal-binder-probe.json').write_text(json.dumps(metadata, indent=2) + '\n')
PY
