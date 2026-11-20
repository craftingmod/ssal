#!/usr/bin/env bash
set -euo pipefail

ssal_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ssal_root"

ssal_api=29
ssal_ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
ssal_sdk_roots=()
[[ -n "${ANDROID_SDK_ROOT:-}" ]] && ssal_sdk_roots+=("$ANDROID_SDK_ROOT")
[[ -n "${ANDROID_HOME:-}" ]] && ssal_sdk_roots+=("$ANDROID_HOME")

ssal_host_tag=linux-x86_64
case "$(uname -s)" in
  Darwin)
    ssal_host_tag="darwin-$(uname -m)"
    ;;
  MINGW*|MSYS*|CYGWIN*)
    ssal_host_tag=windows-x86_64
    ;;
esac

ssal_cxx="${SSAL_ANDROID_CXX:-}"
if [[ -z "$ssal_cxx" ]]; then
  if [[ -n "$ssal_ndk_root" ]]; then
    ssal_cxx="$ssal_ndk_root/toolchains/llvm/prebuilt/$ssal_host_tag/bin/aarch64-linux-android${ssal_api}-clang++"
  else
    for ssal_sdk in "${ssal_sdk_roots[@]}"; do
      for ssal_ndk in "$ssal_sdk"/ndk/*; do
        [[ -d "$ssal_ndk" ]] || continue
        ssal_candidate="$ssal_ndk/toolchains/llvm/prebuilt/$ssal_host_tag/bin/aarch64-linux-android${ssal_api}-clang++"
        if [[ -x "$ssal_candidate" ]]; then
          ssal_ndk_root="$ssal_ndk"
          ssal_cxx="$ssal_candidate"
        fi
      done
    done
  fi
fi
if [[ -z "$ssal_cxx" ]]; then
  ssal_cxx="$(command -v "aarch64-linux-android${ssal_api}-clang++" || true)"
fi
[[ -x "$ssal_cxx" ]] || {
  echo "Android NDK AArch64 compiler not found; set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, ANDROID_SDK_ROOT, or SSAL_ANDROID_CXX" >&2
  exit 1
}

ssal_source=out/property-area-prototype/source
ssal_include=out/property-area-live-poc/include
[[ -d "$ssal_source" ]] || { echo "Missing pinned Bionic source: $ssal_source" >&2; exit 1; }
(
  cd "$ssal_source"
  sha256sum --check --status <<'SHA256'
43de5c91c78398d3c5f7f22695ac771509cd3993a8d418f05b9260bc01017959  prop_area.cpp
50b283367065b44370a992d10930b6cf3147b378577d97a85bfff7927f965aba  prop_info.cpp
07da2d23f543533d840f96b4ed6c37ab3a9ec1e5149358767b822bfd158b6101  prop_area.h
5055c2f07cf3c211d3722371a1bf2d1128ef6c66f461fd276f20f631ca6689f0  prop_info.h
SHA256
) || { echo 'Pinned Android 16 r2 Bionic sources are missing or modified' >&2; exit 1; }

mkdir -p "$ssal_include/system_properties" out/bin
cp "$ssal_source/prop_area.h" "$ssal_include/system_properties/prop_area.h"
cp "$ssal_source/prop_info.h" "$ssal_include/system_properties/prop_info.h"

"$ssal_cxx" -std=c++17 -O2 -static -fPIE -pie -fno-exceptions -fno-rtti \
  -Wall -Wextra -Wno-unused-parameter -Wl,--build-id=none \
  -I native/property-area-live-poc/shim \
  -I "$ssal_include" \
  -I "$ssal_source" \
  native/property-area-live-poc/main.cpp \
  native/property-area-live-poc/bionic_area.cpp \
  "$ssal_source/prop_info.cpp" \
  -o out/bin/ssal-property-area-live-poc

ssal_readelf="${ssal_ndk_root:+$ssal_ndk_root/toolchains/llvm/prebuilt/$ssal_host_tag/bin/llvm-readelf}"
if [[ -z "$ssal_readelf" || ! -x "$ssal_readelf" ]]; then
  ssal_readelf="$(command -v llvm-readelf || command -v readelf || true)"
fi
[[ -x "$ssal_readelf" ]] || { echo 'readelf/llvm-readelf is required to verify the Android ELF' >&2; exit 1; }
if "$ssal_readelf" -l out/bin/ssal-property-area-live-poc | grep -q INTERP; then
  echo 'property-area helper unexpectedly has PT_INTERP' >&2
  exit 1
fi
ssal_machine="$("$ssal_readelf" -h out/bin/ssal-property-area-live-poc | sed -n 's/.*Machine: *//p')"
[[ "$ssal_machine" == *AArch64* ]] || { echo "unexpected ELF machine: $ssal_machine" >&2; exit 1; }
if "$ssal_readelf" -d out/bin/ssal-property-area-live-poc 2>/dev/null | grep -q NEEDED; then
  echo 'property-area helper unexpectedly has dynamic dependencies' >&2
  exit 1
fi
echo "ELF_MACHINE=$ssal_machine"
echo "NEW_HELPER_SHA256=$(sha256sum out/bin/ssal-property-area-live-poc | cut -d ' ' -f 1)"
