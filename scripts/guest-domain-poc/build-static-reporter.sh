#!/usr/bin/env bash
set -euo pipefail
cd /src
compiler="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
"$compiler" -static -O2 -Wl,--build-id=none \
  -o out/bin/ssal-sigsegv-static-reporter scripts/guest-domain-poc/static-reporter.c
"$compiler" -nostdlib -static -fno-pic -Wl,-e,_start -Wl,--build-id=none \
  -o out/bin/ssal-sigsegv-bare-reporter scripts/guest-domain-poc/bare-reporter.S
"$compiler" -nostdlib -static -fno-pic -Wl,-e,_start -Wl,--build-id=none \
  -o out/bin/ssal-sigsegv-bare-exit scripts/guest-domain-poc/bare-exit.S
for reporter in out/bin/ssal-sigsegv-static-reporter out/bin/ssal-sigsegv-bare-reporter out/bin/ssal-sigsegv-bare-exit; do
  if readelf -l "$reporter" | grep -q INTERP; then
    echo "$reporter unexpectedly has PT_INTERP" >&2
    exit 1
  fi
done
