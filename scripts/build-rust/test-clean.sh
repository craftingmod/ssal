#!/usr/bin/env bash
set -euo pipefail
repo_root=$(mktemp -d)
trap 'rm -rf "$repo_root"' EXIT
mkdir -p "$repo_root/scripts/build-rust" "$repo_root/out/bin" "$repo_root/services" "$repo_root/native/binder-probe" "$repo_root/stubs" "$repo_root/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin" "$repo_root/.cache/android16-binder"
cp scripts/build-rust/build-android.sh "$repo_root/scripts/build-rust/"
cp native/binder-probe/context-map.c native/binder-probe/log-to-stderr.c "$repo_root/native/binder-probe/"
printf 'stale\n' > "$repo_root/out/bin/ssal-hwbinder-probe"
printf 'keep\n' > "$repo_root/out/bin/other-tool"
printf 'keep\n' > "$repo_root/.userdata-test.img"
printf 'keep\n' > "$repo_root/.cache/android16-binder/sentinel"
cat > "$repo_root/stubs/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CARGO_LOG"
if [[ "$1" == build ]]; then
    release="$CARGO_TARGET_DIR/aarch64-linux-android/release"
    mkdir -p "$release"
    for name in ssal ssald ssal-sepolicy ssal-selinux-identity ssal-guest-domain-poc ssal-binder-access ssal-enforcing-binder ssal-property-service ssal-lmkd ssal-art-exec-proc ssal-ashmem-probe ssal-selinux-startup-probe ssal-system-server-stall ssal-apexservice ssal-system-suspend ssal-health ssal-gatekeeper ssal-keymint ssal-virtual-composer ssal-vold ssal-netd; do
        printf 'built\n' > "$release/$name"
    done
fi
STUB
cat > "$repo_root/stubs/compiler" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
while (($#)); do
    if [[ "$1" == -o ]]; then shift; mkdir -p "$(dirname "$1")"; : > "$1"; exit 0; fi
    shift
done
exit 1
STUB
chmod +x "$repo_root/stubs/cargo" "$repo_root/stubs/compiler"
cat > "$repo_root/scripts/build-rust/build-hwbinder-probe.sh" <<'STUB'
#!/usr/bin/env bash
[[ $# -eq 0 ]] || exit 1
: > out/bin/ssal-hwbinder-probe
STUB
cat > "$repo_root/scripts/build-rust/build-virtual-audio.sh" <<'STUB'
#!/usr/bin/env bash
[[ $# -eq 0 ]] || exit 1
: > out/bin/ssal-virtual-audio
: > out/bin/ssal-audio-host
STUB
ln -s "$repo_root/stubs/compiler" "$repo_root/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
ln -s "$repo_root/stubs/compiler" "$repo_root/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
printf '#!/usr/bin/env bash\nexit 0\n' > "$repo_root/scripts/ssal-hwbinder-probe.sh"
chmod +x "$repo_root/scripts/ssal-hwbinder-probe.sh"
export PATH="$repo_root/stubs:$PATH" ANDROID_NDK_HOME="$repo_root/ndk" CARGO_TARGET_DIR="$repo_root/custom-target" CARGO_LOG="$repo_root/cargo.log"
(cd "$repo_root" && bash scripts/build-rust/build-android.sh clean)
[[ $(sed -n '1p' "$repo_root/cargo.log") == 'clean --release --target aarch64-linux-android' ]]
[[ $(sed -n '2p' "$repo_root/cargo.log") == 'clean --release --manifest-path services/Cargo.toml --target aarch64-linux-android' ]]
[[ $(wc -l < "$repo_root/cargo.log") -eq 4 ]]
[[ -f "$repo_root/out/bin/ssal" && -f "$repo_root/out/bin/ssal-netd" ]]
[[ -f "$repo_root/out/bin/ssal-hwbinder-probe" && -f "$repo_root/out/bin/ssal-virtual-audio" && -f "$repo_root/out/bin/ssal-audio-host" ]]
[[ -f "$repo_root/out/bin/other-tool" && -f "$repo_root/.userdata-test.img" && -f "$repo_root/.cache/android16-binder/sentinel" ]]
[[ -f "$repo_root/custom-target/aarch64-linux-android/release/ssal" ]]
cp "$repo_root/cargo.log" "$repo_root/cargo.before-failure.log"
printf 'keep-old-output\n' > "$repo_root/out/bin/ssal"
rm "$repo_root/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
if (cd "$repo_root" && bash scripts/build-rust/build-android.sh clean) 2> "$repo_root/missing-lib.log"; then
    echo 'clean unexpectedly succeeded without the NDK linker' >&2
    exit 1
fi
cmp "$repo_root/cargo.before-failure.log" "$repo_root/cargo.log"
[[ $(<"$repo_root/out/bin/ssal") == keep-old-output ]]
grep -q 'Android NDK linker missing' "$repo_root/missing-lib.log"
echo 'build clean self-check passed'
