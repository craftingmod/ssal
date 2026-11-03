# SSAL rsbinder IPC — Phase 2 결과

- 상태: **Android 17: 2A BUILD-PASS, 2B DEVICE-PASS, 2C DEVICE-PASS. Overall Phase 2 remains PARTIAL until Android 16 handset validation.**
- 갱신: 2026-11-03 (Asia/Seoul)
- 계획: [rsbinder-ipc-phase2-plan.md](rsbinder-ipc-phase2-plan.md)
- 구현: [experiments/rsbinder-phase2](../experiments/rsbinder-phase2/README.md)

## 2A — 환경 및 재현 빌드

| 항목 | 결과 |
|---|---|
| Rust / Cargo | 1.90.0 |
| Cargo target | aarch64-linux-android 설치됨 |
| NDK | r30 (30.0.16248370), Windows x86_64 host tools |
| NDK archive | 공식 Windows archive SHA-1 9bf167a1985fa7d4a036186b78f702eab9179408 확인 |
| Link API | 29 |
| cargo-ndk | 미설치; Cargo의 target linker를 직접 지정 |
| rsbinder | 정확히 0.12.0 |
| Android compatibility feature | android_16_plus; Android 16/17 전용 범위 |
| rsbinder-aidl | rsbinder 0.12.0의 빌드 의존성으로 lockfile에 0.12.0 포함; probe에서 직접 사용하지 않음 |
| host tests | 1 passed; device, service, and expected descriptor must be explicit |
| host cargo check | passed |
| Android AArch64 cargo check | passed |
| Android AArch64 release build | passed |
| ELF | ELF64 AArch64, interpreter /system/bin/linker64, dependencies libdl.so, libc.so |

Build commands:

    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "V:\workspace\Toy\ssal\.cache\android-sdk-phase2\android-ndk-r30\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android29-clang.cmd"
    cargo test --locked --manifest-path experiments/rsbinder-phase2/Cargo.toml
    cargo check --locked --manifest-path experiments/rsbinder-phase2/Cargo.toml --target aarch64-linux-android
    cargo build --release --locked --manifest-path experiments/rsbinder-phase2/Cargo.toml --target aarch64-linux-android

The linker environment variable above was set to the verified local NDK r30 path. The probe binaries are:

| Binary | SHA-256 |
|---|---|
| host_probe | 810D221D41A52784666D0CC63DC16C696F69F8C9DBA5C1448562EEFAB022B1DF |
| guest_probe | A32451023BDEDC8B2F6E7D81000ADC552D1B515395607471D91AE163E9763C4C |

## Connected-device preflight

The initial read-only preflight found one connected device, SM-S937N: Android **17 / API 37**, arm64-v8a, global SELinux **Enforcing**, and ADB shell UID/GID 0 in u:r:ksu:s0. Its build fingerprint is recorded redacted as samsung/psqksx/psq:17/[redacted]. The device briefly disconnected before staging, then reconnected; final checks completed on the reconnected device.

The requested Host path /dev/binder is a symlink to /dev/binderfs/binder. Both paths resolve to the same character device: st_dev=33, inode 4, rdev=507:1, mode 0666, label u:object_r:binder_device:s0. A read-only baseline found the package service and its descriptor android.content.pm.IPackageManager.

The plan's device target is Android 16. Upstream rsbinder 0.12.0 documents SDK 37 using the same Android 16 Binder/ServiceManager variant, and this build uses android_16_plus; nevertheless, a result on this connected device is labeled Android 17 and does not establish a result on Android 16.

## Host probe action and recovery record

- Before staging, `/data/local/tmp/ssal-rsbinder-phase2-host-probe-20261103` was confirmed absent. The only device changes were this temporary binary and one short-lived probe process. It performed no ServiceManager registration or service method call.
- The exact Host probe binary was removed after it exited; the path was verified absent. If interrupted, terminate only the probe's recorded PID first, then remove that exact file.
- Guest testing recreates the disposable Test B Private Binder session with the installed `/data/adb/modules/ssal/bin/ssal probe-servicemanager profile1` command. Before the first attempt, the exact Guest binary and log paths were confirmed absent. The Guest binary and private property area existed only in that session's tmpfs; the binary was labeled `u:object_r:shell_exec:s0`. The Test B harness owns its manager/service process reaping, Binder and mount cleanup, and registry isolation checks. After collection, all temporary device files with the `ssal-rsbinder-phase2-*20261103` prefix were removed and the path listing was verified empty. If interrupted, terminate only the recorded rsbinder probe PID and let the harness complete its normal cleanup. No Host service, SELinux policy, installed daemon, or Context Manager was modified.

### Recovery after the attempted Guest session

The second Test B run failed outer loop-release verification with `session backing still attached to /dev/block/loop38` and created a same-boot recovery marker for `/data/local/ssal/mnt/prepare-1439-1793704430446`. The rsbinder Guest process did not start. The observer's exact C++ `service check aidl_lazy_test_1` process was still alive in a private mount namespace; after terminating that process and its exact observer shell, the loop backing disappeared. This was the likely cause of the failed verification.

Read-only recovery checks found no process mountinfo entry or loop backing reference under the scratch/session image. The retained `system`, `data`, `rootfs`, `apex-cache`, and `loop-devices` directories were empty. After confirming the matching boot ID and marker scope, the five empty directories and exact scratch root were removed with `rmdir`, followed by `/data/local/ssal/state/binder-recovery-required.json`. Both paths were verified absent. A C++ Test B rerun then completed with its inner cleanup and outer loop-release checks passing. Host `package` remained available, `aidl_lazy_test_1` remained absent from Host, and SELinux stayed Enforcing. The earlier live C++ `service check aidl_lazy_test_1` process was the likely reason the first outer loop-release check failed; that causal link is an inference.

## 2B — Host read-only rsbinder probe

**DEVICE-PASS on Android 17 / API 37.** Run ID `1793704316632-9666`; device SM-S937N; PID 9666, UID/GID 0, context `u:r:ksu:s0`, mount namespace `mnt:[4026532950]`. The probe explicitly initialized `/dev/binder`, negotiated protocol 8, found `package`, and matched descriptor `android.content.pm.IPackageManager`. The process-state FD and requested path both resolved to Host Binder `dev=33, inode=4, rdev=507:1`; probe before/after identity matched. Afterward, `service check package` and its `INTERFACE_TRANSACTION` descriptor matched the read-only preflight, SELinux remained Enforcing, Guest test service remained absent from Host, and no AVC denial for PID 9666 appeared in the collected logcat window. Exact staged binary and path were removed and verified absent. This is Android 17 evidence; the planned Host target is Android 16.

## 2C — Guest Private Binder probe

**DEVICE-PASS on Android 17 / API 37** on SM-S937N. The Guest root used by Test B is Android 16 / SDK 36. Final run ID `1793712674806-14033`, Test B session `f7900911-c061-4570-8f65-900571a55c11-13641`, UID/GID 1000. The requested `/dev/binder` and the `ProcessState` FD both resolved to the private Binder device (`rdev=507:5`, inode 8, mode 0600); Host Binder remains a different device (`rdev=507:1`). Binder protocol 8 was negotiated.

### Confirmed cause and fix

rsbinder 0.12.0's `get_android_sdk_version()` caches `rsproperties::get_or("ro.build.version.sdk", 0)` in a `OnceLock`. `hub::default()` obtains `ProcessState::context_object()` and selects its ServiceManager variant from that cached SDK; an unsupported SDK value of 0 returns `StatusCode::InvalidOperation`. The earlier `servicemanager_connect: InvalidOperation` symptom therefore came from Guest SDK detection, not Binder handle 0 or the private Binder device.

Before the fix, the Test B helper supplied `/dev/__properties__` as one 128 KiB regular file, mode 0444, labeled `tmpfs`. The privileged Guest `getprop` control returned SDK 36, but the shell-context Rust process could not read the property area: `getprop=None`, Bionic `__system_property_get` returned length 0, `rsproperties` failed opening `property_info` with `ENOTDIR`, and rsbinder cached SDK 0. `ProcessState::context_object()` and handle 0 acquisition had already passed. A label control showed that relabeling the flat file `properties_device` still left shell `open`, `read`, and `map` denied; directory search was allowed. SELinux stayed Enforcing, and no permissive mode or policy change was used.

The diagnostic-only initializer now creates a modern private property directory from the Guest's own `/system/build.prop` SDK 36 value. It writes the `property_info` trie and labels the directory `properties_device`, the trie `property_info`, and the SDK value `build_prop`; `rsproperties` then initializes from that directory and self-checks SDK 36. No Host property values are read or copied. The change is confined to the rsbinder experiment and an opt-in `phase2c-diagnostic` build feature; no rsbinder SDK override was used.

| Guest-process SDK source | Before | After |
|---|---:|---:|
| Guest setup-context `getprop` control | `36` | `36` |
| Rust-process `getprop` | `null` | `36` |
| Bionic `__system_property_get` | length `0`, value `null` | length `2`, value `36` |
| `rsproperties::get` | `Not a directory (os error 20)` | `36` |
| `rsbinder::get_android_sdk_version()` | `0` | `36` |
| `ProcessState::context_object()` / handle 0 | passed | passed |

The before record is from session `...-3462`, probe `1793711200372-4395`, and failed first at `sdk_detection` / `sdk_mismatch`. After the fix, all seven recorded stages passed: Binder initialization, handle 0 acquisition, SDK detection, ServiceManager proxy construction, service lookup, `INTERFACE_TRANSACTION`, and Binder identity verification. `aidl_lazy_test_1` was found, and its descriptor matched `BBinder`. The C++ Test B service is `Echo : BBinder`; the previous empty-string expectation was incorrect.

Before/after values and SELinux label-control results are preserved in [Phase 2C diagnostic evidence](rsbinder-phase2c-diagnostics-20261103.json). Full raw runner logs remain in the workspace `.cache` directory as recorded in that JSON.

### Test and cleanup results

The existing C++ Test B implementation and its installed helper binaries were preserved. Final Test B checks passed: `servicemanager`, `android_service_selinux`, `host_registry_isolation`, `property_host_unchanged`, and `cleanup`; the separate `rsbinder_guest_probe` check also passed. Host `package` remained available; Host lookup of `aidl_lazy_test_1` remained absent. `host_framework_unchanged` and `host_mounts_unchanged` were true, Host property `changed_names` was empty, and the SELinux boundary was unchanged.

Regression validation passed: root library tests `4/4`, rsbinder experiment tests `1/1`, Android `ssald` checks with the default and diagnostic feature, Android release builds of the diagnostic runner and Guest probe, and `cargo fmt --all -- --check`.

The earlier retained process was the shell `service check aidl_lazy_test_1` observer from the manual diagnostic attempt; it held a reference to the Guest mount namespace. It was terminated and the exact loop backing release was confirmed before that scratch session was removed. The final integrated probe uses the tracked Guest child instead of a detached observer. The child was reaped before Test B cleanup; all 55 loop allocations were released, the mount cleanup check passed, no relevant observer/probe process remained, `/data/local/ssal/mnt` was empty, and the recovery marker was absent. The final Host checks remained unchanged: SDK 37, SELinux Enforcing, `package` found, `aidl_lazy_test_1` not found.

## Remaining Phase 2 gates

- [x] Run the Host rsbinder probe and preserve descriptor and Host-state evidence on Android 17.
- [x] Diagnose and fix Guest SDK/property-area detection; repeat Guest ServiceManager lookup and descriptor transaction successfully.
- [x] Confirm Guest service invisibility to Host, Host `package` availability, unchanged Host state, and full session cleanup.
- [ ] Repeat the device gates on the plan's Android 16 handset target.

Android 17 is the only device evidence in this result. Android 16 handset validation remains a separate gate; no Phase 3 or HAL proxy work was started.

The generated Guest property area is diagnostic and minimal: it contains SDK 36 plus the default property context. This confirms the rsbinder SDK and ServiceManager path, but does not validate a complete init-populated Guest property set.
