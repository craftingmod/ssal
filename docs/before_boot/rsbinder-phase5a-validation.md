# SSAL Phase 5A Validation

- 검증일: 2026-11-04 (Asia/Seoul)
- 기기: Samsung SM-S937N, Android 17 Host
- 진행 상태: 완료 (경계별 PASS/PARTIAL/UNKNOWN 구분)
- 적용 범위: Phase 5A-Fix 결과의 런타임 확인. Guest 서비스 및 system_server는 시작하지 않는다.

## 빌드 기록 (배포 전)

기존 `out/bin` 바이너리는 변경된 소스보다 오래되어 실행 검증에 사용할 수 없다. WSLc의 기존 `ssal-dev` 컨테이너와 `ssal-builder:dev` 이미지로 현재 소스를 Android AArch64용 release 빌드했다. WSLc 정보 조회와 컨테이너 실행은 일반 sandbox에서 `E_ACCESSDENIED`였고, 승인된 elevated 실행에서는 WSLc SessionManager 3.0.3 및 기존 컨테이너를 확인했다. 컨테이너나 이미지는 재생성하지 않았다.

전용 Cargo target dir `/build/phase5a-validation`를 사용했고, 결과는 기존 `out/bin`을 덮어쓰지 않는 `out/phase5a-validation/bin/`에 저장했다. 빌드 성공 전에 기존 바이너리를 사용하지 않았다.

| 항목 | 값 |
|---|---|
| Cargo package | `ssal 0.1.0` |
| Module version | `0.1.0-alpha` |
| RPC version | `2` |
| Target | `aarch64-linux-android` (ELF64 AArch64) |
| Rust / Cargo | `1.90.0` |
| Android NDK | r30, `Pkg.Revision=30.0.16248370` |
| 빌드 산출물 경로 | `out/phase5a-validation/bin/` |
| 배포 전 기록 시각 | 2026-11-04 02:03 Asia/Seoul |

| 바이너리 | 크기 (bytes) | SHA-256 |
|---|---:|---|
| `ssal` | 1,124,744 | `1d25b8b326961eaced69b6bf805421e1fa5e240f073da76619dabb1f95cc564a` |
| `ssald` | 1,503,008 | `21a5c4e8d4fb99e09f0e4859b878e2a78a4da499a8e32d05ccb436009f51568d` |
| `ssal-selinux-identity` | 591,048 | `1295abba10df884551a27b6dd7b1dc0df2d568c6bcb35d66a2a2d2168492fe90` |
| `ssal-guest-domain-poc` | 864,896 | `2c7a35e632aad741b5ecc2397cb189b178c736ba64044bf7db26df8c27458dc1` |
| `ssal-binder-access` | 579,936 | `cc21021567e9575a04b52b02960fe79b749b0b01937e70db9fe1087156c9d368` |
| `ssal-enforcing-binder` | 833,504 | `2280d480a5cc95926b835f6803e64ef30aba20b9fa5f3840add12fdf383b4065` |
| `ssal-property-area-live-poc` (native proc reporter) | 9,273,144 | `bdab7c5f05f160c98041a092777632e354d70e184bb6c29a62dd27c9bf8a2415` |

The six SSAL artifact hashes were recorded before any of those outputs were staged for this task. The old `out/bin/ssal`, `out/bin/ssald`, and `out/bin/ssal-enforcing-binder` differ from the new outputs; the other three hashes match. The native helper hash was recorded later, before its use in this task. Device staging and verification are recorded below.

The native proc reporter was rebuilt from `native/property-area-live-poc/` and pinned Android 16 Bionic source in the existing WSLc container. It is static ELF64 AArch64, protocol 1. Its SHA-256 matches the previously staged device helper, whose `ssal_guest_probe_exec` label was confirmed; no new helper copy was deployed. It was selected for `SSAL_PROC_ONLY=1`, but the read-only preflight failed before child creation, so the reporter did not run.

## Runtime results

### Build and regression checks

The initial `wslc` calls failed with `E_ACCESSDENIED` from the normal sandbox. An elevated read-only retry reached WSLc SessionManager 3.0.3, session `wslc-cli-alyac`, and the existing `ssal-dev` container (`966cf393e32d`, image `ssal-builder:dev`). Reusing that container fixed the access issue; the container and image were not recreated. The Windows fallback NDK download/build tree was removed after the WSLc build succeeded.

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo test --locked --features phase3-diagnostic -- --test-threads=1` | PASS: 74 passed, 3 ignored (root/capability-dependent) |
| Phase 2 crate tests | PASS: 1 passed |
| Phase 3 crate tests | PASS: no tests defined |
| Android AArch64 `cargo check --locked --target ... --features phase3-diagnostic` | PASS |
| Android AArch64 `cargo check --locked --tests --target ... --features phase3-diagnostic` | PASS |

The outputs were staged temporarily under `/data/local/tmp/ssal-phase5a-validation-20261104/bin`, verified against the recorded hashes, and removed after testing. Nothing in `/data/adb/modules/ssal/bin` was replaced and the Host `ssald` service was not restarted.

### Disposable Guest `/dev`

Ran the current `ssald --prepare-worker` against the registered Android 16 image (`1793366406758-25627`, SHA-256 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`) and a newly created empty userdata directory. A temporary copy of the profile metadata was used; the existing profile and userdata were not modified.

| Observation | Result |
|---|---|
| Worker mount namespace | `mnt:[4026536262]`; Host remained `mnt:[4026532950]` |
| Guest `/dev` | tmpfs, mount ID `9902`, `rw,nosuid,noexec`, 4 MiB, mode `0755`, label `u:object_r:tmpfs:s0` |
| `/dev/null` | `rdev=1:3`, label `null_device`, source mount `9476`, Guest bind mount `9903` |
| `/dev/zero` | `rdev=1:5`, label `zero_device`, source mount `9476`, Guest bind mount `9904` |
| `/dev/random` | `rdev=1:8`, label `random_device`, source mount `9476`, Guest bind mount `9905` |
| `/dev/urandom` | `rdev=1:9`, label `random_device`, source mount `9476`, Guest bind mount `9906` |
| Guest `/dev` entries | Exact allowlist: `binderfs`, `block`, `null`, `random`, `socket`, `urandom`, `zero` |
| Host endpoints in Guest `/dev` | Host Binder nodes, property area/sockets, binder-control, and HAL nodes absent; allowlist verification passed |

The worker reached the existing fail-closed linkerconfig gate and exited with the expected error: `Guest executable launch blocked: Host proc/root, exec-FD and signal/ptrace boundaries have not passed Phase 5A-Fix`. It did not execute Guest `linkerconfig` or a Guest service. Its rootfs residual-mount check passed, all 55 loop-backed system/APEX resources were released, and the Host mount table contained no task path afterward. The temporary test directory was removed. This is a PASS for the tested `/dev` composition and cleanup path, not for Guest executable admission.

### Private Binder, Host paths and FDs

The current Guest `/dev` intentionally contains no Binder device. Reused Phase 2–4 device evidence from 2026-10-31 records Host identities `binder=507:1`, `hwbinder=507:2`, `vndbinder=507:3` and private binderfs identities `binder=507:5`, `hwbinder=507:6`, `vndbinder=507:7`, with the corresponding Binder, HWBinder and VNDBinder SELinux labels. The private Binder session used mount ID `224`; its Binder protocol was 8. The existing Enforcing test also verified the private context manager/registry path without invoking Host Binder IPC. HW/VND Binder service communication itself was not tested. See [`private-binder-device-20261031.json`](private-binder-device-20261031.json) and [`enforcing-binder-device-20261031.md`](enforcing-binder-device-20261031.md).

The reused Enforcing test recorded Host `/proc` root/FD paths as `ENOENT` for the selected test credentials and confirmed Host root, Binder, property, kmsg and socket FDs were not inherited. This is historical Phase 2–4 evidence, not a rerun of the Phase 5A worker. It did not test signal/ptrace permissions against Host processes.

For the current test-only path, the rebuilt `ssal-guest-domain-poc` and source-matched native proc reporter passed the artifact, ELF and helper-label checks. Read-only `--proc-only-preflight` then stopped because the current SELinux AV query returned `EINVAL (22)` (`allowed_mask=unknown`; target Enforcing state query failed). The preflight created no child and attempted no mount. No signal or ptrace operation was directed at a Host process. The existing POC child path also inherits the launching KSU UID/GID/groups/capabilities instead of setting an explicit reduced credential set, so it was not run. A constrained diagnostic child is therefore **not validated in this run**.

### Host state and cleanup

| State | Before / after observation |
|---|---|
| SELinux | Enforcing before and after |
| Loaded policy SHA-256 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` before and after |
| Installed `sepolicy.rule` SHA-256 | `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389` before and after |
| Host mount namespace | `mnt:[4026532950]` before and after; no test mount remained |
| Host BinderFS | mount ID `107`; Host node identities and labels remained `507:1`, `507:2`, `507:3` |
| Core Host processes | init, zygote64, system_server, installd, netd, adbd and servicemanager retained their recorded PIDs |
| `artd` | Baseline `pidof` returned PID `22327`; final state was no PID / `init.svc.artd=stopped`. No command in this task started, stopped or signaled it; the transition occurred during the observation window and its cause is not established. |
| Host property digest | `getprop` digest changed from `0e47ca5bceb72174fb34318b2ef624d1b833a5797671d1307fa83096859a99d1` to `e1d0294717a1870e7e67a0d8caed892db831fb66e48cbdef98989a9d1f3e145f` and was stable across two final reads. No property write or `setprop` was issued; the digest alone cannot attribute the change, so unchanged Host property contents are **not proven**. |
| Test artifacts | Device staging path absent; test worker exited; loop backing file empty; local NDK fallback tree removed |

No Host service, property, Binder, SELinux policy or permanent rule was intentionally modified. The observed `artd` and property-digest differences are reported as unresolved Host-state observations, not attributed to SSAL.

## Separate decisions

| Scope | Decision |
|---|---|
| Full Android / LineageOS boot | **Not attempted; not validated.** Guest property service/area, current Guest executable admission, and service-level compatibility remain unverified. |
| Limited diagnostic process | **PARTIAL.** Existing Phase 2–4 Private Binder diagnostics ran with UID/GID `1000:1000`, group `[3009]`, zero capability sets and explicit stdio/trace FDs. No new Phase 5A Host-proc/FD child ran: read-only AV preflight failed with `EINVAL (22)`, and the current POC child lacks an explicit credential drop. |
| Current Guest `/dev` isolation | **PASS for the tested disposable worker path.** |
| Private Binder identity | **PASS in historical Phase 2–4 evidence for all three node identities; not recreated in the new empty Guest `/dev`.** |
| Host path/FD boundary | **PASS in historical Phase 2–4 test scope; current Phase 5A rerun remains partial.** |
| Host signal/ptrace boundary | **UNKNOWN.** No Host process was signaled or ptraced; current non-destructive permission check did not run. |
| PID/IPC namespaces | **UNRESOLVED.** Existing runtime records say PID namespace separation is unavailable and IPC namespace creation returned `EINVAL (22)`; this worker created only a mount namespace. |
| Guest property boundary | **UNIMPLEMENTED / NOT PASS.** Design and Android 16 Bionic requirements remain separate work. |

Next safe execution scope is a test-only helper with a fixed executable hash, UID/GID `1000:1000`, supplementary group `[3009]`, all capability sets zero, `no_new_privs=1`, target context `u:r:ssal_guest_probe:s0`, and only the reporter/stdio trace FDs. Resolve the read-only AV query `EINVAL` and add the explicit credential drop to that test path before running it. Keep the global Guest executable gate and do not start Guest services.

## Property follow-up

Guest property service/area remain unimplemented and are not a PASS criterion in this execution. Android 16 Bionic compatibility and Host property isolation design are recorded in [`rsbinder-phase5a-boundaries.md`](rsbinder-phase5a-boundaries.md). The Guest needs its own property area, property contexts and service socket with enforcing SELinux access checks; Host property backing data and sockets must not be visible or writable from Guest. This remains a separate implementation and runtime validation task.

