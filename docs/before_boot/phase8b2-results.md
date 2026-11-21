# Phase 8B-2 — 결과 요약

## 최종 상태: PARTIAL — Phase 8B-3 HOLD

Guest `system_server` 전환 순서를 실제 GSI에서 고정하고, Guest 전용 startup/final SID를 위한 최소 source patch와 Guest-only 정책 초안을 준비했다. Host 경계 검증 대상 child는 실행하지 않았다. Stock GSI의 마지막 SELinux 전환은 `u:r:system_server:s0`를 하드코딩하므로 현재 image에서 system_server fork는 계속 금지한다.

## 완료한 작업

- GSI SHA-256을 기존 Phase 8B-1 기준선과 대조하고 실제 `plat_seapp_contexts`, CIL, framework, libselinux, ART binary를 확인했다.
- AOSP Android 16 seapp/zygote/startup 정책과 비교했다. Guest seapp selector만 바꾸면 마지막 `setcon()` SID가 Guest-specific으로 바뀌지 않는 점을 확인했다.
- [Guest transition rule 초안](../scripts/guest-domain-poc/phase8b2-domain-transition.rule)과 [GSI source patch 초안](../scripts/guest-domain-poc/phase8b2-guest-gsi.patch)을 작성했다. 정책은 미적용이며 GSI는 미수정이다.
- [경계 결과](phase8b2-boundary-results.md)를 작성하고, 읽기 전용 Host baseline과 아직 판정할 수 없는 Guest child 항목을 분리했다.
- 실제 GSI `init.zygote64.rc`의 `--start-system-server` 경로를 확인했다. SSAL direct zygote launch는 system_server 시작을 요청하지 않으며 profile의 `launch_enabled=false`를 유지한다.

## 검사 결과

| 검사 | 결과 |
|---|---|
| `bun test scripts/guest-domain-poc/phase8b2-policy.test.js` | PASS — 3 tests |
| `git apply --stat scripts/guest-domain-poc/phase8b2-guest-gsi.patch` | PASS — patch parses; not applied to a source tree |
| `ksud sepolicy check` for the 12 candidate statements | PASS — syntax accepted; this does not check policy semantics or apply rules |
| `cargo test --locked` (WSL, UID 1000) | PARTIAL — 21 passed, 2 failed because fixtures were not root-owned; failing cases are `guest_properties::tests::mmap_update_notification_restore_and_sealing` and `guest_properties::server::tests::protocol_ack_denials_and_disk_failure` |
| root-only retry | unavailable — `sudo -n true` reports interactive authentication required |
| `cargo fmt --all -- --check` | FAIL — reports formatting diffs in the already-dirty, user-owned `src/guest_launcher.rs` and in unchanged `src/guest_launcher/fork_probe.rs`; both were left untouched |
| `scripts/build-android.sh` | BLOCKED — `/opt/android-ndk/.../aarch64-linux-android26-clang` is missing; `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, and `ANDROID_HOME` are unset |
| Guest SELinux runtime / boundary tests | NOT RUN — no Guest system_server fork or `SystemServer.main()`/`SystemServer.run()` |

The Android-target build cannot be inferred from the successful host-target Rust test compilation. No Android binary was rebuilt or installed.

## Stop conditions and remaining risks

- Do not use the stock GSI with the current shared final SID. The source patch is unbuilt and may need adjustment to the exact LineageOS source revision.
- The transition rule is diagnostic scaffolding only. Guest system_server capabilities and non-transition permissions remain unobserved; the temporary Guest-only permissive statements are for bounded AVC collection and must be removed before enforcing acceptance.
- Live Host policy is not fully readable, and any active KernelSU policy additions are not isolated from the base policy. No live policy change was attempted.
- Phase 8B-1 Java-child/cgroup successes do not cover this UID 1000 system_server child. Host negative probes, Host endpoint boundaries, and system_server cleanup remain untested.

Full static path and credential contract: [SELinux transition analysis](phase8b2-selinux-transition.md). Host/Guest observations: [boundary results](phase8b2-boundary-results.md).
