# Phase 7I SSAL 실기기 재검증

2026-11-06 19:30 KST, SM-S937N에서 수정본을 실행했다. **PARTIAL — Phase 7I 기능 검사는 통과했으나 Host process snapshot이 달라 runner가 exit 1을 반환했다.** SELinux·KernelSU 정책은 이번 실행에서 변경하지 않았다.

## 기능 결과

| 항목 | 결과 | 증거 |
|---|---|---|
| Guest Property 및 persistent restore | **PASS** | `u:r:ssal_property:s0`; Guest property area `[198,12]`, Guest `/data` device `1050416`이 Host와 분리됨. `persist.ssal_probe=7` 복구 및 volatile key 부재. [`worker.log`](../out/five-controlled-retest-20261106-193026-verified/device-run/run-1793961038/worker.log) |
| Private Binder / AIDL | **PASS** | Guest Binder `507:5`와 Host Binder `507:1` 분리. `PHASE5B=PASS`, AIDL call/callback/object transfer 성공. |
| Guest Zygote | **PASS** | UID 1000 readiness client가 `arm64-v8a` ABI 응답을 받음. `PHASE7A_ZYGOTE=PASS`; Guest Zygote socket 정리 확인. |
| Java child | **PASS** | `ForkProbe` 실행, UID/GID 10000, capabilities 0, Guest namespaces/cgroup. Guest property, Private Binder, userdata read/write 모두 PASS; child exit 0 및 pidfd reap. |
| Guest cleanup | **PASS** | Guest cgroup 제거, rootfs 잔여 mount 없음, 56개 loop allocation 해제. |

`worker_exit=0`이지만 Host 안전 스냅샷은 byte-identical이 아니어서 runner가 exit 1을 반환했다. 비교 차이는 사전 스냅샷에 있던 비핵심 앱 `dev.imranr.obtainium` PID 17735 한 건의 소멸이다. init, Host Zygote PID 2222, system_server PID 3266, ServiceManager, boot ID, SELinux Enforcing 및 PID 1 mountinfo hash는 유지됐다. 해당 앱은 실행 구간에 WorkManager 작업을 성공적으로 마친 로그가 있으며, 저장된 구간에는 대응하는 `lmkd Reclaim`이 없다. 앱 종료와 SSAL 사이의 인과는 확인하지 못했다. [`host-diff-summary.txt`](../out/five-controlled-retest-20261106-193026-verified/host-diff-summary.txt), [`host-before.txt`](../out/five-controlled-retest-20261106-193026-verified/host-before.txt), [`host-after.txt`](../out/five-controlled-retest-20261106-193026-verified/host-after.txt)

기기 boot ID는 `bfa2e92a-3dd0-42e5-8d1f-e03b55bc73da`로 전후 동일했고 Host `getenforce=Enforcing`, 주요 서비스 PID도 유지됐다. 종료 후 retest staging, Guest mount, Guest cgroup 잔여물은 없다. [`final-device-state.txt`](../out/five-controlled-retest-20261106-193026-verified/final-device-state.txt)

## FIVE / DEFEX / AVC / KernelSU / 커널

- 실행 window에서 FIVE 문자열 0건, SELinux `avc: denied` 0건, kernel panic/Oops 0건이다. 재부팅도 없어 과거 panic 로그와 원인 비교할 대상은 없었다.
- DEFEX link-protection 기록 3건이 `ssald`의 `/sys/kernel/debug`, `/system/bin`, `/system/bin/init` 접근에 대해 남았다: [`after-dmesg.txt`](../out/five-controlled-retest-20261106-193026-verified/after-dmesg.txt). 저장된 logcat/dmesg에서 해당 window의 `lmkd Reclaim`은 발견되지 않았다.
- KernelSU는 `samsung-v2.2 (uapi: 5)`였고 feature list가 전후 같았다. 이번 재실행에서는 `ksud sepolicy apply/patch`를 호출하지 않았다. 기존과 같은 boot ID를 유지해 이미 있던 Guest-only 정책 상태를 재사용했다. Host global SELinux는 Enforcing이었다.
- 원본 전후 커널·logcat 파일과 선별 결과: [`out/five-controlled-retest-20261106-193026-verified/`](../out/five-controlled-retest-20261106-193026-verified/), [`run-window-filtered.txt`](../out/five-controlled-retest-20261106-193026-verified/run-window-filtered.txt).

## staging 원인과 수정

첫 재검증에서 `ssal-phase2-log.so`가 빠진 것은 아니었다. 파일은 push됐고 `runtime_bins` 경로에서 Guest `/run/ssal`로 bind됐다. 문제는 임시 staging이 logger, `phase3-ipc`, `ssald`를 `0700`으로 만들었다는 점이다. UID 1000 ServiceManager가 logger를 읽지 못해 linker가 `not found`를 냈고, 다음 실행에서는 AIDL helper와 UID 1000 readiness client가 실행되지 않았다.

`ssal-phase2-log.so`는 ServiceManager 바이너리 자체의 필수 dependency는 아니다. `LD_PRELOAD`로 Android 로그를 서비스 stderr에 전달하는 진단 helper이며, 현재 7I harness의 `manager.wait_text("Starting sm instance")` readiness 확인이 해당 출력을 사용하므로 preload는 유지했다.

[`guest_launcher.rs`](../src/guest_launcher.rs)는 실행 중 `ssald`와 Guest runtime helper의 mode에 read/execute bit를 보장한 뒤 Guest bind를 수행한다. 최종 실기기 시험은 이 파일들을 의도적으로 `0700`으로 stage했고, 실행 뒤 `0755`가 된 것과 `phase3-ipc`, ServiceManager, UID 1000 readiness client의 성공을 확인했다. Guest boot JAR은 `0644`로 stage했다.

## 로컬 검증 및 최종 판정

- `cargo test --locked --bin ssald guest_launcher::tests::runtime_helper_is_accessible_after_guest_staging`: **1 passed**.
- `bash scripts/build-guest-launcher.sh`: Android arm64 launcher/helper **PASS**. `ssald` SHA-256: `E770692039ECA2C2C9B3EAC04D30DED9279B8A1ED6A8EB93B4306416D6682622`.
- 수정본으로 Phase 7I Property, Private Binder/AIDL, Guest Zygote, Java child 경로의 실기기 재검증이 가능했고 기능 검사는 모두 통과했다. `HOST_SAFETY_SNAPSHOT=UNCHANGED` 조건만 비핵심 앱 PID 변화로 실패해 전체 판정은 **PARTIAL**이다. 해당 실행의 [`runner-output.txt`](../out/five-controlled-retest-20261106-193026-verified/runner-output.txt)를 참고한다.

이전 19:10 KST 실행은 logger mode 오류로 ServiceManager readiness 전에 실패했고, DEFEX 기록과 `lmkd` 회수 3건이 있었다. 최종 수정 실행에서는 해당 `lmkd` 회수 로그가 없었다. 이전 실행 자료는 [`out/five-controlled-retest-20261106-190905/`](../out/five-controlled-retest-20261106-190905/)에 보존했다.
