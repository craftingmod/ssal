# SSAL rsbinder Phase 5A — 결과

- 조사일: 2026-11-04 (Asia/Seoul)
- 대상: SM-S937N Android 17 Host / Android 16 SDK 36 Guest image
- 전체 판정: **PARTIAL**
- Phase 5B 판정: **진입 보류**

## 결과 요약

| 확인 항목 | 상태 | 결과 |
|---|---|---|
| Guest `/data` write boundary | PARTIAL | Phase 2의 과거 device evidence는 profile userdata로 쓰기가 분리됐음을 보인다. 같은 Host filesystem 아래에 있는 privileged Host 경로/열린 FD 차단은 입증되지 않았다. |
| Property read/write 경로 | PARTIAL | 기본 profile의 area는 Host 공유다. Test B/Phase 2C override는 Guest 전용 minimal area와 property socket 차단을 확인했지만 운영용 Guest property service/전체 property set은 없다. |
| Private Binder | PARTIAL | Test B의 private `/dev/binder`, Guest ServiceManager 및 registry 격리는 Enforcing 결과에서 통과했다. 기본 profile은 Host device를 공유하며 hwbinder/vndbinder와 FD 전달은 미검증이다. |
| Host process/settings 보존 | PARTIAL | 이번 작업은 Android device에 상태 변경 명령을 보내지 않았다. 현재 Enforcing/policy hashes와 task 중 process/property digest 전후 표본은 동일하다. 현재 Host `artd` PID 22327은 이전 Phase 4 기록과 달라진 상태지만 이 task의 실행 전부터 있었고 시작 시점/원인은 모른다. |
| Phase 1~4 회귀 | PASS (기존 증거) | 요청에 따라 기기/runner 회귀를 재실행하지 않았다. 기존 Phase 4 결과에 Phase 2C, Phase 3 AIDL, Enforcing Test B 결과가 통과로 기록돼 있다. |
| SELinux policy hash rollback | PASS | 현재 live hash가 Phase 4 baseline/final hash와 같고 영구 module rule hash도 기존 값과 같다. 이번 조사에서 policy 변경은 없었다. |

세부 경계별 근거는 [Phase 5A boundary 조사](rsbinder-phase5a-boundaries.md)에 있다. 실제 Guest `installd`/`artd`는 이 Phase 5A 작업에서 실행하지 않았다. 저장된 Phase 2 결과에는 2026-11-03에 실제 daemon을 disposable profile에서 실행한 **이전** 시험이 기록돼 있으며 그 시험은 Permissive 조건이었다. 이를 이번 Enforcing runtime gate로 취급하지 않는다.

## 읽기 전용 Host 확인

현재 기기 snapshot:

| 항목 | 값 |
|---|---|
| Boot ID | `f7900911-c061-4570-8f65-900571a55c11` |
| SELinux | `Enforcing` |
| `/sys/fs/selinux/policy` SHA-256 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` |
| `/data/adb/modules/ssal/sepolicy.rule` SHA-256 | `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389` |
| 현재 Host 프로세스 | `init` PID 1, `zygote64` PID 1854, `system_server` PID 3059, `installd` PID 2607, `artd` PID 22327, `netd` PID 1852, `adbd` PID 30624 |
| `artd` 현재 context | `u:r:artd:s0` |
| Property snapshot digest (`getprop` piped to `sha256sum`) | `e2405ff97dec9d7bdd19c63e278ad1448647dfbf84f4681023080b4ebca02d2d` |
| Host Binder identities | `/dev/binder=507:1`, `/dev/hwbinder=507:2`, `/dev/vndbinder=507:3` |
| SSAL mount scratch / recovery marker | mount scratch 비어 있음; `binder-recovery-required.json` 부재 |

Phase 4 결과의 live policy baseline과 final hash는 모두 `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723`였다. 현재 해시도 일치한다. Permanent module rule hash도 Phase 3/4 기록의 `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389`와 같다. SELinux는 계속 Enforcing이며 이번 작업에서 runtime allow/deny를 적용하지 않았다.

이 조사에서 수행한 기기 명령은 `getenforce`, boot ID/PID/context/stat, 정책 및 property digest, device identity, scratch/recovery marker 확인뿐이다. Host property 값은 화면이나 문서에 출력하지 않았다. Property digest와 두 차례 조회한 `system_server`, `installd`, `artd`, `netd`, `adbd` PID는 같았다. 첫 process 조회는 `zygote`라는 별칭을 사용해 `zygote64`를 별도로 식별하지 못했으며, 최종 표본에서 PID 1854를 확인했다. Host init, zygote, system_server, installd, artd, netd, adbd를 중단하거나 재시작하는 명령은 보내지 않았다.

기존 Phase 4 기록에서는 Host `artd`가 실행 중이지 않았다고 되어 있으나 현재는 PID 22327로 실행 중이다. 이 PID는 이번 task의 첫 read-only snapshot부터 존재했고 이번 task는 `artd` 시작/중단 명령을 실행하지 않았다. 두 기록 사이의 외부 시작 시점과 원인은 확인되지 않아 이전 Phase 4 대비 process continuity는 UNKNOWN으로 남긴다. Host property digest도 과거 Phase 4 digest와 동일한 수집 방식의 비교 자료가 없으므로 과거 상태와의 내용 동등성까지 주장하지 않는다.

## 테스트와 회귀 기록

사용자가 Phase 1~4 회귀를 skip하도록 수정하기 전에 원래 완료 기준에 따라 로컬 unit-test 명령을 실행했다. 이후 Phase 1~4의 device/runner 회귀는 추가 실행하지 않았다.

| 검사 | 결과 |
|---|---|
| Root `cargo test --locked --features phase3-diagnostic` | Windows host unit tests 성공 (exit 0) |
| Phase 2 crate `cargo test --locked` | 1 passed |
| Phase 3 crate `cargo test --locked` | 성공, 정의된 unit test 0개 |
| Root 및 Phase 3 `cargo fmt --check` | 통과 |
| Phase 2 `cargo fmt --check` | 실패: 기존 `experiments/rsbinder-phase2/src/android_probe.rs`, `src/lib.rs` formatting diff. 해당 코드는 수정하지 않음 |
| Phase 2C/Phase 3/Phase 4 실기기 regression | 이번 단계에서 재실행하지 않음. 기존 [Phase 4 결과](rsbinder-phase4-results.md)에 Phase 2C private Binder, Phase 3 Rust AIDL callback/death/reconnect, Enforcing, Host registry/property snapshot 및 SELinux hash rollback 통과가 기록돼 있음 |

Cargo 첫 시도는 제한된 Scoop Cargo cache에 쓸 수 없어 중단됐다. 이어 workspace의 기존 `.cache/cargo-home`을 사용해 root/Phase 3 명령을 완료했다. 이 과정은 Android device를 변경하지 않았다. Phase 2 test도 통과했다. Formatter 차이는 task 이전 source에 있었으며 이번 작업에서 파일을 정리하지 않았다.

## 완료 기준 판정

1. **Guest `/data` 쓰기 경계 — PARTIAL.** Profile userdata bind와 Guest 내부 write/read 및 과거 create/delete는 확인됐다. Host root/FD/proc 경로를 통한 접근 차단은 확인되지 않았다.
2. **Property read/write — PARTIAL.** Guest property area 분리/Host property socket 차단은 시험 override에서만 확인됐다. 기본 profile의 property area는 Host 공유이며 Guest property service와 enforcing property context/AV가 미구현/미검증이다.
3. **Private Binder — PARTIAL.** Test B의 private `binder`와 ServiceManager/registry 격리는 통과했다. 기본 profile은 Host Binder를 상속하며 hwbinder/vndbinder 대상, 일반 runtime fallback 및 FD 전달은 미확인이다.
4. **Host process/settings 보존 — PARTIAL.** 이번 단계의 Android 작업은 읽기 전용이었고 task 중 PIDs·Enforcing·policy hash·property digest가 유지됐다. Phase 4 보관 기록 대비 Host `artd`가 현재 실행 중인 차이는 원인 미확인이다.
5. **Phase 1~4 regression — PASS (기존 결과).** 사용자 정정에 따라 live device/runner test는 생략했다. 기존 결과를 재사용했다.
6. **SELinux hash 복원 — PASS.** 현재 policy hash는 기준/final hash와 일치하고 module rule hash도 그대로다.

## Phase 5B 판단 및 최소 선행 작업

**실제 Guest 서비스 실행으로 넘어갈 수 없다.** 기존 proof는 특정 시험 세션의 Binder/property override와 Phase 2 permissive daemon 동작에 한정된다. 기본 runtime에서 Host Binder/property area가 공유되고 PID/IPC namespace 분리가 없으며 `/proc`/상속 FD Host 접근과 production daemon의 Enforcing 권한이 입증되지 않았다.

Phase 5B를 다시 검토하기 전에 필요한 최소 항목:

1. Guest runtime 진입점에서 private `/dev/binder`와 Guest ServiceManager를 기본값으로 강제하고, hwbinder/vndbinder를 사용할지 격리/명시적 차단을 정한다. device 및 process FD를 매번 대조하고 fallback을 fail-closed 처리한다.
2. Host property area를 Guest root에서 숨기고 private property area, Guest property service socket/server, Android 16 context trie 및 guest-only persistence를 한 세트로 구성한다. 필요한 이름·type·peer UID/GID/context만 정한 뒤 SELinux AV를 읽기 전용으로 확인한다. Host `ctl.*`/`sys.powerctl` route는 만들지 않는다.
3. `/proc/1/root`, Host `/proc/*/fd`, inherited FD, shared `/sys/fs/cgroup`/`bpf` 등 Host 도달 경로를 Guest production domain 대상으로 음성 검사한다. PID/IPC namespace가 불가능한 한계는 우회해 숨기지 말고 경로와 FD gate로 보완한 뒤 남은 위험을 문서화한다.
4. Guest service의 UID/GID/groups, capabilities, NNP/seccomp, SELinux domain, root/executable, Binder FD와 write paths를 고정한다. `artd` test shim의 `CAP_SYS_ADMIN` 예외를 production에 그대로 넘기지 않는다. 필요한 경우에만 최소 policy 후보를 제안하고 runtime allow를 사용한다면 종료 후 hash 원복을 증명한다.

이 경계들이 별도의 승인된 isolated Guest test로 통과하고 Host snapshot/hash가 그대로일 때까지 `installd`/`artd` 실행 gate는 닫힌 상태다.
