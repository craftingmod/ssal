# SSAL Phase 5A-Fix — 결과

- 검증일: 2026-11-04 (Asia/Seoul)
- 대상: SM-S937N / Android 17 Host, Android 16 SDK 36 Guest 경로
- 최종 판정: **PARTIAL**
- Phase 5B 진입: **NO-GO**

실제 Guest mount, Guest property 요청, Guest 서비스 자격의 Host proc/FD 음성 시험을 수행하지 않았다. 코드 변경과 Android 대상 타입검사만으로 격리를 PASS 처리하지 않는다.

## 수정 결과와 경계별 판정

| 항목 | 판정 | 근거 및 남은 범위 |
|---|---|---|
| P0 `/dev` 전체 공유 제거 | **PARTIAL** | `initial.json`은 Host `/dev` 재귀 bind를 제거하고 Guest tmpfs를 사용한다. `/dev/null`, `zero`, `random`, `urandom`만 예상 character-device rdev와 root:root `0666`을 검사해 개별 bind하며, Guest/Host mount ID도 달라야 한다. Host Binder, property, `binder-control`, HAL 노드는 기본 allowlist에 없다. 실제 Android mount는 실행하지 않아 기기 동작과 실제 SELinux 라벨/access는 미확인이다. |
| P0 Guest property | **PARTIAL** | 기본 profile에서 Host `/dev/__properties__`와 Host property sockets가 들어오지 않도록 `/dev`를 새로 구성하고, Guest 경로에 해당 항목이 있으면 검사 실패한다. Guest Android 16 Bionic property area, property service, contexts, persist 처리와 enforcing AV 검증은 미구현이다. Guest property 읽기·쓰기가 실제 Guest 영역을 쓴다는 증거가 없고, Host property 비영향 시험도 수행하지 않았다. |
| P0 Host path/FD 경계 | **PARTIAL (fail-closed)** | Guest `linkerconfig`, `guest_probe`, SELinux identity 실행 경계에 gate를 두어 현재 표준 `prepare` 경로의 모든 Guest GSI 실행을 차단한다. `prepare`는 linkerconfig 직전에 실패해 일반 정리 경로로 mount를 해제한다. FD helper는 snapshot 시점의 allowlist 밖 FD를 `pre_exec`에서 닫고 identity가 재사용된 번호와 구분한다. 다만 snapshot 이후 동시 FD 생성 admission, exec-stop FD 목록, `/proc/<pid>/{root,fd,ns}` 및 Host signal/ptrace의 Guest 권한 음성 시험은 확인하지 않았다. 차단은 경계 검증을 대신하지 않으며 이 상태로 Phase 5B는 NO-GO다. |
| P1 Binder 3종 | **PARTIAL** | 기존 Private Binder 구현을 재사용하며 기본 profile은 Host Binder 노드를 제공하지 않는다. 기존 Phase 2~4 기록은 private `/dev/binder` (`rdev=507:5`, Host `507:1`)와 ServiceManager registry 분리를 특정 시험에서 통과로 기록한다. 이번 수정 후 Guest 실행은 하지 않았고 `/dev/hwbinder`, `/dev/vndbinder`의 Guest identity/context는 여전히 UNKNOWN이다. |
| P1 UID/GID, groups, capabilities, namespaces | **UNKNOWN** | 이번 단계에서 Guest production service를 실행하지 않았다. 과거 Phase 2 daemon credential 결과는 Permissive 및 시험 전용 조건이므로 Enforcing production 근거로 재사용하지 않는다. PID/IPC 격리와 Host process 접근 대체 차단도 통과 확인이 없다. |
| Guest 실행 fail-closed gate | **PARTIAL** | `linkerconfig` 실행 전에 gate가 실패하고 `guest_probe`/SELinux identity helper도 같은 gate를 확인하도록 구현했다. Android 대상 test 코드는 타입검사됐지만 기기나 Linux에서 gate 실행과 mount 정리를 관측하지 않았다. 따라서 현재 표준 경로에서 Guest GSI binary가 실행되지 않는다는 런타임 보증은 아직 확인되지 않았다. |
| Android service 실행 계약 | **PARTIAL (구성만)** | 기존 service contract의 `launch_enabled=false` 검증을 유지했다. 이번 단계에 Guest `installd`, `artd`, `zygote`, `system_server`는 실행하지 않았다. 이는 서비스 자체가 안전하다는 PASS가 아니다. |

기본 profile의 writable `/sys/fs/cgroup` 및 `/sys/fs/bpf` Host bind도 제거했다. 새 `/dev`는 Host 장치 트리를 재귀 공유하지 않는다. Host `/vendor`/`odm` 등 read-only 공유와 fresh sysfs/공유 커널의 다른 경로까지 격리됐다는 뜻은 아니다.

## 코드·회귀 검사

| 검사 | 결과 |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo test --locked --features phase3-diagnostic` | PASS, Windows host에서 실행. root suite는 25개 테스트(공통 4, diagnostic 21) 통과. Android 전용 mount/FD 경로 테스트는 이 실행에서 포함되지 않음. |
| Phase 2 crate `cargo test --locked` | PASS, 1개 통과 |
| Phase 3 crate `cargo test --locked` | PASS, 정의된 unit test 0개 |
| `cargo check --locked --target aarch64-linux-android --features phase3-diagnostic` | PASS, Android release target 코드 타입검사 |
| `cargo check --locked --tests --target aarch64-linux-android --features phase3-diagnostic` | PASS, Android target test 코드 타입검사. 테스트 실행 결과는 아님. |
| Phase 1~4 실기기/runner 회귀 | UNKNOWN, 이번 단계에 재실행하지 않음. 기존 기록은 과거 시험 결과로만 유지. |
| Phase 2 formatter 차이 | 별도 기술 부채로 유지. `experiments/rsbinder-phase2/src/android_probe.rs`와 `src/lib.rs`는 수정하지 않음. |

연결 기기에서 수정 바이너리 빌드·배포·`ssal prepare` 실행은 하지 않았다. Linux Android NDK 빌드 컨테이너 조회가 `E_ACCESSDENIED`로 막혀 기기용 변경 바이너리를 만들 수 없었고, 기존 `out/bin/ssal`은 변경 전 빌드다. 코드상 실행 gate가 `linkerconfig` 앞에서 거부하도록 구성했지만 기기에서 이 실패 및 mount 정리를 관측하지 않았다. 따라서 아래 기기 snapshot은 Guest 격리 시험이 아니라 작업 전후 Host 상태 보존 확인이다.

## Host 상태 작업 전후 비교

값은 모두 연결 기기에서 `su -c` 읽기 전용 조회로 수집했다. Property 값은 출력하지 않고 `getprop | sha256sum` digest만 기록했다.

| Host 상태 | 작업 전 | 작업 후 | 판정 |
|---|---|---|---|
| SELinux | Enforcing | Enforcing | 동일 |
| `/sys/fs/selinux/policy` SHA-256 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` | 동일 | 동일 |
| `/data/adb/modules/ssal/sepolicy.rule` SHA-256 | `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389` | 동일 | 동일 |
| Host property digest | `0bdc4e85752cd68c3e482dffe3544e4cadfdbd46d243554371a10fc48e6cd985` | 동일 | 동일 |
| 핵심 프로세스 PID | init 1, zygote64 1854, system_server 3059, installd 2607, artd 22327, netd 1852, adbd 30624 | 동일 | 동일 |
| 핵심 서비스 상태 | zygote, installd, artd, netd, adbd 모두 running | 동일 | 동일 |
| Host Binder nodes | binder `507:1`, hwbinder `507:2`, vndbinder `507:3`; 각 root:root `0666` | 동일 | 동일 |
| Host `binder-control` | `507:0`, root:root `0600`, `binder_device` label | 동일 | 동일 |

`artd`는 작업 전부터 PID 22327로 실행 중이었다. 이 단계에서 Host 서비스를 중지·재시작하지 않았다. policy 및 permanent rule hash가 동일하고 코드 변경도 영구 규칙 파일을 건드리지 않았다. 이 비교는 이번 작업 중 Host 설정을 바꾸지 않았다는 증거이며 Guest property write 비영향이나 `/proc` 접근 차단 증거는 아니다.

## Phase 5B 판정

**NO-GO.** `/dev` 전체 공유와 Host cgroup/BPF RW bind는 코드에서 제거했고 Guest binary는 fail-closed gate로 막았지만, 새 profile은 실기기에서 아직 mount 검증되지 않았다. Guest property service/area가 없고 실제 Guest property 변경 시험이 없다. Host proc/root/FD 및 signal/ptrace 경계, production UID/GID/groups/capabilities/SELinux 권한, hwbinder/vndbinder identity도 확인되지 않았다. 검증되지 않은 이 항목들은 모두 차단 조건으로 유지한다.

재진입 전 필요한 작업은 다음으로 제한한다.

1. Guest `/dev` allowlist와 Private Binder를 disposable namespace에서 실행하고 mount/device/SELinux identity를 수집한다.
2. Android 16 Bionic에 맞는 Guest property area/service를 별도 설계·구현하고 Guest read/write 및 Host property 무변경을 시험한다.
3. Guest 자격의 exec-stop FD 목록, `/proc/*/{root,fd,ns}`, signal/ptrace 접근을 비파괴 음성 시험한다. PID/IPC namespace 분리와 동등하다고 간주하지 않는다.
4. Binder 3종, 실제 service UID/GID/groups/capabilities, enforcing context/AV를 관찰한다. 모르는 항목은 UNKNOWN으로 남긴다.
