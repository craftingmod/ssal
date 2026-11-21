# Private Binder Test B hardening — 2026-11-03

실제 Android 16 Guest `servicemanager`의 등록·조회·nonce 호출과 양방향 레지스트리 격리가 SM-S937N/profile1에서 **Enforcing 상태로 통과**했다. 최종 보고서는 `phase1_complete=true`이며 다섯 필드가 모두 `passed`다. `switch`와 운영 서비스 `launch_enabled=false`는 유지한다. 설치 데몬은 교체하지 않았고 시험은 제한된 임시 바이너리로 수행했다. 모듈 정책에는 전용 테스트 도메인용 규칙을 포함한다.

| 필드 | Permissive 진단 | Enforcing 초기 실행 | Enforcing hardening 후 |
| --- | --- | --- | --- |
| `servicemanager` | passed | failed — `add_denied` | passed |
| `android_service_selinux` | failed — Enforcing 조건 미충족 | passed | passed |
| `host_registry_isolation` | passed | not_run | passed |
| `property_host_unchanged` | passed | passed | passed |
| `cleanup` | passed | passed | passed |

[최종 Enforcing 원시 증거](servicemanager-test-b-enforcing-hardened-device-20261103.json), [Permissive 진단](servicemanager-test-b-permissive-device-20261103.json), [초기 Enforcing 실패 증거](servicemanager-test-b-enforcing-device-20261103.json)는 boot/session ID, 이미지 SHA-256, helper/Guest 라이브러리 manifest, 실행 자격, 실제 PID/starttime/SID/root/executable/Binder FD, Host 비교 및 정리 결과를 포함한다. 최종 실행은 global Enforcing에서 manager와 시험 서버 도메인이 모두 nonpermissive임을 확인했다. 실효 AV sequence/domain flags와 적용 정책 hash를 기록했다.

## 구현한 경계

- `ssal probe-servicemanager PROFILE_NAME`은 새 binderfs 세션에서 고정 `/system/bin/servicemanager`만 실행한다. PID의 실제 `u:r:servicemanager:s0`, UID/GID 1000, 보조 그룹 3009, capability 0, NNP/seccomp, root·실행 파일 inode, 세션 장치의 dev/inode/rdev를 확인한 뒤 후속 시험을 진행한다.
- Guest `/dev`는 private Binder와 null 및 세션 일반 로그 파일만 제공한다. property 영역과 소켓은 빈 새 디렉터리다. 상속 FD를 exec에서 닫고 모든 `connect`를 seccomp EPERM으로 차단한다. 실제 syscall 차단을 payload 없이 self-check한다. 필터는 실제 서비스 exec에도 유지된다. `ctl.*`를 포함한 Host property 요청을 시험 삼아 보내지 않았다.
- Host property 수집은 Android property API로 수행하고 값은 메모리에서 즉시 해시한다. 줄바꿈을 포함한 값도 텍스트 파싱 없이 비교하며, 값 원문을 일반 로그에 쓰지 않는다. 정상/차단 종료 모두 사후 수집한다.
- proc는 프로세스별 현재 SID 경로만 노출한다. Host PID의 root/FD magic link나 기능하는 전체 proc를 제공하지 않는다. sysfs는 새 뷰로 가리고 selinuxfs의 AV/context 질의만 쓰기 가능하게 남긴다. 모든 제어 항목은 개별 read-only bind다. libselinux는 루트 selinuxfs를 RW로 발견해야 하므로 전체 마운트를 RO로 만들면 SELinux 비활성 오판이 발생한다. helper는 활성 상태와 상태 API 성공도 요구한다.
- 사전 매핑된 `aidl_lazy_test_1`을 Guest에서 등록하고 전용 `u:r:aidl_lazy_test_server:s0` 서버 및 별도 fresh-exec 클라이언트의 nonce와 서버 PID를 확인한다. Host의 `activity` 조회를 양성 대조군으로 확인한 뒤 Host→Guest 시험 이름과 Guest→Host `activity`가 각각 미등록인지 검사한다. Host 조회기는 init의 mount namespace로 진입하고 실제 root/namespace를 확인한다. Host에서는 등록하지 않는다.
- 조회는 고정 Android 16 AIDL의 비 lazy `checkService` transaction이다. transport/Status/nullable Binder 파싱과 실제 service_contexts 매핑·find 권한·SELinux 활성 상태가 모두 확인돼야 미등록을 인정한다. null·권한 거부·매핑 부재·통신 실패를 격리 성공으로 기록하지 않는다.
- 모든 프로세스는 생성 직후 Child handle/PID/starttime으로 추적한다. 클라이언트→시험 서버→manager 역순으로 TERM, 유한 대기, 필요한 경우 KILL 후 회수한다. Guest는 fork를 차단하고 thread 생성만 허용하며 감독자 종료 시 PDEATHSIG로 종료한다. 프로세스 회수를 확인하지 못하면 마운트 정리를 진행하지 않는다. 정리 실패는 `RECOVERY_REQUIRED` marker를 남기고 같은 boot의 새 probe를 차단하며 scratch를 보존한다. 바깥 rootfs/loop 정리 실패에도 같은 marker를 적용한다.

## 실기기 결과

초기 Enforcing 실패의 원인은 shell에서 실행한 서버가 임의 시험 이름을 등록하려 한 점이다. 실제 service_contexts에서 임의 이름은 `default_android_service`로 매핑되고 shell에는 `add`가 허용되지 않아 ServiceManager가 등록을 거부했다. private Binder 장치 open/read/write/ioctl은 이미 허용돼 있었다. Permissive에서는 격리 흐름 자체가 동작했지만 shell의 add/find AVC가 남아 있어 Enforcing 통과 증거로 취급하지 않았다.

Hardening에서는 기존 AOSP 매핑 `aidl_lazy_test_1 → aidl_lazy_test_service`와 전용 `aidl_lazy_test_server` 도메인을 사용했다. 모듈 `sepolicy.rule`에 다음 여섯 허용 규칙을 추가했다: 전용 실행 파일의 entrypoint/execute/read/map, 해당 service type의 `service_manager add`, 시험 서버↔`servicemanager`의 call/transfer, 시험 서버↔shell 클라이언트의 transfer. 적용 후 Enforcing 재시험에서 global mode, manager SID `u:r:servicemanager:s0`, 서버 SID `u:r:aidl_lazy_test_server:s0`, 두 도메인의 nonpermissive 상태를 확인했다. 다섯 Test B 필드가 모두 통과했다.

Guest 등록·nonce echo와 Host `activity` 양성 대조군이 성공했고, Host에서 시험 이름은 미등록, Guest에서 Host `activity`는 미등록이었다. Guest private Binder rdev는 129797, Host Binder rdev는 129793이었다. Host framework와 mount 상태가 유지됐고 Host property 변경 이름은 없었다. 프로세스, Binder FD, mount 및 세션 loop 자원 정리도 통과했다. 실행 후 기기는 Enforcing 상태였다.

두 최종 실행 모두 Host Framework PID/starttime/context/executable, init mountinfo와 전체 수집 property 해시가 전후 일치했다. 모든 시험 프로세스를 회수했고 private Binder와 임시 뷰, rootfs, system/data mount 및 세션 loop backing 55개를 해제했다. 별도 정리 스크립트가 exe/root/mountinfo/loop 참조를 확인한 뒤 전용 scratch를 삭제했다. 시험 전 Enforcing을 기록했고 Permissive 시험 후 Enforcing으로 복원했다. 재부팅과 Host Framework 중지는 수행하지 않았다.

초기 실패에서는 property 목록의 줄바꿈, libselinux getcon proc 경로, selinuxfs RO 발견 문제를 확인하고 각각 property API, 제한 proc 별칭, 제어 항목별 RO bind로 수정했다. 초기 SIGABRT·권한 거부 실행도 공통 정리 경로와 property 사후 비교를 거쳤다.

## 검증과 남은 범위

`cargo test --locked`: 67개 passed, 권한이 필요한 기존 3개 ignored. 변경 Rust 대상의 clippy `-D warnings`, cargo fmt, C++ `-Wall -Wextra -Werror`, Android release 빌드, 정리 스크립트 shellcheck 및 모듈 패키징을 통과했다. 전체 대상 clippy는 기존 `ssal-guest-domain-poc`의 별도 경고로 통과하지 못했으며 해당 파일은 수정하지 않았다. 삼성 커널 `vendor/` 소스는 열지 않았다. 실기기의 실효 AV 질의와 정책 판정으로 필요한 권한을 특정할 수 있었다.

실기기에서 Permissive 진단, Enforcing 초기 실패와 hardening 후 Enforcing 통과를 실행했다. 실제 unkillable 프로세스와 mount/loop 정리 실패 주입은 수행하지 않았다. 제한 proc·logging·task profile 생략은 Test B 전용 override이며 운영 Android 런타임 준비 완료가 아니다. 이 시험의 `/data`는 빈 세션 tmpfs이고, **디렉터리 bind Guest `/data` 및 전용 installd/artd 격리(Phase 2)는 미검증**이다. 그 검증 전까지 `switch`는 계속 차단한다.
