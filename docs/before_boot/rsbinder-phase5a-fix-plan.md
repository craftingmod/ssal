# SSAL Phase 5A-Fix — 계획

- 작성일: 2026-11-04 (Asia/Seoul)
- 목표: 기본 Guest mount profile의 Host 장치/property 노출과 Guest exec 경계의 알려진 FD 누출을 줄이고, 검증되지 않은 격리는 실행 차단 사유로 강제한다.
- 범위: Phase 1~4 Private Binder 및 ServiceManager 구현은 재사용한다. 대규모 property-service 구현, init/service 실행, 새 SELinux 규칙은 이번 변경에서 제외한다.

## 확인된 시작 상태

Phase 5A 조사에서 기본 profile은 Host `/dev` 전체를 재귀 bind해 Host Binder와 `/dev/__properties__` area를 공유했고, `/sys/fs/cgroup` 및 `/sys/fs/bpf`도 RW로 연결했다. Guest property service는 없고 PID/IPC namespace 생성은 기기에서 통과하지 못했다. 이 사실은 [Phase 5A 경계 기록](rsbinder-phase5a-boundaries.md)에 근거와 범위가 기록돼 있다.

실행 계약의 `launch_enabled`는 `false`이며 `service_contract` 검증도 이를 강제한다. 이 gate를 유지하고 `installd`, `artd`, `zygote`, `system_server`를 시작하지 않는다.

## 최소 변경

| 항목 | 변경 | 완료 판단 기준 |
|---|---|---|
| Guest `/dev` | rootfs 안에 별도 tmpfs를 만들고 `/dev/null`, `zero`, `random`, `urandom`만 검증 후 개별 bind한다. 허용 장치의 type, rdev, UID/GID, mode, Guest/Host mount ID를 비교한다. Host Binder, `binder-control`, property area, socket, kmsg, 입력·DRM·HAL 노드는 전달하지 않는다. Binder probe는 기존 private binderfs 경로를 계속 사용한다. | 코드에서 mount allowlist·검증이 fail-closed이고 profile 단위 검사가 통과. 실제 Android mount 결과는 별도로 기기 확인 전까지 PARTIAL. |
| Host kernel writable mount | `/sys/fs/cgroup`과 `/sys/fs/bpf`의 Host bind를 제거한다. | 기본 profile에 해당 RW bind가 없음. 공유 sysfs/kernel 경계 자체의 분리는 주장하지 않음. |
| Property 영역 | 새 `/dev`에 Host `/dev/__properties__`와 Host property socket을 넣지 않는다. Android 16 호환 Guest area/service는 이번 단계에서 구현하지 않는다. | 기본 profile 코드에 Host property 경로가 없는지 검토한다. Guest read/write/SELinux 동작은 실기기 확인 전 UNKNOWN/PARTIAL이며 GO 근거가 될 수 없음. |
| 상속 FD | Guest chroot/exec helper는 사전 FD의 descriptor identity를 캡처해 allowlist 밖의 동일 FD를 `pre_exec`에서 닫는다. 표준 I/O는 보존하고, helper executable FD가 필요한 기존 identity probe에는 그 FD만 허용한다. | helper 단위 검증과 Android 대상 타입검사. 실제 Guest 서비스 exec-stop FD 목록은 별도 기기 검증 전까지 UNKNOWN. |
| Host proc/process 경계 | PID namespace 대체 구현이나 영구 SELinux 규칙을 추가하지 않는다. `/proc/<pid>/root`, `/fd`, `/ns`, signal/ptrace 접근은 실제 Guest 자격으로 음성 확인될 때까지 차단 조건이다. | 이 항목이 확인되지 않으면 Phase 5B는 NO-GO. |

이번 수정에서는 위 차단 조건을 실제 실행 gate로 적용했다. `prepare`는 rootfs mount를 만든 뒤 Guest `linkerconfig`를 실행하기 직전에 항상 실패하고 일반 역순 mount 정리로 끝난다. `guest_probe`와 SELinux identity helper에도 같은 gate가 있어, 현재 표준 경로로는 Guest GSI 바이너리가 실행되지 않는다. 이 fail-closed 동작은 실제 Host proc/process 음성 시험을 대체하지 않으며, 경계가 검증될 때까지 `prepare`를 성공 처리하지 않는다.

Android 16 Bionic은 property API와 공유 property area를 사용하고, `__system_property_set` 처리는 별도 init property service 경로에 의존한다. 그러므로 Host area를 숨기는 것만으로 Guest property 기능을 완료했다고 판정하지 않는다. [Bionic Android 16 property API](https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r2/libc/include/sys/system_properties.h), [AOSP Android 16 property service](https://android.googlesource.com/platform/system/core/+/refs/tags/android-16.0.0_r2/init/property_service.cpp).

## 안전·호환성 경계

- `/dev`의 네 pseudo-device는 같은 커널 device identity를 사용하므로 이름만으로 허용하지 않는다. 예상 major/minor와 root:root `0666`, 별도 bind mount ID를 확인하고 실제 Guest SELinux access가 검증되지 않으면 PARTIAL로 남긴다.
- `initial-shared-dev` 문자열은 이미 생성된 profile metadata와의 호환을 위해 유지한다. 실제 `/dev` 구성은 Guest 전용이다.
- GPU, DRM, 입력, HAL, hwbinder/vndbinder는 실제 필요성 및 별도 격리 근거가 없으므로 기본 전달하지 않는다.
- Host 서비스, Enforcing 상태, live/영구 SELinux policy는 변경하지 않는다.

## 검증 순서

1. profile과 장치 allowlist·FD helper 단위 테스트, Android 대상 `cargo check --tests`, Phase 2/3 회귀 테스트를 실행한다.
2. 연결 기기에서는 작업 전후 SELinux 상태, live policy 및 permanent rule hash, 핵심 Host 서비스 PID/state, Host property digest를 읽기 전용으로 비교한다.
3. 코드가 기기에 배포되지 않거나 mount/proc/FD 위험 시험이 비파괴적으로 격리되지 않으면 실기기 실행을 생략하고 UNKNOWN/PARTIAL로 기록한다. 현재 Guest binary gate는 유지한다.
4. Guest `/dev` 및 property path, Binder 3종 identity, Host proc/FD/signal/ptrace 접근은 실행 결과가 관찰된 경우만 판정한다.

## Phase 5B 진입 조건

GO에는 Guest 전용 Android 16 property area와 호환되는 Guest service, Host property write 비영향, actual exec 경계 FD allowlist, Host proc/root/FD 및 signal/ptrace 차단, 실제 Guest 자격의 `/dev`·Binder·SELinux 검증이 모두 필요하다. PID/IPC namespace가 지원되지 않는다는 기존 증거를 다른 격리와 동등하다고 간주하지 않는다. 항목 하나라도 UNKNOWN/PARTIAL이면 NO-GO를 유지한다.
