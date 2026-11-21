# Phase 8A — Host 경계와 SELinux 판단

- 조사일: 2026-11-05 KST
- 범위: Phase 7I 이후 현재 SSAL 경로와 GSI 파일 배치에 대한 정적/기록 근거
- 판정: Host 상태를 변경하지 않았다. `PRIVATE`는 확인된 Guest 전용 경로를, `UNKNOWN`은 아직 시험하지 않은 접근을 뜻한다.

## 자원별 분류

| 자원 | 분류 | 근거와 남은 한계 |
|---|---|---|
| `/dev/binder` | **PRIVATE** | Guest `/dev` 안의 binderfs device를 사용하고 Host Binder와 다른 device identity로 Private AIDL 시험을 통과했다. Phase 7I Java child의 Binder 왕복은 확인했지만 `SystemServer`의 Java `ProcessState`는 미시험이다. |
| `/dev/hwbinder` | **BLOCKED** | Guest `/dev`는 새 tmpfs이며 Host HAL node를 bind하지 않는다. GSI init rc를 Host init에서 실행하지 않는다. |
| `/dev/vndbinder` | **BLOCKED** | Guest `/dev`에 Host vendor Binder node가 없다. 삼성 vendor IPC 연동은 이번 범위 밖이다. |
| `/dev/socket` | **PRIVATE** | Guest socket 디렉터리에 Guest Zygote/Property socket을 생성한다. Phase 7I에서 Host control socket 부재를 확인했다. |
| `/dev/__properties__` | **PRIVATE** | Guest Property Service가 별도 tmpfs area를 만들고 Host identity와 다름을 확인한다. `property_service_for_system`은 Guest에 만들지 않는다. full system_server property context coverage는 미검증이다. |
| `/data` | **PRIVATE** | profile의 별도 ext4 userdata를 Guest mount namespace에 연결했다. Phase 7I는 Guest/Host `/data` device가 다르고 Guest Java child write/read가 통과한 기록이 있다. FBE/CE/DE 수명주기는 미검증이다. |
| `/proc` | **SHARED** | 새 proc mount이지만 PID namespace는 Host와 공유한다. Guest PID와 Host PID가 같은 번호 공간에 있다. 이는 단순 읽기 전용 자료가 아니다. |
| `/proc/<pid>/root`, `/proc/<pid>/fd`, ptrace/signal | **UNKNOWN** | PID 공유 상태에서 Host process root/FD 접근 및 신호 권한을 `system_server`와 같은 UID/domain으로 negative-test하지 않았다. `/dev/binder` 경로를 가려도 Host process가 연 Binder FD에 대한 `/proc` magic-link 경로는 별도 문제다. |
| `/sys` | **READ-ONLY** | 새 sysfs mount을 RO로 제공한다. 경로 쓰기는 막지만 커널·장치 상태 자체는 공유되고 보일 수 있다. RO만으로 `/dev` ioctl이나 다른 kernel API의 부작용을 격리하지 않는다. |
| `/dev` 일반 장치 | **PRIVATE** | 4 MiB Guest tmpfs와 검사된 pseudo-device allowlist를 사용한다. Host `/dev` 전체, kmsg, input, graphics, block, HAL 장치 노드는 넘기지 않는다. |
| `/sys/fs/cgroup` | **PRIVATE (하위 트리)** | SSAL이 만든 `ssal_guest` cgroup 하위 트리만 Guest 경로에 bind하고 Zygote child의 membership을 확인했다. Android 전체 task-profile/서비스 그룹 동작은 검증되지 않았다. |
| `ctl.*`, `sys.powerctl` | **PRIVATE** | SSAL Property Service는 Guest area/socket을 사용하고 서비스 계약은 `forward_ctl=false`다. 이 실행 경로에서 Guest init은 동작하지 않으므로 Guest property write가 Host init action을 일으키지 않는다. future relay나 Host property socket을 추가하면 이 판정은 다시 해야 한다. |
| Host HALs / Host servicemanager | **BLOCKED** | Host Binder/HAL node와 socket을 직접 노출하지 않는다. 기능이 필요해지면 인터페이스별 **RELAY**를 검토한다. 아직 allowlist/relay는 없다. |

마운트의 세부 근거는 [initial mount profile](initial-mount-profile.md#마운트-표), 코드의 Guest `/dev` allowlist는 [`prepare_guest_dev()`](../src/guest_mounts.rs#L238), cgroup은 [`GUEST_CGROUPS`](../src/guest_mounts.rs#L733)에 있다.

## 8B에서 직접 제어해야 하는 Host 위험

### PID, UID, SELinux

Phase 7I Java child는 UID/GID 10000, capabilities 0, `u:r:ssal_guest_probe:s0`였고 Guest root/cgroup에서 정상 종료됐다. system_server는 Android 기본 fork 계약에서 UID/GID 1000/1000이며, Host One UI의 `system_server`도 UID 1000일 수 있다. PID namespace가 같으므로 UID만으로 Guest/Host process를 구분할 수 없다.

실험적 `selinux_android_setcontext()` 결과 `EINVAL`과 retained-domain fallback은 `uid=10000`, `server=0`, `seinfo=ssal_probe`, nice name `ssal-fork-probe` 및 지정 flag가 모두 맞는 probe에만 허용된다. system_server는 UID 1000/server fork이므로 이 fallback에 매칭되지 않으며, 이를 넓혀서는 안 된다. ([Phase 7F-C 결과](zygote-phase7fc-results.md), [fallback을 쓰는 probe 요청](../src/guest_launcher/fork_probe.rs#L7))

Phase 8B는 Host의 `system_server` 도메인을 재사용하지 않고 전용 Guest type (예: `ssal_guest_system_server`)과 그 child만을 위한 specialization을 준비해야 한다. 누락된 Guest type/role/context는 구현 작업이다. 새 Host-domain allow, broad `domain` allow 또는 전역 permissive는 추가하지 않는다. 같은 PID/UID 공간에서 Guest `system_server` type을 permissive로 만들면 `/proc/<pid>/fd`와 process signal의 SELinux 거부도 함께 우회될 수 있다. 따라서 그 Guest domain은 cross-process Host `/proc`/FD/`signal` 경계가 enforcing 상태로 확인될 때까지 enforcing으로 둔다. 다른 안전한 Guest-only probe domain에서 필요한 AVC를 수집하고 정확한 Guest allow만 추가한다.

최소 policy 변경의 범위는 Guest 전용 type/role 유효화, Zygote의 **system_server child**에만 해당 type을 선택하는 context 규칙, 그 Guest type이 직접 사용하는 경로/서비스의 최소 권한이다. system_server는 Zygote child이므로 별도 Host init service나 Host `system_server` executable label 전환을 만들지 않는다. 이 delta는 문서 준비만 했고 적용하지 않았다.

### Capability, PID identity, 메모리

- `src/guest_launcher.rs::command()`는 UID 변경 전에 명시적인 `capset()`/capability drop을 하지 않는다. AOSP `ZygoteInit`의 system_server fork는 parent가 가진 capability 중 일부를 child에 요청한다. `CAP_KILL`, network/time/module 계열의 실제 Guest Zygote/child `CapEff`는 Phase 7I 결과에 기록되지 않았다. Host kernel 전역 상태에 닿는 capability는 Guest `system_server` 시작 전에 명시적으로 제한하고 실제 `/proc/<pid>/status`에서 확인한다.
- Guest cgroup은 현재 code path에서 session-owned subtree이며 cleanup은 점유된 group을 임의 삭제하지 않고 실패로 남긴다. `SSAL_MEMORY_HIGH`/`SSAL_MEMORY_MAX`는 선택 설정이다. Phase 7A의 같은 기기 기록에는 Guest Zygote 시험 중 Host `lmkd` cached app 27개 회수가 있었다. 8B는 기존 memory controller 경로의 유한한 상한을 설정하고 readback하며, 실패 시 무제한 system_server를 시작하지 않는다. ([cgroup 구현](../src/guest_mounts.rs#L741), [memory limit 입력](../src/guest_mounts.rs#L858), [7A 기록](zygote-phase7a-results.md#L21))
- 프로세스 종료는 name 기반 `pkill`이 아니라 session PID + starttime + pidfd, Guest cgroup membership을 사용한다. `system_server`가 추가로 fork한 process가 모두 그 session cgroup에 남는지 확인한 뒤에만 cgroup cleanup을 완료한다. 예상 밖 child나 남은 mount/loop가 있으면 `RECOVERY_REQUIRED`로 기록하고 해당 cgroup/mount를 보존한다.

## SELinux 및 8B 게이트

Host 전역 SELinux는 Phase 7I 실행 전후 Enforcing으로 기록됐다. 이는 Guest `system_server`의 권한을 증명하지 않는다. 8B 시작 전에 다음만 확인한다.

1. `ssal_guest_system_server`가 실제 활성 정책에서 유효한 context이며 Host 기존 `system_server` SID를 사용하지 않는가.
2. system_server의 `/proc/<Host PID>/root`, `/proc/<Host PID>/fd`, ptrace 및 signal 요청이 Host target type에서 거부되는가. 음성 시험은 핵심 Host 서비스에 신호를 보내지 않고 전용 harmless Host test process로 한다.
3. `CapEff`, `CapBnd`, `NoNewPrivs`, seccomp, supplementary groups 및 rlimits가 실행 시 기록되고, Host 전역 작업 권한이 제외됐는가.
4. `/dev/binder`가 private device이고 `/dev/hwbinder`, `/dev/vndbinder`, Host service/control socket, Host property area가 Guest namespace에서 계속 보이지 않는가.
5. Guest property write/`sys.powerctl`가 Guest Property Service area/socket 안에만 남고 Host init/property endpoint로 전달되지 않는가.
6. system_server와 그 child의 cgroup이 세션-owned subtree이며 finite memory cap이 설정·readback됐는가.

Host 전역 enforcing을 유지하고, 막힌 Guest-only type/permission은 좁은 policy delta로 보완한다. 완전한 SELinux 변환, Host HAL relay 또는 전체 부팅 성공을 8B-1/8B-2의 선행조건으로 두지 않는다. 확인된 Host process/FD/property/Binder 제어 경로는 첫 실제 fork 전에 해결해야 한다.
