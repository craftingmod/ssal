# Phase 8B — Guest `system_server` 제한 실행 계획

이 계획은 Phase 8A의 정적 분석을 토대로 한다. Phase 8A에서는 실제 `SystemServer.main()`을 실행하지 않았다. 첫 시도는 Guest process만 실행하고 Host init, Host Binder/property, HAL 및 물리 장치를 제어하지 않는 bounded PoC로 제한한다.

## 실행 전 최소 준비

1. **GSI input 고정:** 이미지 이름/SHA-256, build fingerprint, Guest userdata ID, mount profile, `ssald`/worker hash와 기기 boot ID를 session journal에 묶는다. GSI가 official Android build number상 `android-16.0.0_r4`임과 Lineage source commit unknown을 기록한다.
2. **Guest classpath 보완:** `derive_guest_classpath()`가 결과에서 `SYSTEMSERVERCLASSPATH`를 보존하고, Guest GSI의 system-server jars만으로 값이 구성됐는지 확인한다. `env_clear()` 상태를 유지하고 Host의 `SYSTEMSERVERCLASSPATH`를 상속하지 않는다. `/system/framework/services.jar`, ART/linkerconfig/APEX와 `libandroid_servers.so`의 Guest root identity를 확인한다.
3. **실행 게이트 추가:** 서비스 계약은 계속 launch-disabled로 둔다. 별도 8B 전용 worker opt-in만 `--start-system-server`를 Guest Zygote에 전달한다. Guest `init.zygote64.rc`를 Host init에서 실행하지 않고 Host init control socket에도 연결하지 않는다.
4. **SELinux context 준비:** Host `system_server` SID를 재사용하지 않는다. Guest 전용 `ssal_guest_system_server` type/role/context와 system-server child에만 해당하는 specialization을 준비한다. 현재 `ssal_guest_probe` EINVAL fallback은 UID/server/이름 조건상 매칭하지 않으므로 사용하지 않는다. shared PID+UID 경계가 남아 있는 동안 이 system_server domain은 enforcing으로 시작한다. Host global Enforcing은 계속 유지하고 필요한 Guest-only AVC allow만 반복적으로 좁혀 추가한다.
5. **PID/FD/capability 게이트:** 전용 harmless Host test process만 대상으로 Guest candidate의 `/proc/<pid>/root`, `/proc/<pid>/fd`, ptrace 및 signal denial을 비파괴 방식으로 확인한다. Host core service에는 접근 시험이나 신호를 보내지 않는다. Guest Zygote와 child의 UID/GID/groups, `CapEff/CapBnd`, seccomp/NoNewPrivs, rlimits를 저장한다. Host process-control, module, time, network-admin 등의 kernel-wide capability는 8B milestone에 필요한 최소 집합으로 제한한다.
6. **Private endpoint/cgroup:** Guest `/dev/binder`의 device identity와 Host Binder 차이를 확인하고 `/dev/hwbinder`, `/dev/vndbinder`, Host service socket, property area가 Guest에서 보이지 않는지 확인한다. Guest Property Service가 system-server 시작 property를 받아도 private area에만 기록하는지 확인한다. Guest cgroup membership과 `SSAL_MEMORY_HIGH`/`SSAL_MEMORY_MAX` finite limit/readback을 확인한다. 값이 적용되지 않으면 무제한 실행하지 않는다. 같은 기기의 과거 Phase 7A 실행에서 Host `lmkd` cache 회수가 관측됐으므로 처음부터 Guest memory ceiling을 사용한다.
7. **기준선 기록:** Host boot ID, `Enforcing`, init/adbd/netd/Host Zygote/Host system_server PID+starttime+SID, Host mountinfo, Host property-area/socket identity, binder endpoint identity 및 전체 Guest cgroup 상위 상태를 저장한다. 기존 One UI 핵심 서비스에 요청을 보내지 않는다.

## 단계와 성공 증거

| 단계 | 수행 | 성공 증거 | 첫 실패 시 |
|---|---|---|---|
| **8B-1: fork + Java entrypoint** | 기존 Guest Zygote가 system_server child를 fork하도록 8B flag만 활성화한다. Java entrypoint가 `com.android.server.SystemServer`인지 확인한다. | child PID/starttime, UID/GID/groups, target SID, capabilities/limits, Guest root, private Binder FD, Guest cgroup, entrypoint marker | SELinux specialization, classloader, runtime/linker 또는 property/Binder 준비에서 처음 막힌 지점을 기록하고 Guest child/Zygote만 종료한다. |
| **8B-2: `SystemServer.run()` 진입** | 같은 경로에서 native `android_servers` load와 초기 property/framework setup까지 관찰한다. | `SystemServer.run()` 진입 marker 또는 Guest-only log evidence, Guest property 변경, Host endpoint 변화 없음 | 8B-1 기준선을 비교하고 해당 세션을 cleanup한다. |
| **8B-3: 첫 Bootstrap 호출** | 첫 `startBootstrapServices()` 호출을 허용한다. 첫 실질 실패/예외/서비스 readiness만 기록하며 전체 부팅을 목표로 늘리지 않는다. | Bootstrap 진입 marker와 첫 ServiceManager/service `onStart()` 시도 또는 최초 fatal error 식별 | power/display/installer/HAL/cgroup 중 첫 실패를 분류해 중단한다. Host HAL relay나 다른 subsystem을 현 단계에서 구현하지 않는다. |

현재 GSI는 `ro.debuggable=0`이고 `SystemServer.run()`은 순차 실행된다. 8B-1/8B-2에서 실행을 각 경계에서 정지해야 한다면 exact source revision이 고정된 debug artifact의 one-shot marker/pause hook을 먼저 사용한다. 해당 revision이 준비되지 않으면 세 단계를 한 run에서 자동 진행시키지 말고, 관측 가능한 entry marker를 얻는 좁은 probe 경로를 별도 선택한다. Host init rc를 pause/launcher 용도로 재사용하지 않는다.

## 제한시간과 관측

- 8B-1: fork/Java entrypoint에 최대 30초.
- 8B-2: `run()` 초기 준비에 최대 90초.
- 8B-3: 첫 Bootstrap 서비스 시도에 최대 180초. 45초 동안 새 milestone/trace가 없으면 stall로 기록한다.
- 제한시간은 단계별 상한이다. Guest child가 PID/starttime을 바꾸거나 cgroup을 이탈하거나, Host boundary preflight가 실패하거나, Host `Enforcing`/baseline이 바뀌면 즉시 Guest 세션을 종료한다.
- `ssald` session stdout/stderr와 guest child marker를 저장한다. Guest-private logd가 준비된 경우에만 Guest log buffer를 읽는다. Host `logcat`/logd를 Guest logging endpoint로 bind하지 않는다. AVC는 기기 kernel log에서 session PID, Guest SID, 메시지 timestamp로 선별하고, 원문 로그 전체를 보고서에 복사하지 않는다.
- 자원 기록은 시작/종료 `MemAvailable`, Guest cgroup `memory.current/high/max/events`, Guest process `status/limits/cgroup/fd`, Host process snapshot, Host mount/property/Binder identity다. 수집용 Host read는 기록 후 추가로 쓰지 않는다.

## 종료와 cleanup

1. 새 Zygote fork 요청을 닫고, session에 등록된 system_server PIDFD로 SIGTERM을 보내 최대 5초 기다린다. 계속 살아 있으면 같은 PIDFD로 SIGKILL하고 wait/reap한다. PID 이름만으로 검색/종료하지 않는다.
2. Guest Zygote, Guest Property Service, Guest ServiceManager를 각각 소유 PID/starttime/context와 PIDFD로 종료한다. process group 종료는 그 group 전체가 SSAL session 전용임을 확인한 경우에만 사용한다.
3. Guest child가 session cgroup에 남지 않았는지 확인한 뒤 cgroup을 제거한다. cgroup에 예상 밖 process가 남거나 rmdir 실패 시 해당 cgroup/mount를 보존하고 `RECOVERY_REQUIRED`를 남긴다.
4. Guest socket/Private Binder, userdata bind, APEX/system loop, Guest rootfs mount를 역순으로 해제하고 실제 잔여 mount/loop를 확인한다. Guest userdata 자체는 삭제하거나 초기화하지 않는다.
5. Host 전역 Enforcing, boot ID, 핵심 PID/starttime/SID, mountinfo, Host property/Binder/socket identity가 기준선과 같은지 비교한다. system_server가 Host process/FD/HAL/property endpoint를 사용했거나 이 비교가 달라지면 PASS를 주지 않는다.

## 단계별 판정

- **PASS:** 선택한 8B 단계에 도달했고 Guest-only cleanup이 끝났으며 Host baseline은 동일하다.
- **PARTIAL:** Host 경계는 유지됐지만 SELinux/Classpath/Property/HAL/Display 등 Guest-only 의존성에서 중단했다. 첫 실질 실패만 최소 수정한다.
- **NO-GO:** 실제 Host Binder/Property/HAL, Host process signal/FD/root 또는 Host init 제어가 Guest에서 가능하다는 증거가 나오거나, Guest PID/cgroup만을 안전하게 정리하지 못한 경우다. 이때 direct path를 차단하는 최소 수정만 제안하고 전체 부팅은 시도하지 않는다.

완전한 UI/전체 Android 부팅, SurfaceFlinger 대체, HAL relay, host daemon 교체, SELinux 전체 변환은 이번 첫 실행 목표가 아니다.
