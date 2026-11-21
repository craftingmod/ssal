# Phase 7E — Guest Zygote controlled bring-up

2026-11-05 KST. **판정: NO-GO.** 현재 공통 Launcher의 Host IPC 경계가 요청된 실행 전 조건을 충족한다고 확인할 수 없어 이번 Phase의 Guest Zygote를 실행하지 않았다. 이는 Host Binder 재개방이나 Host 서비스 변경이 이번에 발생했다는 뜻이 아니다.

## 차단 근거

- Launcher는 Host와 PID namespace를 공유하면서 Guest에 procfs를 mount한다 ([mount](../src/guest_mounts.rs), [공통 Launcher](../src/guest_launcher.rs)). Guest Zygote는 UID/GID 0과 `ssal_guest_probe` 도메인으로 실행되며, 기존 실험 정책은 이 도메인을 permissive로 둔다 ([정책](../scripts/guest-domain-poc/phase7d-memory.rule)).
- 이전 실기기 UID 1000 Guest 시험에서 Host servicemanager의 `/proc/<pid>/root`를 열고 Host FD 디렉터리를 열거할 수 있었다. Host FD 대상의 재개방은 시험하지 않았다. `kill(pid, 0)`도 일부 Host PID에 성공했지만 실제 신호 전달은 시험하지 않았다. 상세 자격과 결과는 [이전 시험](guest-service-launcher-results.md)의 ‘Binder EACCES 집중 검증 및 UID 1000 전환’ 참조. 이 관측은 과거 boot의 다른 진단 child에 대한 것이며 현재 Zygote의 성공적인 endpoint 접근을 입증하지 않는다.
- `/dev`의 직접 경로 차단과 FD/env 초기화는 `/proc/<host-pid>/root` 등의 우회 경로를 차단한다는 증거가 아니다. 특히 root와 permissive 조합에 대해 Host Binder, property service, init socket의 재개방 및 연결 불가를 입증하지 못했다. Host IPC 직접 접근 위험을 해소하기 전 실행을 보류하라는 이번 요청의 조건을 적용한다.
- 공유 PID 가시성 자체를 실패로 판정한 것은 아니다. 필요한 것은 실제 Zygote 자격에서 Host IPC에 도달할 수 없다는 경계다. proc 마스킹 또는 enforcing Guest 정책 등 가능한 해결책은 Zygote의 필요한 proc 기능과 Host 안전을 함께 검증해야 하므로 이번에 검증 없이 적용하지 않았다.

## 정적 검사

기존 Phase 7A 경로는 공통 Launcher와 Phase 7D-Fix cgroup 및 진단을 사용한다. Guest `app_process64` 인자는 `-Xzygote /system/bin --zygote --socket-name=ssal_guest_zygote_<pid>`이며 `--start-system-server`는 없다. Guest `derive_classpath`와 ART/APEX, Guest linkerconfig를 사용하고 classpath 경로를 검사한다. `/data`는 Guest userdata identity를 비교한다. 새 `/dev`와 private Binder를 사용하며 직접적인 Host property socket, hwbinder 및 vndbinder 경로의 부재를 검사한다. Guest property area는 제한된 read-only seed이고 Guest property service는 없다.

실행 환경은 `env_clear` 후 명시적으로 설정되고 상속 FD를 닫거나 CLOEXEC 처리한다. Zygote worker는 `CLONE_NEWNET` 및 namespace identity를 검사하므로 abstract socket을 mount namespace만으로 격리한다고 가정하지 않는다. 이들은 코드와 이전 실행의 근거이며 이번 세션의 실제 Zygote 경계 검증 결과는 아니다. UID/GID 0에서 capability와 proc를 통한 접근 범위는 미검증이다. cgroup/task profile은 기존 Guest subtree 구성이며 실제 Zygote 초기화 중의 동작은 미검증이다.

추가로 기존 readiness는 abstract socket 존재만 먼저 확인하며 초기화 완료 로그를 독립적으로 확인하지 않는다. 이후 `/proc/<pid>/task/<pid>/children`을 필수로 읽는데, 이 기기에서 해당 파일의 부재가 [Phase 7D-Fix](zygote-phase7d-fix-results.md)에서 이미 관측됐다. 이를 readiness PASS 근거로 사용하면 안 된다. 격리 해결 후 실제 실행 경로에 맞게 고치고 테스트해야 한다.

## 이번 검증

| 단계 | 결과 |
|---|---|
| Rust `cargo test --locked --bin ssald` | PASS: 44 passed, 3 특권 시험 ignored. WSLc sandbox 밖 실행. |
| Android AArch64 release `scripts/build-guest-launcher.sh` | PASS; `ssal-memory-probe`의 unused 코드 경고 10개. WSLc sandbox 밖 실행. |
| Phase 7D-Fix 실기기 회귀 | NOT RUN. 기존 [결과](zygote-phase7d-fix-results.md)는 이 Phase의 새 실행이 아니다. |
| Zygote 실행 전 격리 | NO-GO: 위 Host proc 우회 경계 미해결. |
| Zygote 실행·초기화·telemetry·종료 경로 | NOT RUN. 초기화 로그, memory telemetry 및 해당 실기기 실행 로그 없음. |
| Host 전후 비교 | 실행이 없어 비교 시험 미실시. 읽기 전용 현재 관측에서 Enforcing, init/zygote64/system_server/adbd/netd/servicemanager/vndservicemanager 존재 확인. |

연결된 SM-S937N에서 읽기 전용 검사 당시 boot ID `a9c9be4c-7c9c-4a84-bedf-e0547c9b3062`, zygote64 PID 1805, system_server 2635, adbd 24465, netd 1803, servicemanager 961이었다. `/sys/fs/cgroup/apps/ssal_guest`, 세 v1 Guest 그룹 및 `/dev/ssal-common-launcher`는 부재했고 root/apps subtree_control은 비어 있었다. 이는 특정 시점의 표본이지 전체 Host endpoint, loop 또는 이전 Guest 자원 전체의 부재 증명이 아니다. Host PID나 cgroup을 변경하거나 live policy를 수정하지 않았다. Hard reboot와 Guest system_server 실행도 하지 않았다.

## 다음 단계 및 복구

실제 Guest Zygote 자격에서 Host `/proc/<pid>/root`, FD 및 대체 경로를 통한 Binder/property/init endpoint 접근을 막는 경계를 구현하고, 비파괴 음성 시험과 private Binder 양성 시험을 같은 자격으로 실행한다. Host global Enforcing을 유지하고 기존 Host domain에 광범위한 권한을 부여하지 않는다. 이후 readiness 검사를 고치고 Phase 7D-Fix 회귀부터 순서대로 재개한다. 격리 실패나 소유권이 불분명한 프로세스가 있으면 강제 종료나 `cgroup.kill`을 사용하지 않는다. 기존 세션 장애 시 수동 복구는 [Phase 7D-Fix 복구 절차](zygote-phase7d-fix-results.md)를 따른다.
