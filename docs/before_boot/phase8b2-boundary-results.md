# Phase 8B-2 — Host/Guest 경계 결과

## 판정

경계 검증은 **PARTIAL / 후보 system_server 테스트 미실행**이다. 읽기 전용 Host 상태는 확인했지만 Guest system_server child가 없으므로 `/proc`, fd, signal, ptrace, Binder, property, socket, credential 및 cgroup 경계를 Phase 8B-2 조건으로 판정할 수 없다. 이를 PASS나 Host 위반으로 기록하지 않는다.

## 읽기 전용 Host 확인

| 확인 | 결과 |
|---|---|
| 기기 | `R5CY52JC03H`, SM-S937N |
| Host SELinux | `getenforce=Enforcing`; `/sys/fs/selinux/enforce=1` |
| Boot ID | `03834516-215d-4fd6-8960-1b833882595e` (Phase 8B-1과 동일) |
| Host `system_server` | PID 2911, `u:r:system_server:s0` |
| OS / SDK | Android 17 / SDK 37 |
| Live policy 전체 확인 | 불가/미확인. `/sys/fs/selinux/policy` 읽기는 Phase 8B-1에서 `EINVAL`; KernelSU 추가 정책도 분리 확인되지 않음 |

이번 Phase에서는 기기에 정책이나 바이너리를 적용하지 않았고, Guest 서비스 프로세스를 시작하거나 종료하지 않았다. Boot ID와 Host SELinux/`system_server` 확인은 읽기 전용 관찰이지 Guest 전환 전후 snapshot 비교가 아니다.

## 검증 항목

| 경계/조건 | Phase 8B-2 결과 | 이유 |
|---|---|---|
| Guest startup SID 및 최종 Guest SID | 미실행 | Guest GSI/seapp/framework 패치와 새 live Guest 정책이 아직 적용되지 않음 |
| Guest UID/GID/groups 및 capability sets | 미관측 | 후보 child를 fork하지 않음 |
| Host `/proc`/fd/signal/ptrace 격리 | 미실행 | system_server child 없이 안전한 대조 대상이 없음 |
| Host Binder/property/socket 비노출 | 미실행 | Host endpoint에는 probe를 보내지 않음 |
| Guest userdata·memory cgroup·PIDFD cleanup | 미실행 | 8B-2 child 또는 cgroup 생성 안 함 |
| Guest-target AVC 수집 | 미실행 | 정책 적용과 Guest domain 실행 안 함 |
| Host enforcing 및 Host PID/context 기본값 | 읽기 전용 확인 | 기존 Host와 같은 boot의 baseline 상태만 확인 |

Phase 8B-1은 별도 Guest Java child 경로에서 Private Binder, Guest userdata, 2 GiB memory limit 및 cleanup을 통과했다. 그 child는 UID 10000 / `ssal_guest_probe`였으므로 system_server 경계의 증거로 재사용하지 않는다. 자세한 기준선은 [Phase 8B-1 결과](phase8b1-preflight-results.md)를 참조한다.

## 다음 제한 실험의 입구 조건

1. Guest 전용 startup/final SID 선택을 반영한 정확한 GSI source/build artifact를 준비하고 해시를 고정한다.
2. 해당 기기의 live policy에서 새 type/attribute/transition이 유효한지 read-only로 좁힌다. Guest-only `permissive` 수집 모드만 허용하고 Host `Enforcing` 및 Host 도메인 권한을 유지한다.
3. 실행 직전 Host enforcing/boot ID/core process/policy snapshot을 기록한다. 실제 GSI init rc는 사용하지 않고, launcher의 `start_system_server=false` 기본값을 유지한다.
4. 후보 child가 생기면 PID/starttime/pidfd를 고정한 뒤 UID, groups, capabilities, SELinux context, `no_new_privs`, seccomp와 cgroup membership을 기록한다.
5. Host sacrificial process에 대한 비파괴 negative probe와 Guest/Host endpoint identity 대조를 수행한다. Host service에 write/transaction을 보내지 않는다.
6. PIDFD 종료, reap, Guest cgroup/mount cleanup, Host snapshot 동일성까지 성공해야 한다. 실험 중 Host 상태 변동 또는 불명확한 child membership이 있으면 즉시 제한 실험을 중단한다.

현재 결과만으로 Phase 8B-3로 넘기지 않는다. 다음 단계는 Guest SID source/build와 실제 Guest-only runtime 정책을 준비하는 것이다.
