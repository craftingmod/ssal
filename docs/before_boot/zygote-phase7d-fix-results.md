# Phase 7D-Fix 결과

2026-11-05 KST, SM-S937N. **판정: PARTIAL.** 최종 빌드에서 Guest subtree membership, 하위 메모리의 상위 집계, 상위 `memory.max` 동작, fork/setsid 자손과 시험한 종료 경로의 정리, Phase 5B 및 Zygote 없는 Phase 6A가 통과했다. 다만 이 커널은 Guest cgroup의 `memory.pressure` 파일을 제공하지 않아 요청된 해당 telemetry를 수집하지 못했다. 일부 단기 실행 child의 종료 직전 membership과 모든 잠재적인 동시 변경 조합도 관측하지 못했으므로 전체 조건의 PASS로 판정하지 않는다.

## 변경

- `/proc/<pid>/cgroup`의 v2 경로와 관측자의 cgroup2 mount root를 결합하고 실제 mount 경로와 Guest leaf를 `canonicalize`해 path component 단위로 검사한다. leaf와 하위를 허용하고 `ssal_guest2` 및 `..`을 거부한다. Guest bind mount와 Host mount의 서로 다른 root를 처리한다. 서비스 시작 직후와 테스트 자손에도 검사를 적용한다.
- 기존 process group 종료와 `PR_SET_PDEATHSIG`를 유지한다. worker는 `PR_SET_CHILD_SUBREAPER`를 설정하고, 종료 시 `waitid`로 자식이 없음을 확인할 때까지 `/proc`에서 자신의 직계·재입양 자손을 찾는다. PID마다 pidfd를 열고 부모와 Guest subtree를 확인한 후에만 pidfd로 signal한다. PIDFD wait로 종료한 자손을 reap한다. 새 자손이 reparent되는 경우 반복 확인한다. 5초 내 확인·정리할 수 없거나 membership이 불명확하면 cgroup과 controller를 보존하고 오류를 낸다. `cgroup.kill`은 사용하지 않는다.
- timeout 중 별도 session의 자손이 stdout/stderr 파이프를 잡고 있어도 무한 대기하지 않게 했다. 리더의 PID 재사용을 피하도록 waitid `WNOWAIT` 후 process group을 종료하고 리더를 reap한다.
- 테스트 helper는 16 MiB를 할당하고 일반 fork 및 `setsid` 자손을 만든다. 별도 memory 제한 시험은 상위 max에 도달하는 순간을 관측하고 중단한다. 기본 high/max는 `max`다. 기존 Android `createProcessGroup`과 Phase 5B v1 profiles는 교체하지 않았다.

## 최종 빌드 검증

최종 `ssald` SHA-256 `a27455166cb0b4f1e00eb3c041802eaae1d5e95575e79b61a39768182105ad2d`; helper SHA-256 `efeebfcc3b77dc7b9dd22e3b823084f47acef771cb35a093fdfb544a3beb0ebe`. 아래 실기기 결과는 모두 이 빌드다.

| 검사 | 결과와 범위 |
|---|---|
| Rust 및 Android | `cargo test --locked --bin ssald` 44 passed / 3 ignored, `ssal-memory-probe` 4 passed. Android AArch64 release 빌드, rustfmt 및 스크립트 `sh -n` PASS. |
| 하위 membership·회계 | [hierarchy.log](../out/phase7d-fix/hierarchy.log): PID 32288, 일반 자식 32289, setsid 자식 32291 모두 `/apps/ssal_guest/phase7d_fix`에 관측됐다. 할당 전 4,603,904 → 후 21,393,408 bytes, 상위 `memory.current` 증가 16,789,504 bytes. 리더와 두 자손 정리 및 controller 복원 PASS. [Phase 7B telemetry](../out/phase7d-fix/hierarchy-telemetry/memory.jsonl). |
| 상위 한도 | [limit.log](../out/phase7d-fix/limit.log), [telemetry](../out/phase7d-fix/limit-telemetry/memory.jsonl): 하위에 속한 PID 32702가 할당할 때 상위 high 100,663,296, max 67,108,864 bytes readback. `memory.current=67,108,864`, `memory.events:max=3` 관측 후 중단했다. OOM이나 high throttling을 통과했다고 주장하지 않는다. 이 값은 통제된 시험값이며 운영 예산이 아니다. |
| 정상 종료 및 setsid | 위 hierarchy 실행에서 일반 fork 및 setsid 자손을 각각 확인했고, setsid 자손은 pidfd signal 및 reap 기록이 있다. |
| SIGINT/TERM/HUP | [INT](../out/phase7d-fix/lifecycle-INT/harness.log), [TERM](../out/phase7d-fix/lifecycle-TERM/harness.log), [HUP](../out/phase7d-fix/lifecycle-HUP/harness.log): Guest 및 두 자손이 살아 있을 때 worker에 각각 전달. 식별된 원래 PID/starttime 부재, 자손 정리, leaf/controller 복원, Host snapshot 전후 일치 PASS. |
| timeout | [timeout](../out/phase7d-fix/lifecycle-timeout/harness.log): Guest 및 자손이 살아 있는 2초 Launcher 시험 timeout 후 동일한 정리 PASS. 공유 `run_with_timeout`의 detached pipe 보유 회귀는 별도 Linux 단위 테스트로 확인했다. |
| 리더 선종료 | [leader](../out/phase7d-fix/lifecycle-leader/harness.log): 소유 리더만 SIGKILL하고 zombie 상태를 확인한 뒤 worker를 중단했다. 남은 자손 정리 및 Host snapshot 일치 PASS. |
| 실행 실패 | [exec-failure.log](../out/phase7d-fix/exec-failure.log): 유효하지 않은 helper의 linker 실행 실패 후 오류 반환 및 cgroup/controller 복원 PASS. |
| Phase 5B | [processgroup.log](../out/phase7d-fix/processgroup.log): UID/PID cgroup `/apps/ssal_guest/system/uid_1000/pid_6924`, v1 CPU/cpuset/blkio profile 및 Host 표본 cgroup 전후 비교 PASS. |
| Phase 6A | [phase6a.log](../out/phase7d-fix/phase6a.log): private Binder/AIDL, Guest servicemanager 및 installd/artd descriptor 확인 PASS. Zygote와 Guest system_server는 실행하지 않았다. |
| Host 및 복원 | 각 lifecycle의 [before/after](../out/phase7d-fix/lifecycle-INT/before.txt)는 부팅 ID, Enforcing, 핵심 PID/starttime/context/cgroup 및 root/apps controller를 포함하고 해당 시험의 after와 동일했다. 다섯 시험의 최초·최종 snapshot도 동일했다. 각 launcher wrapper 및 processgroup의 별도 snapshot도 일치했다. [최종 상태](../out/phase7d-fix/final-state.txt)는 4개 Guest cgroup 부재, root/apps subtree_control 빈 값, Enforcing을 기록한다. |

각 lifecycle 디렉터리에는 `processes.txt`, `identities.txt`, `memory.txt`, `before.txt`, `after.txt`, `worker.log`가 있다. 계층 테스트와 한도 테스트의 Phase 7B 파일에는 `memory.current/peak/high/max/events/stat`, Host PSI 및 가능한 process membership이 있다. `memory.pressure`는 **ENOENT / unavailable**로 기록됐으며 Host `/proc/pressure/memory`를 그 대체 측정치로 간주하지 않는다.

최종 max 시험 직전 Host PSI avg10 some/full은 0/0, 직후도 0/0이었고 total은 각각 약 13.7 ms 증가했다. 예비 시험에서는 max event 149, oom_kill 0이었고 PSI avg10 some/full이 0.72/0.72 → 2.62/2.62로 상승했다. 최초 예비 시험 코드는 OOM kill만 성공으로 판정해 실패했으며, 이는 최종 빌드 PASS 근거로 쓰지 않았다. PSI 변화만으로 인과관계나 Host 전체 무영향을 확정하지 않는다.

## 예비 실패 및 복구

초기 자손 추적 코드는 `/proc/<pid>/task/<tid>/children`을 읽으려 했지만 기기에 파일이 없어 ENOENT가 났다. 안전장치가 cgroup과 controller를 보존했다. `cgroup.events populated=0`, 네 Guest 그룹의 빈 `cgroup.procs` 및 하위 디렉터리 부재, root/apps sibling의 기본 정책과 delegation을 확인한 뒤 빈 그룹을 제거하고 apps → root 순으로 복원했다. [복구 기록](../out/phase7d-fix/recover.log). 이후 `/proc` PPid와 `waitid` 방식으로 수정했다. 별도의 예비 helper 접근 권한·preload 준비 오류와 첫 신호 하네스의 `memory.pressure` ENOENT는 모두 Guest/controller 정리를 확인한 뒤 수정했다.

## 수동 복구와 잔존 위험

SIGKILL, ADB 연결의 비정상 종료, 기기 장애에서는 worker의 cleanup이 실행된다는 보장이 없다. 우선 journal/worker log의 세션 경로, PID 및 starttime, 각 `/proc/<pid>/cgroup`, Guest subtree의 `cgroup.procs`와 `cgroup.events`를 보존한다. 소유권과 PID identity를 확인하지 못한 프로세스는 종료하지 않는다. 소유 자손만 안전하게 종료·reap하고 **모든 하위 그룹이 비고 자식 디렉터리가 없을 때만** 생성한 Guest 하위 그룹과 leaf를 역순 `rmdir`한다. 각 v1 Guest 그룹도 비었을 때만 제거한다.

apps와 root의 다른 자식에 새 memory delegation이나 비기본 high/max/min/low 정책이 없고, 각 `cgroup.subtree_control`이 이 세션이 설정한 예상값일 때만 apps `-memory` → root `-memory`를 실행하고 각각 readback한다. 다른 관리자의 변경이나 불명확한 프로세스가 있으면 강제 복원하지 않고 상태를 보존한다. Host PID는 이동하지 않으며 `cgroup.kill`을 사용하지 않는다. 이 절차는 page-cache charge나 PSI 누계를 과거 값으로 되돌리지는 않는다.

SIGKILL 전체 복구, ADB 단절, PID 재사용 및 외부 관리자와의 모든 경쟁 조합, 장시간 Host 안정성과 hard reboot 후 One UI 복구는 시험하지 않았다. 이전 Phase 7D에서 적용한 Guest permissive live 정책은 현재 boot에 남아 있고 Host global SELinux는 Enforcing이다. 재부팅은 수행하지 않았다. `/dev/ssal-common-launcher` 임시 stage는 증거 수집 후 제거했으며 `/data/local/tmp/ssal-7dfix`와 로컬 `out/phase7d-fix` 증거는 보존했다.
