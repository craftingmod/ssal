# Phase 7D 진행 결과

## 2026-11-05 구현 복구 및 실기기 결과

**부분 완료 — Phase 7D 전체 PASS 아님.** 공통 Launcher와 기존 `apps/ssal_guest`에 memory controller를 연결했다. 작은 Guest 셸, memory 회계 및 controller 복원, memory 활성 상태의 Phase 5B v1 CPU/cpuset/blkio 회귀는 실기기에서 통과했다. 그러나 기존 `createProcessGroup`이 Guest 자식을 leaf 아래의 별도 v2 경로로 옮기는 것이 관측되어 **모든 Guest 프로세스의 최종 membership이 leaf 자체와 정확히 같다는 완료 기준은 미충족**이다. 또한 세션을 벗어난 모든 자손을 안전하게 식별·종료하는 경로와 모든 신호·장애 경로는 아직 검증되지 않았다.

### 구현

- `memory_cgroup.rs`의 Phase 7C root 코드를 재사용한다. Enforcing, cgroup2 mount, canonical 경로, 초기 빈 root/apps delegation, apps 직접 프로세스 부재, leaf 부재를 확인한다. root → apps의 활성화와 readback 후, leaf 생성 전에 역순 roundtrip을 먼저 실행한다. Host sibling의 기본 memory 정책과 delegation도 검사한다.
- 기존 `GuestCgroups`가 leaf 및 v1 그룹을 만들고 정리한다. 전용 leaf가 제거된 뒤 apps → root 순서로 복원하고 readback한다. 다른 관리자의 delegation/정책 변경 또는 남아 있는 leaf가 확인되면 강제 복원하지 않고 오류를 남긴다. 기존 v1 task-profile 설정과 memory task-profile 비활성화는 유지했다.
- `SSAL_MEMORY_HIGH`, `SSAL_MEMORY_MAX`는 양의 정수 바이트 옵션이며 기본값은 둘 다 `max`다. 쓰기 후 readback을 확인한다. Phase 7C의 32 MiB를 실제 Guest 예산으로 쓰지 않았다.
- Launcher child는 v2 및 기존 v1 그룹에 가입하고 exec 전에 `/proc/self/cgroup`의 `0::/apps/ssal_guest`를 검사한다. 부모 종료 시 직계 child에 `PR_SET_PDEATHSIG`를 설정한다. 서비스 리더가 먼저 종료된 경우에도 reap 전에 소유 process group을 정리하도록 했다. 빈 디렉터리만 제거하며, 알 수 없는 PID를 일괄 kill하지 않는다.
- SIGINT/TERM/HUP은 중단 플래그로 처리하고 Launcher 대기 루프 및 timeout 실행에서 정리로 진행한다. 다만 준비 단계에서는 모든 개별 작업을 즉시 중단하지 않는다. 강제 SIGKILL, 새로운 session으로 분리된 후손 및 모든 장애 조합의 자동 정리는 보장하지 않는다.
- Phase 7B `Diagnostics`를 작은 테스트 프로세스에도 연결해 memory.current/peak/high/max/events/stat/pressure, membership, Host PSI/meminfo 등을 수집한다. `--guest-memory-worker`는 Zygote와 system_server를 시작하지 않는다.

### 검증 결과

| 검증 | 결과 |
|---|---|
| `cargo test --locked --bin ssald` | 42 passed, 3 ignored. 한도 파싱 및 종료된 리더의 남은 process group 정리 테스트 포함 |
| `cargo test --locked --bin ssal-memory-probe` | 3 passed. Android AArch64 release `ssald` 빌드 PASS |
| 최종 바이너리 작은 Guest | [run-final.log](../out/phase7d/run-final.log): PID 12559의 최종 v2 경로 `/apps/ssal_guest`, `memory.current=1101824`, 종료·leaf 제거·apps/root 복원 PASS. [Phase 7B telemetry](../out/phase7d/final3-telemetry/memory.jsonl) 보존 |
| 선택 한도 | [limits.log](../out/phase7d/limits.log), [telemetry](../out/phase7d/limit-telemetry/memory.jsonl): high 1 GiB, max 2 GiB readback 및 정리 PASS. 이 값은 동작 확인용이며 실제 Guest 권장 예산이 아니다. 이 시험은 최종 process-group 정리 수정 직전 빌드다. |
| Phase 5B | 최종 바이너리 [processgroup-final3.log](../out/phase7d/processgroup-final3.log): v1 background/top-app/foreground profile 및 cleanup PASS, 표본 Host membership·설정 동일. 단 `createProcessGroup` 이후 PID 13660의 v2 경로는 `/apps/ssal_guest/system/uid_1000/pid_13660`이었다. |
| SIGTERM | [signal.log](../out/phase7d/signal.log): leaf 생성 후 준비 중 SIGTERM, 오류 종료 및 leaf/controller/55개 loop 정리 PASS. 최종 process-group 정리 수정 직전 빌드이며, 실행 중인 Guest 자손에 대한 신호 주입은 아니다. |
| Host | Launcher wrapper의 전후 핵심 프로세스·endpoint snapshot 일치, processgroup 전후 표본 cgroup 설정·membership 일치. 마지막 확인에서 Enforcing, root/apps subtree_control 빈 값, Guest leaf 부재. 전 Host 프로세스와 장시간 영향의 완전한 증명은 아니다. |

최종 `ssald` SHA-256: `80b58f5def59eb295abaa7bf70b46bdbde99182a7dfc21142484a57a27cca8b2`. `/dev/ssal-common-launcher` 임시 stage는 증거를 pull한 뒤 제거했다. `/data/local/tmp/ssal-phase7d-recovery`의 실행 증거는 남겼다.

첫 실행은 새 boot에서 `ssal_guest_probe` 타입이 없어 exec 전 EINVAL로 실패했지만, controller·mount·loop 정리와 Host snapshot은 통과했다. 이후 [최소 실험 정책](../scripts/guest-domain-poc/phase7d-memory.rule)의 Guest 타입, `ksu`에서 해당 타입으로의 좁은 transition, Guest domain permissive만 현재 live 정책에 적용했다. Host global Enforcing은 유지했다. **이 live 정책은 재부팅 전까지 남는다**; 이 기기의 도구에는 타입/allow를 완전히 되돌리는 live rollback이 확인되지 않았다. 재부팅은 실행하지 않았다.

### 남은 작업 및 복구

- `createProcessGroup`의 v2 하위 그룹과 정확한 leaf membership 요구를 함께 만족시키는 기존 경로의 구체적인 처리와 최종 membership 검증이 필요하다. 하위 cgroup의 charge는 계층적으로 상위에 집계되지만 이는 정확한 leaf membership의 증거가 아니다.
- setsid 등으로 기존 process group을 벗어난 Guest 소유 자손, timeout/실행 실패/모든 신호 및 Drop의 정리를 검증해야 한다. 외부 관리자가 Host PID를 leaf에 옮길 가능성을 배제하지 못한 상태에서 `cgroup.kill`을 사용하면 Host 프로세스를 종료할 수 있으므로 적용하지 않았다. 빈 leaf 제거가 실패하면 controller 복원을 강제하지 않는다.
- SIGKILL 또는 기기/ADB 비정상 종료로 cleanup이 실행되지 않으면, 이번 세션의 leaf와 자손 및 소유 PID를 확인하고 소유 프로세스만 정리한 후 빈 leaf를 제거한다. apps 자식의 memory 정책·delegation과 apps subtree_control이 이 세션의 예상 상태인 경우에만 apps `-memory`를 수행하고, root 자식에도 다른 관리자의 정책·delegation이 없을 때 root `-memory`를 수행한다. Host PID를 이동하지 않는다. 충돌이 있으면 상태를 보존한다.
- Guest Zygote/system_server, 모든 자손의 안전한 정리, 장시간 Host 안정성, hard reboot 이후 One UI 복구는 이번에 검증하지 않았다.

---

## 이전 중간 기록

2026-11-05 KST. **미완료 — PASS 아님.** Phase 7C controller 활성화 및 복원 코드를 `src/memory_cgroup.rs`로 분리하고 기존 probe가 이를 사용하도록 했다. 공통 Guest Launcher에는 아직 연결하지 않았다. 기기는 연결되어 있었지만 이번 변경으로 실기기 실험은 실행하지 않았다.

기존 probe의 `cargo test --locked --bin ssal-memory-probe`는 3개 통과했다. 이는 코드 분리 후 단위 테스트 결과이며, controller 조작이나 Launcher 통합의 실기기 검증을 뜻하지 않는다. Phase 7B 진단 코드는 변경하지 않았다.

## 남은 작업

- Launcher 세션에 Phase 7C의 사전 검사와 controller roundtrip, 전용 leaf 및 설정 가능한 예산을 연결한다. 기존 비어 있는 root subtree 조건과 sibling 정책 확인을 유지한다.
- 현재 `GuestCgroups::prepare`는 `apps/ssal_guest`를 Guest의 `/sys/fs/cgroup`에 바인드하고, `guest_launcher::command`는 그 leaf에 가입한다. root 직속 leaf를 추가하면 v2의 최종 membership이 바뀌므로 기존 libprocessgroup 동작과 이후 task profile에 의한 이동을 실측해야 한다. v1 그룹 및 Host membership은 변경하지 않는다.
- 서비스·단기 실행 프로세스의 소유권과 membership을 확인하고, 모든 종료 경로에서 소유 프로세스 종료·reap 후 빈 leaf만 제거한다. SIGINT/SIGTERM/SIGHUP을 포함한 worker 생명주기와 실패 시 controller 복원 오류 전파를 검증한다.
- Phase 7B diagnostics의 측정 대상을 새 leaf로 연결하고 작은 테스트 프로세스, Phase 5B 및 6A 순서로 실기기 회귀를 수행한다. Guest Zygote 및 system_server는 실행하지 않는다.
- SIGKILL 또는 비정상 종료 후 수동 복구 절차를 실제 통합 경로와 함께 작성한다. Phase 7C의 기존 절차는 [결과 문서](zygote-phase7c-results.md)에 있다.
