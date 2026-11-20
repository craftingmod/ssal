# Phase 8B-4B-1 — SystemServer Gate 및 cgroup 사전 검증

2026-11-06 KST. **Phase 8B-4B-2 실제 `forkSystemServer()` 실행은 NO-GO.** 진단 Gate 실패 주입, cgroup API, supervisor 회수 및 7I 회귀를 실기기에서 확인했다. 그러나 stock `system_server` SID / UID 1000의 Guest 진단 child가 Host canary의 signal 권한 검사와 `/proc` 경계를 통과했다. 실제 GSI Zygote의 독립 Gate 적용도 미검증이다. 완료 기준 전체 PASS로 간주하지 않는다.

실제 `forkSystemServer()`, `--start-system-server`, `SystemServer.main()`은 실행하지 않았다. Host/GSI SELinux 정책, 신규 allow, Global Permissive, KernelSU `selinux_hide`를 변경하지 않았다. 기존 permissive Guest 실험 domain과 app-only fallback을 7I 회귀에서 재사용했다. Host Enforcing을 유지했다.

## 구현 범위

- [`system-server-gate.c`](../native/binder-probe/system-server-gate.c): `wrap.system_server` 대상 executable은 인자를 실행하지 않고 `_exit(80)`한다. 별도 library의 system-server startup/final setter entry는 property 선택 여부와 관계없이 `_exit(81/82)`하며 원래 setter나 Java로 돌아가지 않는다. 일반 app setter는 원래 함수를 호출하고, symbol 부재는 실패로 반환한다.
- [`system-server-gate-probe.c`](../native/binder-probe/system-server-gate-probe.c): JVM 없는 native harness. Guest property를 읽어 wrapper를 선택하고, property 누락 시 native terminal Gate를 호출한다. library 부재/오적용은 version handshake에서 종료한다. 이 handshake는 **harness의 admission check**이며 GSI Zygote의 보호 장치라고 주장하지 않는다.
- [`system-server.cpp`](../native/processgroup-probe/system-server.cpp): 고정 GSI의 원본 `libprocessgroup.so`/`libc++.so`에 연결한다. root parent가 별도 native child에 `createProcessGroup(1000,pid,false)`와 `SetProcessProfilesCached(...,{"SystemMemoryProcess"})`를 적용한다. Guest `/apps`, v2 및 노출한 v1 controller의 membership, 유한 parent memory limit, 정상 child exit/reap와 생성 디렉터리 제거를 확인한다. membership parser에는 assert self-check가 있다.
- [`system-server-boundary.c`](../native/binder-probe/system-server-boundary.c): Guest chroot 밖의 disposable Host-root canary와 Guest 안의 probe를 같은 UID/GID 1000, groups 없음, stock final SID, capability 0으로 만든다. credential 변경을 final SID 설정보다 먼저 수행한다. 대상은 supervisor가 생성하고 pidfd로 유지하는 canary PID뿐이다. `kill(pid,0)`, `/proc` open 및 ptrace attach를 검사하고, attach 성공 시 detach하도록 구현했다. 실제 Host 서비스는 검사 대상으로 삼지 않는다.
- [`system_server_preflight.rs`](../src/guest_launcher/system_server_preflight.rs): `SSAL_PHASE8B4B1_ONCE=1`만 허용한다. 7I 경로를 요구하고 8B-3B/3D 진단 및 library overlay와의 혼용을 거부한다. flag를 소비하고 `phase8b4b1/consumed`를 배타적으로 생성한다. 재시도나 실제 system-server launch 옵션은 없다. 직접 소유한 child의 PID/starttime, pidfd open/wait/signal, deadline, reap와 Drop 정리를 담당한다.
- [`guest_launcher.rs`](../src/guest_launcher.rs): opt-in일 때만 helper들을 Guest에 read-only bind하고 Zygote 시작 전에 진단한다. Gate를 실제 Zygote에 preload하지 않는다. flag가 없을 때 기존 경로와 app fork 요청을 유지한다. Binder/Property/Guest cgroup/mount/loop 정리는 기존 supervisor를 재사용한다.
- 빌드: [`build-system-server-preflight.sh`](../scripts/build-rust/build-system-server-preflight.sh). 실행/회귀: [`run-system-server-preflight.sh`](../scripts/run-system-server-preflight.sh). 설치 모듈과 기본 빌드/패키징 경로는 바꾸지 않는다.

**8B-4A 독립 Gate와의 차이:** 이번 library는 setter **진입 시 종료하는 preflight용 구현**이다. 원래 final setter 성공 직후의 binary 제어 흐름에 설치한 Gate가 아니다. 실제 GSI의 hook 누락/오적용에도 Java 진입이 불가능하다는 binary 증거는 아직 없다. 따라서 harness 통과만으로 실제 fork를 허가할 수 없다. 외부 supervisor timeout 역시 `SystemServer.main()` 진입 방지 수단이 될 수 없다.

## 기기 및 증거 위치

- 기기: `R5CY52JC03H`, SM-S937N. boot ID `03834516-215d-4fd6-8960-1b833882595e` 유지.
- GSI 기준: [8B-4A](phase8b4a-system-server-specialization.md)의 Android 16 / SDK 36 이미지. 정책 및 Guest libselinux/libandroid_runtime 교체 없음.
- 최종 진단: `/dev/ssal-phase8b4b1/baseline-1793903708`, 시작 **03:35:08 KST**. worker exit 0, 안전 snapshot 동일, runner는 `NEXT_PHASE=NO_GO`로 종료하도록 구현했다(remote exit 3; adb의 로컬 exit는 1).
- flag-off 회귀: `/dev/ssal-phase8b4b1/regression-1793903764`, 시작 **03:36:04 KST**, worker/runner exit 0.
- 로컬 원본: `out/phase8b4b1/worker-final.log`, `device-final/`, `before-final.txt`, `after-final.txt`, `regression.log`, `regression-before.txt`, `regression-after.txt`, `tests-final.txt`, `final-cleanup.txt`, `final-hashes.txt`.
- 아래 인용의 line 번호는 로컬 원본 기준이다. 원본은 `out/`의 로컬 산출물이고 핵심 결과는 이 문서에도 보존한다. raw logcat/dmesg 전체를 읽거나 수집하지 않았다.

## Gate 실패 주입

`worker-final.log:237–268`. 모든 case에서 해당 child의 PID/starttime 및 pidfd 기반 reap를 확인했다. Native harness와 wrapper에는 JVM이나 framework class 실행 경로가 없다.

| 주입 | 관측 | 판정 범위 |
|---|---|---|
| Guest `wrap.system_server` 설정 및 wrapper 실행 | exit 80 | property readback 후 terminal wrapper 종료 |
| system-server startup setter 호출 | exit 81 | 원래 startup setter 실행 전 차단 |
| property 빈 값/누락 | exit 82 | wrapper 선택 없이 native terminal Gate 종료 |
| property 빈 값 + reporting stderr FD 닫기 | exit 82 | 보고 실패에도 Java 복귀 없음 |
| hook library 부재 | exit 83 | harness admission 차단 |
| 다른 library로 오적용 | exit 83 | version symbol 부재로 admission 차단 |
| 존재하지 않는 wrapper exec | exit 84 | exec 실패 직후 `_exit`, fallback 없음 |
| wrapper가 실패(`/system/bin/false`) | exit 1 | 실패 wrapper 실행 후 child 종료 |
| Gate 미도달/조기 종료 | exit 86 | 소유 child exit 감지와 reap |
| Gate 미도달/hang | 500 ms deadline, SIGKILL | pidfd로 종료 및 reap |

Property는 Guest Property Service에만 설정했으며 property 누락 case에서 빈 값으로 되돌렸다. `control-disconnected`는 보고용 stderr 단절 시험이다. 향후 실제 native Gate용 readiness/control FD protocol의 검증을 대신하지 않는다. 실패하는 wrapper와 exec도 native harness에서 주입했으며 `ZygoteInit.handleSystemServerProcess()`를 실행한 것이 아니다.

## cgroup 실기기 결과

`device-final/cgroup-self-test.log:1`, `device-final/cgroup.log:1–27`, `worker-final.log:269–273`:

```text
guest_memory_max=1073741824 apps=1 per_app_memcg=0
createProcessGroup uid=1000 pid=11178 result=0 errno=2
0::/apps/ssal_guest/system/uid_1000/pid_11178
SystemMemoryProcess result=1 errno=0 conditional_in_zygote=0
SystemMemoryProcess_moved_to_system=0
diagnostic_child_reaped pid=11178 status=0
SSAL_SS_CGROUP=PASS
```

성공 반환 시 errno는 이전 syscall의 잔여 값일 수 있으므로 `result=0, errno=2`를 실패로 판정하지 않는다. v1 cpu/cpuset/blkio는 모두 `/ssal_guest`에 남았다. 별도 bind하지 않은 v1 freezer/cpuacct의 `/` membership은 기록하되 Guest v1 bind 이탈과 혼동하지 않았다. 이 controller들에 대한 완전 격리를 입증한 것은 아니다.

Guest `/sys/fs/cgroup`은 Host `/sys/fs/cgroup/apps/ssal_guest`의 bind다. 기존 app fork 준비가 그 안에 `apps`를 만들고, 이번 진단이 `system`을 만들었다. UID/PID 그룹과 `system`은 진단에서 제거했고 나머지 Guest subtree는 기존 정리 경로에서 제거했다. 상위 Guest memory.high **768 MiB**, memory.max **1 GiB**가 하위 PID group의 유효 상한이다. 하위 controller를 새로 활성화하거나 Host PID를 옮기지 않았다.

`UsePerAppMemcg()`는 **false**였다. GSI의 실제 `SystemMemoryProcess` API도 별도 호출해 true 반환을 확인했으나 membership은 PID leaf에 그대로 남았다. 따라서 **API 호환 PASS / 강제 profile migration은 미입증**이다. 고정 source snapshot `out/phase5b-processgroup/source/task_profiles.cpp:975–989`의 v2 `JoinCgroup` 무시 동작과 일치한다. 실제 Zygote에서도 같은 property 조건이면 이 profile은 조건부 미호출이다. property나 GSI가 바뀌면 다시 검증해야 한다.

**Host cgroup 불변성의 제한:** 기존 `GuestMemory::prepare()`는 유한 memory limit를 제공하려고 Host 공용 v2 root와 `apps`의 `cgroup.subtree_control`을 일시적으로 `+memory`/`-memory` 변경한다. `worker-final.log:18–25,343–344`에 기록돼 있다. Host sibling memory limit/추가 delegation은 기존 코드에서 검사했고 핵심 서비스 membership 및 전후 controller 상태는 동일했다. 그러나 **실행 중에도 Host 공용 ancestor 설정이 불변이었다는 조건은 충족하지 못한다.** 이번 단계에서 이를 숨기거나 기존 memory lifecycle을 확장하지 않았다. subtree-only 쓰기가 엄격한 선행 조건이라면 별도 해결 전 NO-GO다.

## Host 경계 부정 테스트 — FAIL

`device-final/host-canary.log:1–60`, `device-final/boundary.log:1–65`. Host canary PID **11179**, Guest probe PID **11180**. 둘 다 `u:r:system_server:s0`, UID/GID 네 필드 모두 1000, supplementary groups 없음, CapInh/Prm/Eff/Amb=0, CapBnd=`000001ffffffffff`, NoNewPrivs=1, Seccomp=0이었다. 실제 SystemServer 프로세스가 아닌 native 진단 프로세스다.

| Host canary 대상 검사 | 결과 | 의미 |
|---|---|---|
| `kill(11179,0)` | 0 | 신호 권한 검사 통과; 실제 신호는 보내지 않음 |
| `/proc/11179/root` open | 성공 | Guest chroot 밖 canary의 root 경로 접근 차단 실패 |
| `/proc/11179/fd` open | 성공 | canary FD 디렉터리 open 차단 실패 |
| `/proc/11179/fd/0` open | 성공 | canary의 무해한 `/dev/null` FD 접근 차단 실패 |
| `PTRACE_ATTACH` | -1 / EACCES(13) | 이 조건에서 ptrace 거부; attach 실패로 detach 불필요 |

```text
boundary signal0 result=0 errno=0
boundary path=/proc/11179/root result=0 errno=0
boundary path=/proc/11179/fd result=0 errno=0
boundary path=/proc/11179/fd/0 result=0 errno=0
boundary ptrace_attach result=-1 errno=13
SSAL_SS_BOUNDARY=FAIL credential_model=uid1000-groups0-caps0-stock_sid
```

열린 FD는 즉시 닫았고 실제 Host 파일 내용이나 FD 디렉터리 항목을 읽지 않았다. canary는 supervisor의 private mount namespace에서 Guest chroot 밖 Host root view와 Host 쪽 cgroup을 상속했다. Guest PID/user namespace는 공유 상태다. 따라서 stock SID 재사용 자체가 아니라 **관측된 Host canary 접근 성공**을 NO-GO 근거로 삼는다.

최종 SID 이후 일반 inherited log FD의 출력이 보이지 않아 진단 시작 전에 전용 output file을 16 KiB로 mmap했다. SID 전환 뒤 결과를 그 mapping에 기록하고 supervisor가 회수했다. 이는 실험용 보고 채널이며 일반 Host FD 접근 허용이나 SELinux allow를 추가한 것이 아니다. 기존 mapping/상속 FD가 SID 전환 뒤에도 남는다는 점도 다음 단계의 FD 점검 대상이다.

이 결과는 실제 Host `system_server`의 dumpability, GSI supplementary groups, seccomp 또는 capability 조합을 완전히 재현한 것이 아니다. canary는 명시적으로 dumpable이다. 그러나 더 좁은 groups/capability 조건에서도 접근이 성공했으므로 현재 통제 조건만으로 signal 및 `/proc` 경계를 보장할 수 없다. `CAP_KILL`, `CAP_SYS_PTRACE` 추가로 이를 해결할 수 없고 SYS_TIME, SYS_NICE, wake/suspend 등 전역 capability의 안전성도 여전히 미입증이다. 실제 Host 서비스 대상 검사를 확대하지 않았다.

## Supervisor, 회귀 및 Host 보존

`worker-final.log:237–279,313–348`, `regression.log:267–302`:

- 직접 진단 child는 PID/starttime + pidfd로 추적하고, `waitid(P_PIDFD, WNOWAIT)` 후 종료/reap했다. timeout child PID 11173은 SIGKILL 및 reap, canary PID 11179도 pidfd로 종료/reap했다. cgroup helper 내부의 native grandchild는 그 parent가 pipe와 `waitpid`로 회수하며 독립 pidfd 추적은 하지 않는다. 실제 Zygote가 만든 system-server child를 supervisor가 인계받는 경로는 이번 검증 범위 밖이다. Gate 조건이 실패해도 실제 system-server 실행으로 자동 진행하는 코드가 없다.
- `cargo test --locked --bin ssald`: **51 passed, 0 failed, 4 ignored**. 추가 자체 검증은 조기 exit, timeout, Drop 시 child 회수 및 ECHILD를 검사한다. Android NDK 빌드 `-Wall -Wextra -Werror`, 새 shell 스크립트 구문 검사 통과. 전체 cargo fmt check는 기존 파일의 formatting 차이도 보고해 통과하지 않았으며 신규 module만 rustfmt했다.
- flag-on 실행: Property Service ready/restore PASS, Private Binder/AIDL PASS, Java child PID **11231**, UID/GID 10000, groups 없음, capabilities 0. property/private_binder/userdata read-write PASS. Zygote가 pidfd exit 및 reap를 확인했다.
- flag-off 실행: 신규 preflight marker/child 없이 기존 7I 경로 통과. Java child PID **14042**, property/private_binder/userdata PASS 및 정상 reap. 기존 app-only `SSAL_PHASE7FC_BYPASS_SETCONTEXT=1`을 재사용했으며 production specialization PASS를 뜻하지 않는다.
- 두 최종 실행에서 `HOST_SAFETY_SNAPSHOT=UNCHANGED`. init, zygote64, system_server, servicemanager, surfaceflinger, adbd, netd, lmkd, installd의 PID/starttime/SID/credentials/capabilities/cgroup 및 핵심 endpoint identity가 동일했다. Host Enforcing과 `selinux_hide (ID=4) ENABLED`, boot ID를 유지했다.
- Host property 전체 원본은 따로 저장한다. 첫 실행에서 자연 변동한 thermal telemetry `sys.siop.level`, `wlan.p2p.temp` 두 키만 snapshot 동등성 비교에서 제외했다. 첫 실행의 diff는 이 두 키뿐이었다. 나머지 키와 core snapshot은 유지했다.
- 양쪽 worker에서 Guest userdata marker 제거, Guest cgroup 정리, rootfs mount 및 **56개 loop allocation 해제** 확인. 최종 read-only 검사에서도 네 Guest cgroup과 helper mapping의 부재를 확인했다(`final-cleanup.txt:1–5,41`, `FINAL_CLEANUP=PASS`). `/dev/ssal-phase8b4b1`의 실행파일/증거 staging만 남기며 활성 Guest 자원을 유지하지 않는다.
- active policy hash는 권한상 **UNAVAILABLE**이었다. `sepolicy.rule` hash와 Enforcing/feature readback만 확인했으며 활성 정책 hash 불변을 검증했다고 주장하지 않는다.

## 재현 및 판정

기존 `ssal-dev` 컨테이너/NDK와 고정 GSI 라이브러리를 사용한다. WSLc는 저장소 규칙에 따라 sandbox 밖에서 실행했다.

```text
wslc exec ssal-dev bash -c 'bash scripts/build-rust/build-system-server-preflight.sh'
# 기존 Android build-android.sh 경로로 ssald를 빌드해 out/phase8b4b1/bin에 배치
# 기존 7I helper들과 신규 bin을 /dev/ssal-phase8b4b1에 staging 후 chmod 755
adb shell su -c 'sh /dev/ssal-phase8b4b1/run.sh baseline'
adb shell su -c 'sh /dev/ssal-phase8b4b1/run.sh regression'
```

실기기 사용 ssald SHA-256 `21baeb644d31bbc989c8edfd41426ca591b2ccd9b0cfd26895f4c4c6e538d21e`, Gate library `4eb92ef10f43bede207f6ae4f8600e4f56776bc71b70e3a98fa0531051bc168c`, cgroup probe `94748b0c9f9a097c8f60c71c0d102dc55b0d40c252485b9c653a6c642d83ad10`, boundary probe `b1bc25ebee7d2b0f025bd997613ab2888eaa5db85d8b7f0054fd24e431eae684`.

| 8B-4B-2 선행 조건 | 판정 |
|---|---|
| terminal wrapper/native Gate harness 실패 주입 | PASS, harness 범위 |
| 실제 GSI에서 wrapper/hook 실패에도 Java 이전 독립 차단 | **미검증 → NO-GO** |
| 현 GSI cgroup API / finite limit / membership / 회수 | PASS, `UsePerAppMemcg=false` 조건 |
| 실행 중 Host 공용 cgroup ancestor 완전 불변 | **미충족 → NO-GO** |
| Host canary signal 및 `/proc` 부정 테스트 | **FAIL → NO-GO** |
| 실제 specialization과 동일한 groups/capabilities/seccomp 검증 | **미검증 → NO-GO** |
| 진단 supervisor timeout/exit/reap/cleanup | PASS |
| 기존 7I 회귀 및 Host 핵심 서비스/Enforcing 보존 | PASS |

**최종 판정: NO-GO.** 정책 변경 없이 Host signal/`/proc` 경계를 통제할 방법과 실제 GSI native Gate 적용/검증을 먼저 마련해야 한다. cgroup 공용 ancestor 변경도 엄격한 불변성 조건에 맞춰 별도 해결해야 한다. 이번 결과로 실제 fork를 강행하지 않는다.
