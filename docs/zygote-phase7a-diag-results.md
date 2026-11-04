# Phase 7A-Diag — Zygote crash와 메모리 영향

2026-11-04 KST. 판정은 보존된 Phase 7A 로그와 이번 read-only 기기 조사에 한정한다. Phase 5B/6A/6B의 기존 PASS를 변경하지 않았다. 이번에는 Guest를 실행하거나 기기 설정을 변경하지 않았다.

| 항목 | 판정 | 근거 |
|---|---|---|
| 기존 SIGABRT 원인 분석 | **UNKNOWN** | PID 15920의 signal 6 외 fatal 원인, abort message, stack이 없다. |
| LMK 영향과 인과관계 | **PARTIAL** | 당시 27건의 cached app 회수와 low/min watermark는 확인됐으나 Guest 기여량과 인과는 UNKNOWN. |
| Guest 전용 메모리 제한 | **FAIL** | 현재 기존 Guest 부모에 memory controller가 전달되지 않아 제한 파일을 사용할 수 없다. 실제 적용과 격리 검증을 하지 못했다. |
| 충돌 진단 수집 경로 | **PARTIAL** | 기존 로그와 종료 signal은 수집되지만 전용 pipe, native abort/backtrace 및 충돌 직전 cgroup 메모리는 미구현·미검증이다. |
| 안전 조건 충족 시 재실행 | **UNKNOWN** | 필수 조건 미충족으로 미실행. 충돌 진단 목표도 미달. |
| Host 핵심 상태와 Guest cleanup | **PARTIAL** | 기존 실행의 cleanup 및 core snapshot PASS; 이번 read-only 잔여 확인은 통과했으나 이번 실행 전후 비교는 해당 없음. |

## 기존 SIGABRT 증거

[worker.log](zygote-phase7a-run-20261104/worker.log)에서 Guest property SDK 36/ABI 및 property socket 부재, private Binder AIDL, Guest classpath 46/14 항목 생성은 통과했다. linkerconfig 생성 전의 설정 파일 부재 경고는 helper 성공 전후에 나타났고, servicemanager ready-property 설정 실패는 property service 부재에 따른 별도 관측이다. 어느 쪽도 abort 원인으로 입증되지 않았다. Zygote는 독립 net namespace의 고유 abstract socket 준비 전에 `SIGABRT`, `SI_QUEUE`로 종료했다. ART 초기화의 성공 여부, Java fatal, linker의 Zygote 실행 실패, property/socket 문제 여부는 해당 메시지가 없어 판정할 수 없다. crash buffer와 새 tombstone에도 PID의 원인 기록이 없었다. [기존 결과](zygote-phase7a-results.md), [Host 영향 요약](zygote-phase7a-run-20261104/host-impact-summary.txt) 참조. 추측에 근거한 수정은 하지 않았다.

## 메모리 및 계층 관측

이번 관측에서 MemTotal 11,379,976 kB, MemAvailable 7,443,504 kB, MemFree 833,740 kB, Cached 4,612,496 kB였다. 최초 PSI `some avg10=0.00 avg60=0.43`, `full avg10=0.00 avg60=0.39`; 이후 `some/full avg10=0.35`였다. 단일 시점의 가용량이나 PSI로 안정적인 실행 여유를 보증할 수 없다. 최근 logcat에는 Guest 실행 없이도 23:47:25에 low watermark 또는 낮은 filecache를 이유로 여러 cached app을 회수한 기록이 있다. 이것은 당시 27건을 설명하거나 Guest의 기여를 배제하는 증거가 아니다.

`/sys/fs/cgroup`은 cgroup v2, `/dev/cpuctl`, `/dev/cpuset`, `/dev/blkio`는 v1이다. v2 root의 `cgroup.controllers`는 `memory`지만 `cgroup.subtree_control`은 비어 있고 `/sys/fs/cgroup/apps/cgroup.controllers`도 비어 있다. 따라서 기존 Guest 경로 `/sys/fs/cgroup/apps/ssal_guest`에 memory controller가 상속되지 않는다. Guest subtree는 현재 정리되어 없어 과거 `memory.current`, `memory.peak`, `memory.events`, process RSS/PSS와 file/anon 사용량을 복구할 수 없다. root에는 `memory.high`/`memory.max` 파일이 없으며, Guest에서의 파일 존재 및 쓰기 성공도 확인하지 못했다. 커널의 일반적인 memory controller 노출과 Guest에서의 실제 사용 가능성은 다르다.

APEX 준비는 54개 패키지와 55개 loop를 사용했고, ART 및 dex/JAR 매핑은 메모리와 cache에 영향을 줄 가능성이 있다. 그러나 당시 cgroup `memory.stat`, `memory.peak`, 프로세스 `smaps` 및 시계열이 없어 각각의 기여도와 LMK 인과는 **UNKNOWN**이다. APEX 준비는 `guest_mounts::verify`의 worker에서 서비스 child가 Guest cgroup에 들어가기 전에 수행되므로, 설령 서비스에만 제한을 적용해도 준비 단계의 cache를 포괄한다고 볼 수 없다. 공유 file cache의 charge 소유권도 별도 실측이 필요하다.

## 제한 및 진단 설계와 차단점

기존 launcher의 각 서비스 child는 exec 전에 네 Guest cgroup에 가입하며 자식은 통상 상속한다. 그러나 worker 자체와 APEX 준비 전체가 해당 memory subtree에 포함된다는 보장은 없고, 실행 중 모든 후손의 실제 membership과 Host PID 배제도 검증되지 않았다. `apps`에 controller를 전달하려면 상위 공통 `cgroup.subtree_control` 변경이 필요하다. 이는 Host 공통 계층에 영향을 줄 수 있으며 사용자가 금지한 Host 전체 메모리 정책 변경과 안전 경계를 벗어날 가능성이 있어 시도하지 않았다. 따라서 현재 여유량만으로 high/max 수치를 선택하거나 적용하지 않았다. 적절한 Guest 전용 controller 경로가 검증되면 실제 membership과 Host PID 부재를 확인하고, high/max readback, `memory.events` delta, cgroup 및 Host PSI, lmkd와 core 상태 감시 및 종료 후 원상 복구를 함께 확인해야 한다. 그 전에는 재실행하지 않는다.

현재 `Service::start`는 stdout/stderr를 같은 Guest 전용 정규 파일로 보내고 LD_PRELOAD 로거를 사용하며, readiness 대기에서 종료 status와 해당 파일을 보고한다. 전용 stdout/stderr pipe는 아직 구현되지 않았다. 안전한 다음 진단에는 각 pipe의 동시 draining과 bounded 저장, signal/status 및 살아 있는 동안 memory.current/peak/events의 주기적 기록이 필요하다. native abort message는 stderr 또는 Guest 전용 crash 수집기가 실제 전달하는지 검증해야 하며, 기존 파일 수집만으로 확보를 보장할 수 없다. Guest 전용 tombstone/backtrace 경로도 준비되지 않았다. Host debuggerd/tombstoned, Host socket 및 Binder endpoint는 사용하거나 변경하지 않았다.

기존 `Service::stop`은 소유 process group을 종료하지만 group을 벗어난 후손 전체에 대한 실측 증거가 없고, cgroup cleanup은 비어 있지 않으면 실패를 드러내는 방식이다. Guest 전체 cleanup 경로는 재실행 gate로 추가 검증해야 한다. 전용 pipe 및 메모리 감시 구현은 controller 차단을 해소하지 못하고 실기기 검증도 불가능하므로 이번에는 미완성 코드로 기존 PASS 경로를 변경하지 않았다.

## 현재 Host 및 잔여 상태

이번 기기는 이전 Phase 7A의 boot ID `f7900911-c061-4570-8f65-900571a55c11`과 다른 boot ID였다. 이전 PID와 현재 PID를 동일 수명으로 비교할 수 없다. 이번 관측에서 global SELinux Enforcing, init, zygote64, system_server, installd, lmkd 존재, artd stopped를 확인했다. 네 `ssal_guest` cgroup과 `/dev/ssal-common-launcher`는 존재하지 않았다. `ssald` PID 8398은 존재하지만 이름만으로 실행 중인 Guest 서비스로 판정하지 않았다. 이번 관측은 전체 loop 및 모든 Guest 후손의 완전한 부재를 증명하지 않는다. 기존 Phase 7A 실행 직후에는 cgroup/rootfs 및 55 loop 정리가 검증됐다.

## 별도 backlog

1. Host 공통 정책을 바꾸지 않고 사용 가능한 Guest 전용 memory controller 계층이 있는지 확인하고, 불가능하면 허용 범위를 재결정한다. APEX 준비를 포함한 전체 비용과 Host 배제를 검증한다.
2. 전용 pipe 수집, native abort/backtrace 경로와 bounded drain을 구현하고 안전한 모의 프로세스로 검증한다. memory 시계열과 모든 후손 cleanup 검증을 추가한다.
3. 실제 제한값은 안정된 Host baseline과 실측 비용을 근거로 정하고, 모든 재실행 gate와 중단 조건을 구현·검증한 뒤에만 최대 1회 실행한다.
4. 확보된 fatal 또는 유효한 backtrace에 근거해 원인을 분석한다. artd dexopt backlog는 별개로 유지한다.
