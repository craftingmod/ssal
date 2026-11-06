# SSAL — FIVE double put 회피 가능성 분석

조사일: 2026-11-06

## 판정

**PARTIAL.** BDZJ2 바이너리에서 task_alloc hook이 0이 아닌 값을 반환하면 FIVE 정리가 두 번 실행되는 경로는 확인됐다. SSAL이 직접 만드는 thread와 subprocess는 생성 전에 부모 SID의 유효 fork 권한을 확인하고 불확실하면 차단하도록 설계할 수 있다. 하지만 실제 패닉 당시의 fork 거부는 확인되지 않았고, 정확한 적용 정책·활성 LSM hook·일부 표준 라이브러리 clone flags도 확보되지 않았다. Guest Zygote 내부 fork와 SSAL 밖에서 발생하는 오류까지 SSAL 코드만으로 통제할 수 없으므로 신뢰성 있는 전면 회피는 입증되지 않는다.

이번 보고서는 정적 분석과 설계만 수행했다. SSAL/커널 코드, SELinux 정책은 수정하지 않았고 실기기에서 fork 실패나 패닉을 재현하지 않았다. 바이너리 근거는 BDZJ2에서 추출한 kernel.raw, 소스 대조는 로컬 BYI3 common 트리다. BYI3를 BDZJ2와 같은 소스라고 간주하지 않는다.

## Phase 1 — security_task_alloc 오류 경로

### dispatcher와 정리 순서

BDZJ2 바이너리의 security_task_alloc은 0x6f74ec이다. task blob 크기가 0이면 child의 security 포인터를 NULL로 두고, 크기가 있으면 0x31900c allocator에 크기와 GFP_KERNEL을 전달한다. 할당 실패는 -ENOMEM으로 반환한다. 이 분기는 security_task_free을 호출하지 않는다. 성공 뒤 0xde8670 helper와 LSM task_alloc hook 목록을 처리한다.

LSM dispatcher는 hook을 순서대로 호출하고 첫 nonzero 결과에서 중단한다. hook 결과가 nonzero이면 그 값을 보존한 채 security_task_free(child)를 호출하고 같은 오류를 caller에게 반환한다. BYI3 source의 구현은 security/security.c:784-800, 2911-2937에 있다. BDZJ2 disassembly는 0x6f7574의 indirect hook call, 0x6f7578의 zero 검사, 0x6f7584의 security_task_free call을 확인한다.

security_task_free은 task_free hook dispatcher 다음 FIVE의 five_task_free을 호출한다. 이어 LSM security blob만 해제하고 NULL로 만든다. FIVE 포인터는 지우지 않는다. 이 순서는 BDZJ2의 0x6f75ac-0x6f7620과 기존 분석의 panic LR에 맞는다.

copy_process는 security_task_alloc이 실패하면 같은 child 포인터를 0xac904의 task_integrity_cleanup에 넘긴다. 이 경로는 bad_fork_cleanup_audit으로 이동하므로 bad_fork_cleanup_security의 추가 security_task_free은 통과하지 않는다. 따라서 task_alloc hook 실패 한 번이 FIVE put 두 번으로 이어지는 것은 바이너리에서 **CONFIRMED**다. 근거 callsite는 0xabbb8-0xabbdc, dispatcher는 0x6f74ec-0x6f75a4다.

### 미식별 helper와 각 오류 분류

이전 보고서에서 미식별로 남긴 주요 helper는 BDZJ2의 0xde8670이다. 해당 위치는 security_task_alloc에서 blob 준비 후 hook 순회 전에 불리고, security_task_free에서도 task_free hook보다 먼저 불린다. BYI3 source의 security/security.c와 drivers/uh/kdp.c:451-463에 대조하면 이름과 역할은 security_integrity_current()에 강하게 대응한다. 이 함수는 현재 credential이 KDP credential-integrity 조건을 만족하는지 검사한다. kdp_enable 상태에서 credential/security 또는 mm integrity 비교가 실패하면 panic하고, 정상 반환은 0이다. BDZJ2 disassembly도 정상 경로의 0 반환과 panic 경로를 보이며 일반 nonzero errno 반환은 확인되지 않는다. 이름의 바이너리 symbol은 stripped 상태라 source-correlated attribution으로 기록한다.

별도 allocator 0x31900c는 security blob을 준비하는 kzalloc 경로다. 반환값 NULL은 -ENOMEM이며 이 경우 내부 security_task_free은 없다.

| 실패 지점 | 동작 및 FIVE 정리 | 판정 |
|---|---|---|
| dup_task_integrity의 새 tint 할당 실패 | security_task_alloc 이전에 -ENOMEM으로 빠진다. 유효한 child tint가 없으며 이 경로에서 security_task_free 또는 두 번째 tint put은 확인되지 않는다. | **CONFIRMED — double put 아님** |
| security blob kzalloc 실패 | security_task_alloc이 -ENOMEM을 바로 반환한다. copy_process의 task_integrity_cleanup 한 번만 실행된다. | **CONFIRMED — double put 아님** |
| security_integrity_current의 KDP 검사 | 정상 시 0, credential integrity 위반 시 panic. 일반적인 hook 오류 반환은 아니다. KDP panic은 별도 실패 종류다. | **CONFIRMED — 이 경로 자체는 double put 반환 경로 아님** |
| LSM task_alloc hook의 nonzero 반환 | security_task_alloc 내부 security_task_free의 FIVE put 뒤 copy_process가 같은 tint를 다시 정리한다. | **CONFIRMED — 정적 double put 경로** |
| SELinux PROCESS__FORK 거부 | BYI3 selinux_task_alloc은 current SID에서 같은 SID로 process:fork를 avc_has_perm으로 검사한다. Enforcing 거부는 nonzero 반환 후보이며 위 정리 경로에 들어갈 수 있다. BDZJ2에서 개별 SELinux 함수 본문은 복구되지 않았고 정책도 미확인이다. | **POSSIBLE — 발동 입력 후보, 실제 발생은 미확인** |
| 다른 LSM task_alloc hook의 nonzero | dispatcher는 원인과 관계없이 첫 nonzero hook에서 같은 정리를 수행한다. BYI3 AppArmor/TOMOYO 구현은 확인 범위에서 0을 반환하지만 BDZJ2의 실제 hook 구성/config는 미확인이다. | **CONFIRMED — generic 경로; 구체 provider는 INCONCLUSIVE** |
| security_task_alloc 성공 후 copy_process의 후속 실패 | bad_fork_cleanup_security에서 security_task_free 한 번으로 정리되고, 앞서 언급한 task_integrity_cleanup 분기로 가지 않는다. | **CONFIRMED — 이 경로는 double put 아님** |

BYI3 common에는 FIVE GKI20 task_alloc_wrapper가 별도 android_rvh_security_task_alloc trace hook으로 등록돼 있고 tint 할당 실패 시 -ENOMEM을 기록할 수 있다(five/gki/five_main.c:859-883, 969-970). 이는 LSM task_alloc hook 자체와 다른 mechanism이다. 확인한 BYI3 fork.c/security.c에는 그 tracepoint emission이 없고, BDZJ2의 인접 copy_process disassembly는 dup_task_integrity → security_task_alloc 순서를 보인다. 따라서 이 wrapper를 BDZJ2의 추가 오류 반환 경로로 확정하지 않는다. BDZJ2 최종 config 및 tracepoint wiring은 **INCONCLUSIVE**다.

### 실패 유형별 double put 결과

일반 fork(!CLONE_VM)는 child 전용 tint를 count 1로 만든다. hook 오류 시 security_task_free의 첫 put이 객체를 해제할 수 있고 caller의 두 번째 정리는 같은 포인터를 다시 읽는다. 이는 즉시 UAF 또는 추가 BUG 위험이다. CLONE_VM에서는 parent tint 참조를 child와 공유하며 count를 올린 뒤, 두 정리가 그 count를 연속으로 내린다. 추가 tint 소유자가 없다면 parent 참조까지 소비해 parent pointer가 stale해질 수 있고 이후 parent RCU task-free에서 zero-count BUG가 가능하다. 비동기 FIVE 참조 등 다른 소유자가 있으면 시점은 달라지지만 undercount 위험은 남는다.

## Phase 2 — SSAL 프로세스 생성 주체

SELinux hook은 clone_flags나 child의 향후 SID를 검사하지 않는다. source와 target 모두 호출 시점 current SID다. 따라서 fork 검사는 자식의 pre_exec, attr/exec 지정, setresuid/setresgid보다 먼저 실제 생성 syscall을 수행하는 부모 task를 기준으로 한다. SSAL 코드가 Guest launcher에서 예약하는 exec context는 이 검사 시점에 부모 SID를 바꾸지 않는다.

| 생성 경로 / 호출 위치 | 생성 요청 부모와 예상 신원 | CLONE_VM | PROCESS__FORK 검사 대상과 실패 위험 |
|---|---|---|---|
| module/service.sh:3에서 ssald 실행 | KernelSU module service shell이 ssald를 시작한다. 예상 UID/GID 0:0, SID u:r:ksu:s0이나 이 시작 부모의 incident 시점 SID는 로그에 없다. | shell 구현에 따라 달라 코드에서 확정 불가 | ssald가 아니라 module shell의 current SID. 거부되면 시작 fork도 generic task_alloc 오류 경로 후보가 된다. |
| 백그라운드 등록 thread, src/ssald.rs:395-401; Unix 요청별 thread, :564-574 | 이미 실행 중인 ssald가 부모. 예상 UID/GID 0:0, 과거 관측 기반 SID u:r:ksu:s0; 해당 incident thread의 SID는 보존되지 않았다. | **예.** std::thread::spawn은 공유 주소 공간 thread 생성이다. | 호출 thread SID → 같은 SID. denied hook이면 CLONE_VM tint 공유 ref를 두 번 낮춰 parent의 이후 RCU free를 위험에 빠뜨릴 수 있다. |
| worker/getprop subprocess, src/ssald.rs:223, 417-434 및 guest_probe.rs:484 | ssald/요청 처리 thread가 부모. 예상 0:0, u:r:ksu:s0. process child의 pre_exec 이후 자격·SID와 부모의 fork SID는 별개다. | 코드가 CLONE_VM을 지정하지 않는다. Rust std target의 내부 syscall flags는 저장소에 고정돼 있지 않아 **정확한 값은 미확인**; 일반 process-spawn 의미만으로 vfork 구현을 배제하지 않는다. | 실제 spawn 호출 thread의 SID. nonzero면 같은 generic double put; VM 여부에 따라 immediate child UAF 또는 공유 tint undercount 영향이 달라진다. |
| Guest 서비스 시작, src/guest_launcher.rs:25-94, 320 | 별도 Guest launcher 프로세스는 없다. launcher 코드는 ssald 내부 모듈이며 ssald가 Service::start를 호출한다. 부모 예상 0:0/u:r:ksu:s0. child는 fork 이후 pre_exec에서 attr/exec와 UID/GID 설정, cgroup 작업을 한다. | std::process 내부 flag는 미확인; 명시적 CLONE_VM 없음 | **부모 u:r:ksu:s0**에서 검사한다. child가 u:r:ssal_guest_probe:s0 또는 u:r:ssal_property:s0로 exec하려 해도 생성 시점에는 아직 대상 SID가 아니다. |
| Guest Zygote native fork 및 Java child | 현재 launcher 경로는 app_process64를 --zygote로 실행하고 코드에서 Guest Zygote SID u:r:ssal_guest_probe:s0, UID/GID 0:0을 확인한다(guest_launcher.rs:1278-1318). Private Binder 요청을 받아 실제 child fork를 수행하는 부모는 ssald client가 아니라 Zygote다. Java child UID/GID는 fork 후 요청별로 정해진다. | Android Zygote의 일반 fork 의미상 아니오; GSI native 구현은 이 저장소에 없어 flags 자체는 직접 검증되지 않았다. | u:r:ssal_guest_probe:s0 → 같은 SID. denial은 Zygote의 nonzero hook 후보지만 SSAL Rust launcher는 그 내부 fork를 감싸지 않는다. |
| 향후 system_server | 현재 launch 인자에 start-system-server가 없고 코드도 start_system_server=false를 출력한다. 계획된 system_server는 Zygote child이며 예상 UID/GID는 1000:1000이다. | 일반 Zygote fork는 공유 VM 아님; 정확한 native flags는 미확인 | 생성 검사는 계속 Zygote SID u:r:ssal_guest_probe:s0에서 이뤄진다. child의 system_server SID와 1000:1000 자격은 fork 이후 적용된다. system_server가 나중에 자체 thread/process를 만들 때의 부모 SID는 별도 system_server이며 SSAL 통제 밖이다. |
| SELinux transition 진단 fork, src/selinux_probe.rs:121-199 | SSAL 진단 worker가 직접 libc::fork 후 child에서 attr/exec를 쓴다. ssald 내부에서 호출되면 예상 부모 0:0/u:r:ksu:s0이며, child의 pending exec 설정은 fork 이후다. | 아니오(fork() 사용) | 생성 syscall의 현재 부모 SID. SELinux denial이면 동일 실패 경로 후보. 이 항목은 실제 SSAL 서비스가 아니라 probe 경로다. |

src/guest_launcher/fork_probe.rs:188-212의 --zygote-fork-client는 ssald가 Command::spawn으로 시작하는 별도 client다. 이 client의 fork 검사는 ssald SID에서 먼저 일어나며, 이후 Binder 요청을 처리하는 Zygote의 child fork는 앞 표의 별도 검사다. src/guest_probe.rs:495의 stdout/stderr reader threads도 현재 SSAL 부모 프로세스에서 CLONE_VM thread를 만든다. 여러 진단용 Command/fork 경로는 같은 caller-SID 원칙을 따른다. src/unix.rs:262 등 일부 fork/threads는 cfg(test) 안에 있어 서비스 runtime 경로에서 제외했다.

실행 코드가 설정하는 Guest Zygote SID는 u:r:ssal_guest_probe:s0이지만 module/profiles/services/initial.json:55는 u:r:zygote:s0로 기록돼 있다. 이 profile metadata와 현재 launcher 구현이 일치하지 않으므로 실제 적용 SID는 런타임 기록 없이는 확정하지 않는다.

서비스 helper가 child에서 UID/GID를 바꾸는 것은 부모의 fork 권한을 대체하지 않는다. 따라서 Guest child를 root 또는 system UID로 만들 것이라는 목표만으로 fork 검사가 통과한다고 판단할 수 없다.

## Phase 3 — 정책과 AVC

| 주체 | 확보 자료 | PROCESS__FORK 판정 |
|---|---|---|
| ksu / ssald | 과거 live 기록은 ksu 관리 도메인이 permissive였다고 설명한다. 2026-11-04 수집 Host active policy binary는 보관돼 있으나 현 환경에 이를 질의할 SETools 분석기가 없고, 이 binary가 crash boot의 정확한 policy/permissive map이라고 입증되지 않았다. | **UNKNOWN.** 적용 당시 self-fork allow와 per-domain permissive 상태를 확정할 수 없다. ksu가 당시 permissive였다면 일반 SELinux denial은 nonzero hook 반환 원인이 되지 않는다. |
| Guest Zygote / ssal_guest_probe | module/sepolicy.rule:15-18은 ssal_guest_probe 타입과 permissive 선언을 포함한다. 이 규칙이 crash 시 적용됐다는 증거는 없고, 여기에 process:fork allow 규칙도 없다. | **UNKNOWN.** 정책 source 파일만으로 effective AV 또는 동적 permissive map을 확정할 수 없다. Guest SID가 enforcing 상태였다면 정확한 self-fork AV가 필요하다. |
| system_server | SSAL이 실행하는 초기 Zygote fork의 부모가 아니다. 이후 system_server 자체 thread/process 권한은 별도 policy decision이다. | **UNKNOWN.** 현재 저장물에서 해당 self-fork 결정은 확인되지 않는다. |
| Host zygote 및 One UI 프로세스 | 2026-11-04 Host policy binary와 과거 CIL은 있으나 crash 시점 결정과 조건부 규칙/동적 map을 복구하지 못했다. | **UNKNOWN.** SSAL 전용 분석으로 Host 전역의 fork 안전성을 증명할 수 없다. |

정책 참고 자료에는 2026-11-04 Host active binary가 있으나 SETools 수준 분석은 아직 수행되지 않았다. 2026-10-30 CIL 재구성은 neverallow 검사를 생략하는 -N 모드였고, Guest/삼성 vendor 조합도 오류가 남아 현재의 merged Guest policy가 아니다. 컴파일된 policy binary에는 neverallow 선언이 런타임 permission으로 보존되지 않으므로 별도 source 검증이 필요하다. conditional allow 활성 값, exact process transition 및 KernelSU가 runtime에 추가한 규칙도 crash 시점 기준으로 UNKNOWN이다. 모듈의 permissive 설정은 적용됨의 증거가 아니며 이번 설계에서 우회책으로 사용하지 않는다.

저장된 last_kmsg.txt에는 avc: denied, PROCESS__FORK, security_task_alloc, selinux_task_alloc 일치 항목이 없다. 반면 58280.991069에 audit_lost=16773, rate_limit=5, backlog_limit=64 및 rate limit exceeded가 기록돼 있다(lines 18183-84). 따라서 AVC 부재는 denial이 없었다는 강한 반증이 아니다. SELinux 정책 변경, live query, 실제 fork 실패 유발은 이번 단계에서 하지 않았다.

## Phase 4 — SSAL 회피 설계 비교

| 방법 | 적용과 기대 효과 | 호환성·경계·잔여 한계 |
|---|---|---|
| A. fork 권한 사전 확인 | 기존 selinux_probe의 selinuxfs/access query(src/selinux_probe.rs:92-116)를 바탕으로 실제 caller thread SID를 읽고 SID→같은 SID, process:fork의 allowed/permissive/sequence를 조회한다. query()는 현재 private이므로 호출부에서 쓸 작은 interface가 필요하다. 허용이 거부되거나 조회에 실패하면 syscall 전에 중단한다. | global Enforcing을 유지한 read-only 검사와 호환된다. ksu와 Guest Zygote를 각각 확인해야 한다. permissive flag는 실제 SELinux 반환 동작과 enforcing 상태를 구별하기 위해 기록하되 Guest permissive를 우회책으로 받아들이지 않는다. SELinux만 검사하며 다른 LSM 오류를 막지 못한다. policy sequence나 SID가 바뀌면 query와 clone 사이에 TOCTOU가 남는다. |
| B. 부모 SID allowlist | ssald가 만드는 process/thread는 예상한 u:r:ksu:s0 caller에서만 허용하고, Guest Zygote 기반 child는 예상 Guest domain에서만 허용한다. child의 pre_exec SID를 부모 SID로 오인하지 않는다. | Host zygote/system_server를 Guest spawn parent로 허용하지 않아 경계를 유지한다. SID 일치만으로 process:fork 허용은 증명되지 않는다. Zygote 내부 각 요청의 호출은 SSAL launcher 밖에서 발생한다. |
| C. fail-closed gate | A와 B를 합쳐 current SID, exact fork AV, domain permissive flag, global Enforcing 및 policy sequence가 확인되지 않으면 SSAL-owned spawn을 실행하지 않는다. 새 process를 만들지 않는 검사라 denied fork를 유발하지 않는다. | Enforcing은 유지할 수 있지만 Guest 시작이나 서비스가 차단될 수 있다. spawn 전 확인 뒤 정책/SID 변경 가능성이 있고, gate는 non-SELinux LSM hook 결과를 예측하지 못한다. Zygote가 private Binder를 통해 내부적으로 만드는 모든 child를 SSAL code만으로 매번 검사하지 못한다. |
| D. 생성 구조 변경 | ssald의 CLONE_VM thread 생성을 줄이거나 단일 event loop로 바꾸면 해당 thread 경로 노출은 줄어든다. | thread concurrency와 요청 처리 구조를 건드리고, Command child·Zygote fork는 남는다. 모든 child 생성 중단만이 완전한 SSAL 노출 제거지만 Guest Zygote/Private Binder 목표와 양립하지 않는다. 현재 근거만으로 구조 변경을 정당화하기 어렵다. |

### 최소 설계안

별도 구현 Phase에서 A+B+C를 SSAL이 직접 호출하는 모든 thread/process 생성점에 적용하는 것이 최소 설계다. 공통 검사는 현재 thread의 SID, 같은 SID의 process:fork effective AV, per-domain permissive flag, global Enforcing 및 access sequence를 조회하고 상태가 거부/불명/변경이면 fork 전에 실패해야 한다. 검사 대상은 ssald job/listener threads, worker/getprop Command 경로, guest_launcher Service::start, selinux_probe child 등이다. 기존 selinuxfs/access parser와 query logic을 재사용하되 필요한 최소 interface만 노출하고 검사 결과를 로그로 남긴다.

Guest Zygote 시작 전에는 예상 target인 ssal_guest_probe의 self process:fork AV도 별도로 조회하고 허용/Enforcing 조건이 확인되지 않으면 Guest 시작을 거부해야 한다. 이후 Zygote 내부 fork는 SSAL 부모가 아니므로 이 gate가 각 Binder 요청을 대신 보호하지 않는다. 확인하지 못한 Zygote policy 상태라면 launcher에서 Zygote 요청을 제공하지 않는 fail-closed 선택이 필요하다. Private Binder나 Host One UI 프로세스에 새 권한을 주는 정책 변경은 이 설계에 포함하지 않는다.

사전 검사는 SSAL의 known SELinux 거부를 줄일 뿐, panic 예방 보증이 아니다. 다른 task_alloc LSM hook이 실패하거나 policy/credential이 검사 직후 변하면 double-put path는 남는다. CLONE_VM thread 제거도 일반 process-spawn 실패를 해결하지 않는다.

## Phase 5 — 기존 panic 원인 가설

가설: SSAL 실행 중 특정 부모 SID의 PROCESS__FORK 거부가 task_alloc 오류를 만들었고, BDZJ2 FIVE double put이 tint count를 손상시켜 이후 RCU task-free에서 panic을 일으켰다.

| 지지하는 증거 | 반대 증거 또는 확인되지 않은 점 |
|---|---|
| BDZJ2 binary에 nonzero task_alloc hook → security_task_free → 같은 child의 task_integrity_cleanup 경로가 있다. last_kmsg의 PC/LR는 five_task_free+0x40, security_task_free+0x5c이고 stack은 __put_task_struct → delayed_put_task_struct → rcu_do_batch를 포함한다(lines 18208-09, 18222-25). 이는 zero-count put panic과 맞는다. | last_kmsg는 실패한 fork, task_alloc errno, clone_flags, 대상 task PID/TGID/부모 SID를 보존하지 않는다. RCU worker rcuop/4는 free 중인 대상 task가 아니다. |
| crash 직전 로그에는 ssald task와 KernelSU setresuid 기록이 있어 SSAL 활동과 시간상 인접하다. | 시간상 인접성은 fork denial이나 SSAL task가 대상이라는 증거가 아니다. panic 약 0.1초 전 main task의 UID 변경도 대상 task를 특정하지 않는다. |
| SELinux selinux_task_alloc source는 process:fork 거부를 nonzero로 돌려줄 수 있으며 이는 확인된 generic cleanup 오류와 연결 가능하다. | 현재/incident policy에서 ksu 또는 ssal_guest_probe의 effective fork 결정과 permissive 상태가 UNKNOWN이다. 과거 ksu permissive 관측이 그대로였다면 SELinux denial은 보통 task_alloc error가 되지 않는다. |
| 보존 로그에서 audit_lost가 16,773까지 증가해 AVC 누락 가능성이 크다. | 기존 AVC가 없다는 사실만으로 가설을 반증할 수는 없지만, 누락 가능성도 가설을 입증하지는 않는다. 다른 LSM 오류, 다른 refcount 경로 또는 선행 메모리 손상도 배제되지 않는다. |

**가설 최종 상태: POSSIBLE, 원인 확정 아님.** 확인된 것은 zero-count FIVE put panic과 바이너리의 조건부 double-put 결함이다. 특정 부모 SID의 fork denial이 실제 발생해 이 패닉을 유발했다는 증거는 없다.

지연 RCU free와 직접 연결하려면 공유 tint를 손상시킬 수 있는 CLONE_VM 실패 분기가 특히 설명력이 있지만, 일반 fork 오류 경로의 이후 task-free 또는 별도 corruption 가능성도 남는다. 로그에는 clone_flags가 없어 이 둘을 구분할 수 없다. BUG_ON은 put 시 count가 0이었다는 사실을 보일 뿐, 이전 decrement가 underflow했다거나 해당 double put이 원인이었다는 증명은 아니다.

## 다음 안전 검증 계획

1. 오프라인에서 BDZJ2와 정확히 일치하는 vmlinux/System.map/.config 또는 build symbols를 확보해 0xde8670 helper, 활성 KDP/LSM 구성, GKI10/GKI20 경로를 대조한다. 기존 BDZJ2 boot/kernel hash와 firmware source revision도 구분해 보관한다.
2. 보관된 2026-11-04 policy binary를 호환 SETools 또는 Android policy parser로만 오프라인 분석한다. ksu, ssal_guest_probe, system_server의 self process:fork, conditional rule, type/role/constraint 결과를 확인한다. binary 밖의 KernelSU permissive map이나 incident 시점 runtime patch는 별도 증거 없이는 UNKNOWN으로 둔다.
3. 이미 수집한 로그만 대상으로 AVC, audit loss, ssald PID/UID/SID, 자연 발생한 process creation 오류의 상관관계를 계속 확인한다. 이후 자료가 자연 발생 incident에서 제공되면 raw 전체를 불러오지 말고 필요한 행만 필터링한다.
4. 별도 구현 Phase가 승인되면 먼저 host-only fixture로 gate의 허용/거부/unknown 동작을 검증한다. 실기기 확인이 필요해도 새 policy/fork 실패/프로세스 종료 실험 없이, 승인된 별도 read-only 관측만으로 current SID, effective process:fork AV, permissive flag, policy sequence를 확인한다. 실제 fork를 시도해 거부 여부를 시험하지 않는다.

이번 단계에서 코드 수정, 테스트 실행, live policy query, 실기기 process creation/termination, setenforce, policy patch, KernelSU/FIVE/DEFEX 변경은 수행하지 않았다.
