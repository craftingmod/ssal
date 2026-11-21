# SSAL Phase 5B — Shared PID Process Management 조사

작성일: 2026-11-04
범위: AOSP Android 16 (`android16-release`, lmkd `android-16.0.0_r3`) 구현, 저장소의 SSAL 실행·마운트 계약, `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img` 안의 실제 `cgroups.json`/`task_profiles.json`, SM-S937N의 이전 읽기 전용 런타임 기록. Guest system_server/lmkd는 실행하지 않았다. 이 조사에서 공유 PID 관리 판정을 완료했다. Lineage framework patch와 다른 이미지 버전의 차이는 **UNKNOWN**이다.

## 결론

**공유 PID Namespace는 확정 아키텍처이며, PID Namespace 부재는 BLOCKER가 아니다.** Zygote는 자신이 fork한 자식을 추적하고, ActivityManager는 자기 `ProcessRecord`에 등록된 PID를 대상으로 종료 요청을 만든다. 같은 PID 공간에서 Host PID를 볼 수 있다는 사실이나 `kill(pid, 0)` 성공만으로 정상 Guest 프로세스 관리가 Host 프로세스를 종료 대상으로 선택한다고 볼 수 없다. AOSP 정상 경로의 UID 전역 `/proc` 검색·종료는 확인되지 않았다.

첫 Guest system_server/앱 실행 전 cgroup/task-profile 경로를 확정해야 한다. GSI 기본 v2 UID/PID 경로(`uid_<uid>/pid_<pid>`)는 이전 Host 관측 경로(`/system/uid_<uid>/pid_<pid>`)와 다르므로, 해당 경로가 그대로 유지되면 일반 v2 `kill/remove` 호출이 Host 프로세스 그룹을 고르는 경로는 확인되지 않았다. 반면 이미지 task profile은 v1 cpu/cpuset/blkio 경로도 사용하고, 전체 Host cgroup root를 Guest에 보이면 Host subtree 노출 및 잘못된 경로 설정 위험이 남는다. **Guest 전용 cgroup subtree/경로와 v1 task-profile 처리를 확정하는 것이 우선**이다. cgroup을 숨기는 현재 Guest mount는 Host cgroup 삭제를 막지만 libprocessgroup과 task profile의 성공을 보장하지 않는다.

**공유 PID 조사 완료.** Phase 5B의 나머지 Binder/property/launcher 검증은 계속한다. Guest cgroup compatibility가 현재 선행 작업이며, 이어 남은 검증을 마친 후 Phase 6A의 installd/artd 실행으로 진행한다. 여기서 확인한 정상 PID 관리 경로에 대한 아키텍처 **BLOCKER는 없다**.

## 코드·환경 근거

참조 구현:

- [AOSP `ProcessList.java`](https://android.googlesource.com/platform/frameworks/base/+/android16-release/services/core/java/com/android/server/am/ProcessList.java), [ActivityManagerService.java](https://android.googlesource.com/platform/frameworks/base/+/android16-release/services/core/java/com/android/server/am/ActivityManagerService.java), [Process.java](https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/java/android/os/Process.java)
- [AOSP ZygoteServer.java](https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/java/com/android/internal/os/ZygoteServer.java), [ZygoteProcess.java](https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/java/com/android/internal/os/ZygoteProcess.java)
- [AOSP `PhantomProcessList.java`](https://android.googlesource.com/platform/frameworks/base/+/android16-release/services/core/java/com/android/server/am/PhantomProcessList.java), [its JNI cgroup path](https://android.googlesource.com/platform/frameworks/base/+/android16-release/services/core/jni/com_android_server_am_PhantomProcessList.cpp)
- [AOSP `libprocessgroup/processgroup.cpp`](https://android.googlesource.com/platform/system/core/+/android16-release/libprocessgroup/processgroup.cpp), [task_profiles.cpp](https://android.googlesource.com/platform/system/core/+/android16-release/libprocessgroup/task_profiles.cpp), [init `service.cpp`](https://android.googlesource.com/platform/system/core/+/android16-release/init/service.cpp)
- [AOSP cgroup configuration guide](https://source.android.com/docs/core/perf/cgroups), [AOSP Zygote JNI specialization](https://android.googlesource.com/platform/frameworks/base/+/b1fc5a4c7ee9dffe48f143c580d88ee4862f3c2e/core/jni/com_android_internal_os_Zygote.cpp)
- [Android 16 lmkd source](https://android.googlesource.com/platform/system/memory/lmkd/+/refs/tags/android-16.0.0_r3/lmkd.cpp)

호출 이름과 의미는 AOSP 구현 계보를 기준으로 정리했다. vendor framework patch, Lineage cherry-pick, 실제 Guest 이미지의 활성 init rc와 task profile에 따라 달라질 수 있다. 특히 syscall별 전체 정적 검색 결과로 `tkill`/`tgkill`/`pidfd_send_signal`의 사용 부재를 증명하지는 않는다.

기기의 이전 읽기 전용 기록에서 확인한 값:

- Boot ID `f7900911-c061-4570-8f65-900571a55c11`; `CONFIG_PID_NS` 미설정, `/proc/1/ns/pid` 링크 없음.
- `/proc/1/cgroup`의 cgroup v2 경로는 `/`; 실제 Host 프로세스는 `/sys/fs/cgroup/system/uid_<uid>/pid_<pid>` 아래에 있음.
- cgroup v1 freezer/cpuset/cpuacct/cpu/blkio와 cgroup v2가 함께 마운트되어 있고, `CONFIG_CGROUPS=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_CGROUP_PIDS` 미설정.
- Guest 초기 mount profile은 `/sys`를 새 RO sysfs로 만들며 `/sys/fs/cgroup`과 `/sys/fs/bpf`를 bind하지 않는다. Guest `/dev`는 전용 tmpfs이고 `/dev/socket`도 비어 있는 Guest 경로다.
- Host `lmkd`(PID 941), `zygote64`(27927), `system_server`(28271), `/dev/socket/zygote`, `/dev/socket/lmkd`가 존재했다. 명령은 조회만 했다. Guest system_server/lmkd는 실행하지 않았다.

이전 조사 시점에는 ADB가 연결되지 않아 controller/delegation 값이 미확인이었다. 아래 2026-11-04 재조회가 해당 공백을 대체한다.

### 2026-11-04 SM-S937N 읽기 전용 cgroup 확인

ADB root shell에서 읽기 전용으로 재확인했다. Boot ID는 `f7900911-c061-4570-8f65-900571a55c11`, Host SELinux는 `Enforcing`이다. cgroup mount는 이전 기록과 같고 Host init/zygote64/system_server/lmkd가 계속 존재한다. `cgroup.controllers`/`subtree_control`, cgroup membership, mountinfo와 cpuset 값을 읽었으며 cgroup 파일 쓰기, mount, signal은 수행하지 않았다.

| 영역 | 현재 관측 | 의미 |
|---|---|---|
| v2 root `/sys/fs/cgroup` | `cgroup.controllers=memory`, `cgroup.subtree_control` 비어 있음; root의 `cgroup.procs`는 785개 | `memory`는 root에서만 보이고 child에 위임되지 않음. PID controller 미지원 설정과 일치. |
| v2 `/sys/fs/cgroup/system` | `cgroup.controllers`와 `subtree_control` 비어 있음; Host UID/PID 그룹이 이 아래 존재 | 여기서 Guest memory controller를 받을 수 없음. 기존 Host branch를 Guest root로 재사용하지 않음. |
| v2 `/sys/fs/cgroup/apps` | Host UID 그룹이 이미 존재, direct `cgroup.procs`는 0; `cgroup.controllers`/`subtree_control` 비어 있음; `cgroup.freeze` 존재 | Guest 전용 child를 두면 sibling Host 앱 UID 그룹과 경로가 분리된다. memory는 사용 불가 상태; cgroup v2 freezer interface는 존재. |
| v1 | `/dev/cpuctl`(cpu), `/dev/cpuset`, `/dev/blkio`, `/dev/freezer`, `/dev/acct` mount 존재. 이미지가 쓰는 CPU/cpuset/blkio 그룹 이름들이 root에 이미 있음. cpuset root `cpus/effective_cpus=0-7`, `mems/effective_mems=0` | v1 root를 Guest에 노출하면 GSI task profiles가 Host hierarchy를 직접 조작할 수 있음. 전용 child subtree와 Guest 전용 mount view가 필요. |
| Host 대표 PID | PID 941은 v2 `/system/uid_1069/pid_941`, zygote 27927은 `/system/uid_0/pid_27927`, system_server 28271은 `/system/uid_1000/pid_28271` | Host 경로는 분명히 `/system` 가지임. |

### Guest cgroup 경로 계약

**경로 설계는 다음으로 확정한다; 실제 cgroup 생성/마운트는 아직 하지 않았다.** 사용자가 요청한 읽기 전용 확인을 넘어서 Host cgroup을 변경하지 않았다.

- Host 쪽에서 각 실제 controller에 고유한 child root를 두는 계획: v2 `/sys/fs/cgroup/apps/ssal_guest`; v1 `/dev/cpuctl/ssal_guest`, `/dev/cpuset/ssal_guest`, `/dev/blkio/ssal_guest`.
- Guest mount namespace에는 각각의 child root만 기존 GSI 설정 대상인 `/sys/fs/cgroup`, `/dev/cpuctl`, `/dev/cpuset`, `/dev/blkio`로 bind한다. Host controller root와 `/sys/fs/cgroup/system` 또는 `/sys/fs/cgroup/apps` 전체는 Guest에 노출하지 않는다. 그러면 Android가 만든 `uid_<uid>/pid_<pid>`와 task-profile 그룹은 bind한 Guest root 아래에서만 생성·삭제된다. Guest `kill/remove` 경로는 Host의 `/system/uid_*/pid_*` 및 Host v1 그룹 바깥이다.
- Guest config에서 optional v2 `memory` activation/profile을 비활성화한다. 현재 `/apps`에는 memory controller가 위임되지 않았고 이를 활성화하려면 parent/root `cgroup.subtree_control` 변경이 필요해, 이번 Host 안전 조건에서는 수행하지 않는다. GSI의 `freezer` task profile이 쓰는 v2 `cgroup.freeze`는 `/apps`에서 읽기 가능함을 확인했다.
- GSI가 참조하는 v1 cpu/cpuset/blkio profile 그룹만 전용 root 아래 재현하고, cpuset 자식은 현재 허용 CPU `0-7`과 mem `0`을 기준으로 준비한다. cgroup 생성 시점과 정확한 profile 목록은 Guest init 대신 supervisor 준비 단계에서 처리해야 한다. 이미지 task profile 이름/속성 외에 초기 그룹 설정값은 아직 실제로 구성·검증하지 않았다.
- `libprocessgroup`가 보는 mountpoint를 이 전용 bind root로 한정하면 API 코드 자체의 수정은 우선 필요하지 않다. `createProcessGroup`/`setProcessGroup`/`killProcessGroup`/`removeProcessGroup`가 외부 root를 직접 조합하는지 실제 GSI 바이너리/Lineage patch로 대조하고, supervisor cleanup도 고정된 Guest root 및 PID+starttime/pidfd 검증을 사용한다.

**현재 readiness: 아직 Phase 6A 진입 불가.** `/apps/ssal_guest` 등은 아직 존재하지 않는다. v1 새 child 생성·cpuset 초기화·bind mount 및 Guest용 task-profile 준비는 실제 Host cgroup 변경이므로 읽기 전용 단계에는 포함되지 않았으며, ADB root가 된다는 사실만으로 Host Enforcing 정책에서 해당 작업이 허용된다고 단정하지 않는다. 승인된 구성 실험 전까지 Guest system_server/앱의 cgroup API 실행은 보류한다. cgroup 없는 모드도 Android 16 app-zygote assertion 경로 때문에 승인된 대안이 아니다.

## LineageOS 23.2 이미지의 cgroup 설정

이미지 파일 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img`를 WSL의 `debugfs`로 읽었다. 이미지와 JSON 파일은 수정하지 않았다. 이 이미지의 `/etc/cgroups.json`(이미지의 `/system/etc/cgroups.json` 경로)은 다음을 선언한다.

- cgroup v1: `blkio` → `/dev/blkio`, `cpu` → `/dev/cpuctl`, `cpuset` → `/dev/cpuset`.
- cgroup v2: root `/sys/fs/cgroup`; `freezer`는 필수 경로, `memory`는 `NeedsActivation: true`, `MaxActivationDepth: 3`, `Optional: true`.
- `task_profiles.json`은 `JoinCgroup`으로 v1 `cpu`(system/background/foreground/top-app 등), `cpuset`(background/foreground/top-app 등), `blkio`를 사용한다. v2 memory는 `memory.max`, `memory.low` 등의 attribute로 연결되고 `Frozen`/`Unfrozen`은 `cgroup.freeze`를 쓴다. 예를 들어 `SCHED_SP_BACKGROUND`, `SCHED_SP_FOREGROUND`, `SCHED_SP_TOP_APP`, `CPUSET_SP_*`, `SystemMemoryProcess`가 cgroup 작업을 포함한다.

GSI의 v2 controller root `/sys/fs/cgroup`를 Host mount에 그대로 대입할 때, 이전 기기 기록의 Host 프로세스 경로는 `/sys/fs/cgroup/system/uid_<uid>/pid_<pid>`이고 GSI의 Guest 경로는 `/sys/fs/cgroup/uid_<uid>/pid_<pid>`가 된다. 즉 정상 `uid,pid` 기반 Guest `kill/remove` 대상은 Host의 `/system` 가지와 다른 경로다. 다만 root 전체 노출은 Guest mount에서 Host subtree를 보이게 하며, v1 task profile 목적지는 별도 격리되지 않는다.

따라서 Guest cgroup을 완전히 숨기는 현재 mount 설계는 Host cgroup 경로를 보호하지만 이 이미지의 모든 task profile과 앱 process-group lifecycle이 동작한다는 뜻은 아니다. 특히 task profile의 v1 cpu/cpuset/blkio 경로는 별도 목적지가 없으면 실패할 수 있다. Guest init을 실행하지 않으므로 이미지 init이 선언한 cgroup mount/activation도 자동으로 발생하지 않는다.

**cgroup 비활성 모드 판정: UNKNOWN, Phase 6A 진입용으로 승인 불가.** Android 16 Zygote JNI의 기본 앱 specialization은 `createProcessGroup` 실패를 로그하고 계속하는 경로가 있다. 반면 `ProcessList`의 WebView/app-zygote 경로는 `Process.createProcessGroup` 실패 시 `ESRCH`를 제외하고 `AssertionError`를 던진다. 따라서 cgroup 없는 실행은 모든 앱 spawn 경로에서 안전한 대체 모드가 아니며 forked child·task profile·cleanup도 보장하지 않는다. 실제 Lineage 23.2 variant의 런타임 부팅은 시험하지 않았다. 모든 cgroup 의존 task profile을 Guest 전용 경로로 재배치하거나, 호출 경로별 비치명 동작을 확인해야 한다.

## Guest cgroup subtree 판단 및 현재 조치

- **기술적 가능성: 조건부 가능.** 기기 기록에는 cgroup v2 hierarchy와 `/system` 하위 cgroup이 보이고 커널 `CONFIG_CGROUPS=y`다. v2 subtree는 cgroup namespace 없이도 선택된 subtree만 Guest `/sys/fs/cgroup`에 bind하는 설계가 가능하다. 다만 각 parent의 `cgroup.controllers`/`cgroup.subtree_control`, cpuset 값과 상위 delegation이 맞아야 한다. 이번 세션에는 기기가 ADB에 연결되지 않아 이 controller 상태를 읽지 못했다.
- **아직 구성하지 않음.** `cgroup.controllers`와 `cgroup.subtree_control`의 현재 값을 이번 세션에 읽을 수 없었고, 사용자가 Host cgroup 변경 실험을 금지했다. Host hierarchy에 directory 생성, controller 활성화, task 이동, cgroup 삭제를 하지 않았다.
- **v2 하나로 끝나지 않음.** 이미지 task profile은 v1 cpu/cpuset/blkio mount 경로도 필요로 한다. v2 subtree만 선택하면 이 profile들을 만족하지 못하므로 Guest view 안의 해당 v1 controller도 Guest 전용 하위 경로로 제공하거나, Android 16 caller를 기준으로 Guest 전용 task-profile 대체 정의를 검증해야 한다. 현재 initial mount profile의 Guest `/dev`에는 Host `/dev/cpuctl`, `/dev/cpuset`, `/dev/blkio`가 없다.
- **권장 경로:** supervisor가 세션 수명 동안 전용 cgroup root/subtree를 소유하고, 이미지의 Guest cgroups 설정·task profile controller 경로를 그 전용 subtree에 맞춘다. `createProcessGroup`, `setProcessGroup`/task profile, `killProcessGroup`, `removeProcessGroup` 모두 그 root 안에서만 동작하도록 경로·mount를 제한한다. Guest lmkd는 첫 부팅에서 실행하지 않는다.
- **Host init ctl 차단:** 기존 [Guest 서비스 실행 계약](service-execution-contract.md)은 Guest `ctl.*`을 Host init에 보내지 않도록 정한다. 현재 Guest mount에는 Host property area/socket과 Host `/dev/socket`이 없고 Guest property service도 아직 없다. private property/control을 추가할 때는 알 수 없는 `ctl.*`을 기본 거부하고 supervisor의 명시적 서비스명만 내부 처리해야 한다.

정상 Guest 프로세스 관리가 Host PID를 종료 대상으로 선택하지 않는다는 판정은 위 AOSP ProcessRecord/zygote-child 분석에 근거한다. 실기기 Guest AMS 경로는 아직 실행하지 않았다. 검증 재개 시 Guest 전용 child만 생성·종료하고 supervisor가 선택한 Guest PID/starttime을 기록하며, Host 프로세스에는 신호를 보내지 않는다. `kill(pid,0)` 및 `/proc` 가시성 결과는 대상 선택 검증을 대신하지도, 단독 NO-GO 조건도 아니다.

## Android 프로세스 관리 경로

| 경로 | 대상 선택·동작 | 공유 PID Namespace 영향 | 판정 |
|---|---|---|---|
| Zygote spawn | `ZygoteProcess`가 Zygote socket으로 요청하고 Zygote가 `fork()` 후 자식을 specialize한다. system_server도 Zygote가 fork한다. 자식의 PID를 Zygote 응답으로 framework에 돌려준다. | PID는 Host 전체와 전역 유일하다. 부모·자식 관계와 fork한 자식의 소유 추적은 namespace 공유로 바뀌지 않는다. | **SAFE** |
| Zygote child exit | Zygote의 SIGCHLD 처리/`waitpid`는 Zygote의 실제 자식만 회수한다. 임의의 같은 UID 또는 Host PID를 찾아 `waitpid(-1)`로 거둬들이는 것이 아니다. | Host init/다른 프로세스의 자식은 Zygote가 회수할 수 없다. Zygote가 종료되면 기존 Guest 자식은 Guest PID 1이 없으므로 Host init 등 커널 reparent 규칙으로 넘어갈 수 있다. | 정상 회수 **SAFE**; 재시작 정리 **FIX** |
| Zygote restart | init의 `critical`, `onrestart`, 서비스 재시작 action은 해당 rc를 읽고 서비스를 소유한 init에만 적용된다. SSAL은 Guest init/rc를 실행하지 않고 supervisor가 Guest 명령을 띄우는 구조다. | Guest rc를 Host init에 import하면 Guest `zygote`라는 이름도 Host 서비스 이름과 충돌할 수 있고 onrestart가 Host 서비스를 건드릴 수 있다. 지금 구조에서 자동 실행되는 것은 아니다. | Host init에 Guest rc 미등록 **FIX 조건**; 조건을 지키면 **SAFE** |
| AMS 앱 추적 | `ProcessList`/`ProcessRecord`가 앱의 PID, UID, process/package 이름, 프로세스 상태를 보유한다. `killPackageProcessesLSP`, force-stop 등은 프레임워크의 해당 프로세스 레코드를 골라 종료한다. 이름으로 전체 `/proc`의 동일 UID 프로세스를 검색해 종료하는 일반 경로가 아니다. | Guest package manager/system_server가 만든 Guest 레코드만 대상이다. Host와 Guest가 같은 앱 UID를 써도 PID·ProcessRecord가 일치하지 않으면 UID 같음만으로 Host 앱을 고르지 않는다. | **SAFE** |
| 앱 단일 종료 | Android `Process.killProcess(pid)`/native 경로는 PID에 `SIGKILL`을 보낸다(통상 `kill(2)`). `killProcessQuiet` 계열도 PID 기반이다. 일부 경로는 `Process.killProcessGroup(uid,pid)`를 추가 호출한다. | 살아 있는 Host와 Guest는 PID가 겹치지 않는다. 다만 자식 종료/AMS 정리와 신호 사이에 PID가 종료·재사용되는 좁은 stale-PID 경쟁은 pidfd 없이 이론상 존재한다. | **DEFER**: supervisor의 PID+starttime/pidfd 검증; AMS 내부 신호는 별도 계측 필요 |
| UID/package 종료 | AMS는 자체 프로세스 표와 package/user/appId 필터로 대상 레코드를 찾고, 해당 PID별 종료·그룹 종료를 요청한다. `killUid`류도 framework가 보유한 프로세스 후보를 정리하는 것이며 공유 커널 UID 자체가 자동으로 Host/Guest 프로세스 집합을 분리하지는 않는다. | 정상 Guest AMS 등록 밖의 Host 프로세스를 UID만으로 찾아 종료한다는 코드 경로는 확인되지 않았다. 서비스가 별도 `/proc` UID scan을 추가하거나 native vendor 코드가 다르면 재검증해야 한다. | AOSP 경로 **SAFE**; Lineage/vendor 확장 **UNKNOWN** |
| Phantom/앱 자식 관리 | Android 16 `PhantomProcessList`는 AMS의 관리 앱 PID부터 순회하고 각 앱의 `CgroupProcs` attribute 경로에서 `cgroup.procs`를 읽어 추가 자식을 등록한다. 전체 `/proc`에서 UID가 같은 프로세스를 고르지 않는다. child PID가 이미 AMS에 있거나 app-zygote로 확인되면 별도 phantom으로 취급하지 않는다. | Guest의 cgroup v2 경로가 기본 `/sys/fs/cgroup/uid_<uid>/pid_<pid>`이고 Host가 `/sys/fs/cgroup/system/uid_<uid>/pid_<pid>`를 유지하면 Guest 앱의 child 후보 파일은 Host group과 다르다. cgroup 경로가 없으면 파일 열기가 실패해 phantom child 탐색이 반환되므로 Guest child 추적은 약해진다. | 대상 경로 **SAFE**(기본 v2 root 조건); child 추적 **FIX** |
| PID syscall | 직접 종료의 핵심은 PID 신호와 libprocessgroup 그룹 종료다. 일반 Android 앱 수명주기에서 PID를 전부 훑는 `tkill`/`tgkill`/`pidfd_send_signal` 호출 경로는 이 검토에서 확인하지 못했다. `pidfd_send_signal` 부재를 확정하지 않는다. | `kill(pid,0)` 성공은 존재/권한 확인일 뿐 종료 대상 선택이나 실제 신호 증거가 아니다. | syscall 변형 상세 **UNKNOWN**; PID 가시성만으로 FAIL 아님 |

### Zygote socket

init이 Zygote용 filesystem socket(`/dev/socket/zygote`, secondary socket 등)을 만들고 FD를 서비스에 전달한다. Host와 Guest에서 **같은 underlying `/dev/socket`**을 사용하면 경로 unlink/rebind 및 잘못된 socket 접속이 충돌한다. 현재 SSAL mount profile처럼 Guest 전용 `/dev` tmpfs와 별도 `/dev/socket`을 제공하면 같은 경로 문자열은 별개의 inode/socket이므로 pathname 충돌은 낮다. Guest Zygote는 Host init의 socket FD를 상속하지 않고 Guest socket을 직접 만들거나 supervisor가 전용 socket을 준비해야 한다.

Filesystem mount 분리는 Linux abstract UNIX socket namespace를 분리하지 않는다. 같은 abstract 주소를 쓰는 서비스는 충돌할 수 있으므로 Guest framework Binder/property/lmkd 소켓은 별도 이름·전용 endpoint가 필요하다. Zygote filesystem socket 자체는 현재 mount 설계로 분리 가능하다(**FIX**, 아직 Guest Zygote 실증 전).

### `/proc` 탐색과 phantom child

Android 16 `PhantomProcessList`는 전체 `/proc`을 UID 기준으로 훑어 Host PID를 후보로 삼지 않는다. AMS가 관리하는 각 앱 `ProcessRecord`를 시작점으로 삼아 그 앱의 `CgroupProcs` attribute가 가리키는 `cgroup.procs`만 읽는다. 그 파일에서 찾은 child는 `/proc/<pid>/cmdline`과 UID를 조회해 기록하고, 이미 AMS에 있거나 app-zygote로 분류된 PID는 별도 phantom으로 취급하지 않는다. Phantom 종료 요청은 해당 child PID에 `killProcessQuiet`와 `killProcessGroup`을 적용한다.

따라서 이 경로에서 중요한 것은 Host `/proc`의 가시성 자체가 아니라 Guest 앱별 cgroup의 소유 경로다. GSI 기본 v2 root의 Guest `uid/pid`는 기기 기록의 Host `/system/uid/pid`와 구별된다. Guest cgroup을 아예 숨기면 phantom child 탐색이 실패해 Guest 자식 관리가 약해지므로, Guest 전용 cgroup 경로 제공이 필요하다. Guest AMS의 실제 실행 검증은 아직 하지 않았다.

## ActivityManager 종료·복구 상세

정상 앱 시작에서는 Zygote가 fork한 PID가 framework로 반환되고 ProcessList가 프로세스 레코드에 PID/UID를 결합한다. 종료 사유(앱 force-stop, package update, ANR, 메모리 회수 등)는 달라도 종료는 보통 해당 레코드의 PID와 UID/PID 프로세스 그룹을 대상으로 한다. 앱 프로세스가 직접 만든 자식은 앱과 같은 UID여도 AMS의 별도 ProcessRecord가 없을 수 있으므로 `killProcessGroup`의 cgroup 정리 또는 Zygote/서비스 종료 시 그룹·supervisor 정리가 중요하다.

Guest system_server의 UID 기준 조회는 Host 시스템 전체를 UID로 찾아 처리하는 기능이 아니다. 그러나 동일 UID라는 사실만으로 DAC/SELinux 격리가 생기는 것도 아니다. `kill(pid,0)`와 proc 가시성 시험에서 확인된 신호 가능성은 기존 [Guest service launcher 결과](guest-service-launcher-results.md)의 별도 런타임 증거이며, 실제 신호를 보내지 않았다. Guest domain을 permissive로 두면 Guest 코드가 직접 임의의 Host PID에 신호를 보내는 것을 막는 정책 경계로 삼을 수 없다. 이는 AOSP의 정상 AMS 표적 선택과 구분해야 하는 Host 보호 문제이며 Phase 5B 실행 경계에서 계속 해결해야 한다.

Supervisor는 자기가 시작한 Guest root process와 서비스 PID를 `pidfd`가 가능하면 pidfd로, 그렇지 않으면 PID+`/proc/<pid>/stat` starttime+boot ID로 기록한다. 중지 시 Guest Zygote의 추가 spawn을 먼저 막고 추적된 프로세스만 종료한다. 이 목록은 Guest AMS가 보유한 내부 ProcessRecord를 제한하지 않는다. system_server 경로 자체에 Host 신호 방어가 생기는 것으로 간주해서는 안 된다.

## libprocessgroup / cgroup

Android 16 `libprocessgroup`는 `createProcessGroup(uid,pid)`, `setProcessGroup`, task profile 적용, `killProcessGroup(uid,pid,signal)`, `removeProcessGroup`를 제공한다. cgroup v2 구현은 설정된 controller root 아래 `uid_<uid>/pid_<pid>` 형태의 경로를 구성한다. 종료 시 원래 PID를 먼저 신호하고, 그룹 cgroup의 `cgroup.procs`/`cgroup.kill`을 이용해 구성원을 처리하며 그룹 경로를 정리한다. cgroup v2 SIGKILL 경로에서는 OS process group(-initialPid)에도 신호를 보내 cgroup 밖으로 옮겨진 앱 관련 process를 처리하는 구현이 있다. v1 경로도 cgroup 내 PID들을 열거해 `kill(pid, signal)`하고 UID/PID 디렉터리를 제거한다. 정확한 분기는 기기 cgroups.json/controller 버전에 의존한다.

| 위험/조건 | 충돌 분석 | 판정과 최소 처리 |
|---|---|---|
| Host cgroup root를 Guest에 그대로 RW bind | Guest `removeProcessGroup`/task profile이 공유 Host hierarchy를 직접 수정할 수 있다. 경로는 UID+PID로 정해져 생존 PID 자체는 전역 유일하지만, 같은 root를 공유하면 cgroup 관리 권한과 stale group 재사용 경쟁에 Host 대상이 들어올 여지가 있다. | **FIX**: Guest에 Host root 전체를 노출하지 않는다. 현재 mount profile처럼 숨기면 Host 보호에는 유리하나, cgroup 생성·이동·삭제가 실패할 수 있음. |
| Guest 전용 cgroup subtree | cgroup namespace 없이 Host가 `/sys/fs/cgroup/.../ssal_guest` 같은 빈 subtree를 만들고 controller를 적절히 위임한 다음 Guest에서 그 subtree만 보이도록 bind 가능하다. Guest `cgroups.json`/task profile 경로를 그 root 기준으로 맞춘다. | 권장 **FIX**. 실제 subtree 생성·controller delegation은 아직 하지 않았으며, controller가 활성화 가능한지·systemd/vendor 정책과 충돌 없는지는 실행 전 읽기 전용 진단 및 별도 제한 실험으로 확정. Guest 경로만 RW bind하고 Host system/uid 경로를 열지 않는다. |
| Host cgroup 미노출 | SSAL의 현재 선택이다. `CgroupsAvailable()`/controller path가 감지되지 않거나 cgroup 경로가 없으면 `createProcessGroup` 및 task profile이 실패할 수 있다. 앱 단일 PID 신호는 남더라도 forked child 정리, oom/profile 정책은 불완전할 수 있다. | **FIX**: “안전하게 숨겼음”을 “정상 그룹 관리 동작”으로 간주하지 않는다. 지원 cgroup 경로를 명시하거나 libprocessgroup의 Guest cgroup 비활성 동작을 검증. |
| Host와 Guest UID 일치 | 경로에서 UID만 쓰지 않고 PID도 사용. AMS가 등록하지 않은 Host 앱을 UID만으로 자동 종료하지 않는다. | 기본적으로 **SAFE**. 공유 상위 hierarchy 접근 권한은 UID 분리만으로 해결되지 않음. |

기기 진단상 v2 controller root는 Host의 `/sys/fs/cgroup/system`이고 그 아래 Host system/앱 UID/PID별 그룹이 있다. `/sys/fs/cgroup/cgroup.controllers` 등을 읽었지만 변경하지 않았다. 상위 `/sys/fs/cgroup`은 `system:system` 소유 권한도 관측되어 단순 UID 전용 하위 디렉터리 이름만으로 안전성을 추정해서는 안 된다. subtree를 만들 때 Host 프로세스를 이동하거나 Host cgroup을 삭제하지 않는다. 이 문서 작성 중 subtree는 생성하지 않았다.

## lmkd / 메모리 압력

`lmkd`는 프로세스의 `oom_score_adj`, 메모리 압력(PSI/vmpressure), RSS/swap 등을 사용해 후보를 선택한다. Android framework/init은 후보 PID/UID와 oom adjustment를 lmkd에 등록한다. lmkd가 Guest system_server의 앱 레지스트리를 공유하는 것이 아니라 각 framework가 등록한 프로세스 집합을 바탕으로 동작한다. Host lmkd는 기본 구성에서 Host system_server가 등록하지 않은 Guest 앱 PID를 후보로 선택하지 않는 것으로 분석했다(**AOSP 경로 SAFE**). 다만 Host는 Guest 앱이 소비한 메모리까지 포함한 실제 시스템 전체 압력을 보며 Host 앱을 더 일찍 회수할 수 있다.

Guest lmkd를 같이 실행하면 전역 메모리 압력/PSI를 공유하고 같은 프로세스 테이블에서 Guest에 등록된 PID를 신호한다. 정상 등록이 정확해도 Guest 메모리만 계산하거나 Host와 kill budget을 조정하지 않으며, Guest permissive/root 성격의 프로세스 권한·cgroup 설정까지 포함한 공존 안전성을 입증하지 않았다. `/dev/socket/lmkd` 경로는 Guest `/dev`가 분리하면 분리되지만 abstract endpoint와 init-provided socket FD의 이름·소유권은 별도 주의가 필요하다.

**최소 조치:** 첫 bring-up에서 Guest lmkd를 시작하지 않고 Host lmkd만 둔다. Guest framework가 lmkd 연결/등록 실패를 허용하는지, oom_score_adj를 직접 쓰는지, 초기 서비스가 lmkd를 필수로 기다리는지는 Guest system_server 없이 확인할 수 없으므로 **FIX/UNKNOWN**. 후속으로만 Guest lmkd를 별도 endpoint·Guest 후보 등록을 갖춰 평가한다. “Host lmkd가 Guest를 고르지 않음”은 Guest가 Host를 고를 위험을 상쇄하지 않는다.

## init와 서비스 생명주기

Host init은 자기 rc에 등록된 서비스만 시작·중지·재시작하고, 해당 서비스의 child process group/socket/cgroup을 정리한다. Android `ctl.start/stop/restart`는 Host property service로 전달되면 이름과 PID namespace로 자동 Guest 라우팅되지 않는다. Guest init을 두지 않는 SSAL은 Guest 서비스를 직접 실행하고 종료·의존성·재시작을 supervisor가 소유한다.

- Guest rc 전체를 Host init에 import하지 않는다. 이름이 같은 zygote 등은 기존 Host 서비스를 재시작할 수 있고, `onrestart`는 Host HAL/service/power action을 수행할 수 있다. **확인된 호출 조건부 위험: BLOCKER** — Host init에 Guest rc/ctl이 연결되는 구성을 금지한다. 현재 실행 계약은 Guest `ctl.*`을 Host init에 전달하지 않도록 한다.
- Guest `ctl.*`은 private property/service manager에서 거부하거나 supervisor의 정확한 allowlist 명령으로 변환한다. Host property socket/영역을 공유하지 않는다. 기존 계약에서 목표로 정했지만 구현 전이다(**FIX**).
- Zygote/system_server crash 시 Host init의 자동 restart가 Guest에 적용되지 않는다. supervisor가 상태를 감지하고 자식 정리를 끝낸 뒤에만 Guest 서비스 재시작을 시작한다. PID만 보고 kill하지 말고 PID+starttime/pidfd 검증 및 Guest cgroup 경계를 쓴다(**FIX**).
- Guest 서비스가 Host init으로부터 socket/FD를 받지 않는다. Guest socket 경로는 전용 `/dev`에 만들고 추적한다. 이름 같은 filesystem socket도 inode/mount 분리 여부를 검증한다(**SAFE 조건**).

여기서 **BLOCKER**는 이 조건을 어겼을 때 AOSP init의 정상 동작이 Host 서비스를 건드리는 구체 경로를 뜻하며, 현재 SSAL 구조에서 발생 중이라는 뜻은 아니다. 전체 판정상 공유 PID 기반 AOSP 앱 관리의 Host 종료 경로는 발견되지 않았다.

## 위험 목록

| ID | 분류 | 확인한 경로/조건 | 필요한 조치 |
|---|---|---|---|
| P1 | **SAFE** | Zygote는 fork 자식만 회수하고 ProcessList는 framework가 등록한 PID 레코드를 선택한다. UID가 같다는 이유만으로 전체 `/proc` Host 프로세스를 종료하지 않는다. | Guest 앱 등록·종료 runtime 확인. |
| P2 | **FIX** | GSI v2 기본 `uid_<uid>/pid_<pid>`는 관측된 Host `/system/uid_<uid>/pid_<pid>`와 다르므로 해당 v2 경로에서 직접 Host 그룹 선택은 확인되지 않음. 하지만 v1 task profile root는 공유되고 전체 cgroup root 노출은 Host subtree를 Guest에 보임. | 읽기 전용 확인 완료. Guest 전용 mount root를 v2 `/sys/fs/cgroup/apps/ssal_guest`, v1 cpu/cpuset/blkio `/ssal_guest`로 고정하고 Host root는 감춘다. |
| P3 | **UNKNOWN** | Guest mount에서 cgroup을 숨기면 Host tree 변경은 막지만 GSI task profile의 JoinCgroup 및 libprocessgroup create/set/kill/remove 동작은 미검증. Android 16 일부 app-zygote 경로는 create 실패를 허용하지 않음. | 제안된 Guest subtree와 task-profile 초기화를 실제 구성·실행으로 확인하기 전 Phase 6A 진입 금지. cgroup 미지원 모드는 현 단계 대안이 아님. |
| P4 | **FIX** | Guest rc/`ctl.*`을 Host init/property control로 전달하면 같은 이름의 Host 서비스 또는 onrestart action을 실행할 수 있다. | 기존 contract대로 Guest-local supervisor 라우팅만 허용. |
| P5 | **FIX** | Guest system_server/lmkd 직접 기동 시 Host lmkd와 endpoint·global pressure 공유가 검증 안 됨. | 초기 Guest lmkd 비활성; framework graceful handling 조사. |
| P6 | **DEFER** | AMS의 stale PID가 종료 직후 재사용된 극단 경쟁은 raw PID signal API에 남는다. Supervisor의 starttime 검사는 AMS 신호와 별도다. | supervisor는 pidfd 우선, starttime fallback; 실제 AMS 재사용 경쟁을 의도적으로 만들지 말고 코드/계측 검토. |
| P7 | **SAFE** | Guest 전용 `/dev` 및 socket mount는 filesystem Zygote socket 경로 충돌을 막는다. | Guest socket 별도 생성 및 FD 상속 확인. |
| P8 | **UNKNOWN** | 정확한 GSI `cgroups.json`/`task_profiles.json`과 현재 controller 상태는 확인했으나, 활성 런타임 profile, Lineage/vendor patch의 UID sweep, native HAL/vendor daemon 및 syscall 변형은 미확인. | Guest용 profile 설정과 실제 실행 경로 비교. |
| P9 | **BLOCKER (구성 위반 시)** | Guest init rc/ctl이 Host init에서 처리되어 기존 이름 서비스와 onrestart action을 건드리는 경로. | Host init에 Guest rc 등록 금지; property bridge에서 ctl 전달 차단. 현재 의도된 구조에서는 회피 가능. |

## 권장 최소 설계

1. 공유 PID namespace를 고정 아키텍처로 유지한다. Host/Guest 모두 정상 kernel PID를 쓰며 supervisor가 Guest PID, starttime/boot ID와 가능하면 pidfd를 기록한다.
2. Guest Android 기본 UID/GID를 유지하되 UID를 프로세스 소유권의 유일한 기준으로 사용하지 않는다. AMS는 Guest ProcessRecord로, supervisor는 자신이 생성한 세션 프로세스로 대상을 선택한다.
3. Host init과 property service를 유지한다. Guest `ctl.*`은 Host init에 보내지 않고 Guest supervisor의 명시적 서비스 작업으로 제한한다.
4. Host cgroup hierarchy의 root를 Guest에 노출하지 않는다. Guest root는 v2 `/sys/fs/cgroup/apps/ssal_guest`, v1 cpu/cpuset/blkio 각 `/ssal_guest` child를 사용하고 Guest의 기존 Android controller mountpoint로 bind한다. GSI optional v2 memory action은 끄고, v1 task-profile group을 해당 전용 root 아래 준비한다. 실제 구성이 검증되기 전 system_server/app spawn은 보류한다.
5. Guest Zygote는 자기 child를 관리하고 Guest system_server는 자체 ProcessList 앱 PID를 관리한다. 이 규칙은 Guest의 임의 Host PID signal을 제한하지 않으므로 permissive 동안 Host PID 신호를 막는 launcher/SELinux 경계는 별도 필수 조건이다.
6. 첫 Guest framework bring-up에서 lmkd는 시작하지 않는다. Host lmkd는 계속 활성 상태로 둔다.
7. 이미 승인된 private Binder/mount 설계는 유지하되 `/dev/socket`, framework Binder, property와 cgroup 경로의 분리 증거를 실행 세션에서 다시 확인한다.

완전한 PID 격리, Guest PID 1, UID remap, 전체 프로세스 관리자, Host cgroup 복제/가상화는 이번 조사에서 필요하다고 판단하지 않았다.

## Phase 5B 남은 일과 Phase 6 진입 조건

**Phase 5B에서 남은 일**

1. 읽기 전용 cgroup controller/subtree/cpuset 확인은 완료했다. controller root는 변경하지 않았다.
2. Guest 전용 cgroup 경로 계약은 위와 같이 확정했다. 다음은 명시적으로 허용된 구성 작업에서만 전용 child root와 mount/profile 초기화를 수행하고, Host 계층 외부 접근이 없음을 읽기 전용으로 대조하는 것이다.
3. Guest child의 supervisor PID+starttime/pidfd 추적·정상 종료 및 Guest-only PID 선택을 확인한다. Host 프로세스에는 신호를 보내지 않는다.
4. 이후 기존 Phase 5B Binder/property/공통 launcher 검증으로 복귀한다. Guest lmkd는 첫 부팅에 포함하지 않는다.

**Phase 6A 진입은 아직 대기.** 공유 PID namespace는 조건이 아니다. cgroup 경로/기능과 기존 Phase 5B Binder/property/launcher 검증이 남아 있다. 이어 남은 검증을 완료한 뒤 사용자 지시에 따라 Phase 6A installd/artd 실행으로 진행한다. Guest lmkd는 첫 부팅에서 제외한다.

단계별 실행 허용 조건:

| 단계 | 허용 조건 |
|---|---|
| Phase 6A: installd/artd | cgroup 경로·task profile 계약 확정, 기존 Phase 5B Binder/property/launcher 검증 완료, Guest 전용 실행 환경과 Host init ctl 차단 확인. Host Enforcing 유지, Guest 정책은 허용 범위에서 permissive. Guest lmkd는 미기동. 정상 프로세스 종료는 Guest PID만 대상으로 확인하고 Host에는 신호하지 않는다. |
| Phase 6B: system_server 진입 | 6A 통과, Guest `libprocessgroup`의 create/set/kill/remove 동작을 Guest 전용 subtree 또는 검증한 cgroup 없는 모드로 한정, package/UID 종료가 Guest 레코드만 대상으로 함, Host init ctl 및 Host property/Binder/HAL 부작용 없음. |
| Phase 6C: 앱·메모리 관리 | 6B 이후 Guest 앱 시작/force-stop/ANR 및 자식 정리, Host lmkd만으로 부팅 가능한지 관찰. Guest lmkd는 별도 설계·승인 실험으로 분리. |

테스트로 추가 실행하거나 실제 Host에 종료 신호/cgroup 변경을 하지 않았다. 문서만 추가했다.
