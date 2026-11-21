# Samsung FIVE 중복 put 후보 후속 조사

조사일: 2026-11-06  
범위: 저장된 panic 자료와 BYI3 체크아웃의 정적 코드·빌드 설정만 읽었다. 패닉 재현, 실기기 조작, 커널/KernelSU/SSAL 코드 수정, SELinux 정책 변경은 하지 않았다.  
판정: **BYI3 `common` 트리에서 조건부 중복 put 결함은 정적으로 확인됨. BDZJ2 실행 커널에서 같은 코드였는지와 이번 panic의 실제 trigger는 미확인.**

## 1. 조사 결론

로컬 `kernel_platform/common` 트리에서 `security_task_alloc()`의 LSM `task_alloc` hook이 오류를 반환하는 경우, 같은 자식 task의 FIVE tint를 두 번 put하는 제어 흐름이 확인된다.

첫 put은 `security_task_alloc()`의 오류 처리 안에서 호출하는 `security_task_free()` → `five_task_free()`에서 발생한다. 이어 `copy_process()`가 실패 처리에서 `task_integrity_cleanup(p)`를 별도로 호출한다. 이 결함은 hook 오류가 실제로 발생해야 작동한다.

현재 소스 구성에서 일반 LSM hook 중 실제 nonzero를 반환할 수 있는 것은 SELinux의 `selinux_task_alloc()`이다. 이 hook은 현재 SID에 대해 `PROCESS__FORK` 허용 여부를 검사한다. Enforcing 상태에서 정책이 이를 거부하면 `-EACCES`가 반환된다. AppArmor와 TOMOYO의 해당 hook은 이 트리에서 항상 0을 반환한다. 로컬 GKI security config는 SELinux를 켜고 AppArmor/TOMOYO는 켜지 않지만, BDZJ2 기기의 최종 `.config` 및 부팅 `lsm=` 설정은 확보되지 않았다.

`CLONE_VM`에서는 두 번의 put 때문에 새 자식 참조뿐 아니라 tint의 기존 참조 하나까지 소비한다. 기존 참조가 부모 task의 유일한 참조라면 부모가 보유한 포인터가 남은 상태로 객체가 해제된다. 일반 fork에서는 자식 전용 count-1 tint가 첫 put에서 해제되고, 두 번째 put이 해제된 주소를 다시 읽는다. 이 두 경로는 각각 이후 부모의 지연 해제 BUG 가능성과 실패 중인 clone 경로의 즉시 UAF/BUG 가능성을 만든다.

정적 분석은 **BYI3 `common` 코드의 조건부 결함**은 증명하지만, 패닉 로그에는 실패한 `task_alloc`이나 대상 task 식별 정보가 없고 실행 커널은 `BDZJ2`다. 따라서 이번 사건의 원인으로 확정할 수는 없다.

## 2. `security_task_alloc()`의 LSM hook과 오류 조건

검토 파일은 `vendor/S937NKSU2BYI3/kernel_platform/common/`이다. `LSM_HOOK_INIT(task_alloc, ...)` 검색에서 SELinux, AppArmor, TOMOYO 세 hook이 확인됐다. 공통 보안 코드는 `call_int_hook()`에서 hook 목록을 순회하며 첫 nonzero 결과에서 멈춘다 (`security/security.c:784-800`).

| Hook | 동작 | nonzero 반환 조건 | BYI3 `gki_sec_defconfig` 기준 |
|---|---|---|---|
| SELinux `selinux_task_alloc` (`security/selinux/hooks.c:3996-4003`, 등록 7104) | `current_sid()`를 source/target SID로 놓고 `SECCLASS_PROCESS / PROCESS__FORK` 권한 검사 | SELinux 정책이 `fork`를 거부하면 AVC가 보통 `-EACCES`를 반환한다. Enforcing에서 거부가 오류가 된다. AVC 경로의 다른 `-errno`도 API상 가능하지만 이 hook에서 확인된 일반적인 거부 조건은 권한 거부다. | `CONFIG_SECURITY_SELINUX=y`; 세 hook 중 유일하게 로컬 config에서 확실히 활성화된 제공자 |
| AppArmor `apparmor_task_alloc` (`security/apparmor/lsm.c:105-113`, 등록 1333) | `aa_dup_task_ctx()`가 label 참조를 복제 | hook은 `aa_dup_task_ctx()` 후 0을 반환한다. 해당 함수는 label 참조만 복사/증가하고 오류 반환 경로가 없다. | config에서 `CONFIG_SECURITY_APPARMOR=y` 확인 안 됨 |
| TOMOYO `tomoyo_task_alloc` (`security/tomoyo/tomoyo.c:507-520`, 등록 552) | 도메인 포인터를 복사하고 `users`를 증가 | 구현 주석과 함수가 0을 반환한다. | config에서 `CONFIG_SECURITY_TOMOYO=y` 확인 안 됨 |

이 검색 범위에서 Smack, capabilities, Landlock, LoadPin, Yama, SafeSetID, BPF LSM, Samsung DEFEX/PROCA/Kumiho의 `task_alloc` hook 등록은 찾지 못했다. FIVE의 legacy `five_task_free()`는 일반 LSM `task_alloc` hook이 아니다.

### hook 호출 전후의 오류

`security_task_alloc()`은 먼저 `lsm_task_alloc()`로 composite LSM task blob을 `kzalloc()`한다 (`security/security.c:648-660, 2911-2920`). 이 할당이 실패하면 `-ENOMEM`으로 바로 반환하며 `security_task_free()`는 호출하지 않는다. 이후 `call_int_hook(task_alloc, ...)`가 nonzero를 반환한 경우에만 함수가 `security_task_free(task)`를 호출한다.

`call_int_hook()` 안의 `security_integrity_current()`는 KDP credential 무결성 검사다 (`security.c:784-800`, `drivers/uh/kdp.c:451-463`). 정상일 때 0을 반환하고, credential integrity 위반이면 오류 코드를 반환하는 대신 `panic()`한다. 그러므로 이 검사는 `security_task_alloc()`의 중복 정리 오류 반환 경로와 구분해야 한다.

GKI20 FIVE 코드에는 별도의 `task_alloc_wrapper()` trace hook이 있으며, wrapper가 호출되면 tint 할당 실패 시 `*r = -ENOMEM`을 쓴다 (`security/samsung/five/gki/five_main.c:859-894`). 이는 `LSM_HOOK_INIT(task_alloc, ...)`는 아니다. 체크아웃에서 확인한 것은 trace hook 등록이며, 정확한 BDZJ2의 tracepoint emission 경로는 확인되지 않았다. 로컬 `common/security/samsung/five/Makefile`은 `CONFIG_FIVE_GKI_20`일 때만 GKI20 객체를 선택한다. 이 패키지의 `common/BUILD.bazel`은 `gki_sec_defconfig` fragment를 적용하고, 그 파일은 `CONFIG_FIVE_GKI_10=y`를 설정한다. 따라서 BYI3의 설정 의도는 GKI10 legacy `fork.c` 경로다. BDZJ2에 실제 적용된 최종 config는 별도로 확인되지 않았다.

## 3. 중복 정리 제어 흐름 증명

BYI3의 `kernel/fork.c:2010-2031, 2579-2585, 2883-2885`와 `security/security.c:2911-2937`를 따라간 흐름이다.

```text
copy_process()
  dup_task_integrity(clone_flags, p)
    CLONE_VM:  task_integrity_get(parent_tint); child에 같은 포인터 저장
    일반 fork: task_integrity_alloc(); child에 새 count-1 포인터 저장

  security_task_alloc(p, clone_flags)
    lsm_task_alloc() 오류(-ENOMEM)
      즉시 반환; security_task_free()는 호출하지 않음
      copy_process의 task_integrity_cleanup(p)만 실행

    lsm_task_alloc() 성공 후 task_alloc hook 오류(예: SELinux -EACCES)
      security_task_free(p)
        call_void_hook(task_free, p)
        five_task_free(p) → task_integrity_put(TASK_INTEGRITY(p))
      오류 반환
      copy_process의 task_integrity_cleanup(p)
        같은 포인터에 task_integrity_put()을 다시 실행

  security_task_alloc() 성공 후 후속 오류
    bad_fork_cleanup_security → security_task_free(p) 한 번
    task_integrity_cleanup(p)는 이 경로에 없음
```

`security_task_free()`가 LSM task-free hooks와 함께 FIVE 해제를 수행한다는 점이 핵심이다. 동시에 `copy_process()`는 `security_task_alloc()`의 모든 오류 결과에 대해 Five 전용 `task_integrity_cleanup()`을 수행한다. 두 함수 사이에는 오류 발생 지점이나 첫 put 여부를 나타내는 상태가 전달되지 않는다.

따라서 오류 분기별 결과는 다음과 같다.

| 오류 지점 | `security_task_free()` 내부 Five put | caller `task_integrity_cleanup()` | 결과 |
|---|---:|---:|---|
| `dup_task_integrity()`에서 일반 fork tint 할당 실패 | 없음 | 없음 | `-ENOMEM`으로 audit 정리로 이동. put 대상이 없으므로 이 후보의 이중 해제 아님. |
| `lsm_task_alloc()` composite blob 할당 실패 | 없음 | 1회 | 정상적인 단일 tint 정리. 중복 put 아님. |
| `task_alloc` LSM hook이 nonzero 반환 | 1회 | 1회 | **같은 FIVE 포인터에 중복 put. 정적 결함.** |
| `security_task_alloc()` 성공 후 `copy_semundo` 등 후속 단계 오류 | `bad_fork_cleanup_security`에서 1회 | 없음 | 단일 정리. |

여기서 `security_task_free()`는 BYI3 `common/security/security.c:2930-2937`의 구현이다. 같은 패키지의 `msm-kernel/security/security.c:2916-2924`에는 직접 `five_task_free()` 호출이 없다. 실제 빌드가 어느 소스 조합을 사용했는지 확인하지 않고 두 파일을 동일하다고 취급해서는 안 된다.

## 4. `CLONE_VM`과 일반 fork의 refcount 변화

`task_integrity`의 count는 task 소유권만 세지는 않는다. FIVE 비동기 작업이 별도 참조를 보유할 수 있으므로 아래의 `N`은 clone 전 공유 tint의 총 참조 수다.

### `CLONE_VM`

`dup_task_integrity()`가 기존 tint를 get하므로 `N → N+1`이다. hook 오류 처리의 `security_task_free()`가 put해 `N`으로, `copy_process()`의 추가 cleanup이 다시 put해 `N-1`이 된다. 즉 실패한 자식이 취득한 참조를 돌려주는 수준에서 끝나지 않고 **clone 전 존재하던 참조 하나를 추가로 소비**한다.

- `N=1`이고 그 참조가 부모 task의 참조라면 `N+1 → N → N-1`은 `1 → 2 → 1 → 0`이다. `task_integrity_free()`가 공유 tint를 해제하지만 부모 `task_struct`의 `TASK_INTEGRITY` 포인터는 지워지지 않는다. 이후 부모의 `five_task_free()`가 이미 해제된 객체를 put하면 zero-count `BUG_ON`에 도달할 수 있다.
- `N>1`이면 어떤 논리적 소유자의 참조가 빠졌는지 count만으로 구분할 수 없다. 부모 외에 비동기 FIVE work가 참조 중일 수 있다. 남은 count에 따라 즉시 free가 되지 않아도 향후 수명 계산이 한 참조만큼 어긋난다.

### 일반 fork (`!CLONE_VM`)

자식은 부모와 독립적인 count-1 tint를 할당한다. hook 오류의 내부 정리 첫 put에서 `1 → 0`으로 해제된다. caller 정리 두 번째 put은 같은 자식 `task_struct`의 포인터를 통해 **해제된 tint 주소를 다시 읽는다**. 부모 tint count는 건드리지 않는다. slab 메모리가 아직 재사용되지 않아 zero 값이 남아 있으면 caller의 `BUG_ON(!atomic_read(...))`에서 바로 멈출 수 있고, 재사용/변조되었다면 다른 UAF 또는 손상으로 이어질 수 있다.

`task_integrity_cleanup()`은 포인터를 NULL로 만들지 않는다. generic `task_integrity_put()`은 NULL guard 없이 `atomic_read()`와 decrement를 실행한다 (`include/linux/task_integrity.h:142-153`). 따라서 위 두 번째 put을 막아주지 않는다.

## 5. SSAL 실행 경로 진입 가능성

- `src/ssald.rs:395-401`은 비동기 `add` job용 thread를 만들고, `src/ssald.rs:564-574`는 incoming 요청마다 worker thread를 만든다. Rust thread는 동일 주소 공간을 공유하는 OS thread이므로 Linux에서 `CLONE_VM` 조건에 해당하는 경로에 들어간다. 정확한 libc/Rust runtime의 syscall 구현은 SSAL 저장소에 포함되지 않아 syscall flag 자체는 여기서 확인하지 않았다.
- `src/guest_launcher.rs:246-348`의 `Service::start()`는 `Command::spawn()`으로 Guest service를 실행하며, Zygote도 이 경로를 사용한다. 이 또한 `copy_process()`와 `security_task_alloc()`을 거치지만, 프로세스 spawn 구현의 실제 clone flags는 SSAL 코드만으로 확정하지 않는다. 일반 fork라면 위의 자식 전용 tint 중복 put 변형이, 내부 구현이 `CLONE_VM` 계열이면 공유 tint 변형이 해당한다.
- `guest_launcher.rs:58-89`의 `pre_exec`는 자식이 생성된 뒤 실행되어 cgroup 이동, `/proc/thread-self/attr/exec` 기록, groups/GID/UID 변경을 수행한다. `security_task_alloc()`은 `copy_process()` 중 자식이 `pre_exec`에 진입하기 전에 실행된다. 따라서 이 오류에서 SELinux `PROCESS__FORK` 검사는 부모의 현재 SID를 사용하며, 자식의 예정 Guest exec context 또는 pre-exec UID/GID는 그 fork 권한 검사에 영향을 주지 않는다.
- Android Zygote가 Guest 내부에서 만드는 자식들도 커널 task 생성 경로를 통과한다. 다만 ART의 clone flags와 이번 패닉 대상이 어느 자식이었는지는 SSAL 소스나 기존 panic dump에서 확인되지 않는다.

`ssald`가 `u:r:ksu:s0`에 있다는 기존 보고를 전제로 하면, 그 SID의 `PROCESS__FORK` 거부는 thread/process 생성 hook을 실패시킬 수 있다. 다만 SELinux check는 부모 SID에서 실행되며, 정책이 허용돼 성공한 다른 생성 경로와 구분할 사건별 AVC 기록이 없다. 기존 panic 자료에는 이 hook 오류나 `PROCESS__FORK` 거부가 확인되지 않았고 audit 유실 경고가 있어 부재를 증명할 수도 없다.

또한 `lsm_task_alloc()`에서 메모리 부족으로 발생하는 `-ENOMEM`은 이 정적 이중 put 경로의 trigger가 아니다. 이 오류는 내부 `security_task_free()` 없이 caller의 Five cleanup 한 번만 탄다.

## 6. 실행 BDZJ2와 BYI3 소스의 대응

| 자료 | 식별 정보 | 확인 결과 |
|---|---|---|
| 실행 panic/kernel | `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k`; hash `4ada8571dcf2ef127627ffc0429891950f882248` | S937N/PSQ의 BDZJ2 build임. panic trace는 `five_task_free → security_task_free`를 보인다. |
| 로컬 Samsung source 패키지 | `vendor/S937NKSU2BYI3` | 이름과 README 대상은 PSQ/S937 계열 BYI3. 디렉터리는 Git에서 ignore되어 있고 소스 파일은 저장소 index에 없어 해당 파일들의 commit/revision을 확인할 수 없다. |
| BYI3의 GKI base | `kernel_platform/common` | `common/BUILD.bazel`은 `gki_sec_defconfig` fragment를 적용한다. `msm_kernel_la.bzl:480-483`의 non-consolidate MSM target은 `//common:kernel_aarch64`를 base로 선택한다. 그 common 코드에는 Five의 `security_task_free()` 호출과 `fork.c`의 duplicate cleanup 경로가 함께 있다. |
| BYI3의 MSM tree copy | `kernel_platform/msm-kernel` | 해당 `security/security.c`는 `five_task_free()`를 직접 부르지 않고 `kernel/fork.c`에도 common 트리의 `dup_task_integrity()`/`task_integrity_cleanup()`가 없다. BYI3 패키지 안에서도 두 트리의 코드가 다르다. |

Bazel 설정상 BYI3 제품 GKI base는 `common` 트리를 사용하는 것으로 보이며, 이 때문에 이전 조사에서 분석한 common 구현은 이 패키지의 실제 후보 입력이다. 그러나 현재 workspace에는 BDZJ2 source archive, 최종 `.config`, matching `vmlinux`/`System.map`, build manifest가 없다. panic의 함수명·주소만으로 `fork.c`의 정확한 오류 cleanup이 BDZJ2에도 동일했다고 증명할 수 없다. 따라서 위 정적 결함을 BDZJ2 바이너리에 그대로 귀속시키지 않는다.

## 7. 최소 수정 방향 (코드 변경 없음)

BYI3 common 제어 흐름에서는 단일 소유자가 FIVE rollback을 수행하도록 해야 한다. 간단한 계약은 `security_task_alloc()`이 **모든 반환 오류에서 Five 참조를 정확히 한 번 정리**하고, `copy_process()`의 `security_task_alloc()` 실패 분기에서는 별도 `task_integrity_cleanup()`을 하지 않는 것이다.

이 계약을 적용한다면 두 오류 유형을 따로 처리해야 한다.

1. `lsm_task_alloc()` 실패는 LSM task blob이 준비되지 않은 상태라 일반 `security_task_free()`를 호출하면 안전하지 않을 수 있다. 이 조기 실패에서는 Five tint만 한 번 put한다.
2. LSM hook 실패는 현재처럼 `security_task_free()`를 호출해 LSM rollback과 Five put을 한 번 수행한다.

이후 caller의 중복 cleanup을 제거하면 두 경우 모두 tint를 한 번만 정리한다. 또는 security rollback을 LSM blob 해제와 Five 참조 해제로 분리해 caller가 Five 정리를 한 번만 소유하도록 할 수 있다. 어느 방향이든 검증해야 할 조건은 다음과 같다: 조기 blob 할당 실패 누수 없음, hook 실패 시 같은 tint에 put 한 번, 정상 이후 fork 실패 시 task-free 한 번, CLONE_VM/비공유 fork 양쪽에서 부모와 자식 소유권 보존. 이번 요청 범위에서는 코드를 변경하거나 테스트하지 않았다.

## 최종 판정

**정적 결함: BYI3 `common`의 `task_alloc` hook 오류 분기에서 조건부 double put 확인.** SELinux `PROCESS__FORK` 거부가 로컬 코드에서 가능한 trigger다. `CLONE_VM`이면 부모/기존 공유 tint의 참조를 하나 빼앗고, 일반 fork이면 이미 해제된 자식 tint를 다시 put한다.

**이번 BDZJ2 panic 원인: 미확인.** 실행 커널의 정확한 소스·config와 대상 task/LSM hook 오류 자료가 없어, BYI3의 정적 결함이 관측된 RCU callback panic을 만들었다고 확정할 수 없다.
