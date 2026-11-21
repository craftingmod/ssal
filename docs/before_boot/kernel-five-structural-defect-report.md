# Samsung FIVE `task_integrity` 구조적 결함 보고서

작성일: 2026-11-06  
범위: Phase 8B-5 패닉 자료, 체크아웃된 `S937NKSU2BYI3` 소스, 보관된 BDZJ2 boot image의 선택 구간 정적 비교. 실기기 재실행 및 커널·KernelSU·SELinux 정책 수정 없음.

## 요약 판정

`security_task_alloc()`의 LSM `task_alloc` hook이 실패하면, 내부 오류 정리와 `copy_process()`의 오류 정리가 같은 task-integrity 참조를 각각 put할 수 있다. 이 조건부 double put은 BYI3 소스와 BDZJ2 실행 이미지 모두에서 제어·데이터 흐름으로 확인된다. **구조적 결함은 확인됨.**

Phase 8B-5에서 재현된 `five_task_free+0x40` 패닉은 이 결함과 양립하지만, 덤프가 실패한 hook, clone flags, tint 소유 task를 식별하지 않아 **이번 패닉의 원인으로 확정할 수 없다.** 패닉에서 직접 확인되는 것은 `task_integrity_put()`이 `usage_count == 0`인 객체를 검사해 BUG를 냈다는 사실이다. BUG_ON 이전이므로 이 경로에서 추가 decrement는 실행되지 않았다. 이를 로그만으로 “refcount underflow”라고 부르면 안 된다.

## Phase 8B-5 패닉과 이전 조사 대조

정책 규칙을 적용한 8B-5 단발 재실행에서 Guest Zygote admission 이후 패닉이 났다. 저장된 dump는 다음 서명을 기록한다.

```text
kernel BUG at include/linux/task_integrity.h:150
pc : five_task_free+0x40/0x70
lr : security_task_free+0x5c/0x7c
five_task_free -> __put_task_struct -> delayed_put_task_struct
             -> rcu_do_batch -> rcu_nocb_cb_kthread
```

현재 task `rcuop/4` PID 53은 RCU callback worker다. 해제 대상 task의 PID/TGID/comm은 이 stack에서 알 수 없다. 첫 8B-5 재개에서 패닉이 없었던 사실과, 정책 적용 후 재실행에서 패닉이 발생한 사실도 구분한다. 두 실행 간 결과 차이는 실행 조건과 시간적 상관관계일 뿐, SELinux 정책이나 Zygote가 참조 오류를 일으켰다는 인과 증거가 아니다.

이 결과는 기존 FIVE 수명 감사와 일치한다. 감사에서 조건부 fork rollback double put은 정적 코드 결함으로 확인됐으나, 사건 원인은 가능성에 머물렀다. 새 8B-5 dump도 같은 zero-count RCU task-free 서명을 재확인했을 뿐, 결함이 있는 fork rollback 경로가 선행 실행됐다는 증거를 추가하지 않았다.

근거: [Phase 8B-5 기록](phase8b5-resume-20261106.md), [FIVE 수명 감사](five-lifetime-race-audit.md), [패닉 발췌](../out/phase8b5-resume-20261106/panic-excerpt.txt).

## 참조 수명 추적

### 정상 생성·복제·해제

- 새 `task_integrity`는 `usage_count=1`로 초기화된다 (`security/samsung/five/task_integrity.c`).
- `copy_process()`의 `CLONE_VM` 경로는 현재 task의 tint에 `get()`하고 같은 포인터를 자식에 저장한다. 일반 fork는 새 tint를 할당해 자식에 저장한다 (`kernel/fork.c:2010-2025`).
- 최종 task 해제는 `security_task_free()`에서 `five_task_free()`를 호출하고, 이는 해당 task가 소유한 tint를 put한다 (`security/security.c:2930-2937`, `security/samsung/five/five_main.c:452-455`).
- FIVE 비동기 이벤트는 tint 참조를 별도로 보유한다. 이벤트도 task_struct 참조를 잡아 worker와 task 종료가 겹칠 때 최종 task-free를 늦춘다. 검토한 정상 worker/exit 순서만으로 이중 put이 발생하는 경로는 확인되지 않았다.

`task_integrity_get/put()`은 `atomic_read()`의 zero 검사와 atomic 증감이 분리돼 있고, 포인터 자체에는 RCU accessor나 수명 lock이 없다 (`include/linux/task_integrity.h:142-153`). 따라서 유효한 소유 참조를 전제로 한 atomic 증감 문제와, 참조 없이 raw 포인터를 읽는 별도 UAF 경쟁을 구별해야 한다.

### 확인된 fork rollback double put

BYI3 `common` 소스의 흐름은 다음과 같다.

```text
copy_process(child)
  dup_task_integrity(flags, child)
    CLONE_VM: parent tint get; child에 같은 포인터 저장
    일반 fork: 새 tint alloc(ref=1); child에 저장
  security_task_alloc(child, flags)
    LSM task_alloc hook 오류 시 security_task_free(child)
      five_task_free(child): child tint put #1
  security_task_alloc 오류 반환
  copy_process 오류 분기: task_integrity_cleanup(child)
    같은 child tint put #2
```

`security_task_free()`는 FIVE 포인터를 NULL로 만들지 않는다. 이어지는 `task_integrity_cleanup()`도 같은 필드를 다시 읽으므로 중복 정리가 가능하다 (`kernel/fork.c:2028-2031, 2579-2585`; `security/security.c:2911-2920, 2930-2937`).

참조 효과는 clone 형태에 따라 다르다.

| 경로 | 첫 번째 put | 두 번째 put의 영향 |
|---|---|---|
| `CLONE_VM` | 부모/자식이 공유한 tint 참조 수 감소 | 부모가 계속 포인터를 보유한 상태에서 객체가 0이 되어 해제될 수 있음. 부모의 이후 RCU task-free가 stale/zero-count tint를 put할 수 있음. |
| 일반 fork | 새 자식 tint의 유일한 참조 해제 가능 | 같은 오류 정리 중 이미 해제된 포인터를 다시 참조해 UAF/double put 가능. 후속 증상은 slab 재사용 상태에 따라 달라질 수 있음. |

이 경로는 `lsm_task_alloc()`의 blob 할당 자체가 실패한 경우와 다르다. blob 할당 실패는 `security_task_alloc()`이 내부 `security_task_free()` 없이 반환하므로 현재 소스상 caller의 단일 tint cleanup만 수행된다. double put 후보의 조건은 blob 준비 뒤 task_alloc hook이 오류를 반환해 내부 free 경로까지 진입하는 경우다.

## 대안 후보 구분

| 후보 | 정적 판정 | 이번 패닉 설명력 |
|---|---|---|
| hook 실패 시 fork rollback double put | **구조적 결함 확인** | 가장 강한 후보. 단, 실패 이벤트와 대상 task/clone flags가 dump에 없어 사건 인과는 미확정. |
| 초기 tint 참조 누락 | 정상 생성·fork 경로에서 일반적 누락은 확인되지 않음. exec tint 할당 실패 시 NULL 포인터를 대입하고 이전 tint를 put하는 별도 실패 처리 문제가 소스에 있음 (`five_main.c:643-665`). | 현 zero-count RCU BUG와 연결하는 증거 없음. NULL 경로라면 다른 오류 형태가 예상됨. |
| `task_integrity_get/put()`의 atomic 경쟁 자체 | 유효한 참조가 보장된 상황에서 증감 자체의 손상 증거 없음. check와 inc/dec가 분리돼 있다는 점은 생존 포인터 확보가 보장되지 않을 때 위험 요소. | 직접 원인으로 지지되지 않음. |
| exec tint 교체와 `/proc` FIVE raw-pointer 조회 경쟁 | 소스상 조회가 별도 tint 참조 없이 포인터를 읽는 UAF 가능성 있음. `value_lock`은 포인터 수명을 보호하지 않음 (`fs/proc/base.c:3291-3352`). | 가능성은 있으나 이번 RCU free BUG와 직접 연결하는 증거가 약함. |
| 정상 FIVE worker와 task exit 경쟁 | async tint 및 task_struct 참조가 수명을 분리해 보호함. | 단독 원인 후보로 지지되지 않음. |

## BDZJ2 실행 바이너리와 BYI3 소스의 대조

보관된 `out/boot.img`에서 추출한 ARM64 커널의 release 문자열 및 Samsung 후행 메타데이터는 패닉 기록의 `S937NKSSBDZJ2` 계열 식별과 일치한다. 바이너리 분석은 다음 핵심 동작을 확인했다.

- panic PC 위치의 zero-count 검사 뒤 `brk #0x800` 명령이 패닉 dump의 함수 상대 오프셋 및 명령어와 일치한다.
- `security_task_free()`가 `five_task_free()`를 부르는 경로가 LR/직접 call과 맞는다.
- 복구된 `dup_task_integrity`는 `CLONE_VM` 분기에서 참조를 증가시켜 tint를 공유하고, 일반 fork 분기에서 tint를 할당한다.
- `security_task_alloc()` hook 오류 정리와 `copy_process()` 오류 cleanup이 같은 자식 task tint 필드를 put하는 순서가 확인된다.

따라서 fork rollback double put은 BYI3 텍스트만 보고 BDZJ2에 외삽한 가설이 아니라, 저장된 BDZJ2 실행 이미지에서 선택 경로의 구조가 확인된 결함이다. 다만 다음 항목은 미확정이다.

- 패닉 로그 build hash `4ada8571dcf2ef127627ffc0429891950f882248`를 추출 이미지와 일치시키지 못했다.
- 정확한 BDZJ2 `.config`, `vmlinux`, `System.map`은 확보되지 않았다. 바이너리는 stripped이며 일부 함수 경계/이름은 제어 흐름, 상대 오프셋 및 데이터 흐름으로 추정했다.
- 개별 `selinux_task_alloc()` 구현은 BDZJ2 바이너리에서 독립 복구하지 못했다. SELinux의 `PROCESS__FORK` 거부 가능성은 BYI3 소스에서 확인되지만, 보존 패닉 로그에서는 해당 AVC나 hook 오류를 찾지 못했다.
- 실행 기기 자료는 SM-S937N/PSQ다. 이 결과를 SM-S928N 등 다른 모델의 커널로 일반화할 수 없다.

세부 역어셈블 근거: [BDZJ2 바이너리 분석](five-bdzj2-binary-analysis.md).

## KernelSU 상호작용

패닉 module list에는 `kernelsu(O)`가 있지만, 체크아웃된 KernelSU 소스에서 `TASK_INTEGRITY`, `task_integrity`, `android_oem_data1`, `five_task_free`, `security_task_alloc/free` 직접 참조는 확인되지 않았다. 확인한 `setresuid` hook은 원 syscall을 먼저 실행한 뒤 UID handler를 호출한다. KernelSU는 credentials/SID를 바꾸는 경로를 가지므로 LSM fork hook의 결과에 간접 영향을 줄 가능성은 있지만, FIVE 포인터/refcount를 직접 변경했다는 증거는 없다.

현재 로드됐던 KernelSU 모듈의 정확한 버전/hash도 확인되지 않았다. 따라서 module list와 기존 setresuid 로그는 시간적 맥락이지 원인 증거가 아니다. `PROCESS__FORK` AVC 또는 `security_task_alloc()` 오류가 저장 로그에 없다는 사실은 해당 경로를 입증하지도, 완전히 배제하지도 않는다.

## 우선순위와 최소 수정 방향

1. **우선 수정 대상:** fork 오류 경로에서 FIVE 참조 정리의 단일 소유권을 보장한다. 내부 `security_task_free()`와 caller cleanup이 같은 tint를 각각 put하지 않게 해야 한다.
2. **최소 구조 방향:** task tint 포인터를 가져와 먼저 NULL로 비운 뒤 한 번 put하는 공통 소비(cleanup) 경로를 두고, 동일 task에 대한 반복 cleanup은 no-op가 되게 한다. 실패한 fork child는 아직 외부에 게시되지 않았으므로 이 경로를 단일화하기 적절하다. `task_integrity_put()` 자체를 zero count에서 조용히 반환시키는 방식은 잘못된 소유권을 숨기므로 대체 수정으로 권하지 않는다.
3. **별도 추적:** proc/exec raw-pointer 경쟁은 이번 결함 수정과 섞지 말고, reader가 tint ref를 안전하게 획득하거나 포인터 교체와 수명을 동기화하는 방식으로 별도 검토한다.
4. **원인 귀속 보류:** 정책 변경이나 실기기 재실행 없이 현 보고서의 정적 증거만으로 패닉의 근본 원인을 확정하지 않는다.

## 최종 결론

**확인된 구조적 결함:** LSM task_alloc hook 오류 시 `security_task_alloc()` 내부 정리와 `copy_process()` 오류 정리가 같은 FIVE tint 참조를 중복 put할 수 있으며, 이 흐름은 BYI3 소스와 BDZJ2 이미지에서 모두 관찰된다.

**미확정:** 8B-5에서 재현된 zero-count `five_task_free()` BUG가 실제로 그 fork 오류 경로에서 비롯됐는지 여부. 대상 task, clone flags, hook 오류, tint ref 이력은 덤프에 없다.

**분석 경계:** 새 실기기 실행, 정책/커널/KernelSU 변경, 정확한 BDZJ2 build hash 및 config 검증은 하지 않았다. 따라서 본 문서는 구조적 결함 보고서이며 패닉 원인 확정서가 아니다.
