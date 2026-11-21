# Samsung FIVE 객체 수명·경쟁 조건 감사

조사일: 2026-11-06  
범위: BYI3 체크아웃 소스와 저장된 BDZJ2 커널 이미지 역어셈블 기록의 정적 비교. 실기기 패닉 재현, 커널/KernelSU/SELinux/SSAL 변경은 하지 않았다.  
대상 기기 자료는 SM-S937N (PSQ)이다. 요청의 모델 식별이 이와 다르면 결과를 그대로 일반화하지 않는다.

## 판정 요약

| 후보 | 판정 | 요점 |
|---|---|---|
| `security_task_alloc()` hook 실패 후 동일 child tint를 두 번 put | **CONFIRMED (코드 결함)** / 이번 패닉 원인으로는 **POSSIBLE** | BYI3에서 확인되고 BDZJ2 disassembly에서도 같은 순서와 포인터 데이터 흐름이 확인됨. 하지만 패닉 로그는 앞선 fork 실패를 기록하지 않음. |
| exec 교체와 FIVE 비동기 worker 간 tint UAF | **UNSUPPORTED** | exec는 task 소유 참조를 교체·put하지만, work context가 별도 tint 참조를 보유함. 이벤트는 task_struct 참조도 보유하므로 exit의 최종 LSM free도 미뤄짐. |
| exec 교체와 다른 task의 proc FIVE 조회 간 stale pointer/UAF | **POSSIBLE** | proc 쪽은 tint 참조를 얻지 않고, `value_lock`도 포인터 수명을 보호하지 않는다. 교체와 마지막 put 사이의 구체 interleaving은 성립 가능. 이 경로가 패닉을 만들었다는 로그 증거는 없음. |
| `task_integrity_get/put`의 atomic 연산 자체가 동시 put을 놓쳐 count 손상 | **UNSUPPORTED** (적법하게 소유한 참조를 전제) | inc/dec는 atomic이지만 사전 read는 별개다. 문제는 원자적 덧셈 자체보다 get 전에 유효 참조/포인터 보호가 보장되는지다. 확인한 worker/get 호출은 owner ref 또는 작업 ref를 보유한다. |
| FIVE worker와 task exit의 이중 해제 | **UNSUPPORTED** | worker tint 참조와 이벤트 task_struct 참조가 서로 다른 수명을 지탱하고, worker의 tint put은 task free 이후에도 남은 참조가 보호한다. |
| 패닉의 `five_task_free` zero-count BUG가 위 어느 특정 후보에서 비롯됨 | **POSSIBLE**, 직접 원인은 **미확정** | 덤프는 BUG 순간과 RCU 해제 경로만 식별한다. 선행 오류 이벤트나 대상 task는 식별하지 못한다. |

CONFIRMED는 코드/바이너리에 결함 또는 명령 경로가 존재한다는 뜻이지, 2026-11-06 패닉의 원인이 입증됐다는 뜻은 아니다.

## 범위와 빌드 대응

BYI3 분석의 기준은 `vendor/S937NKSU2BYI3/kernel_platform/common/`이다. 동일 이름의 `msm-kernel` 복사본은 FIVE fork helper가 빠져 있어 여기서는 실행 구현의 기준으로 사용하지 않았다. 기존 바이너리 분석은 `out/five-bdzj2-analysis/kernel.raw`의 image-relative disassembly를 보존한 [five-bdzj2-binary-analysis.md](five-bdzj2-binary-analysis.md)이며, BDZJ2의 `dup_task_integrity`, `security_task_alloc`, cleanup 흐름과 panic instruction을 대조했다. panic build hash를 이미지와 완전 일치시키지 못했으므로 BYI3와 BDZJ2 소스 전체가 동일하다는 가정은 하지 않는다.

BYI3의 `include/linux/task_integrity.h:116-133`에서 `TASK_INTEGRITY(task)`는 `CONFIG_FIVE_GKI_10`이면 `android_oem_data1[2]`, 아니면 `task->integrity` raw 포인터다. 대응하는 `task_integrity_assign()`도 포인터를 평범하게 저장한다. 이 포인터 자체에는 RCU accessor, atomic pointer 교체, 별도 lock이 없다. 바이너리에서 관련 필드는 task 기준 `+0xdd0`, tint의 `usage_count`는 `+8`로 확인됐다. 패닉 PC의 `five_task_free+0x40`은 zero-count 검사에, 이후 decrement는 `atomic_dec_and_test()`에 대응한다.

## 참조 규칙과 원자성

- 새 tint는 `task_integrity_alloc()`에서 `usage_count=1`로 시작한다 (`security/samsung/five/task_integrity.c:51-62`). task 포인터를 보유한 주체가 이 참조를 소유한다.
- `task_integrity_get()`은 `BUG_ON(!atomic_read(count))` 뒤 `atomic_inc()`를 한다. `put()`은 같은 별도 검사 뒤 `atomic_dec_and_test()` 및 zero 시 free를 한다 (`include/linux/task_integrity.h:142-153`). inc/dec는 각각 원자적이지만 check+inc / check+dec는 하나의 원자 연산이 아니다. helper는 NULL을 방어하지 않는다.
- `value_lock`은 tint의 integrity 값/label 데이터, `list_lock`은 event list를 보호한다. 어느 lock도 task의 raw tint 포인터 대입/수명 전체를 보호하지 않는다.
- 참조 불변식은 “task 포인터 owner마다 tint ref 하나, async context마다 추가 ref 하나”다. 이 불변식이 유지되면 count 0인 객체에 적법한 새 get을 시도할 수 없다. 보호 없이 raw 포인터를 읽고 `get()`하는 경우에는 atomic count만으로 생존을 복구할 수 없다.
- 일반 thread/process 최종 해제는 task_struct의 usage가 0일 때 `__put_task_struct()`에서 `security_task_free()`를 부르고, 이 함수가 `five_task_free()` → `task_integrity_put(TASK_INTEGRITY(task))`를 실행한다 (`kernel/fork.c:1004-1019`, `security/security.c:2930-2937`, `five/five_main.c:452-455`). 단 `task_struct` 자체의 RCU 지연은 tint ref를 자동으로 하나 더 만들지 않는다.

## 주요 포인터 경로와 순서

### fork / clone

`kernel/fork.c:2010-2025`:

- `CLONE_VM`: 현재 task tint의 get → child task에 동일 포인터 assign. 이는 별도 task owner 참조를 추가한다.
- 일반 fork: 새 tint alloc(초기 ref 1) → child task에 assign.
- 이후 `copy_process()`는 `security_task_alloc()`을 호출한다 (`:2579-2585`). 이 함수는 LSM blob 할당 뒤 `task_alloc` hook을 부르고, hook 오류면 내부에서 `security_task_free(child)`까지 호출한다 (`security/security.c:2911-2920`).
- `security_task_alloc()` 오류 반환 후 `copy_process()`는 다시 `task_integrity_cleanup(child)`를 호출한다. 이 정리는 child의 tint 필드를 NULL로 만들지 않는다.

정적 중복 put interleaving:

```text
초기 tint ref=1 (부모 task)
child: CLONE_VM get → ref=2; child->tint = parent->tint
security_task_alloc: task_alloc hook 오류
  내부 security_task_free(child) → five_task_free(child) put → ref=1
copy_process 오류 정리 → task_integrity_cleanup(child) put → ref=0, tint free
부모는 계속 같은 raw 포인터 보유
부모의 최종 RCU task free → five_task_free(parent) → put(이미 0인 객체)
  => BUG_ON 또는 선행 free/reuse에 따른 UAF
```

일반 fork에서도 같은 hook 오류면 child 전용 ref=1이 내부 put에서 해제되고 caller cleanup이 같은 child 포인터를 재사용한다. 이 경우는 즉시 오류 정리 안에서 UAF/double put 가능성이 있다. 반면 `lsm_task_alloc()` 자체가 실패한 경우 `security_task_alloc()`은 내부 free 없이 반환하므로 이 특정 중복 경로는 발생하지 않는다.

BDZJ2 바이너리 확인: 기존 disassembly 기록의 `dup_task_integrity` (`0xac878`)는 CLONE_VM bit 8에서 공유 tint의 count를 올리고, 아닌 분기에서 할당한다. `copy_process` (`0xabbb8-0xabbdc`)는 해당 helper 다음 `security_task_alloc`을 호출하고 오류 시 동일 child 포인터로 cleanup을 호출한다. `security_task_alloc` hook 오류 분기도 `security_task_free`로 간다. 이는 source-only 가정이 아닌 실제 저장 이미지에서 확인된 구조적 double-put 결함이다. 구체한 주소와 instruction은 위 binary analysis 문서를 참고한다.

### execve

`five/__five_bprm_check()` (`five/five_main.c:643-665`)는 최상위 binfmt depth 0에서 새 tint를 할당해 현재 task 포인터에 대입하고 이전 tint를 put한다. 재귀 depth가 양수이면 새 포인터로 바꾸지 않고 현재 tint에 파일 이벤트를 추가한다.

같은 `CLONE_VM` 그룹의 sibling task는 각자 포인터 owner ref를 갖는다. 한 task의 exec가 자기 포인터만 교체하더라도 sibling의 owner ref가 옛 tint를 보유하므로 정상적인 sibling 참조 아래에서는 옛 객체가 바로 해제되지 않는다. 다만 외부 proc 조회자는 이 owner 수명에 포함되지 않아 별도 후보가 된다. `task_integrity_alloc()` 실패 시 NULL을 assign한 뒤 `old_tint`를 put하고 이후 현재 task에 NULL 포인터가 남는 흐름도 소스상 보인다. 이는 allocation failure 처리 결함 후보지만, BDZJ2 패닉의 zero-count `five_task_free`를 설명하는 특정 증거는 없다.

### FIVE async worker

`push_file_event_bunch()`는 현재 tint의 `list_lock`을 획득한 뒤 첫 event batch일 때 tint get, processing 상태 설정, context에 tint 저장 및 event 연결을 수행한다 (`five_main.c:317-361`). work handler는 context tint를 사용해 event list를 처리하고 끝에서 tint put한다 (`:180-222`). reset 경로도 호출 직후 tint get, 모든 종료 경로에서 put한다 (`:364-405`).

Event 생성은 event마다 `get_task_struct(task)`를 하고, destroy에서 `put_task_struct(task)`를 한다 (`:960-1009`). 따라서 exit와 worker가 겹쳐도 event가 들고 있는 task_struct 참조가 최종 `__put_task_struct()`/`security_task_free()`를 뒤로 미룬다. 마지막 event destroy가 task 최종 put을 일으키더라도 worker context의 tint ref는 아직 남아 있고 worker가 그 뒤 put한다. 정상 경로의 수명 순서는 다음과 같다:

```text
queue: tint get + event task_struct get
exit: task owner ref put (event task ref 때문에 최종 free 보류)
worker: event destroy → event task ref put; context tint ref는 아직 유지
worker: context tint put → 마지막이면 tint free
```

따라서 task exit / RCU callback과 정상 worker 완료만으로 이중 put이 된다는 인터리빙은 확인되지 않았다. fork 오류 정리 같은 별도 ref 불변식 파괴가 끼면 이 결론을 보장할 수 없다.

### task exit와 RCU task free

`delayed_put_task_struct()`는 `put_task_struct()`로 task usage를 최종 감소시키며, task 구조체 해제는 RCU 이후 `__put_task_struct()`에서 이뤄질 수 있다 (`kernel/exit.c:224-238`; `include/linux/sched/task.h:123-162`). RCU는 task_struct 접근자의 grace period를 보장하지만 FIVE tint 자체의 ref는 아니다. panic에서 보인 RCU worker는 그 callback을 수행하는 current task이지, tint가 속했던 종료 대상 task의 식별자가 아니다.

## 외부 raw-pointer 조회 경쟁 후보

`fs/proc/base.c:3291-3352`의 `/proc` FIVE value/label/reset 조회는 `TASK_INTEGRITY(task)`를 직접 읽는다. label 경로는 tint의 `value_lock`만 잠근 뒤 label 포인터를 꺼내 lock 밖에서 사용한다. 조회 코드에는 tint `get()`이 없고, 이 lock은 exec가 task 포인터를 바꾸고 옛 tint를 put하는 것을 막지 않는다. reset field 경로는 tint 수명 lock도 없이 `reset_file`을 읽는다.

가능한 exec/proc interleaving:

```text
Reader: p = TASK_INTEGRITY(target)  // old tint, 별도 ref 없음
Exec:   TASK_INTEGRITY(target) = new tint
Exec:   task_integrity_put(old) → ref 0, slab free
Reader: p->value_lock 또는 p->label/reset_file 접근
        => freed/reused memory 접근 가능
```

이 raw reader 위험은 소스상 구체적이므로 **POSSIBLE**로 판정한다. 동시 조회가 실제로 BDZJ2에 남아 있었는지, faulting stale 주소가 panic의 count=0 대상 tint였는지에 대한 증거는 없다. 이 interleaving에서 일반적으로는 UAF/dereference fault가 예상되며, panic의 zero-count `BUG_ON`과 직접 같은 증상이라고 입증할 수 없다. 따라서 이번 panic 설명력은 double-put보다 낮다.

## 후보 비교와 패닉 증거

저장된 로그 발췌 `docs/boot-incident-20261106/panic-excerpt.txt:18190-18231`은 `kernel BUG at include/linux/task_integrity.h:150`, current `rcuop/4`, `pc: five_task_free+0x40/0x70`, `lr: security_task_free+0x5c/0x7c` 및 unwind `five_task_free → __put_task_struct → delayed_put_task_struct → rcu_do_batch → rcu_nocb_cb_kthread`를 기록한다. 이는 task free 시점에 `usage_count==0`인 포인터를 `five_task_free()`가 put하려 했다는 직접 증거다. BUG_ON 뒤의 decrement/free는 실행되지 않는다. 따라서 로그만으로 “refcount underflow가 일어났다”라고 말할 수 없다.

| 설명 후보 | 패닉과의 적합성 | 누락된 증거 |
|---|---|---|
| fork hook 실패 double put, 특히 CLONE_VM 부모 tint까지 0으로 소진 | 높음: 부모/다른 owner가 나중에 RCU 해제되며 zero-count put을 할 수 있음. 정적 바이너리 결함 확인됨. | 실패한 clone, flags, hook 오류, 대상 task/tint 주소가 로그에 없음. |
| 일반 fork의 child double put | 중간: 같은 정리 오류가 child tint를 해제한 뒤 재사용한다. 이후 RCU까지 stale pointer가 유지됐는지 필요. | 대상 child의 생존/메모리 재사용과 당시 오류 경로 증거 없음. |
| proc 조회 대 exec 포인터 교체 경쟁 | 낮음~중간: 소스상 UAF 가능하나 보통 BUG_ON보다는 접근 fault를 예상. | panic 주소가 reader가 쓴 tint인지 정보 없음; crash trace는 reader 경로가 아닌 RCU free. |
| worker/exit 단독 경합 | 낮음: 별도 tint 및 task_struct 참조가 정상 경로를 보호. | 정상 경로에서 ref 누락을 보여주는 증거 없음. |
| 선행 메모리 손상/외부 중복 put | 배제 불가지만 근거 없음. | 손상 출처나 count history 없음. |

패닉 전 KernelSU setresuid 기록은 시간적으로 근접할 뿐, KernelSU에서 FIVE 포인터/refcount를 직접 쓰는 증거는 확인되지 않았다. `PROCESS__FORK` AVC나 특정 `security_task_alloc` 오류도 보존 로그에서 확인되지 않는다. 따라서 기존 `PROCESS__FORK` 거부 가설만으로 패닉 원인을 주장할 수 없고, 반대로 그것을 완전히 배제할 로그도 없다.

## 결론

가장 강한 정적 결과는 BYI3와 BDZJ2에서 확인한 조건부 fork cleanup double put이다. 이는 실제 코드 결함으로 **CONFIRMED**지만, 저장된 패닉의 선행 원인으로는 **POSSIBLE**에 머문다. 정상적인 async worker/exit 수명 경로는 ref를 분리 보유해 단독 경쟁 후보로는 **UNSUPPORTED**다. 외부 proc FIVE 조회와 exec 교체 사이의 raw tint 수명 경쟁은 소스상 재현 가능한 정적 후보여서 **POSSIBLE**로 기록하되 panic PC 경로와의 연결은 약하다. panic 자체는 `five_task_free()`에서 count 0을 확인했다는 것까지만 확정한다.

### 분석하지 않은 것과 위험

BDZJ2의 전체 실행 바이너리 재역어셈블 및 해당 빌드의 정확한 `.config`/build hash 대조는 하지 않았다. proc 조회 경쟁이 실제 빌드에서 활성화됐는지와 panic 대상 task는 미확인이다. 이 보고서는 정적 후보를 원인으로 확정하지 않는다.
