# Samsung FIVE `five_task_free()` 커널 패닉 조사

조사일: 2026-11-06  
판정: **PARTIAL**  
범위: 기존 저장 자료와 체크아웃된 소스의 읽기 전용 분석. 패닉 재현, 실기기 상태 변경, 커널·SSAL·SELinux·KernelSU 수정은 하지 않았다.

## 요약 판정

저장된 패닉은 `five_task_free()`가 `task_integrity_put()`을 호출한 뒤, `usage_count`가 이미 0인지 확인하는 `BUG_ON`에서 발생했다. 로그의 실행 task는 종료 대상 프로세스가 아니라 RCU callback worker `rcuop/4`(PID 53)다. 종료 대상의 PID/TGID/comm/부모는 이 덤프만으로 식별되지 않는다. 따라서 로그는 “FIVE가 root 프로세스를 거부했다”거나 “KernelSU가 FIVE 객체를 손상시켰다”는 결론을 뒷받침하지 않는다.

체크아웃된 Samsung 소스에는 실제로 중복 put으로 이어질 수 있는 조건부 fork 오류 정리 경로가 있다. `CLONE_VM` 자식의 FIVE 참조를 먼저 증가시킨 다음 `security_task_alloc()`의 LSM hook이 실패하면, 그 함수 내부의 `security_task_free()`와 `copy_process()`의 `task_integrity_cleanup()`가 같은 자식 포인터를 각각 put할 수 있다. 실패 시점에 부모와 공유 중이면 부모 참조까지 소비될 수 있고, 이후 부모 task의 RCU 해제에서 같은 zero-count BUG가 가능하다. 다만 패닉 로그에는 대상 task, clone flags, `task_alloc` 실패가 기록되어 있지 않으므로 이는 구체적인 정적 후보이지 확인된 원인은 아니다.

또한 요청에 적힌 SM-S928N과 확보된 증거가 일치하지 않는다. pstore 대체 자료와 현재 읽기 전용 기기 정보는 모두 **SM-S937N (PSQ)**, 커널 `...S937NKSSBDZJ2...`를 가리킨다. 아래 분석은 이 S937N 자료에 대한 결과이며 S928N에 그대로 적용된다고 볼 수 없다.

## 증거와 기기 식별

| 항목 | 관측값 | 근거와 한계 |
|---|---|---|
| 패닉 자료 | `docs/boot-incident-20261106/last_kmsg.txt`, 발췌 `panic-excerpt.txt`, 메모 `incident-summary.md` | 이 incident에서 확인된 기존 자료. 별도 pstore/ramoops/tombstone/logcat 원본은 확인되지 않았고, `logcat -L` 수집은 실패한 것으로 기록돼 있다. |
| 기기 | `SM-S937N`, product `psq` | incident 메모와 읽기 전용 `adb getprop` 결과. 사용자 요청의 `SM-S928N`과 불일치. |
| 커널 | `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k` | panic dump의 커널 문자열과 기기의 `uname -r`가 일치. build hash `4ada8571dcf2ef127627ffc0429891950f882248`. |
| 보안 패치 수준 | `2026-10-05` | 읽기 전용 `ro.build.version.security_patch`. 이 값만으로 특정 CVE 수정의 바이너리 포함 여부를 증명할 수는 없다. |
| KernelSU | 패닉 모듈 목록에 `kernelsu(O)` | 현재 로드된 모듈의 정확한 버전/build ID는 확보되지 않았다. 저장소 gitlink는 `76a088c5fbff0ec0e5e2a14372e892c1e06da319`이며, 이는 설치된 모듈 버전을 증명하지 않는다. |
| Samsung 소스 | `vendor/S937NKSU2BYI3` | README는 PSQ 계열 `psq_kor_singlex`를 대상으로 한다. 소스 디렉터리의 `BYI3`와 패닉 커널의 `BDZJ2`가 달라 정확한 펌웨어 소스/커밋 일치 증명은 없다. `gki_sec_defconfig`에는 `CONFIG_FIVE_GKI_10=y`가 있으나 이것도 실행 커널의 추출 config로 검증된 것은 아니다. |

기기 일치가 확인된 패닉 소스와 비교할 때 이 로컬 트리는 S937/PSQ 계열의 가장 가까운 확인 가능 소스다. 아래 코드 수준 분석은 해당 트리 기준이며, 바이너리와 정확히 일치하는 소스라고 단정하지 않는다.

## 패닉 경로와 fault 분류

`last_kmsg.txt`의 핵심 기록은 다음과 같다.

- `kernel BUG at include/linux/task_integrity.h:150!`
- `Internal error: Oops - BUG: 00000000f2000800`
- PC: `five_task_free+0x40/0x70`
- LR: `security_task_free+0x5c/0x7c`
- 호출 경로: `five_task_free → __put_task_struct → delayed_put_task_struct → rcu_do_batch → rcu_nocb_cb_kthread → kthread → ret_from_fork`
- faulting instruction: `d4210000` (arm64 BUG trap)
- 덤프의 현재 task: PID 53, comm `rcuop/4`, CPU 1
- ESR/FAR: 확보된 패닉 자료에 유효한 ESR/FAR 값이 기록되어 있지 않다.

소스의 `include/linux/task_integrity.h:148-153`에서 `task_integrity_put()`은 먼저 `BUG_ON(!atomic_read(&intg->usage_count))`를 실행하고, 그 다음에만 `atomic_dec_and_test()`를 한다. 따라서 이 기록이 의미하는 직접 사실은 **BUG_ON을 실행한 순간 해당 포인터의 usage count가 0으로 읽혔다**는 것이다. NULL dereference나 page fault로 보고된 것이 아니며, 이 경로에서 decrement도 실행되지 않았다. 그래서 “refcount underflow가 발생했다”는 것은 로그만으로 확인되지 않는다. 가능한 설명은 이미 0인 객체에 대한 추가 put, 해제된 객체를 가리키는 stale pointer, 또는 선행 메모리 손상이다.

`rcuop/4`는 `__put_task_struct()`를 지연 실행한 RCU callback worker다. RCU callback이 실행되는 동안의 current task이므로 PID 53은 **해제 중이던 대상 task의 PID가 아니다**. 덤프는 해제 대상 task의 식별 정보를 보존하지 않아 PID/TGID/comm/부모를 특정할 수 없다. 따라서 대상이 `ssald`, Guest launcher, Zygote 중 무엇인지도 확인 불가다.

panic 직전 로그에는 `ssald:29160`의 loop mount 활동과 KernelSU `setresuid` 로그가 보인다. 약 0.1015초 전에 `[main:29445] KernelSU: handle_setresuid from 0 to 1000`가 기록됐다. 이 시간적 근접성은 상관관계일 뿐, PID 29445가 해제 대상 task였거나 이 호출이 잘못된 put을 만들었다는 증거는 아니다. 같은 구간에는 audit rate-limit으로 유실된 이벤트도 있다.

## `task_integrity` 객체 수명과 소유권

분석 파일은 `vendor/S937NKSU2BYI3/kernel_platform/common/` 아래에 있다.

| 동작 | 코드 경로 | 소유권 효과 |
|---|---|---|
| init task 생성 | `init/init_task.c:61-64`, `include/linux/init_task.h:43-52` | 정적 init 객체를 만들고 `usage_count=1`로 초기화한다. `CONFIG_FIVE_GKI_10`에서는 task 포인터가 `android_oem_data1[2]`에 저장된다. |
| 일반 할당 | `security/samsung/five/task_integrity.c:47-58` | 전용 slab에서 할당 후 `usage_count=1`. |
| `fork`/`clone`, `CLONE_VM` | `kernel/fork.c:2010-2017` | 부모의 객체에 `get()`하고 자식도 같은 raw 포인터를 보유한다. 따라서 공유 객체의 참조 수가 1 증가한다. thread 생성은 통상 이 공유 경로를 사용한다. |
| `fork`/`clone`, `!CLONE_VM` | `kernel/fork.c:2018-2021` | 자식용 객체를 별도 할당하며 초기 count는 1이다. |
| exec, 재귀 depth 0 | `security/samsung/five/five_main.c:643-665` | 새 객체를 할당해 task 포인터를 교체하고 기존 객체를 put한다. binfmt 재귀 depth가 0보다 크면 이 교체 경로를 타지 않고 기존 객체에 이벤트를 추가한다. |
| FIVE 비동기 작업 | `security/samsung/five/five_main.c:180-220, 326-403, 840-870` | 이벤트 처리 work가 tint 참조를 얻고 worker 완료 시 put한다. 따라서 count는 task 수만 세는 값이 아니며, task 해제 전 비동기 참조도 함께 고려해야 한다. |
| task 최종 해제 | `kernel/exit.c:224-238`, `kernel/fork.c:1004-1019`, `security/security.c:2930-2937`, `security/samsung/five/five_main.c:452-455` | task 구조체는 RCU 경로로 지연 해제되고, `security_task_free()`가 `five_task_free()`를 불러 현재 task 포인터를 put한다. 정상 종료, 신호 종료, 비정상 종료 모두 최종 참조 정리에는 수렴한다. |
| count가 0이 된 뒤 | `task_integrity_put()` 및 `task_integrity_free()` | `atomic_dec_and_test()`가 0을 만들면 label과 file 참조를 정리하고 slab 객체를 반환한다. |

`TASK_INTEGRITY(task)`는 이 트리에서 `CONFIG_FIVE_GKI_10`일 때 `android_oem_data1[2]`를 raw pointer로 읽고 쓴다. 일반 헤더의 `task_integrity_get/put`은 NULL 검사나 pointer lifetime용 RCU를 수행하지 않는다. count는 `refcount_t`가 아니라 `atomic_t`다. get/put은 별도 `atomic_read()` 검사 후 atomic increment/decrement를 하므로 check와 연산 전체가 하나의 원자적 수명 연산은 아니다. `value_lock`과 `list_lock`은 데이터/목록을 보호하며 task pointer 소유권 전체를 보호하지 않는다. 이 경로에서 task_struct 자체의 RCU 지연 해제가 독립적인 `task_integrity` 참조를 대신 보장하지도 않는다.

빌드 선택도 구분해야 한다. 로컬 `security/samsung/five/Makefile`은 `CONFIG_FIVE_GKI_20`일 때만 `gki/task_integrity.o`를 선택하고, 그 대체 헤더의 get/put은 NULL 및 zero count를 조용히 검사해 반환한다. 그렇지 않으면 공통 헤더의 `BUG_ON` 구현과 legacy `task_integrity.c`를 사용한다. 로컬 `gki_sec_defconfig`의 `CONFIG_FIVE_GKI_10=y`는 이 legacy 경로와 맞지만, 정확한 `BDZJ2` 실행 config는 확보되지 않았다. 따라서 GKI20 guard를 이번 PC/BUG 경로의 방어로 간주할 수 없다.

### 조건부 중복 put 후보

현재 트리의 `kernel/fork.c:2579-2585`와 `security/security.c:2911-2920` 조합은 다음 정리 중복을 허용한다.

```text
CLONE_VM 자식 생성
  dup_task_integrity(): 공유 tint get()       count 1 → 2
  security_task_alloc(): lsm_task_alloc 성공
    LSM task_alloc hook 실패
      security_task_free(child)
        five_task_free(child) → put()          count 2 → 1
  copy_process() 오류 분기
    task_integrity_cleanup(child) → put()      count 1 → 0, 객체 free
  부모는 여전히 같은 tint 포인터를 보유
  이후 부모 __put_task_struct() → five_task_free → put(freed/zero 객체)
    task_integrity.h BUG_ON 가능
```

`CLONE_VM`가 아닌 자식은 별도 count-1 객체이므로 첫 번째 put에서 해제된 뒤 두 번째 정리가 같은 자식 포인터를 다시 사용할 수 있다. 이 경우는 이후 부모 RCU callback까지 기다리지 않고 오류 경로에서 UAF/추가 BUG가 날 수 있다. `security_task_alloc()`의 `lsm_task_alloc()` 자체가 실패하면 내부의 `security_task_free()`를 호출하지 않고 반환하므로 위 두 번 put 조건과 다르다. 즉 후보 조건은 특히 **composite blob 할당은 성공했지만 이후 LSM `task_alloc` hook이 실패한 경우**다.

이 정적 경로는 패닉의 zero-count 검사와 기계적으로 부합하지만, 로그에는 실패한 clone, `CLONE_VM`, 실패한 LSM hook 또는 대상 객체 주소가 없다. 현재 패닉의 원인으로 확정할 수 없다.

## KernelSU와 FIVE

현재 체크아웃된 KernelSU 소스에서 확인한 경로는 다음과 같다.

- `kernel/hook/syscall_event_bridge.c:124-134`의 setresuid hook은 이전 UID를 기록하고 원래 syscall을 먼저 실행한다. syscall 성공 뒤 `ksu_handle_setresuid(old_uid, current_uid().val)`를 호출한다.
- `kernel/hook/setuid_hook.c:24` 이후 handler는 로그, UID 기반 상태 조정 및 관련 보조 처리를 한다.
- KernelSU 소스 검색에서 `TASK_INTEGRITY`, `task_integrity`, `android_oem_data1`, `five_task_free`, `security_task_alloc/free` 직접 참조는 확인되지 않았다.
- KernelSU의 다른 경로는 `prepare_creds()`/`commit_creds()`로 credentials를 복사·교체하거나 SELinux context를 바꾼다. 이는 자격 증명과 SID에는 영향을 줄 수 있지만, 확인한 코드에서 FIVE 객체 포인터 또는 count를 직접 조작하지 않는다.

따라서 `u:r:ksu:s0`로 실행되는 사실만으로 FIVE 객체 수명 오류를 설명할 수 없다. KernelSU의 UID/SID 변경이 Five의 exec 평가 결과나 다른 LSM 동작에 간접 영향을 주는 가능성은 남지만, 현재 로그·소스에서 해당 연결은 추적되지 않았다. panic 직전 KernelSU 로그도 성공한 syscall 뒤의 handler 로그여서 원인 증거가 아니다. 로컬 gitlink는 위 표의 해시를 가리키지만 로드된 `.ko`의 버전과 일치하는지 확인되지 않았으므로 적용 바이너리 분석에는 한계가 있다.

## SSAL 경로와 task 종료

검토한 SSAL 코드 경로는 `src/ssald.rs`, `src/guest_launcher.rs`, `src/guest_probe.rs`다.

- `src/ssald.rs:395-401`, `564-574`는 작업용 및 요청 처리용 `std::thread::spawn`을 사용한다. Linux thread 생성은 `CLONE_VM` 공유 주소 공간 경로와 연결되므로, 위 fork 정리 후보의 clone 종류와는 맞닿는 지점이 있다. 하지만 해당 thread의 실제 생성·실패가 패닉 대상이라는 로그 증거는 없다.
- `src/guest_launcher.rs:29-95`는 Guest 명령을 구성한다. `pre_exec`에서 parent-death signal을 설정하고, 필요하면 `/proc/thread-self/attr/exec`에 다음 exec context를 쓰고, `setgroups`, `setresgid`, `setresuid`를 수행한다. 이 경로에서 직접 `capset`을 호출하는 코드는 확인하지 못했다.
- 실행은 `std::process::Command::spawn()`으로 진행된다 (`guest_launcher.rs:246-348`). 명령은 process group을 격리하고, 자식은 Guest cgroup에 들어간다. `guest_probe.rs:327-359`의 `unshare(CLONE_NEWNS)`와 `pivot_root`는 pivot 경로에서만 실행된다. 확인한 경로는 새 PID namespace를 만들지 않으며 파일 상단 주석도 shared PID namespace가 의도된 것이라고 명시한다.
- Zygote는 `app_process64 -Xzygote /system/bin --zygote --socket-name=zygote`로 실행된다 (`guest_launcher.rs:1278-1305`). SSAL은 socket readiness를 확인하고 Zygote의 이른 종료도 감시한다. 이 인자는 system server 자동 시작을 요청하지 않는다.
- `Service::stop()`은 소유한 process group에 SIGKILL을 보내고 직접 자식을 `wait()`한다 (`guest_launcher.rs:431-452`); `Drop`도 stop 경로에 연결돼 있다. Zygote나 자식이 먼저 비정상 종료하더라도 Linux의 종료/최종 task 정리는 정상 종료와 같은 `__put_task_struct → security_task_free → five_task_free` 경로로 수렴한다. 종료 형태는 시점·동시성에는 영향을 줄 수 있지만 FIVE put 호출 자체의 별도 정상/비정상 분기를 만들지는 않는다.

그러므로 SSAL에서 FIVE와 만날 수 있는 지점은 공유 주소 공간 thread 생성, exec 시 새 tint 교체, 자식·서비스 task의 최종 free다. 현재 자료는 panic 대상 task가 이 중 어느 경로였는지 연결하지 못한다. mount namespace/pivot, UID/GID 변경, SELinux exec context도 그 자체로 `task_integrity` count를 변경하지 않는다.

## CVE-2026-20971 / 공개 수정 비교

공개 advisory는 CVE-2026-20971을 Samsung PROCA driver의 use-after-free로 설명하며, SMR 2026년 1월 릴리스보다 이전에 영향을 받는다고 기록한다 ([GitHub Advisory](https://github.com/advisories/GHSA-q9rf-32g7-6fx5), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-20971)). 기술 분석은 PROCA/FIVE procfs reader가 task-integrity 포인터를 보유한 채 concurrent exec가 해당 포인터를 교체하고 옛 객체를 해제하는 수명 경합을 기술한다 ([LucidBit Labs 분석](https://lucidbitlabs.com/blog/when-defenses-become-attack-surface/)).

이번 로그의 직접 경로는 procfs read가 아니라 RCU callback의 `__put_task_struct → security_task_free → five_task_free → task_integrity_put`이며, panic 조건은 count가 0인 객체에 대한 put이다. 두 현상은 같은 객체 계열의 수명 관리라는 넓은 유사성은 있지만, 공개 CVE의 UAF reader 경로와 이번 BUG 조건이 동일하다는 증거는 없다. 따라서 CVE가 이번 패닉을 일으켰다고 확정하지 않는다.

기기의 `2026-10-05` 보안 패치 수준은 2026년 1월 SMR보다 뒤이므로 CVE 수정이 포함됐을 가능성은 높다. 그러나 S937N의 해당 바이너리/정확한 소스에서 패치가 확인되지 않았고, 로컬 소스 폴더도 `BDZJ2` 패닉 build와 다른 `BYI3` 표기다. 이 자료로 수정 포함을 확정하거나, CVE 관련 결함을 완전히 배제할 수 없다. 삼성 공지의 월별 패치 정보는 [Samsung Security Update](https://security.samsungmobile.com/securityUpdate.smsb?year=2026&month=01)에서 확인할 수 있다.

## 원인 가설

| 가설 | 근거 | 반대 근거/미확인 | 신뢰도 | 추가로 필요한 자료 | 커널 변경 없이 SSAL에서 완화 가능성 |
|---|---|---|---|---|---|
| **A. SSAL의 비정상 lifecycle이 커널 결함을 유발** | SSAL은 thread-per-request를 사용하고 Guest 서비스·Zygote의 신호 종료 및 회수가 가능하다. 실제 코드에서 `CLONE_VM` 공유 tint가 쓰이는 thread lifecycle 지점이 있다. | 대상 task PID/comm/부모, 실패한 clone, abnormal exit 증거가 없다. 정상·SIGKILL 종료 모두 같은 최종 FIVE free hook을 거치므로 비정상 종료만으로 BUG가 설명되지는 않는다. | **낮음** | crash 직전 task 생성/종료 기록과 PID 매핑, `copy_process`/LSM 오류 기록, 대상 task의 clone flags | 이번 증거만으로 특정 SSAL 작업을 바꿀 근거는 없다. 추가 진단 전 lifecycle 변경은 원인 확인을 흐릴 수 있다. |
| **B. KernelSU와 FIVE 간 credential/수명 충돌** | panic 직전 setresuid handler 로그가 있고 현재 SSAL 도메인이 `u:r:ksu:s0`라고 보고됐다. KernelSU가 credentials/SELinux SID를 조정하는 경로는 있다. | 확인한 KernelSU source는 FIVE 포인터와 count를 직접 다루지 않는다. hook은 원래 setresuid 성공 뒤 부가 처리한다. task identity를 panic 대상과 연결할 수 없다. | **낮음** | 실제 로드된 KernelSU 버전·모듈 해시, firmware-matched KernelSU/FIVE 소스와 hook 순서, incident task credential/SID | 도메인이나 정책을 바꾸지 않고는 현재 입증된 SSAL 측 완화가 없다. setresuid 로그만으로 변경해서는 안 된다. |
| **C. Samsung FIVE 자체 또는 lifecycle hook의 refcount/UAF/double-free 결함** | panic은 `usage_count==0`의 직접 BUG다. 로컬 `copy_process()` 오류 경로에서 `security_task_free()`와 `task_integrity_cleanup()`가 조건에 따라 같은 tint를 중복 put할 수 있는 구체적 코드 후보가 있다. | 후보 실행 조건(`task_alloc` hook 실패 및 clone flag)이 로그에 없다. 로컬 소스가 정확한 `BDZJ2` 소스임을 증명하지 못한다. 초기 zero count가 다른 이유일 가능성도 남는다. | **중간 (가장 구체적인 정적 후보; 원인 확정 아님)** | 정확한 build source/config, 실패한 `task_alloc` hook·clone trace, task tint 주소/count trace 또는 재현 없이 얻은 동등한 crash 기록 | SSAL에서 신뢰성 있게 고칠 수 있는 원인이 아니다. 실패 경로를 식별하기 전에 임의로 thread/clone 동작을 바꾸는 것은 완화로 검증되지 않는다. |
| **D. 다른 커널 손상이 FIVE task cleanup에서 뒤늦게 노출** | zero count는 선행 pointer/count 손상이나 stale pointer의 결과일 수 있다. 로그에는 대상 task와 객체 생성 이력이 없다. | BUG는 FIVE invariant 검사에서 정확히 잡혔지만, 다른 corruptor를 가리키는 slab/KASAN/ESR/FAR 증거는 없다. | **낮음~중간** | full vendor crash artifact, matching symbols/config, 메모리 오류·KASAN·slab 진단이 자연 발생 시 수집된 경우 | SSAL이 원인이라는 증거가 없어 안정적 완화는 판단 불가. 읽기 전용 상관관계 자료를 보존한다. |

현재 가장 강한 결론은 **zero-count put이라는 실패 조건**이다. **C의 조건부 fork 오류 정리 중복 put**은 코드상 검토 우선순위가 높은 후보지만, 이번 사건에서 해당 경로가 실행됐다고 증명되지는 않는다. A/B는 현재 로그의 시간적 연관 이상으로 올라가지 못하며, D도 배제할 수 없다.

## 수정 없이 가능한 후속 진단

1. S928N이 실제 조사 대상이면 해당 기기에서 읽기 전용으로 model, fingerprint, `uname -r`, security patch 수준을 확보하고 이번 S937N artifact와 분리한다.
2. panic build `BDZJ2`와 정확히 대응하는 Samsung source revision, `.config`, `vmlinux`, `System.map`, build ID를 확보해 PC/LR와 line mapping을 재확인한다. 현재 `S937NKSU2BYI3` 트리는 유사 계열 비교 자료로만 취급한다.
3. 이미 저장된 `last_kmsg` 원본과 pstore/ramoops 파일을 보존하고, 자연 발생한 incident 이후에만 추가 자료를 읽는다. 종료 대상 PID/TGID/comm/parent, clone flags, 직전 task_alloc 오류, FIVE count 경고가 포함된 전체 call trace를 확보한다. 패닉 재현 목적의 반복 실행은 하지 않는다.
4. 현재 로드된 KernelSU 모듈의 read-only 버전/build ID/hash와 SSAL 실행 로그를 함께 기록한다. `setresuid` 전후의 UID/SID와 SSAL task PID/TID를 기록하되, 이를 FIVE 객체 변경 증거로 간주하지 않는다.
5. 비교 가능한 자연 발생 로그에서 `task_alloc` 오류와 thread/clone 실패가 함께 보이는지 확인한다. 해당 상관관계가 없으면 조건부 중복 put 후보의 우선도를 낮춘다. 진단 과정에서 정책, 커널, KernelSU 또는 SSAL 동작을 변경하지 않는다.

이 후속 자료로 객체 주소/count의 소유권 전이를 연결할 수 없다면 결론은 계속 부분 판정으로 남는다. 특히 동일한 task의 tint 포인터와 refcount 이력이 있어야 “어떤 객체가 어떤 경로에서 잘못 해제/참조됐는가”를 확정할 수 있다.

## 최종 판정: PARTIAL

확인된 원인은 `task_integrity_put()`의 zero-count `BUG_ON`이며 실행은 delayed RCU task-free 경로에서 일어났다. 잘못된 put의 대상 task 및 선행 객체 경로는 현재 로그로 추적되지 않았다. 로컬 Samsung 소스에서 조건부 중복 put 후보를 발견했으나, exact firmware source 매칭과 해당 실패 경로 실행 증거가 없어 **ROOT CAUSE IDENTIFIED**로 판정할 수 없다. 또한 조사 자료가 S928N이 아니라 S937N에 해당할 가능성이 확정적이어서 S928N 패닉 원인으로도 일반화하지 않는다.
