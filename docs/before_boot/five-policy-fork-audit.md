# SSAL Phase FIVE-POLICY — Effective Fork Permission Audit

조사일: 2026-11-06  
범위: 저장된 SELinux policy binary, 저장소의 기존 source/profile/log 정적 분석. 기기 접근, fork 재현, policy/KernelSU/FIVE/SSAL 수정은 하지 않았다.

## 판정

**SELinux `PROCESS__FORK` 거부 가설: WEAKENED.**

2026-11-04 보관 Host 정책에서 `ksu`의 self-fork는 `domain` attribute를 대상으로 한 명시적 allow에 포함되고 `ksu`는 domain-permissive다. `zygote`와 `system_server`도 self-fork allow가 있고 permissive type이 아니다. 이 정책 스냅샷에서 이 세 도메인의 self-fork가 enforcing denial을 일으켰을 가능성은 낮다. 반면 `ssal_guest_probe` type은 저장 정책에 없어 Guest Zygote의 유효 권한을 그 binary로 판정할 수 없다. 저장 정책은 11월 4일 것이고 패닉은 11월 6일이므로 패닉 시 실제 정책, 런타임 추가 규칙, permissive map을 증명하지 않는다. 따라서 가설은 약화되지만 반증되지는 않았다.

## 분석 자료와 방법

- 입력: [`out/selinux-check/2026-11-04-host-active-policy.bin`](../out/selinux-check/2026-11-04-host-active-policy.bin), SHA-256 `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` (3,140,889 bytes).
- SETools 4.6.0의 `sesearch`/`seinfo`로 WSL에서 binary를 직접 읽어 질의했다. 도구 패키지만 WSL `/tmp`에 추출했으며 repo, 기기, 정책은 변경하지 않았다.
- Self query: `sesearch -A -s TYPE -t TYPE -c process -p fork POLICY`. Attribute membership에 따른 유효 규칙을 포함한다. 추가로 direct source/target-only(`-ds -dt`) 규칙과 전체 `process:fork` conditional rule을 확인했다.
- Constraint query: `seinfo POLICY --constrain process`; permissive query: `seinfo POLICY --permissive`.

## 보관 정책 결과

| 도메인 | Self `process:fork` allow | Conditional rule | Binary의 domain-permissive 상태 | 판정 |
|---|---|---|---|---|
| `ksu` | 있음. `allow ksu domain:process { ... fork ... }`가 매칭된다. `ksu` 자신이 `domain` 대상 집합에 포함되어 self access가 허용된다. exact `ksu → ksu` allow는 없지만 effective self rule은 명시적 allow에 의해 허용된다. | fork 권한을 주는 conditional rule 검색 결과 없음 | **permissive** (`seinfo` 결과 유일 항목: `ksu`) | 허용이며 permissive |
| `ssal_guest_probe` | 계산 불가. 이 type은 binary에 선언되어 있지 않다. | 계산 불가 | 계산 불가 | 이 정책 snapshot으로는 판단 불가 |
| `zygote` | 있음. `allow zygote zygote:process { ... fork ... }` | conditional fork rule 없음 | permissive 목록에 없음 | 허용, enforcing domain |
| `system_server` | 있음. `allow system_server system_server:process { ... fork ... }` | conditional fork rule 없음 | permissive 목록에 없음 | 허용, enforcing domain |

전체 policy의 conditional `process:fork` allow 검색도 결과가 없었다. `process` class constraints는 3개이며 권한 집합은 각각 `{dyntransition, transition}`, `{getattr, getcap, getpgid, getsched, getsession, ptrace, share}`, `{ptrace, setcap, setpgid, setrlimit, setsched, share, sigkill, signal, sigstop}`이다. **어느 constraint에도 `fork`가 없어** 위 허용을 뒤집는 process constraint를 찾지 못했다. Binary 분석으로 소스 단계의 `neverallow` 적합성을 증명할 수는 없다. `seinfo`가 보고하는 permissive type도 저장 binary 안의 상태일 뿐 전역 enforcing 값이나 이후 KernelSU 동적 변경을 나타내지는 않는다.

## Guest Zygote SID: 코드, 선언, 런타임 증거

- [`src/guest_launcher.rs`](../src/guest_launcher.rs#L18)는 Guest context 상수로 `u:r:ssal_guest_probe:s0`를 정의한다. Zygote 실행도 같은 context로 시작하고(`#L1278-L1302`), 시작 후 `/proc/<pid>/attr/current`를 읽어 이 SID인지 검사한다(`#L1310-L1318`). 검증을 통과한 경우에만 `Guest Zygote ready ... domain=...`를 기록한다(`#L1349`). 따라서 **현재 launcher의 의도 SID는 `ssal_guest_probe`**다.
- [`module/profiles/concurrent/services/initial.json`](../module/profiles/concurrent/services/initial.json#L55)은 `zygote` 서비스 SID를 `u:r:zygote:s0`로 선언한다. 전역 `selinux.permissive` 선언은 `false`다(`#L20`). 따라서 profile SID와 launcher의 의도 SID는 서로 다르다. Profile metadata를 실제 실행 SID의 증거로 볼 수 없다.
- 2026-11-04 [`worker.log`](zygote-phase7a-run-20261104/worker.log#L234-L247)는 Zygote 시작을 기록한 뒤, abstract socket readiness 전에 PID 15920이 SIGABRT로 종료됐다고 기록한다. `Guest Zygote ready` 또는 해당 PID의 `attr/current`는 기록되지 않았다. 이 실행 로그로 실제 Zygote SID를 확정할 수 없다. 같은 run의 다른 Guest 서비스는 `ssal_guest_probe` SID를 기록하지만 이는 Zygote PID의 SID를 증명하지 않는다. Host `before.txt`/`after.txt`의 `u:r:zygote:s0`와 `u:r:system_server:s0`도 Host 프로세스 관측이다.

요약하면 **launch code expected SID = `ssal_guest_probe`; service profile declared SID = `zygote`; observed Guest Zygote PID SID = 미관측**이다. 또한 11월 4일 Host binary에 `ssal_guest_probe` type이 없고 로컬 `module/sepolicy.rule`의 permissive 선언만으로 당시 동적 policy 적용을 증명할 수 없다.

## 패닉 시점 정책과 로그의 한계

보관 binary는 11월 4일 Host active policy이고, 패닉 excerpt는 11월 6일이다. 동일한 boot/policy sequence라는 자료가 없다. 특히 binary는 KernelSU가 runtime에 추가한 policy/permissive 설정이나 패닉 당시 live policy를 대변한다고 가정할 수 없다.

[`last_kmsg.txt`](boot-incident-20261106/last_kmsg.txt#L18183-L18191)는 panic 직전 `audit_lost=16773`, `audit_rate_limit=5`, `audit rate limit exceeded`를 기록하고, 이후 `include/linux/task_integrity.h:150`의 BUG를 보고한다. Stack은 `five_task_free+0x40 → __put_task_struct → delayed_put_task_struct → rcu_do_batch`다(`#L18208-L18231`). 기존 검색에서 AVC/`PROCESS__FORK`/`selinux_task_alloc` 기록은 없었지만 audit 유실이 커서 부재는 반증이 아니다. 로그는 실패한 fork, task_alloc 반환값, 대상 task PID/부모 SID, clone flags를 보존하지 않는다. `rcuop/4`는 free callback 실행자이지 손상된 task가 누구인지 알려주지 않는다. 직전 `ssald` 및 KernelSU UID 로그는 시간상 정황일 뿐 해당 task의 fork 실패나 SID를 특정하지 않는다.

## FIVE 오류 경로 재평가

기존 [`five-task-free-followup.md`](five-task-free-followup.md)와 [`five-double-put-avoidance.md`](five-double-put-avoidance.md)의 정적 분석에 따르면, 조사한 BYI3 common 코드에서는 LSM `task_alloc` hook 오류일 때 `security_task_free()`의 `five_task_free()`와 `copy_process()`의 `task_integrity_cleanup()`가 같은 tint를 중복 put하는 경로가 있다. 이 결함은 일반 fork에서는 해제된 child tint를 다시 put할 수 있고, `CLONE_VM`에서는 공유 tint count를 child가 취득하기 전보다 하나 더 낮춰 parent의 stale pointer와 지연 RCU free BUG로 이어질 수 있다. observed RCU panic과 호환되는 수명 오류 후보이지만, BYI3 코드 경로가 BDZJ2 패닉 커널에 동일하게 포함됐다는 증거는 별도다.

- `ksu`가 실제 SSAL parent였다는 가정에서는 저장 정책상 fork allow와 permissive 상태가 함께 있어 `PROCESS__FORK` 거부를 generic LSM 오류 trigger로 볼 근거가 약하다. 다만 패닉 boot의 동일 상태였음은 확인되지 않았다.
- Guest Zygote가 실제 parent였는지도, 그 PID가 어떤 SID였는지도 확인되지 않았다. Code path가 의도한 `ssal_guest_probe`는 보관 정책에 없으므로 해당 domain에서 fork denial이 가능했는지는 여전히 미결이다. Readiness 이전 SIGABRT는 실행 실패 증거지만 LSM fork 오류 증거는 아니다.
- 동일 보관 정책에서 Host `zygote`/`system_server`는 self-fork를 명시적으로 허용한다. 이 결과는 해당 snapshot의 해당 SID에 대해서만 유효하며, 패닉 시점 Host policy를 대신하지 않는다.
- FIVE 조사 문서가 인용한 BYI3 common tree에서는 일반 LSM `task_alloc` hook 중 SELinux만 nonzero 오류를 반환할 수 있고, AppArmor/TOMOYO hook은 0을 반환한다. 이 코드/config를 BDZJ2의 확정 사실로 확대할 수 없다. LSM task blob의 `-ENOMEM` 조기 실패는 `security_task_free()` 없이 caller cleanup 한 번만 수행하는 경로라 이 double-put trigger와 구분된다. `security_integrity_current()`의 KDP credential 오류는 errno 경로가 아니라 panic 경로다. 별도 FIVE trace-hook/tint allocation 경로와 정확한 BDZJ2 LSM/config wiring도 미확인이다.

따라서 우선순위는 (1) RCU `five_task_free` zero-count BUG에 맞는 **FIVE 참조 수명 손상**을 상위 원인 계층으로 유지하고, (2) 이를 유발한 `PROCESS__FORK` 거부는 보관 정책의 `ksu`, `zygote`, `system_server` 결과에 비추어 하향 조정하며, (3) 미관측 `ssal_guest_probe`, 다른 nonzero task_alloc hook/config, FIVE 참조 관리의 다른 손상 경로 및 BDZJ2 소스 차이를 미해결 대안으로 둔다. 이번 정적 자료만으로 trigger를 선택하지 않는다.

## 최종 결론

**WEAKENED — SELinux `PROCESS__FORK` 거부 가설.** 보관된 Host policy에서 확인 가능한 세 도메인은 모두 self-fork allow를 가지며, `ksu`는 permissive이기까지 하다. 하지만 Guest Zygote 도메인은 그 binary에서 빠져 있고, 패닉 boot의 live policy 및 실행 PID SID가 없다. 따라서 이 결론은 “패닉 당시 denial이 없었다”는 뜻이 아니다. FIVE double-put/lifetime 경로는 여전히 panic shape와 양립하는 별도 trigger chain 후보이며, actual BDZJ2 구현·오류 반환이 확인되지 않아 사건 원인으로 확정할 수 없다.
