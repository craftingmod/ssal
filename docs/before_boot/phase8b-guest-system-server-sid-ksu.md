# Phase 8B — KernelSU Guest System Server SID 획득

2026-11-06 KST. **Native startup→final SID 획득 PASS / Enforcing PASS / disposable canary signal·proc 접근 차단 PASS.** 실제 patched GSI `forkSystemServer()` 및 Framework 부팅은 미실행이다.

사용자가 KernelSU를 통한 Guest SELinux 항목 추가를 허용한 후 [이전 EINVAL 결과](phase8b-guest-system-server-sid.md)를 이어서 진단했다. 새 type을 공유 커널 policy에 추가했으며 기존 Host type/rule을 제거·덮어쓰기·완화하지 않았다. Host 프로세스·module `sepolicy.rule`·GSI 이미지는 수정하지 않았다.

## 적용한 최소 delta와 첫 실패

[`phase8b-guest-system-server.rule`](../scripts/guest-domain-poc/phase8b-guest-system-server.rule)을 `ksud sepolicy check` 후 `apply`했다. Guest startup/final type과 domain/coredomain attribute, 두 type의 명시적 `enforce`, Guest 전이 및 종료 통지 규칙을 추가했다. 전역 permissive와 Host domain의 신규 allow는 없다.

04:19:11의 첫 실행에서는 새 context validation과 startup 전환이 성공했지만 final 전환은 **EACCES(13)**였다. [`run1/probe.txt`](../out/phase8b-sid-ksu/run1/probe.txt):4–8. 따라서 앞선 EINVAL은 context 미등록 문제였고, 그 문제가 해결된 뒤 권한 문제에 도달했다.

SELinuxFS access query로 다음을 구분했다 ([`access-run1.jsonl`](../out/phase8b-sid-ksu/access-run1.jsonl):2–7).

- startup→final `process dyntransition`은 이미 allowed=true였다.
- startup→자신 `process setcurrent`는 allowed=false였다. KernelSU가 `self` target을 기대대로 확장하지 않은 것으로 판단했다. 명시적 동일 type 이름으로 바꾼 뒤 allowed=true가 됐다.
- 새 SID가 자신의 proc attr에 접근하기 위한 같은 type의 `dir search`, `file open/read/write`도 없었다. startup에는 이 권한을, final에는 readback용 `dir search`, `file open/read`만 추가했다. Host 파일 type에 광범위 allow를 주지 않았다.

초기 `enforcing` 키워드와 comment 안 세미콜론은 KernelSU parser에서 거부돼 각각 `enforce`, 마침표로 수정했다. 이 syntax 실패는 runtime 전이 실패와 별개이며 해당 시도에서는 apply 단계에 진입하지 않았다. `ksud` 성공 종료만으로 권한 적용을 판정하지 않고 query와 실제 syscall을 사용했다.

04:20:32에는 startup/final setter가 모두 0을 반환하고 final readback이 `u:r:ssal_guest_ss:s0`였다 ([`run2/probe.txt`](../out/phase8b-sid-ksu/run2/probe.txt):7–8). 명시적 새 Guest SID를 획득했으며 stock SID 또는 기존 `ssal_guest_probe` 유지로 성공을 위조하지 않았다.

## 최종 단발 canary 실행

SM-S937N `R5CY52JC03H`, **04:23:05 +0900**. [`final/probe.txt`](../out/phase8b-sid-ksu/final/probe.txt)의 줄 번호다.

| 검사 | 관측 | 판정 |
|---|---|---|
| Guest startup context validation | result=29 errno=0 (:4) | PASS |
| Guest final context validation | result=21 errno=0 (:5) | PASS |
| Host canary | PID 26143, `u:r:system_server:s0` (:6) | disposable control |
| 시작 SID | UID/GID 1000, `u:r:ssal_guest_probe:s0` (:7) | PASS |
| startup `setcon()` | result=0 errno=0 (:8) | PASS |
| final `setcon()` 및 readback | result=0 errno=0, **`u:r:ssal_guest_ss:s0`** (:9) | **SID 획득 PASS** |
| canary `kill(pid,0)` | -1/EACCES(13) (:12), 실제 신호 없음 | 접근 차단 PASS |
| canary proc root/fd/fd0 open | 모두 -1/ENOENT(2) (:13–15), 내용 미열람 | 접근 차단 PASS, 기존 procfs 조건 |
| parent reference | canary live=1, parent root open=1 (:18) | ENOENT가 canary 소멸 때문이 아님 |
| 정리 | probe 26144, canary 26143 모두 reap (:17,19), 별도 PID 부재 확인 | PASS |
| 종료 및 Host snapshot | exit 0, 전후 동일 (:20–21) | PASS |

이 진단은 native `setcon()`을 사용하는 UID/GID 1000·groups 없음의 disposable process다. 실제 GSI `selinux_android_setcontext()`의 seapp lookup이나 `selinux_android_setcon()`의 property 재초기화는 실행하지 않았다. probe와 canary는 기존 Host mount/PID view에서 동작한다. 같은 Host procfs의 **기존 `hidepid=invisible,gid=3009`**가 적용된 결과이며, 이 결과를 SELinux 단독 proc 차단 또는 새 proc namespace의 효과로 주장하지 않는다. `hidepid=4` 실험은 하지 않았다.

처음 proc ENOENT를 EACCES/EPERM과 구별하지 못한 판정기는 FAIL을 출력했다 (`run3/probe.txt`). canary liveness와 parent reference 검사를 추가해 live target의 은폐를 확인한 최종 실행만 PASS로 판정했다. 수정 과정에서 Linux mock의 parent proc 접근이 차단되어 빌드가 중단됐고, 직후 한 번은 이전 binary가 실행되어 같은 보수적 FAIL을 냈다. 이 실행은 최종 성공 근거에 포함하지 않았다. 외부 Host PID 입력·Host 서비스에 대한 signal/ptrace·파일 내용 읽기는 없다. ptrace는 이번 검사에서 미실행이다.

## Enforcing, Host 보존과 증거

- Global `getenforce=Enforcing`, SELinuxFS enforce=1 유지. [`access-final.jsonl`](../out/phase8b-sid-ksu/access-final.jsonl)의 startup/final access vector `flags=0`도 확인해 두 새 domain의 permissive 상태에 의존하지 않았음을 확인했다.
- Host 핵심 서비스 PID/starttime/SID/credentials/capabilities/cgroup, boot ID, KernelSU features, PID 1 mountinfo 및 module `sepolicy.rule` hash는 정책 추가 전과 최종 후에 동일했다.
- 정책 추가 **전** active policy hash는 UNAVAILABLE이었다. 추가 후에는 읽을 수 있었으며 최종 실행 전후 SHA-256은 `3a387548b2236f190ea070cc8c0bc12de73842c6874754c441b9a3601d565dd9`로 동일했다. 변경 전 정책과 byte-for-byte 비교한 것은 아니다. pre-policy snapshot과 최종 snapshot의 차이는 이 hash availability 행뿐이다.
- 최종 [`before.txt`](../out/phase8b-sid-ksu/final/before.txt) / [`after.txt`](../out/phase8b-sid-ksu/final/after.txt) SHA-256은 모두 `3572eb5dc079de38c083505eecc2f338113cf0a529ec26135bbb95176ee7b727`이다.
- 최종 probe SHA-256 `91fa3006131086f9a417590a4c19323d17c031c723c360f6c982241fa07a6bbc`, 적용 rule SHA-256 `3d709cdefef251c2785b00283d9165457e735bd489663991b128a44ceb680b28`. 적용 내용과 KernelSU 출력은 `final/guest.rule`, `final/policy-check.txt`, `final/policy-apply.txt`에 보존했다.
- `scripts/test-system-server-sid.py` PASS: pinned GSI patch 보존·덮어쓰기 거부, setter 실패 전달, startup 실패 시 final 미호출, 잘못된 옵션 거부, canary 회수 및 실패 시 접근 검사 미실행. Linux/Android 빌드 `-Wall -Wextra -Werror`, shell syntax 검사 PASS. WSLc는 sandbox 밖에서 실행했다.
- dmesg/logcat에서 Guest type만 사전 필터링했으나 실제 AVC는 확보되지 않았다. 위 원인 판정은 raw log 전체 또는 추측한 AVC가 아니라 SELinuxFS query 및 실제 syscall 반환값에 근거한다. bulk 분석 대상이 없어 로그 subagent는 사용하지 않았다.

## 현재 상태와 잔여 문제

**최종 Guest SID 획득 진단은 성공했다.** 두 새 Guest context의 kernel 유효성과 native startup→final 전이는 더 이상 차단 요인이 아니다. syscall `setcon()` 성공과 final SID readback을 확보했다.

실제 patched GSI `forkSystemServer()`의 최종 SID 획득은 아직 입증되지 않았다. GSI seapp lookup, final wrapper의 property 재초기화, ART hook, credentials/seccomp/cgroup, private Binder/property 서비스 접근 및 Framework 첫 부팅은 별도 runtime 검증 대상이다. 기존 cgroup 공용 ancestor·native gate 문제도 이 policy delta로 해결됐다고 주장하지 않는다. Guest 서비스 접근 AVC가 없으므로 서비스 정책이 충분하다는 판정도 하지 않는다.

**live Guest policy 추가분은 현재 커널에 남겨 두었다.** KernelSU 동적 type/rule 삭제는 시도하지 않았다. module policy 파일에는 영구 저장하지 않았으므로 이후 세션에서는 context 유효성을 재확인하고 기존 Guest type을 재사용해야 한다. 기기의 probe/query executable과 `/data/local/tmp` 전송 파일은 제거했으며 `/dev/ssal-guest-system-server-sid-ksu/`의 rule·runner·텍스트 증거는 보존했다. mount/cgroup/loop 자원은 생성하지 않았다.
