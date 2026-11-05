# Phase 8B — Guest System Server SID 분리

2026-11-06 KST. **GSI 패치 산출물 생성 PASS / Guest 최종 SID 획득 FAIL / Host 상태 보존 PASS.** 실제 `forkSystemServer()` 및 Framework 실행은 하지 않았다. 실패를 stock SID, 기존 Guest SID 유지, setter 성공 위조로 우회하지 않았다.

후속: KernelSU Guest policy 추가 승인 후 [native SID 획득 및 canary 검사는 PASS](phase8b-guest-system-server-sid-ksu.md)했다. 아래 내용은 policy 추가 전 실패 기록이며, 실제 patched GSI fork는 후속에서도 미실행이다.

## 재검토와 확인된 경로

- [8B-2](phase8b2-selinux-transition.md)의 source patch는 미적용 초안이었다. [8B-3B](phase8b3b-results.md)의 native 진단에서는 stock startup → stock final 전환이 실제 성공했으므로, startup 전이가 항상 실패한다는 가정은 사용하지 않는다.
- [8B-4B-1](phase8b4b1-system-server-preflight.md)에서는 동일 UID/stock SID canary의 signal0 및 proc root/FD 접근이 성공했다. 이는 관측된 경계 실패이며 SID 문자열이 같다는 정적 경고와 구분한다.
- [Hardcoded Context Audit](hardcoded-selinux-context-audit.md)의 arm64 GSI를 다시 disassemble했다. `forkSystemServer()` → native specialization → `selinux_android_setcontext(..., true, ...)` 호출 VA **0x260c78** → ART system-server hook → literal 로드 **0x260dc8/0x260dcc** → `selinux_android_setcon` 호출 **0x260dd0** 순서다. 마지막 setter의 0 이외 반환은 기존 fatal 분기로 간다. ART hook은 최종 setter보다 앞에 있다.
- literal의 파일 offset/VA는 **0x948fc**, 값은 `u:r:system_server:s0`다. 이 빌드의 해당 PT_LOAD에서는 file offset과 VA가 같다. `seapp_contexts`만 바꾸면 마지막 target은 바뀌지 않는다.

## 최소 GSI 패치

[`patch-system-server-sid.py`](../scripts/patch-system-server-sid.py)는 고정된 두 입력의 SHA-256과 실제 callsite instruction을 검사하고 **별도 디렉터리**에 산출물을 만든다. 원본 이미지·추출물 및 기기 GSI는 수정하지 않았다.

| 대상 | 변경 |
|---|---|
| Guest arm64 `libandroid_runtime.so` | offset 0x948fc의 NUL 종료 literal만 `u:r:ssal_guest_ss:s0`로 대체 |
| Guest `plat_seapp_contexts` | `isSystemServer=true domain=ssal_guest_ss_startup`으로 selector 변경 |

`ssal_guest_ss`는 `system_server`와 길이가 같아 ELF 배치, pointer instruction, setter와 fatal 분기를 변경하지 않는다. 8B-2 초안의 긴 type 이름과는 **다른 type**이며 이번 [정책 초안](../scripts/guest-domain-poc/phase8b-guest-system-server.rule)도 이 이름을 사용한다. 설치된 seapp 파일에는 build-time neverallow 행이 없어 새 행을 주입하지 않았다. 재빌드 시 source의 Guest type neverallow 검사는 8B-2 source patch와 같은 방식으로 적용해야 한다.

| 파일 | SHA-256 |
|---|---|
| 입력 runtime | `d35220026ef94be6992d8b9b31cd446f937b8e782833813b2ac68140f41fc035` |
| 입력 seapp | `7a4d14a898fb234d87cd49ae106e245324ad365d9029230d2a6306e6d4aa7a7a` |
| 출력 runtime | `aa9ba993930cdf961c2d2a8e5022a87fca79283688faa8135d414cf7c656a923` |
| 출력 seapp | `5dedabe4fc84cb3344f55bb9e054e92b008fedee847deae7f6f4ad7c7b639d0b` |

출력: `out/phase8b-sid/patched/` (arm64 한 빌드 전용). launcher 연결, 원본 image repack 및 설치는 하지 않았다. 정책이 target context를 받아들이지 않는 상태에서 patched Zygote를 실행하지 않았다.

## 단발 실기기 검증

SM-S937N, serial `R5CY52JC03H`, **04:09:20 +0900**. 증거는 [`out/phase8b-sid/probe.txt`](../out/phase8b-sid/probe.txt)의 줄 번호 기준이다. raw logcat/dmesg/AVC는 수집하지 않았으며 bulk 로그 분석 대상도 없다.

[`guest-system-server-sid.c`](../native/binder-probe/guest-system-server-sid.c)는 native 진단이며 GSI Zygote가 아니다. root parent는 SELinuxFS context validation만 수행하고, disposable child는 `ssal_guest_probe`로 진입한 뒤 groups를 비우고 UID/GID 1000으로 낮춘 다음 **Guest final target에 직접 `setcon()`**을 호출한다. startup 및 ART 경로를 재현하지 않는다. Android 시스템 `libselinux.so`를 사용하므로 GSI `selinux_android_setcon()`의 property 재초기화까지 검증한 것이 아니다.

| 검사 | 관측 | 판정 |
|---|---|---|
| 알려진 Guest source context validation | `ssal_guest_probe`: result=24 errno=0 (:2) | PASS control |
| 알려진 stock final context validation | `system_server`: result=21 errno=0 (:3), 전환은 하지 않음 | PASS control |
| 새 Guest startup context validation | result=-1 errno=22 (:4) | FAIL |
| 새 Guest final context validation | result=-1 errno=22 (:5) | FAIL |
| 실제 final `setcon()` | result=-1 errno=22, before=after=`u:r:ssal_guest_probe:s0` (:6–7) | **SID 획득 FAIL** |
| startup 전환 / 실제 GSI fork | 미실행 (:8–9) | NOT RUN |
| Guest final SID에서 Host canary 접근 | target SID 획득 실패로 미실행 (:9) | **NOT RUN, 격리 PASS 아님** |
| child 정리 | PID 23938 reap, exit 1 (:10–11), 별도 PID 부재 확인 | PASS |
| Enforcing / Host 전후 snapshot | Enforcing=1 유지, snapshot 동일 (:12) | PASS |

원인은 현재 커널이 두 새 context를 인정하지 않는다는 것이다. 알려진 context validation은 같은 root 호출에서 성공했으며, 실제 setter도 EINVAL을 반환했다. 이것을 `dyntransition` allow 부족에 의한 EACCES로 해석하지 않는다. 커널 정책 전체를 읽지 못했으므로 내부 type table 부재와 role/type 조합 문제까지 개별적으로 확정하지는 않는다.

Host sepolicy 변경 금지 조건에 따라 `ksud sepolicy patch/apply`, 전역·domain permissive 변경은 모두 실행하지 않았다. 공유 커널에서는 GSI의 seapp/CIL 파일만 수정해도 실행 중 SELinux policy에 새 SID가 생기지 않는다. 따라서 Guest-only 새 type/role 유효성과 startup/final 전이 규칙을 **실제 로드된 정책에 반영하지 않은 상태**가 현재 실행 차단 원인이다. 준비한 rule은 검토용이며 적용하지 않았다. 이 조건을 해결하지 않은 채 다른 SID로 재시도하지 않았다.

## 검증, 보존 범위 및 잔여 문제

- `python3 scripts/test-system-server-sid.py`: PASS. pinned 입력 패치, literal 외 runtime 전체 byte 보존, selector 외 seapp 보존, 잘못된 입력 거부, mock setter EINVAL 보존, stock target fallback 부재 및 child reap 검사.
- Android NDK arm64 빌드와 Linux mock 빌드: `-Wall -Wextra -Werror` PASS. runner `sh -n` PASS. WSLc는 저장소 지침에 따라 sandbox 밖에서 실행했다.
- Host snapshot: boot ID, Global Enforcing, KernelSU feature 상태, module `sepolicy.rule` hash, PID 1 mountinfo hash, init/zygote64/system_server/servicemanager/surfaceflinger/adbd/netd/lmkd/installd의 PID/starttime/SID/credentials/capabilities/cgroup 동일. [`before.txt`](../out/phase8b-sid/before.txt) / [`after.txt`](../out/phase8b-sid/after.txt) SHA-256은 모두 `65504cb9bc70d499b21020dd7a6d514e416cc775345de8bb5356e03a5e9dc499`.
- active kernel policy hash는 **UNAVAILABLE**이며 정책 전체 불변을 hash로 검증했다고 주장하지 않는다. Host 서비스에 신호·ptrace를 보내거나 설정을 변경하지 않았다. canary도 만들지 않았다.
- probe SHA-256: `be71dbc291674df5d2499ca7c1e3e8eceb7f3b6ee1dd07d1f852a817f0736d82`. 실행 후 기기 probe와 `/data/local/tmp` 전송 파일은 제거했다. `/dev/ssal-guest-system-server-sid/`에는 runner와 텍스트 증거만 남겼다. mount/cgroup/loop 자원은 생성하지 않았다.
- 잔여 **정책 선행 문제**: Guest startup/final context의 kernel 유효성. 그 후에야 `setcurrent`/`dyntransition`, role 제약, exit notification 및 실제 GSI setter의 후속 property 접근을 검증할 수 있다. 검토용 delta는 이 모든 권한의 충분성을 증명하지 않는다.
- 잔여 **런타임 미검증**: patched `forkSystemServer()`의 startup/final 실제 SID, GSI `selinux_android_setcon()` 반환, enforcing 상태에서 canary signal/proc/ptrace 차단, 실제 credentials/cgroup/FD 및 Framework 첫 부팅. 기존 cgroup 공용 ancestor와 native gate 문제도 이번 literal 패치로 해결되지 않는다.

이번 단계에서는 `hidepid=4` 실험을 진행하지 않았다. **완료 판정: GSI target 분리 패치는 생성했으나, Guest System Server의 최종 SID 분리 성공은 입증되지 않았고 실제 setter 진단은 실패했다.** 새 context 유효성 문제와 아직 도달하지 않은 서비스 접근 정책 문제를 분리하여 남긴다.

재현 (기기 실행 전 probe staging 필요):

```sh
wslc exec ssal-dev python3 scripts/test-system-server-sid.py
wslc exec ssal-dev python3 scripts/patch-system-server-sid.py out/phase7fb/source/libandroid_runtime.so out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system/etc/selinux/plat_seapp_contexts out/phase8b-sid/new-output
adb shell su -c 'sh /dev/ssal-guest-system-server-sid/run.sh'
```
