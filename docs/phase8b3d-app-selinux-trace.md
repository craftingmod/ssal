# Phase 8B-3D — App SELinux EINVAL 정밀 진단 및 동일 SID 수정

2026-11-06 KST. **최초 실패는 seapp lookup이 아니라 `security_check_context()` 내부의 SELinuxFS context write다.** Guest-only 타입을 선택하는 lookup은 성공한다. 기기의 KernelSU `selinux_hide`는 app UID에 별도 정책 뷰를 제공하며, UID 10000의 Guest context 검사를 `EINVAL`로 거부한다. 동일 SID 비교를 재검증보다 먼저 수행하는 Guest libselinux 수정으로 **Strict No-op Java child PASS**를 확인했다. 기존 fallback 모드 및 원본 라이브러리 복원 회귀도 PASS다.

## 실험 경계와 구현

- 기기 `R5CY52JC03H`, SM-S937N, 기존 `ssal-dev` Android 빌드 컨테이너와 NDK 재사용. Host/GSI policy, 신규 allow, global permissive, `selinux_hide` 설정 변경 없음. 기존 Guest 실험 도메인의 permissive 상태를 새로 변경하지 않았다.
- system image `/data/local/ssal/images/1793366406758-25627/system.img`, userdata `/data/local/ssal/guests/phase5a-bringup-20261104/userdata.img`. `/dev/ssal-phase8b3d`에 별도 staging했고 기존 phase7i/8b3b 실행 파일은 덮어쓰지 않았다.
- [`app-selinux-trace.c`](../native/binder-probe/app-selinux-trace.c): 기존 투명 no-op API wrapper를 재사용하고 libc `fopen`, `__write_chk`, 실제 `setcon`을 관측한다. 입력 errno, 원본 인자/길이, 결과 errno를 보존하며 결과를 성공으로 바꾸지 않는다. `pread`로 plat 규칙을 관측하므로 parser의 파일 위치를 바꾸지 않는다.
- 같은 파일의 Native probe는 UID/GID 0·1000·10000의 별도 Guest 프로세스에서 실행한다. Guest root/net/cgroup 경계를 기존 launcher로 구성하며 ART·SystemServer.main을 호출하지 않는다. 동일 overlay를 Zygote보다 먼저 설치하고 hidden context/lookup/check 함수의 결과와 전체 API를 비교한다. UID1000과 10000 모두 effective/permitted capability가 0이다.
- hidden 함수 호출 전 원본 GNU build ID와 함수/호출부 명령을 확인한다. 지원 build ID는 `7288c5fc0eb3408220b5893e7d0e2b89` 하나다. lookup 결과·target·UID별 검사 결과가 예상과 다르면 helper가 exit 2로 실패한다.
- launcher의 `SSAL_PHASE8B3D_TRACE`와 `SSAL_PHASE8B3D_SAME_CONTEXT`는 기본 비활성이다. 후자는 **Guest root의 `/system/lib64/libselinux.so`에 읽기 전용 bind**만 설치한다. 이미지 파일과 Host 라이브러리는 수정하지 않는다. module 패키지/기본 실행 경로에는 진단 산출물을 추가하지 않았다.

## 실제 로드 파일과 규칙

원본 라이브러리 최종 재현은 `out/phase8b3d/noop-1793900327/`이다. Zygote는 아래 네 경로를 각각 두 번 성공적으로 열었다. 첫 번째는 규칙 수집, 두 번째는 parsing에 해당한다. 성공 호출에 남아 있는 errno=2는 실패 판정이 아니다.

| 로드 경로 | 증거 |
|---|---|
| `/system/etc/selinux/plat_seapp_contexts` | `worker/phase7b/stderr.log:233–234,238–239` |
| `/system_ext/etc/selinux/system_ext_seapp_contexts` | 같은 파일 235,240행 |
| `/product/etc/selinux/product_seapp_contexts` | 같은 파일 236,241행 |
| `/vendor/etc/selinux/vendor_seapp_contexts` | 같은 파일 237,242행 |

열린 plat 파일의 실제 내용도 `user=_app seinfo=ssal_probe domain=ssal_guest_probe`로 기록됐다. `/odm` 파일의 성공 open은 관측되지 않았다. fallback root 경로(`/plat_seapp_contexts` 등)를 로드했다는 증거도 없다. vendor 코드베이스는 읽지 않았다.

Native UID10000 lookup은 **`result=0`**, target은 **`u:r:ssal_guest_probe:s0`**, 기존 SID도 같은 문자열이다(`worker.log:355`). 즉 이 실행에서 규칙 매칭 실패나 MLS 계산 오류는 아니다. 실제 Java child가 이후 context 검사에 전달한 문자열도 동일하다(`stderr.log:305`). Java child의 lookup 반환 register 자체를 breakpoint로 기록한 것은 아니지만, 해당 분기를 통과한 후에만 실행되는 검사 write와 target을 직접 관측했고 Native에서 같은 lookup을 독립 확인했다.

## 최초 실패와 내부 호출 흐름

원본 Guest libselinux를 역어셈블한 증거는 `out/phase8b3d/setcontext-disassembly.txt`다. 실제 바이너리는 다음 흐름이다.

```text
selinux_android_setcontext
  getcon@plt → context_new [hidden, 0xd664]
  seapp_context_lookup [direct BL, 0xa424] → 0
  context_str [hidden, 0xd854] → u:r:ssal_guest_probe:s0
  security_check_context [direct BL, 0xd0f0]
    __open_2 → /sys/fs/selinux/context
    __write_chk(fd, context, strlen(context)+1, ...) → -1/EINVAL  ← 최초 실패
  error → -1/EINVAL
  strcmp / setcon@plt / __system_properties_init 미도달
```

**libselinux 내부의 lookup/check는 심볼 interposer를 우회한다.** 또 setter 경로는 `selinux_android_setcon`을 호출하는 대신 inline된 `setcon@plt`와 property 초기화다. 8B-3B의 `selinux_android_setcon` 로그 부재만으로 setter 미호출을 확정할 수 없었던 이유다. 이번에는 실제 libc write와 `setcon`을 관측하고, 바이너리의 오류 분기까지 대조했다.

2026-11-06 **02:39:03.195 KST**, 원본 strict child PID **17328**:

```text
setcontext(uid=10000, server=0, seinfo=ssal_probe, name=ssal-fork-probe)
write(/sys/fs/selinux/context, "u:r:ssal_guest_probe:s0\0", 24) = -1, errno=22
setcontext = -1, errno=22; before=after=u:r:ssal_guest_probe:s0
JNI FatalError → SIGABRT → Zygote child reap
```

증거: `noop-1793900327/worker/phase7b/stderr.log:304–309,362–364`. 해당 child에서 실제 `setcon` 호출은 없다. 단순 로그 부재뿐 아니라 검사 실패 후 setter를 건너뛰는 제어 흐름으로 확인했다.

## 원인: app UID에 적용되는 SELinux Hide 정책 뷰

동일 Guest SID/namespace 조건에서 process UID만 달리한 Native 결과:

| 실제 UID/GID | lookup | Guest context 직접 검사 | 원본 setcontext |
|---|---:|---:|---:|
| 0 | 0 | 0 | 0 |
| 1000, capabilities=0 | 0 | 0 | 0 |
| 10000, capabilities=0 | 0 | -1 / EINVAL | -1 / EINVAL |

`noop-1793900327/worker.log:238–277,281–320,324–363`. Guest context는 NUL 제외 23 bytes와 포함 24 bytes 모두 UID10000에서 실패했고 UID0/1000에서는 canonical 문자열 readback까지 성공했다. 대조 context `u:r:system_server_startup:s0`는 모든 UID에서 NUL 포함/제외 모두 검사에 성공했다. **이 대조는 context query만 수행했으며 system_server SID로 전환하지 않았다.** 길이·NUL·capability 차이는 원인이 아니다.

기기 `ksud samsung-v2.2 (uapi: 5)`의 read-only feature 조회는 **`selinux_hide (ID=4) ENABLED`**, 설명은 app UID의 `/sys/fs/selinux` 응답 sanitize다(`device-features.txt:16–17`, `final-cleanup.txt:32–33`). 실행 커널에도 `my_write_context`, `security_context_to_sid_with_policy`, `ksu_selinux_hide_enabled` 심볼이 존재한다(`final-cleanup.txt:15–17`).

[KernelSU 공식 구현](https://github.com/tiann/KernelSU/blob/db6263d3bdf136c9f478308351dc6fa62a92edba/kernel/feature/selinux_hide.c#L95)은 UID<10000을 원래 validator로 전달하고 app UID는 `backup_sepolicy`에서 context를 검사한다. 동적으로 추가한 Guest type이 app용 backup 뷰에 없으면 원래 실행 SID로 존재하더라도 검사에서는 `EINVAL`이 된다. 실제 UID별 결과, 활성 feature, 실행 심볼이 이 경로와 일치한다. 고정 소스 사본은 `out/phase8b3d/ksu-selinux-hide.c`다.

따라서 **이번 API 실패 원인은 app UID의 SELinux Hide context 검증 뷰와 Guest-only 타입 사이의 불일치**다. Host active policy 전체가 해당 타입을 모른다거나 `process:transition` allow가 없어서 발생한 오류로 해석하면 안 된다. 설치된 samsung-v2.2의 정확한 소스/기계어와 upstream 전체를 byte 단위 비교하지는 않았다. 설정을 끄는 전역 A/B 실험도 하지 않았다. 확정한 runtime 경계는 UID10000의 context write 거부이며, 위 backup 정책 구현은 그 경계를 설명하는 공식 소스 근거다.

## 적용한 최소 수정

기존 libselinux는 target과 current가 같아 setter가 불필요해도 먼저 context를 재검증했다. 이를 아래 순서로 바꿨다.

```text
getcon → context_new → seapp lookup → context_str
  target == current: success, SID 유지, 검사/setter 없음
  target != current: 기존 security_check_context → 기존 setter/property 초기화
```

[`phase8b3d-same-context.patch`](../scripts/guest-domain-poc/phase8b3d-same-context.patch)가 소스 수정안이다. 실기기에서는 해당 소스 변경과 같은 제어 흐름을 갖도록 원본 바이너리의 `0x16abc–0x16ad0` **6개 명령, 24-byte 범위**를 재배치했다. [`patch-app-selinux-same-context.py`](../scripts/patch-app-selinux-same-context.py)는 원본 전체 SHA-256 및 기존 명령을 검증한 뒤 별도 파일을 만든다. unsupported input은 출력 없이 실패한다. 호출 대상, lookup, context 생성/해제, setter와 property 초기화는 바꾸지 않는다. disassembly와 변경 범위 검증은 `patched-disassembly.txt`, `patch-validation.txt`에 있다.

| Guest 라이브러리 | SHA-256 |
|---|---|
| 원본 | `9801ecf09ba52fcdd937b8195119996450628cf66e40b5896c1c5475411d3818` |
| 동일 SID 수정 | `f6d505753d378a33a148f3230cc81072fcd463bcb503dbb0aad41c5a5484ab9e` |

수정은 errno를 검사하거나 `EINVAL`을 성공으로 치환하지 않는다. **lookup이 성공하고 계산 문자열이 실제 current 문자열과 같을 때만** 아무 전이도 하지 않고 반환한다. 다른 SID의 검증은 계속 필요하다. 수정 Native probe에서 `ssal_missing_probe`의 lookup/API는 `-1`로 유지됐다(`noop-1793900447/worker.log:362–364`). 이 lookup 오류는 errno를 설정하지 않아 errno=0일 수 있지만 반환값은 실패다.

이 변경은 실험용 Guest overlay로 구현·검증했으며 기본 실행 경로에 강제 적용하지 않았다. 기기 staging 수정 라이브러리는 종료 후 제거했다. 재사용 시 고정 바이너리 patch보다 위 Guest libselinux 소스 패치를 해당 GSI 빌드에 적용하는 편이 유지보수에 적합하다. 원본 GNU build ID note는 바이너리 실험에서 유지되므로 수정 파일은 **SHA-256으로 구분**해야 한다.

## 비교 및 회귀

모든 아래 경로는 `out/phase8b3d/` 기준이다. worker exit와 harness snapshot 결과를 구분한다.

| 실행 | 결과 | Host snapshot |
|---|---|---|
| `noop-1793900327` 원본 + strict trace | Native UID10000 검사/API EINVAL, Java SIGABRT, worker exit 1 | 전후 동일 |
| `noop-1793900447` 수정 + strict trace | Native 직접 검사는 여전히 EINVAL, API 성공; Java Property/Binder/userdata PASS, exit 0/reap | 전후 동일 |
| `baseline-1793900497` 수정 + 기존 fallback 모드 | 원본 API result=0, fallback 불사용; Java PASS | 전후 동일 |
| `baseline-1793900541` 원본 복원 + 기존 fallback | 원본 API EINVAL, 기존 retained-domain fallback; Java PASS | 전후 동일 |

수정 strict native UID10000: `noop-1793900447/worker.log:326,355–365`. direct check는 `-1/EINVAL`, 전체 API는 `0`, 종료 SID는 기존 Guest SID다. 실제 Java child PID **19327**, **02:41:03.918 KST**, `stderr.log:304–305`에서 API `0`, errno=0, before=after가 동일하다. Java 결과와 정상 종료/회수는 `worker.log:403–413`이다. 실제 child의 재검증 write와 setter 호출은 없다.

수정 baseline은 `baseline-1793900497/worker/phase7b/stderr.log:393`에서 API 성공, 원본 복원은 `baseline-1793900541/worker/phase7b/stderr.log:395–397`에서 EINVAL/기존 fallback이다. 모두 `worker.log:271,281`에서 Java와 exit/reap PASS다.

초기 진단 `noop-1793899820`과 초기 baseline `baseline-1793900048`은 Host property `sys.siop.level`, `wlan.p2p.temp` 값만 -3→-2로 바뀌어 기존 harness의 exact snapshot 검사가 실패했다. 이를 성공으로 덮어쓰지 않았다. 다른 core 항목 차이는 없었고 최종 세 회귀는 exact equality를 확보했다. 전체 검산은 `snapshot-verification.json`이다.

## Host 상태 및 정리

- 최종 strict/fixed baseline/restored baseline 전후 snapshot의 Host service PID/starttime, SID, credentials, capability, namespace, PID1 mountinfo, property 출력, endpoint metadata, loop 목록, module rule hash가 byte-for-byte 동일하다.
- Global Enforcing 유지. boot ID `03834516-215d-4fd6-8960-1b833882595e`, Host Zygote PID1840/starttime783, system_server PID2911/starttime934 유지. adbd/netd/servicemanager/surfaceflinger도 정상 SID/PID 유지(`final-cleanup.txt:2–9`).
- module `sepolicy.rule` SHA-256 `f23c957c0eb653b8fdcba5f0d6151c1687aeb4545ef0d7ad1b87963511a6801d` 동일. active `/sys/fs/selinux/policy` export는 기존처럼 EINVAL로 불가하므로 active binary hash 동일성은 미검증이다.
- fixed strict `worker.log:428–434`: Java userdata probe 정리, Guest cgroup 제거, residual rootfs mount 없음, loop allocation **56개** 해제. 두 baseline도 `worker.log:296–302`에서 동일 정리 PASS.
- 최종 별도 검사에서 Guest cgroup/session mount/loop, trace SO 잔여 매핑 없음. Host 주요 프로세스 SID 정상. 임시 trace SO/helper/수정 라이브러리와 전송 파일 제거 완료(`final-cleanup.txt:3,35`). 텍스트 실행 증거와 기존 실행 도구는 보존했다.
- raw logcat/dmesg 전체를 주 에이전트 문맥에 읽지 않았다. 로컬 prefilter 후 Luna에게 실패/회귀/정리 분석을 위임했다. 필터 dmesg에는 이 EINVAL보다 먼저 발생한 관련 AVC 원인 증거가 없었다. 실시간 syscall 로그가 최초 실패를 확정한다.

## 빌드·재현 및 검증

WSLc는 저장소 규칙에 따라 sandbox 밖에서 실행했다. 기존 컨테이너에서 로그인 셸은 cargo PATH를 지워 `cargo: command not found`였으므로 `bash -c`/직접 exec를 사용했다. NDK와 cargo를 신규 설치하지 않았다.

```sh
wslc exec ssal-dev bash scripts/build-guest-launcher.sh
wslc exec ssal-dev bash scripts/build-app-selinux-trace.sh
wslc exec ssal-dev python3 scripts/test-app-selinux-trace.py
```

build trace 스크립트는 원본 Guest 라이브러리 `out/phase7fb/source/libselinux.so`를 입력으로 쓴다. `out/phase8b3d/bin`은 원본 진단용 helper/SO, `fixed`는 수정용 helper/라이브러리, `run.sh`는 기존 8B-3B safety harness를 새 staging 경로와 trace flag로 생성한 것이다. helper는 기존 `ssal-selinux-startup-probe` 슬롯 이름으로 staging하므로 **기본 startup helper로 설치하면 안 된다.**

기기에 기존 worker 도구와 갱신한 ssald/run.sh/trace SO를 별도 staging한 뒤:

```sh
# 원본 helper를 staging, SAME_CONTEXT 없이 원본 실패 재현
sh /dev/ssal-phase8b3d/run.sh noop
# fixed helper와 ssal-libselinux-same-context.so를 staging
SSAL_PHASE8B3D_SAME_CONTEXT=1 sh /dev/ssal-phase8b3d/run.sh noop
```

baseline 회귀는 run.sh에서 `export SSAL_PHASE8B3D_TRACE` 줄만 뺀 `regression.sh`로 실행했다. 수정 baseline은 SAME_CONTEXT=1, 원본 복원 baseline은 해당 변수를 설정하지 않았다. 현재 기기의 trace/helper/fixed library는 정리됐으므로 재실행하려면 다시 staging해야 한다.

- Android launcher/helper/SO 빌드 PASS, 기존 memory-probe dead-code warning만 유지(`build.txt`).
- 새 trace 투명성 테스트 PASS: context/길이, incoming errno, 반환값과 errno, 실패 fopen 보존(`trace-tests.txt`).
- 기존 no-op 8조합·missing symbol 테스트 및 fallback/crash tests PASS(`noop-tests.txt`, `diag-tests.txt`).
- `cargo test --locked --bin ssald`: **50 passed, 0 failed, 4 ignored**(`rust-tests.txt`).
- exact input 거부/6명령 변경 범위, source patch dry-run, Python 및 shell 문법 PASS(`patch-validation.txt`, `source-patch-check.txt`).

미검증: 전체 LineageOS 부팅, 실제 SystemServer specialization, 다른 SID로의 수정 라이브러리 전이 회귀, 다른 GSI/32-bit, 설치된 KSU 소스와 upstream의 완전 일치. 이 수정은 **동일 SID 유지 경로만 해결**하며, app UID에서 다른 Guest-only SID를 검증·설정하는 SELinux Hide 충돌은 별도 과제다.
