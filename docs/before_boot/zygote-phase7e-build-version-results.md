# Phase 7E — Build.VERSION 초기화 수정

2026-11-05 KST. **PASS: 기존 Build.VERSION ArrayIndexOutOfBoundsException 해결 및 class/full preload 완료.** Zygote 상주·ABI readiness는 다음 socket 오류로 아직 미완료다. 로그 시각은 Guest logger 기준이며 클라이언트 KST와 같은 시간대라고 가정하지 않는다.

## 원인 확인

[Android 16 r3 Build.java](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r3/core/java/android/os/Build.java)의 `getStringList()`는 property가 빈 문자열이면 빈 배열을 반환한다. `ALL_CODENAMES`는 `ro.build.version.all_codenames`에서 만들어지고 `ACTIVE_CODENAMES` 초기화가 `[0]`에 접근한다. 참조 소스에서는 해당 표현식이 524행이고, 실제 Guest stack의 line table은 `Build.java:522`다. 소스 버전의 행 번호가 완전히 같다고 가정하지 않았다. [확보한 참조 소스](../out/phase7e-build-version/Build.android16.java).

현재 기기의 사용 중 Guest system image를 별도 mount namespace에서 읽기 전용으로 열어 `/system/build.prop`를 추출했다. SDK 36, full SDK 36.1, codename REL, **all_codenames REL**이다. 해당 key는 원본 37행과 191행에 있으며 값이 모두 같다. 원본과 복사본 SHA-256 모두 `a84de5aa57503072aac70e446aab709b9c424acb47d15e1c756c6ec34ee6a9c0`이다. [원본](../out/phase7e-build-version/guest-original-build.prop), [추출·해시 로그](../out/phase7e-build-version/guest-original-properties.log).

기존 seed 목록에는 all_codenames가 없었다. 이를 코드만으로 판단하지 않고, 기존 helper로 baseline Zygote를 실행했다. Guest 전용 diagnostic preload constructor에서 bionic의 `__system_property_find/get`으로 **실제 Zygote PID의 값**을 읽었다. dex2oat 자식도 preload를 상속하므로 로그에는 자식 PID가 별도로 나오며 비교에는 worker가 생성한 Zygote PID만 사용했다.

| 값 | Guest 원본 | baseline Zygote PID 10426 | 수정 후 Zygote PID 11327 |
|---|---|---|---|
| ro.build.version.sdk | 36 | present=1, 36 | present=1, 36 |
| ro.build.version.codename | REL | present=1, REL | present=1, REL |
| ro.build.version.all_codenames | REL | **present=0, 빈 값** | **present=1, REL** |

baseline stderr 1~3행과 수정 후 stderr 1~3행이 실제 bionic 관측이다. maps에서 property area는 각각 해당 실행의 `worker/rootfs/dev/__properties__` 파일이다. 기존 launcher의 Host/Guest area dev·inode 비교, Host serial/property socket 부재 검사도 유지했다. Host SDK는 37이고 Guest 관측은 36이다. Host 속성을 복사하지 않았다.

baseline은 `11-04 17:54:46.075`, stderr 147~148행에서 `Build$VERSION`의 같은 `ArrayIndexOutOfBoundsException: length=0; index=0`을 재현했다.

## 최소 수정

- `experiments/rsbinder-phase2/src/lib.rs`: Guest build.prop의 정확한 all_codenames key에서 값을 읽는 작은 parser와 테스트를 추가했다. 누락/빈 값은 오류로 반환하며 REL이나 Host 값으로 대체하지 않는다.
- `experiments/rsbinder-phase2/src/android_probe.rs`: 기존 private area seed에 이 값 한 개를 추가했다. rsproperties readback이 원본과 같은지 검증하고 초기화 JSON에 원본·관측값을 남긴다. 실제 실행 JSON의 두 값 모두 REL이다 (`fixed/worker.log:198`).
- `native/binder-probe/zygote-diagnostics.c`: Android에서 위 세 key의 존재·값을 실제 실행 프로세스에서 읽어 stderr에 남긴다. setter나 Host 조회 경로는 없다.

Launcher·ART·Framework·Binder·SELinux·cgroup 구조는 변경하지 않았다. 기존 SDK 36.1 이미지 제한도 그대로다. build.prop 전체나 임의의 Host 속성을 가져오는 기능을 추가하지 않았다.

## 수정 후 실기기 결과

Guest Zygote PID 11327에서 기존 Build.VERSION 예외와 SIGSEGV가 재발하지 않았다. 기존 class 초기화 실패 없이 다음을 완료했다.

| Guest 로그 시각 | 관측 | fixed stderr 행 |
|---|---|---|
| 17:56:03.429 | **18,803 classes preload 완료**, 631ms | 259~260 |
| 17:56:03.456 | 41 resources preload 완료 | 289~290 |
| 17:56:03.528 | ZygoteHooks.endPreload 호출 | 297 |
| 17:56:03.531 | **end preload**, 총 856ms | 300~301 |
| 17:56:03.585 | ZygoteInit 단계와 GC 완료 | 305~307 |

optional class-not-found, Aconfig, trace file, boot-image read-barrier fallback 경고는 남아 있다. 이들을 이번 fatal 원인으로 해석하거나 추측으로 수정하지 않았다. 실제 로그의 `Build$VERSION; failed initialization` 및 `ArrayIndexOutOfBoundsException` 부재와 full preload 완료를 assert로 확인했다. 별도 reflection probe로 Build.VERSION 필드를 출력한 것은 아니다.

**다음 오류의 최초 지점:** preload 이후 `17:56:03.585`에 `Unable to fetch Zygote socket file descriptor` 및 USAP pool FD 조회 오류가 나온다 (`stderr:308~309`). 이어 command socket 접속을 받는 시점인 `17:56:03.590`에 최초 fatal이 발생한다 (`stderr:315~322`).

```text
com.android.internal.os.ZygoteSecurityException:
  Only system UID is allowed to connect to Zygote.
  ZygoteConnection.<init>(ZygoteConnection.java:97)
  ZygoteServer.createNewConnection(ZygoteServer.java:210)
  ZygoteServer.acceptCommandPeer(ZygoteServer.java:201)
  ZygoteServer.runSelectLoop(ZygoteServer.java:510)
  ZygoteInit.main(ZygoteInit.java:916)
```

현재 `Service::wait_for_socket`은 root worker에서 `UnixStream::connect`와 `--query-abi-list`를 수행한다 (`src/guest_launcher.rs:245`). 이 readiness client의 UID와 관련된 실패로 보이지만 실제 peer credential dump는 수집하지 않았다. 이번 요청에 따라 다음 장애는 기록하고 socket/UID 경로를 추가 수정하지 않았다. Java fatal 후 native exit code는 0이며 worker는 readiness 이전 종료를 실패로 처리했다.

## Host 보호와 cleanup

Zygote 실행은 baseline/수정 후 각 1회였다. 기존 프로파일의 공유 PID/procfs, Guest private Binder, Guest userdata와 Guest-only permissive 진단 경계를 유지했다. `--start-system-server`, Host property setter/임의 복사, Host 서비스 조작·핵심 PID attach/kill, global permissive, policy 추가 및 재부팅은 수행하지 않았다.

- 두 실행 모두 Enforcing, boot ID, PID 1 mountinfo, Host core PID/starttime/credentials와 IPC endpoint snapshot이 일치했다. 모든 `ro.*` Host 속성과 비교 대상 version 속성도 전후 일치했다.
- baseline은 전체 Host snapshot/getprop도 일치했다. 수정 후 전체 property hash는 달라졌으며, 원문 비교상 변경은 **`sys.siop.level`, `wlan.p2p.temp` 두 key의 -2 → -3**뿐이다. SSAL이 이를 썼다는 증거는 없으며 이 결과를 전체 Host 속성 불변으로 표시하지 않는다. [자동 대조 결과](../out/phase7e-build-version/verification.json).
- 두 Zygote 실행에서 cgroup cleanup, rootfs residual mount 부재, 55개 loop 해제를 확인했다. 기존 helper SIGTERM/timeout 회귀도 각각 `LIFECYCLE_PASS`: pidfd reap, controller 원복 및 Host 핵심 snapshot 비교를 통과했다. 이는 Zygote 자체의 SIGTERM/timeout 시험은 아니다.
- 최종 Guest v2/v1 그룹 부재, controller 원복, 세션 process root/exe 및 loop backing 부재를 확인하고 전용 tmpfs를 unmount/rmdir했다. `BUILD_VERSION_CLEANUP_PASS`를 확보했다. Guest 영구 userdata와 증거는 보존했다.

## 검사와 증거

- property helper Rust 단위 테스트 **2 passed** (원본 REL/개발 codename 유지, 누락/빈 값 거부 포함).
- ssald Rust **46 passed, 3 privileged ignored**. Android AArch64 release 및 guest_probe 빌드 PASS. Rust fmt/native crash collector 자가검증 PASS. 기존 memory-probe dead-code 경고는 남아 있다.
- 기기에 배포한 수정 guest_probe SHA-256: `24db6b5f468e4c4b240ae227bc218dce2770d32decb3692d4dd5579363f4b7d7`. 로컬 결과와 일치한다. 나머지 binary hash는 verification.json에 있다.
- [baseline bionic 관측](../out/phase7e-build-version/baseline-zygote-properties.txt), [수정 후 bionic 관측](../out/phase7e-build-version/fixed-zygote-properties.txt), [baseline stderr](../out/phase7e-build-version/baseline/worker/phase7b/stderr.log), [수정 후 stderr](../out/phase7e-build-version/fixed/worker/phase7b/stderr.log), [필터 로그](../out/phase7e-build-version/fixed-filter.log). bulk 필터 로그 분석은 Luna에 위임했다.
- Host [before](../out/phase7e-build-version/fixed/before.txt) / [after](../out/phase7e-build-version/fixed/after.txt), raw properties [before](../out/phase7e-build-version/fixed/properties-before.txt) / [after](../out/phase7e-build-version/fixed/properties-after.txt).
- [property tests](../out/phase7e-build-version/property-tests.log), [launcher tests](../out/phase7e-build-version/launcher-tests.log), [Android build](../out/phase7e-build-version/android-build.log), [native tests](../out/phase7e-build-version/native-tests.log), [lifecycle 회귀](../out/phase7e-build-version/lifecycle-regression.log), [cleanup](../out/phase7e-build-version/cleanup.log).

이 PASS는 Build.VERSION 초기화와 preload에 한정된다. ABI 응답·Zygote 상주·전체 Android 부팅·장시간 Host 안정성과 재부팅 복구는 아직 검증되지 않았다.
