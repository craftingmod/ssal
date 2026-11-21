# Phase 8B-3C — App SELinux `EINVAL` 원인 분석

2026-11-06 KST. **최초 실패가 `selinux_android_setcontext()` 내부임은 재현됐지만, 현재 증거로 `seapp_context_lookup()`와 `security_check_context()` 중 하나까지는 특정되지 않았다.** 실패 child에서 `setcon` 호출은 계측되지 않았다. 따라서 원인은 이 두 선행 단계 중 하나로 제한되며, setcon/transition 권한 문제라는 증거는 없다.

## 결론

- 실제 Zygote child는 `setcontext(10000, false, "ssal_probe", "ssal-fork-probe")`에서 `-1/EINVAL`을 받았고, `selinux_android_setcon()` 단계에 이르지 못한 것으로 보인다. no-op interposer 로그에는 setcontext entry/result만 있고, 해당 child의 setcon 인자 로그는 없다. 동적 심볼 interposition이 libselinux 내부 호출에도 적용되는지 별도 검증하지 않았으므로, 이는 강한 정황이지 단독 확증은 아니다.
- Guest Zygote에 설정된 전용 seapp 규칙은 `user=_app seinfo=ssal_probe domain=ssal_guest_probe`다. AOSP libselinux 구현대로 이 규칙이 실제 로드되어 매칭됐다면, 기존 SID의 type만 `ssal_guest_probe`로 바꾸며 생략된 `levelFrom`은 `none`이므로 계산 target은 **`u:r:ssal_guest_probe:s0`**다. 이 target은 당시 child의 기존 SID와 동일하다. 런타임에서 계산된 target 문자열 자체는 기록되지 않아 이 부분은 규칙과 AOSP 구현에서 도출한 값이다.
- 이 context는 Zygote에서 SELinuxFS `/sys/fs/selinux/context`에 쓰기 검사로 유효했고(`result=23`, 8B-3B `stderr.log:8`), 실패 전후 child SID도 동일했다(`stderr.log:297`). 따라서 `ssal_guest_probe`의 type/SID가 해당 실행의 live policy에서 유효했다는 점은 뒷받침된다. 다만 8B-3B에는 `/sys/fs/selinux/policy` 읽기가 `EINVAL`이라 live binary policy를 export/hash하지 못했다. 2026-11-04에 저장한 Host policy hash는 다른 시점의 자료이고, 당시 offline 분석에서 `ssal_guest_probe`가 없었다. 그 뒤 KSU 동적 정책으로 타입이 추가됐을 수 있어 그 저장본만으로 8B-3B 시점의 Host active policy를 판정할 수 없다.
- 이 경로의 기대 target type은 기존 Guest SID와 같아 SELinux domain transition 자체가 필요하지 않다. libselinux는 context가 현재 SID와 같으면 `setcon`을 건너뛴다. 따라서 `process:transition` 권한을 추가하는 것은 근거 없는 수정이다. `setcon`이 실제 호출됐다면 검사할 권한은 `process:setcurrent`이며, 현재 로그는 그 호출도 증명하지 않는다.

## 호출 경로와 실패 위치

Android libselinux의 경로는 다음 순서다.

1. `is_selinux_enabled()`와 `getcon()`으로 현재 SID를 읽는다.
2. `context_new(orig_ctx)` 후 `seapp_context_lookup(SEAPP_DOMAIN, uid, isSystemServer, seinfo, pkgname, ctx)`를 호출한다.
3. 계산된 context 문자열을 얻고 `security_check_context(ctx_str)`로 커널 policy 유효성을 검사한다.
4. 새 문자열과 기존 문자열이 다를 때만 `selinux_android_setcon(ctx_str)`을 호출한다.
5. 오류는 공통 `Error setting context for app ...: strerror(errno)`로 보고되므로 이 메시지만으로 2/3/4 단계를 구별할 수 없다. [AOSP libselinux `android_device.c`](https://android.googlesource.com/platform/external/selinux/%2B/refs/heads/master/libselinux/src/android/android_device.c#92)

UID 10000은 Android의 `_app` 범위다. 실험 Guest overlay의 `user=_app seinfo=ssal_probe` 항목이 매칭돼야 하고, AOSP lookup은 선택 항목의 `domain`을 context type으로 설정한다. `levelFrom`이 없으면 `LEVELFROM_NONE`이라 기존 MLS range를 유지한다. [AOSP `android_seapp.c` lookup](https://android.googlesource.com/platform/external/selinux/%2B/main/libselinux/src/android/android_seapp.c#694) [AOSP `seapp_contexts` 규칙 설명](https://android.googlesource.com/platform/system/sepolicy/%2B/cfeaa1c664afbd10c7a52e845ec4c08c9eabb525/private/seapp_contexts)

8B-3B 실기기 증거, Guest Zygote PID 27910 / child PID 27960, 2026-11-06 02:04 KST:

```text
SSAL_SELINUX_ARGS ... uid=10000 server=0 seinfo=ssal_probe name=ssal-fork-probe
SELinux: selinux_android_setcontext: Error setting context ... Invalid argument
SSAL_SELINUX_NOOP ... result=-1 errno=22
  before=u:r:ssal_guest_probe:s0 after=u:r:ssal_guest_probe:s0
JNI FatalError ... selinux_android_setcontext(...) failed
```

근거 파일: `out/phase8b3b/noop-1793898233/worker/phase7b/stderr.log:294-298`. 로그에서 setcon wrapper entry를 찾을 수 없고, fatal 이후 JNI가 abort했다. 로그만으로 seapp 규칙이 실제 로드됐는지, `security_check_context()`가 어떤 문자열을 검사했는지는 알 수 없다. 그래서 최초 확정 위치는 **API 내부, seapp lookup/context 유효성 검사/미관측 setter 중 선행 부분**이다. 현재 정황은 setter보다 앞선 단계에 무게를 두지만, 별도 계측 전에는 둘 중 하나로 단정하지 않는다.

## 기존 fallback과 원본 호출 비교

기존 fallback은 특정 probe 인자(UID 10000, `ssal_probe`, `ssal-fork-probe`)와 제한된 실행 조건에서만 작동한다. 원본 API의 `EINVAL` 뒤, 기대 context `u:r:ssal_guest_probe:s0`가 SELinuxFS 검사에 통과하고 현재 child context와 일치하는지 확인한 다음 기존 SID를 유지한 채 성공으로 반환한다. 즉 fallback은 seapp 계산이나 domain transition을 성공시킨 것이 아니라, 해당 probe는 이미 허용된 Guest SID에 있으므로 불필요한 재설정을 생략한다.

baseline에서 Java Property/Binder/userdata 검사, 정상 종료 및 child 회수가 통과했다. strict no-op에서는 같은 원본 `EINVAL`을 보존하여 JNI fatal/SIGABRT가 났고, baseline 복원 후 정상 경로가 다시 통과했다. 따라서 정상 child 경로 보존은 PASS, 원본 API의 독립 성공은 FAIL이다. 근거는 [Phase 8B-3B 결과](phase8b3b-results.md)의 실행 표와 worker 로그다.

## Active policy 및 권한 판단

| 질문 | 결과 |
|---|---|
| 선택 target SID | `u:r:ssal_guest_probe:s0` — Guest overlay와 AOSP lookup 의미에서 추론; 런타임 계산 문자열 미계측 |
| live policy에서 해당 SID 유효성 | SELinuxFS context 검사 성공 및 Guest 프로세스의 실제 SID로 확인 |
| 8B-3B Host active binary policy type/AV | binary 읽기 `EINVAL`; byte/hash 및 전체 AV 분석 불가 |
| transition 허용 여부 | 이번 동작은 동일 type target을 기대하므로 transition 불필요. `process:transition`은 이번 `EINVAL`의 해결 권한으로 볼 근거 없음 |
| `process:setcurrent` | `selinux_android_setcon()` 호출이 확인되지 않아 미측정; 새 allow를 제안할 증거 없음 |

Host active policy의 유효성 확인을 현재 실행 SID의 유효성 이상으로 확대하지 않는다. 새 allow, Host/GSI 정책 수정, permissive 변경 없이 본 분석을 완료했다. 기존 정상 fallback을 제거하거나 범위를 넓힐 근거도 없다.

## 최소 수정안 및 다음 구분 실험

현재 증거로 Host 정책이나 Java child 경로를 수정하지 않는다. 안전한 최소 동작은 이미 있는 probe 한정 retained-domain fallback을 유지하는 것이다. 원본 libselinux 호출을 성공시키려면 먼저 `seapp_context_lookup()`의 반환값과 선택 규칙, `security_check_context()`에 전달되는 정확한 context를 각각 계측해야 한다. 기존 no-op 로그는 `selinux_android_setcontext`와 `selinux_android_setcon`만 감시하므로 이 구분을 할 수 없다.

다음 별도 Native probe는 Guest root/cgroup/network 경계 안에서 같은 `uid/seinfo/name`으로 `selinux_android_setcontext()`를 한 번 호출하고, entry/exit SID와 errno, `security_check_context` 호출 인자·결과, `selinux_android_setcon` 호출 인자·결과를 기록해야 한다. seapp lookup 규칙을 시험 전에 기록하고, 새 native process를 종료·회수한다. 먼저 확인할 것은 새 권한이 아니라 규칙 로드/매칭과 계산 문자열이다. 이번 실행에서는 8B-3B의 UID 1000 startup helper가 startup/final API 전이를 재확인했지만, 요청한 UID 10000 app-context 분리 probe는 만들거나 실행하지 않았다.

최소 후보는 Guest runtime overlay의 단일 규칙에 `name=ssal-fork-probe`를 추가해 match 대상을 더 좁히는 것이다. 다만 현재 규칙이 선택되지 않았다는 증거는 없고, 이를 추가해도 실패 단계를 고치지는 않으므로 진단 전 적용안으로 권하지 않는다. `levelFrom=none`도 현재 규칙과 동등한 기본값이라 수정이 아니다. context 검사나 실제 setter가 실패한다는 후속 증거가 나오면 그때 Guest-only context 설계로 다시 판단한다. `allow process transition`, `allow process setcurrent`, 전역 permissive는 이 보고서의 수정안이 아니다.

## 회귀 결과와 제한

- 실기기: 8B-3B 최종 strict no-op에서 app child `EINVAL` → JNI fatal → SIGABRT 재현; 기존 baseline 복원 실행에서 Java 검사, worker 종료 및 child reap PASS.
- Host 안전: 당시 전/후 snapshot 동일, global Enforcing 유지, Host 주요 process SID/namespace 및 module rule hash 동일. 활성 policy binary hash는 얻지 못했으므로 binary 동등성은 미확인.
- 이번 8B-3C 작업에서는 별도 app-context probe 빌드를 시도했지만 WSL에 Android NDK가 없고(`ANDROID_NDK_HOME` 미설정, 기본 `/opt/android-ndk` 없음) 빌드가 시작되지 않아 실행하지 못했다. 미검증 코드는 저장소에 남기지 않았다. 따라서 새 probe, `levelFrom`/seapp 수정 회귀, 전체 GSI 부팅 회귀는 수행하지 않았다.
- 미확인: 정확한 runtime 선택 규칙/target 문자열, EINVAL을 실제로 만든 하위 호출, 8B-3B 당시 active policy의 type/AV 전체, Zygote의 내부 setcon 동적 바인딩 여부.
