# Phase 7E-Retry — Guest Zygote

2026-11-05 KST. **판정: PARTIAL.** SM-S937N의 순정 Host 커널에서 Guest `app_process64`를 실행하고 여러 초기화 실패를 해결했지만, 최종 실행은 socket 준비 전 SIGSEGV로 종료됐다. Zygote 상주와 초기화 완료는 확인하지 못했다. 공유 PID/procfs는 이 판정의 차단 사유가 아니다.

## 변경

- Guest init이 없는 상황에서 Guest `/dev/socket/zygote`와 `usap_pool_primary` listening FD를 만들고 `ANDROID_SOCKET_*`로 전달한다. 루트 전환의 일반 FD 정리 이후 이 두 FD만 exec에 보존한다. 로컬 테스트에서 두 소켓 FD의 exec 상속을 확인했다. Android 16 [ZygoteInit](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r3/core/java/com/android/internal/os/ZygoteInit.java)은 임의 socket 이름을 직접 bind하는 것이 아니라 primary 여부를 정하고 ZygoteServer를 만든다. 기존 abstract socket 가정은 잘못됐다. 실제 Guest Zygote는 아직 socket 사용 지점에 도달하지 않아 이미지에서 FD 소비를 실증하지 못했다.
- 준비 판정은 소켓 파일 존재가 아니라 `--query-abi-list`에 대한 `arm64-v8a` 응답으로 한다. 초기화 완료 전 생성된 listening FD 자체를 성공으로 세지 않는다. 기기에는 없는 `/proc/<pid>/task/<pid>/children` 의존을 제거했다. 자손 정리는 기존 subreaper/pidfd 경로를 유지한다.
- 실측 오류에 따라 Guest build.prop의 `ro.build.version.sdk_full=36.1`, Guest userdata의 `dalvik-cache`, Guest adbd APEX의 라이브러리 경로를 준비했다. 현재 property helper는 SDK 36.1 이미지에 한정한다.
- Zygote가 세션 리더일 때 Android 자신의 `setpgid(0,0)`가 EPERM으로 실패했다. 해당 실행 파일만 독립 process group에 두고 세션 리더가 되지 않게 했다. 다른 실행 경로의 `setsid`는 유지한다. 해당 group과 반복 `setpgid`를 단위 테스트했다.

## 실기기 실행

모든 실행은 `--start-system-server` 없이 공통 Launcher를 사용했다. Guest network namespace는 Host와 달랐고, Guest 전용 data identity 검사, private Binder 및 AIDL smoke, Guest property read와 control socket 부재 검사를 통과했다. 예를 들어 최종 실행의 Binder는 Guest `507:5`, Host `507:1`; Guest `/dev/hwbinder`, `/dev/vndbinder`, property/init socket은 직접 노출되지 않았다. 사전에 주입한 Host `/data` FD가 Guest shell 실행 후 사라진 것도 검사했다. 이는 Zygote 자신의 모든 FD를 실행 중 직접 열거한 결과는 아니다. Guest property service는 없고 shell의 `ctl.start`는 실패했다. [최종 worker 로그](../out/phase7e-retry/device-run5/worker.log).

| 실행 | 관측된 최초 실패 | 근거 |
|---|---|---|
| 1 | linker 초기화 중 `libmeminfo.so` abort. Guest 라이브러리의 return offset `0x21500` 직전 분기는 `ro.build.version.sdk_full` 부재에서 abort한다. | [stderr](../out/phase7e-retry/device-run/worker/phase7b/stderr.log); 추출한 Guest 라이브러리 SHA-256 `5ca43ee4b3a50099461cd5df5332b27d9b19889bcc452276b61f0520bfc75ad4` |
| 2 | `Error creating cache dir /data/dalvik-cache/arm64`: 상위 Guest 디렉터리가 없었다. | [stderr](../out/phase7e-retry/device-run2/worker/phase7b/stderr.log) |
| 3 | ART가 Guest boot image의 read barrier 불일치를 보고하고 Guest dex2oat를 실행한 후 `libadbconnection_client.so`를 찾지 못해 abort. | [stderr](../out/phase7e-retry/device-run3/worker/phase7b/stderr.log) |
| 4 | Java `ZygoteInit.main`의 `setpgid`가 EPERM. | [stderr](../out/phase7e-retry/device-run4/worker/phase7b/stderr.log) |
| 5 | PID 21160, UID/GID 0, `/apps/ssal_guest`에서 ART와 Java native 라이브러리 초기화 후 `SIGSEGV`, `SEGV_MAPERR`, fault address `0x278`. PC와 stack은 미수집. socket 응답 이전 종료. | [stderr](../out/phase7e-retry/device-run5/worker/phase7b/stderr.log), [metadata](../out/phase7e-retry/device-run5/worker/phase7b/metadata.jsonl) |

로그의 기기 시각은 `11-04 17:18`~`17:25`로 표시된다. 보고서 날짜는 클라이언트 KST 기준이며 두 시계를 동일하다고 가정하지 않는다. `metadata.jsonl`의 epoch와 elapsed는 기기 관측값이다.

## 검증 및 Host 상태

- 최종 `ssald` SHA-256 `b7ad3ce4c0a5c76e04e2228e85e4eaddde2ba3866f1d4fe9f1a232c7d1401af9`; Guest helper `e9bf0d16cae2a19919ee5441235ba828e928b0633ec27efd43eb8c1e23b1d83a`. Rust `ssald` 테스트 46 passed, 3 privileged ignored; Android AArch64 release 빌드 PASS. 소켓 FD 상속과 Zygote process group 테스트 포함.
- 최종 바이너리의 7D-Fix helper SIGTERM 및 timeout 회귀에서 자손 membership, pidfd reap, cgroup/controller 복원과 Host snapshot 비교 PASS. [결과](../out/phase7e-retry/final-regression.log), [TERM 자료](../out/phase7e-retry/lifecycle-term-final), [timeout 자료](../out/phase7e-retry/lifecycle-timeout-final). 이들은 Zygote 자체의 SIGTERM이나 timeout 시험은 아니다.
- 각 Zygote 실행의 Host snapshot은 전후 일치했다. 스냅샷은 Enforcing, boot ID, PID 1 mountinfo hash, property hash, 주요 프로세스 및 일부 socket/Binder identity를 포함하며 전체 Host 무영향의 증명은 아니다. 실행 후 `ssal_guest` v2 및 세 v1 그룹은 없고 root/apps memory delegation은 빈 상태였다. worker는 각 실행의 rootfs residual mount 부재와 55개 loop 해제를 보고했다. 임시 stage는 로그를 수집한 후 제거했다. Host init 서비스 stop/start/restart, Host global permissive, hard reboot는 수행하지 않았다. 이번 Phase에 live policy를 추가로 적용하지 않았다.
- 최종 실행의 Guest memory peak는 284,045,312 bytes; high 536,870,912, max 805,306,368 bytes, `memory.events`의 high/max/oom/oom_kill은 0이었다. [시계열](../out/phase7e-retry/device-run5/worker/phase7b/memory.jsonl)은 current/peak/events/stat, process status 및 Host PSI를 담는다. Guest `memory.pressure`는 기기에 없어 unavailable이다. worker의 APEX 준비와 공유 cache 전체가 Guest cgroup에 청구된다는 보장은 없다.

## 남은 작업과 복구

`SIGSEGV`의 Guest 전용 PC와 stack을 수집하고 원인을 수정한 뒤 실제 FD 수신, Zygote socket 응답, preload 완료, 상주와 FD/Binder identity를 검증해야 한다. Zygote 자체의 정상 종료·SIGTERM·timeout·자체 오류별 cleanup도 다시 확인해야 한다. Host의 LMK와 다른 프로세스 전체에 미치는 영향은 정량적으로 확정하지 않았다.

PID/procfs 공유로 Host PID가 보이며 의도적인 `/proc/<pid>/root` 또는 `/proc/<pid>/fd` 우회가 가능할 수 있다. 이는 신뢰 Guest 모델의 알려진 한계다. Guest property service와 전체 framework 동작은 미구현이다. 강제 종료나 ADB 단절 시에는 [Phase 7D-Fix 수동 복구](zygote-phase7d-fix-results.md)의 PID/starttime 및 cgroup 소유권 확인을 먼저 따르고 불명확한 PID를 종료하지 않는다.
