# Phase 7E Socket Fix — Guest Zygote

2026-11-05 KST. **PARTIAL**: UID 1000 readiness client가 Guest 전용 socket에서 `arm64-v8a` 응답을 받고 Zygote가 5초 상주했다. 전체 PASS에 필요한 graceful Zygote 종료와 launcher 자체 timeout은 검증되지 않았다. 기존 normal cleanup은 SIGKILL이다. Host socket 충돌이나 손상은 관측되지 않았다.

## 변경과 자격 증명

root launcher는 유지하고 `--zygote-readiness-client` 별도 child에서 supplementary group 제거, real/effective/saved GID 및 UID 1000 설정, `no_new_privs`와 exec 시 불필요한 FD 정리를 수행한다. child는 UID/EUID/GID/EGID와 inheritable/permitted/effective/ambient capability가 0인지 실제로 검사한 후 `--query-abi-list`만 보낸다. Guest command socket만 `root:system 0660`으로 설정한다. 소켓 디렉터리로 이동한 뒤 UID를 바꾸므로 root 전용 session 상위 경로 권한을 열지 않는다. ABI 길이와 값이 정확하고 응답 후 Zygote가 살아 있어야 성공한다. EOF, timeout, 연결 거부, 잘못된 응답은 성공이 아니다. Framework의 UID 검사는 수정하지 않았다.

최종 실행에서 client PID 24308은 UID/EUID/GID/EGID 1000, 위 capability sets 0을 보고했고 ABI `arm64-v8a`를 받았다 ([worker.log:247](../out/phase7e-socket-fix/run3/worker.log)). Zygote가 연결을 받아 응답한 것은 peer credential 검사 통과와 일치한다. [AOSP ZygoteConnection](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/com/android/internal/os/ZygoteConnection.java)은 peer credential의 UID가 system인지 검사한다. **Guest Zygote 쪽 `SO_PEERCRED` 원시 PID/UID/GID dump는 수집하지 못했으므로 직접 dump로 검증했다고 주장하지 않는다.**

## Socket 및 preload

최종 Guest의 `/dev/socket/zygote` 파일 inode 20, UID 0, GID 1000, mode 0660. Zygote PID 24307의 `ANDROID_SOCKET_zygote=60`, FD 60 `socket:[1631557]`; USAP은 환경변수 61, FD 61 `socket:[1631558]`였다. 파일 inode와 kernel socket inode는 별개다. 두 상속 FD와 파일 inode가 5초 후에도 유지됐다 ([worker.log:249](../out/phase7e-socket-fix/run3/worker.log)). Guest root 및 network namespace, private Binder는 기존 검사로 확인했고 Host `/dev/socket/zygote`와 Host snapshot은 유지됐다. 전체 inherited FD 목록과 socket `getsockname` 값은 수집하지 않았다.

소켓 경고는 실제 command 연결 실패가 아니다. 두 경고 후 연결 수락 및 ABI 응답이 관측됐다. 다만 native socket FD 조회 실패 자체는 남아 있다. [AOSP Java 경로](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/com/android/internal/os/Zygote.java)는 환경변수 FD로 `LocalServerSocket`을 만들고, [native 초기화](https://android.googlesource.com/platform/frameworks/base.git/+/97ffe12dd9214ef33c007303342cd6151bd71bf9/core/jni/com_android_internal_os_Zygote.cpp)는 `android_get_control_socket`을 별도로 조회한다. [libcutils 구현](https://android.googlesource.com/platform/system/core/+/0f62f623fb06724ad8792eac99651f670b1fa7d3/libcutils/sockets_unix.cpp)은 `getsockname` 경로가 `/dev/socket/<name>`과 일치해야 한다. 현재 launcher는 Guest root의 절대 경로로 bind하므로 이 경로 검사가 실패할 가능성이 높다. 이는 소스에 근거한 추론이며 실제 `getsockname` 값과 native 내부 FD 값은 직접 덤프하지 않았다. Native FD bookkeeping 및 이후 fork/USAP 동작에 대한 영향은 미검증이므로 경고를 무해하다고 단정하지 않는다.

Run2 stderr에서 Guest logger 시각 11-04 18:19:28.844에 18,803개 class preload 완료, 18:19:28.946에 두 native 경고, 18:19:28.950에 command socket 연결 수락이 기록됐다 ([stderr:259](../out/phase7e-socket-fix/run2/worker/phase7b/stderr.log)). 필터 검사에서 fatal/uncaught/abort는 없었다. Guest logger 시각을 KST로 가정하지 않는다. Build.VERSION 오류나 기존 SIGSEGV 재발은 관측되지 않았다.

## 상주와 정리

최종 Zygote PID 24307, starttime 1322407이 5초 유지되고 `/apps/ssal_guest` membership이 재검증됐다 ([worker.log:256](../out/phase7e-socket-fix/run3/worker.log)). Run2의 cgroup memory peak는 304,013,312 bytes, high/max/oom/oom_kill events는 0이었다 ([telemetry](../out/phase7e-socket-fix/run2/worker/phase7b/memory.jsonl)). 전체 자손 목록과 장시간 상주는 확인하지 않았다.

| 독립 실행 | 관측 결과 |
|---|---|
| 정상 launcher 완료 | ABI 응답 및 5초 상주 후 기존 launcher가 Zygote process group에 **SIGKILL**, reap 및 socket 삭제. 자연 종료나 graceful 종료가 아니다. [로그](../out/phase7e-socket-fix/run3/worker.log) |
| launcher SIGTERM | readiness 후 worker에 SIGTERM; Zygote PID/starttime 소멸, cgroup cleanup, loop 55개 해제, Host 핵심 snapshot 일치. [로그](../out/phase7e-socket-fix/term/worker.log) |
| 외부 deadline | readiness 후 1초 외부 타이머가 worker에 SIGTERM; 같은 검사를 통과. **launcher 자체 timeout이나 Zygote에 직접 전달한 SIGTERM 시험이 아니다.** [로그](../out/phase7e-socket-fix/timeout/worker.log) |

각 실행의 readiness helper는 동기적으로 wait되어 응답 이전에 reap된다. 모든 Guest 자손을 개별 PID로 추적해 잔존 부재를 증명한 것은 아니다. 최종 session 전용 tmpfs를 해제했고 v2/v1 Guest cgroup 부재, memory controller 원복, session 경로를 root/exe로 사용하는 process 및 loop backing 부재를 기존 cleanup 검사로 확인했다. 영구 Guest userdata는 보존했다. 전체 snapshot이 일치한 정상 실행과 SIGTERM/deadline의 전후 snapshot은 각각 [run3](../out/phase7e-socket-fix/run3/before.txt), [term](../out/phase7e-socket-fix/term/before.txt), [timeout](../out/phase7e-socket-fix/timeout/before.txt) 및 같은 디렉터리의 `after.txt`에 있다. Host SELinux는 Enforcing을 유지했다. Host init/Zygote/system_server 및 socket/property service 조작, hard reboot, Guest system_server 실행은 하지 않았다.

## 검증 범위

- Launcher 관련 Rust 테스트 6개 통과. ABI 정상/잘못된 값/EOF 테스트 포함. Android AArch64 ssald release 빌드 성공, 기기 바이너리 SHA-256 `a865165be6b2839b6b51ae7bc7ae6e586c4b86217cfa5ba5b7dc0d229d7dc92e`.
- 전체 ssald 테스트는 **46 passed, 1 failed, 3 ignored**. 기존 `zygote_diagnostics::tests::pipes_are_bounded_reaped_and_record_signal_without_controller`가 WSL에서 예상 1,048,576 대신 786,432 bytes로 실패했고 단독 재실행에서도 재현됐다. 해당 진단 코드는 이번에 변경하지 않았으며, 실패를 환경 문제로 단정하지 않는다.
- 실제 ABI 통과와 상주에 한정된 결과다. Zygote의 graceful 종료, 내장 timeout, native FD 경고 원인의 직접 확인, 실제 peer credential dump, 모든 자손 및 장시간 안정성은 남았다.
