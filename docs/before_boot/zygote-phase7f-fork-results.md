# Phase 7F — Native socket 및 controlled fork

2026-11-05 KST. **미완료: native socket 경계에서 중단.** 이번 세션에서는 원인 가설을 확인할 실기기 FD 계측이나 수정, Zygote 재실행을 하지 못했다. Guest 이미지의 fork 경로와 안전한 entrypoint도 확인하지 못했으므로 fork 명령을 보내지 않았다. 아래 과거 결과와 이번 관측을 구분한다. 다음 Phase 진입은 보류한다.

| 항목 | 결과 | 근거 및 범위 |
|---|---|---|
| Native socket | PARTIAL | bind 코드와 Linux 임시 소켓을 조사했다. 실제 Guest `getsockname`, native 반환값 및 경고 해소는 미확인. |
| Readiness | NOT TESTED | 이번 실기기 실행 없음. Phase 7E에서는 UID 1000으로 `arm64-v8a` 응답을 받았다. |
| Zygote 상주 | NOT TESTED | 이번 실기기 실행 없음. Phase 7E에서는 PID/starttime이 5초 유지됐다. |
| Controlled fork / 자식 실행 / 자식 격리 | NOT TESTED | fork 명령을 전송하지 않았다. 자식 PID, 자격, namespace, cgroup, FD 및 종료 상태 없음. |
| Cleanup | NOT TESTED | 이번에 Guest를 실행하지 않았으므로 새 cleanup 시험이 없다. |
| Host 보존 | PARTIAL | 실행 전후 snapshot 비교는 없다. 읽기 전용 현재 표본에서 Enforcing 및 핵심 프로세스가 관측됐다. |

## 조사와 변경

코드 변경은 없다. 이 문서만 추가했다. [launcher](../src/guest_launcher.rs)는 `root/dev/socket/{zygote,usap_pool_primary}`를 bind한 뒤 FD를 환경변수로 넘긴다. [root 전환](../src/guest_probe.rs)은 그 다음 자식의 `pre_exec`에서 수행된다. 따라서 bind 경로가 Guest 내부의 `/dev/socket/...`과 다르다는 가설은 코드와 일치한다. 그러나 실제 Android Guest FD의 `getsockname()`과 `android_get_control_socket()` 결과는 아직 직접 수집하지 않았으므로 원인으로 확정할 수 없다. 기존 FD 상속 단위 테스트는 경로를 검증하지 않는다.

WSLc의 임시 디렉터리에서 Python Unix stream socket을 bind하고 listen한 실험에서는 `getsockname=/tmp/tmp8e51x_xo/zygote`, `SO_TYPE=1`, `SO_ACCEPTCONN=1`이었다. 이것은 Linux 일반 동작에 대한 별도 실험이지 Guest FD 계측이 아니다.

Phase 7E의 [기록](zygote-phase7e-socket-fix-results.md)에서는 Guest socket **파일** inode 20과 FD 60/61의 **kernel socket** inode 1631557/1631558을 각각 기록했다. Client PID 24308은 UID/EUID/GID/EGID 1000, capability 0으로 ABI를 받았고 Zygote PID 24307, starttime 1322407이 5초 유지됐다. 이 기록은 이번 회귀 결과가 아니다. 당시 socket type, listen 상태, 실제 `getsockname` 및 Guest 측 peer credential은 수집되지 않았다.

## 테스트 실패 조사

이전 `pipes_are_bounded_reaped_and_record_signal_without_controller` 실패는 이번 `cargo test --locked --bin ssald`와 전체 `cargo test --locked`에서 재현되지 않았다. 두 실행 모두 ssald 기준 47 passed, 3 ignored다. 전체 테스트도 성공했다. Android AArch64 release 빌드는 성공했고 `ssal-memory-probe` unused 코드 경고 10개가 있었다.

정적 조사에서 [진단 drain](../src/zygote_diagnostics.rs)은 호출당 최대 32회, 각 8192 bytes를 읽고, `finish`는 각 파이프에 대해 이를 한 번 호출한다. 자식 종료 시 읽을 수 있는 데이터가 이 한도를 넘으면 남을 수 있으므로 이전에 기대 1,048,576 대신 786,432 bytes가 기록된 현상과 양립한다. 다만 당시 파이프 상태를 수집하지 않아 이것이 실제 원인임을 증명하지 못했다. 진단 구현은 이번에 바꾸지 않았다. 이 문제는 socket 변경이 없는 현재 코드에서도 관찰 가능한 잠재적 수집 한계다.

## 재현한 명령과 Host 표본

WSLc 명령은 sandbox 밖에서 실행했다.

```powershell
wslc exec --workdir /src ssal-dev cargo test --locked --bin ssald
wslc exec --workdir /src ssal-dev cargo test --locked
wslc exec --workdir /src ssal-dev bash scripts/build-guest-launcher.sh
wslc exec --workdir /src ssal-dev python3 -c 'import socket,tempfile,os; d=tempfile.TemporaryDirectory(); p=os.path.join(d.name,"zygote"); s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.bind(p); s.listen(); print("bind_path="+p); print("getsockname="+s.getsockname()); print("type=",s.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE),"acceptconn=",s.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)); s.close(); d.cleanup()'
adb devices -l
adb shell su -c 'stat -c %n:%d:%i:%a:%u:%g /dev/socket/zygote /dev/socket/property_service /dev/binder; getenforce; cat /proc/sys/kernel/random/boot_id; test ! -e /sys/fs/cgroup/apps/ssal_guest && echo guest_cgroup_absent; test ! -e /dev/ssal-common-launcher && echo stage_absent'
```

SM-S937N은 연결 상태였고 boot ID는 `a9c9be4c-7c9c-4a84-bedf-e0547c9b3062`, SELinux는 Enforcing이었다. Host zygote64 PID 1805, system_server 2635, adbd 24465, netd 1803이 읽기 전용 검사에서 관측됐다. Host socket 파일 `/dev/socket/zygote`의 dev/inode는 18/2017, mode 0660, UID/GID 0/1000이었다. Guest cgroup과 session stage는 그 표본 시점에 없었다. 이 표본은 전후 비교나 모든 잔여 자원의 부재 증명이 아니다.

## 남은 작업

1. Guest Zygote 실제 FD에서 환경변수, `fcntl`, `SO_TYPE`, `SO_ACCEPTCONN`, `getsockname`, native 조회 결과를 수집하고 Guest와 Host의 파일 inode 및 kernel socket inode를 구분한다. 실제 값에 따라 Guest root 전환 후 bind하도록 고치고 Host socket을 건드리지 않는지 확인한다.
2. Launcher 전체 deadline, 정상 종료와 SIGKILL 안전망, PID/starttime 기반 자손 추적 및 별도의 launcher/Zygote SIGTERM 시험을 구현·검증한다. 기존 launcher의 readiness deadline은 전체 launcher deadline이 아니다.
3. 실제 Guest Android 16 이미지에 대응하는 Zygote 파서, 인증, fork/specialize, entrypoint, USAP, SELinux 전환, 상속 FD 및 reap 경로를 조사한다. 안전한 최소 entrypoint와 의도한 자격이 확인될 때만 fork를 실행한다.
4. UID 1000 ABI 회귀, 부모·자식 정보, cleanup 및 Host 전후 snapshot을 수집한다. 공유 PID namespace에서는 Host PID가 보이며 PID만으로 신호 대상을 식별하면 안 된다.

이번 세션에서 Guest system_server, 일반 서비스, fork, live SELinux 정책 변경, Host 서비스 중단 및 hard reboot는 수행하지 않았다. Guest 측 permissive 정책 적용이나 원복도 수행하지 않았다.
