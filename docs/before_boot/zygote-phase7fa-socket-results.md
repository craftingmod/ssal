# Phase 7F-A — Guest native socket 실기기 검증

2026-11-05 KST. **PASS: 실제 Guest socket 경로 불일치를 측정하고 수정했으며 native 경고와 UID 1000 ABI readiness를 재검증했다.** 기기는 SM-S937N, boot ID `a9c9be4c-7c9c-4a84-bedf-e0547c9b3062`다. Guest system_server와 controlled fork는 실행하지 않았다.

## 실측과 수정

기존 Guest 진단 preload에서 실제 Zygote 프로세스의 환경변수 FD에 `getsockname`, `SO_TYPE`, `SO_ACCEPTCONN`을 호출했다. 아래 값은 각각 [수정 전](../out/phase7fa/baseline/worker/phase7b/stderr.log) 1–2행과 [수정 후](../out/phase7fa/fixed/worker/phase7b/stderr.log) 1–2행이다. 같은 preload를 상속한 다른 PID의 기록은 Zygote 측정과 구분했다.

| 항목 | 수정 전 PID 1403 | 수정 후 PID 2417 |
|---|---|---|
| `ANDROID_SOCKET_zygote` | FD 60, `/dev/ssal-common-launcher/run-1793817436/worker/rootfs/dev/socket/zygote` | FD 60, `/dev/socket/zygote` |
| `ANDROID_SOCKET_usap_pool_primary` | FD 61, 같은 rootfs 아래 `dev/socket/usap_pool_primary` | FD 61, `/dev/socket/usap_pool_primary` |
| 양쪽 FD 상태 | `getsockname=0`, `AF_UNIX`, `SO_TYPE=1` (STREAM), `SO_ACCEPTCONN=1` | 동일 |

[libcutils의 `android_get_control_socket()` 구현](https://android.googlesource.com/platform/system/core/+/0f62f623fb06724ad8792eac99651f670b1fa7d3/libcutils/sockets_unix.cpp)은 환경변수 FD의 `getsockname()` 경로를 `/dev/socket/<name>`과 비교한다. 수정 전 값은 이 조건과 다르고 수정 후 값은 일치한다. 수정 전 Zygote logger 시각 `11-04 18:37:25.984`에 두 native FD 조회 오류가 발생했고 ([312–313행](../out/phase7fa/baseline/worker/phase7b/stderr.log)), 수정 후 로그에는 두 오류가 없다. 수정 후 `18:38:41.254`에 command 연결 수락이 기록됐다 ([316행](../out/phase7fa/fixed/worker/phase7b/stderr.log)). Logger 시각을 KST로 가정하지 않는다. native 함수의 반환값을 직접 계측한 것은 아니다.

Launcher는 FD 번호를 미리 확보하고, 기존 Guest root 전환 이후 자식에서 `/dev/socket`에 bind·listen하고 해당 FD로 복제한다. Zygote socket의 `root:system 0660`과 기존 cleanup은 유지한다. Host 전역 socket이나 property는 변경하지 않았다.

## Readiness와 정리

- 수정 후 UID/EUID/GID/EGID 1000, capability 0인 client PID 2418이 `arm64-v8a`를 받았다. Zygote PID 2417은 starttime 1426646으로 5초 상주했고 Guest cgroup membership이 확인됐다 ([worker.log](../out/phase7fa/fixed/worker.log)).
- 정상 launcher 완료는 기존 경로대로 Zygote process group을 SIGKILL하고 reap한다. 자연 종료나 graceful 종료를 뜻하지 않는다. Guest cgroup cleanup, 잔여 rootfs mount 부재, loop 55개 해제가 확인됐다. 수정 전과 후 각각 Host 전후 snapshot이 일치했다 ([수정 전](../out/phase7fa/baseline/before.txt), [수정 후](../out/phase7fa/fixed/before.txt); 각 디렉터리에 `after.txt` 포함).
- 별도 실행에서 readiness 후 **launcher에 SIGTERM**을 전달했다. worker exit 1, PID/starttime 소멸, Guest cgroup 부재 및 Host snapshot 일치로 기존 lifecycle 검사 `LIFECYCLE_PASS`를 받았다 ([증거](../out/phase7fa/term/worker.log), [전](../out/phase7fa/term/before.txt), [후](../out/phase7fa/term/after.txt)). Zygote에 직접 SIGTERM을 보낸 시험은 아니다.
- 실험 후 session tmpfs를 해제하고 stage 및 Guest cgroup 부재, memory subtree control 원복, Host SELinux Enforcing을 확인했다. Host init, Zygote, system_server, adbd, netd 등은 기존 snapshot 비교에 포함된다.

## 빌드와 범위

WSLc를 sandbox 밖에서 실행하여 `cargo test --locked`와 `scripts/build-guest-launcher.sh` Android AArch64 release 빌드가 성공했다. 기존 unused 코드 경고는 남는다. 실기기 측정은 preload constructor 시점의 FD 상태이며 장시간 상주, 모든 자손과 실제 fork/USAP 동작은 검증하지 않았다. 이 Phase는 SELinux 정책을 확장하지 않았다.
