# SSAL Graphics P0.2 — 실제 Guest SID 프레임 전송

2026-11-19 18:12:23 KST 후속 검증은 **PASS**였다. 전역·Guest·전용 Host 브리지 모두 Enforcing인 상태에서 양측 peer 자격, 4×4 RGBA8·stride 16·RED 16/16 및 양측 종료 코드 0을 확인했다. 아래는 초기 `ksu` 수신기를 사용한 실행 기록이다. [전용 Host 브리지 최종 검증](guest-graphics-p02-selinux-access-report.md#전용-host-브리지의-enforcing-검증)

2026-11-19 16:25 KST · **FAIL — 접근제어.** Lenovo TB320FC의 `y702` 프로필에서 실제 SSAL Guest Shell을 시작했다. Host의 `AF_UNIX/SOCK_SEQPACKET` 수신기가 준비된 상태에서 Guest 송신기 PID 532의 `connect()`가 `EACCES`를 반환했다. Guest 종료 코드는 1이었다. 연결을 기다리던 Host 수신기를 종료해 코드 143으로 회수했다. [Guest 실행](../out/guest-graphics-p02/guest.txt#L10) · [Host 수신기](../out/guest-graphics-p02/receiver.txt) · [종료 코드](../out/guest-graphics-p02/result.txt)

| 단계 | 판정 | 증거 |
| --- | --- | --- |
| 실제 SSAL 환경 진입 | **PASS** | Guest Shell PID 494에서 mapped SID `u:r:ssal_p0001_shell:s0`, UID/GID 2000, supplementary groups 없음, capability 0을 관측했다. 별도 mount·network namespace에서 송신 명령을 실행했다. |
| 접근제어 | **FAIL** | Guest `socket()` 성공 뒤 최초 실패 호출은 pathname `connect()`였다. 소켓 소유자는 2000:2000, mode는 0600이었다. |
| IPC 프레임 전송과 peer 인증 | **미도달** | `accept()`가 완료되지 않아 `SO_PEERCRED`/`SO_PEERSEC`, `send()`/`recv()`, 4×4 RGBA8·stride 16·RED 16/16 검증에 도달하지 않았다. |
| ANGLE/SwiftShader/Pastel 렌더링 | **미도달** | 송신기는 연결과 Host peer 검사를 EGL 초기화 전에 수행한다. 이번 실행에서는 B0.4 진단 ELF와 Pastel을 배치하거나 로드하지 않았다. |

## Host와 Guest 경계

| 프로세스 | 관측 SID | UID:GID | mount namespace | network namespace |
| --- | --- | --- | --- | --- |
| Host 수신기 PID 514 | `u:r:ksu:s0` | 0:0 | `mnt:[4026532493]` | `net:[4026531983]` |
| Guest Shell PID 494 | `u:r:ssal_p0001_shell:s0` | 2000:2000 | `mnt:[4026535502]` | `net:[4026535124]` |

SID는 Host의 `/proc/<pid>/attr/current`와 Guest Shell의 `id`에서 관측했다. 송신기 PID 532는 호출 직전 UID/GID 2000을 출력했다. Host 수신기는 Host namespace에서 Guest Shell의 `/proc/494/root/data/local/ssal-shell/ssal-p02.KHylgO/frame.sock`에 바인딩했다. Guest에 보인 경로는 `/data/local/ssal-shell/ssal-p02.KHylgO/frame.sock`이다. 소켓 파일의 컨텍스트는 `u:object_r:ssal_p0001_shell_data_file:s0`였다. 각 프로세스의 관측 SID와 연결 시 커널에서 읽는 peer SID는 별개 증거다. [PID·자격 증명·소켓 라벨](../out/guest-graphics-p02/identities.txt) · [송신 호출](../out/guest-graphics-p02/guest.txt#L12)

활성 정책의 `/sys/fs/selinux/access` 조회는 enforcing Guest Shell SID에 대해 실제 소켓 라벨의 `sock_file:write`, Host SID의 `unix_stream_socket:connectto`와 `write`를 모두 거절했다. Host SID에 대한 `fd:use` 조회는 허용이었다. 이 결과와 실제 `EACCES`는 접근제어 실패를 뒷받침한다. PID·경로·SID·시간으로 좁힌 기기 로그에서 해당 호출의 AVC를 찾지 못해 개별 권한 검사 중 무엇이 먼저 거절됐는지는 특정하지 못했다. 권한 변경이나 재시도 없이 송신을 종료했다. [활성 정책 응답과 요청 비트](../out/guest-graphics-p02/av.txt) · [AVC 조회](../out/guest-graphics-p02/avc-search.txt)

17:34 KST 후속 재현에서는 PID를 제한한 커널 추적으로 최초 차단이 소켓 inode의 `sock_file:write`임을 확인했다. [후속 조사와 최소 수정 범위](guest-graphics-p02-selinux-access-report.md#sock_seqpacket-재검증--2026-11-19-173429-kst)

17:52 KST 대조에서는 전용 소켓의 `sock_file:write` 허용 후 Enforcing에서 `connectto` 거부를 확인했다. Guest Shell SID만 잠시 permissive로 전환한 진단 실행은 양측 자격 검증과 RED 16/16 전송을 통과했다. [두 실행의 판정과 정책 복구](guest-graphics-p02-selinux-access-report.md#전용-소켓-쓰기-허용-및-guest-permissive-대조)

P0.1과 같은 `SOCK_SEQPACKET` 레코드, Guest readback, Host 프레임 검증기를 사용한다. SSAL `exec`는 입출력 파이프를 중계하고 상속 FD를 제한하므로 P0.2에는 Guest 쪽 경로에 바인딩하는 수신 모드를 사용했다. 연결이 성립하면 양쪽이 예상한 UID/GID와 peer SID를 검사한 뒤, Guest가 P0.1의 72바이트 레코드를 보내고 Host가 검증한다. Linux에서 P0.1 상속 FD 회귀의 정상 프레임은 통과했고 73바이트와 RED 15/16은 거절됐다. [P0.1 형식과 진단 렌더링](guest-graphics-p01-frame-transfer.md) · [회귀 로그](../out/guest-graphics-p02/p01-regression.txt)

## 재현

1. WSL에서 SSAL의 Android arm64 `ssal`, `ssald`, `ssal-property-service`를 빌드한다. [P0.1 빌드 명령](guest-graphics-p01-frame-transfer.md#재현)으로 `native/guest-angle-b0.c`와 `native/host-frame-p01.c`를 각각 `angle-p02`, `host-frame-p01`로 빌드한다. 기기에 고유한 임시 디렉터리를 만들고 다섯 파일과 설치된 `ssal-context-map.so` 사본을 배치한다.
2. 기존 정책을 사용하도록 `SSAL_SHELL_APPLIED_POLICY_ONLY=1 timeout -k 15 300 "$stage/ssal" exec y702 -- /system/bin/sh -c '…'`로 실제 Guest Shell을 연다. 이 모드는 현재 부팅에 이미 적용된 GSI 정책 계획을 검증하고 적용 루틴을 호출하지 않는다. Guest에서 `$HOME` 아래 새 mode 0700 작업 디렉터리를 만들고 `id`와 `$$`를 출력한다. Host가 수신기를 시작할 때까지 Guest Shell을 유지한다. 최초 실행의 45초 제한은 APEX 준비 13/44에서 종료되어 IPC를 시험하지 못했다. [정책 선택](../src/guest/mount/mod.rs#L117) · [첫 실행 준비 기록](../out/guest-graphics-p02/attempt1/prepare-final.txt)
3. Host에서 `"$stage/host-frame-p01" --listen "/proc/$guest_pid/root$guest_dir/frame.sock" u:r:ssal_p0001_shell:s0`를 실행하고 `Host listening`을 기다린다. Guest Shell의 stdin으로 `angle-p02` 파일 바이트를 전달하고 Guest에서 `head -c "$size"`로 파일을 받아 mode 0700으로 설정한다. Guest에서 `"$guest_dir/angle-p02" vulkan "$guest_dir/frame.sock"`을 실행한다. `connect(): Permission denied`와 코드 1을 확인하고 대기 중인 수신기를 종료한다.
4. Guest 세션을 닫기 전에 Host에서 방금 만든 소켓을 제거하고 Guest에서 실험용 실행 파일과 디렉터리를 제거한다. Host 정책과 PID 1 mountinfo 해시, 서비스 PID, Guest 세션 마운트·루프 회수를 전후 비교한다.

## Host 상태와 정리

16:24:03과 16:25:21에 SELinux Enforcing·활성 정책 SHA-256, boot ID와 PID 1 mountinfo SHA-256, SurfaceFlinger(1537)·servicemanager(714)·hwservicemanager(717)·system_server(2280), Binder 링크·DRM 노드와 `/vendor`·`/odm` mount가 일치했다. 실험 중 Host Binder·SurfaceFlinger·HWC·DRM과 기존 SELinux 정책을 변경하지 않았다. [Host 전](../out/guest-graphics-p02/host-before.txt) · [Host 후](../out/guest-graphics-p02/host-after.txt)

Host가 실험 소켓을 제거했다. SSAL worker는 Guest cgroup 정리, rootfs 잔여 mount 부재, loop 46개 회수를 기록했다. 두 시도의 기기 staging과 첫 시도의 잔여 scratch는 프로세스·mount·loop 참조가 없는 것을 확인한 뒤 제거했다. 이 실험은 기존 `y702` Guest userdata를 사용했고 임시 userdata 이미지는 생성하지 않았다. [정상 세션 회수](../out/guest-graphics-p02/worker-cleanup.txt) · [첫 시도 정리](../out/guest-graphics-p02/cleanup-attempt1.txt) · [최종 정리](../out/guest-graphics-p02/cleanup.txt)
