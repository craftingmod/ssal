# SSAL Graphics P0.2 — SELinux 접근제어 분석 및 권고

## 전용 Host 브리지의 Enforcing 검증

2026-11-19 18:12:23 KST · **PASS — 전역·Guest·Host 브리지 Enforcing.** Lenovo TB320FC의 `y702`에서 양쪽이 `SO_PEERCRED`와 `SO_PEERSEC`를 확인했다. B0.4 ANGLE/Pastel의 SwiftShader가 `glReadPixels`에서 GL 오류 없이 64바이트를 읽었고 Guest가 이를 72바이트 레코드로 전송했다. Host는 4×4 RGBA8, stride 16, RED 16/16을 확인했다. 양쪽 종료 코드는 0이다. [Guest 렌더링과 송신](../out/guest-graphics-p02-bridge/guest.txt#L158) · [Host 수신](../out/guest-graphics-p02-bridge/receiver.txt) · [판정](../out/guest-graphics-p02-bridge/result.txt)

P0.2 브리지 SID는 `u:r:ssal_p0001_p02_frame_bridge:s0`다. 고정 이름 `frame`의 SELinux type은 브리지 SID의 이름 지정 생성 전환으로 `ssal_p0001_p02_frame_socket`이 된다. `p0001` Guest 송신 도메인에 추가하는 권한은 이 소켓 type의 `sock_file:write`와 이 브리지 SID의 `unix_stream_socket:connectto`다. 정책 파일은 시험용으로 분리되어 부팅 때 자동 로드되지 않는다. [브리지 정책](../scripts/guest-frame-p02-bridge.rule)

Host 실행기는 Host mount·network namespace를 유지한 상태에서 실행기를 담은 전용 디렉터리로 chroot한다. UID/GID 2000으로 전환하고 supplementary groups, capability bounding set과 상속 FD를 정리한 뒤 전용 SID로 exec한다. 브리지는 `frame`을 mode 0600으로 열고 각 방향에서 커널이 제공한 peer SID와 UID/GID를 검증한다. `state/`는 브리지 전용 라벨이며 Guest에는 이 라벨에 대한 권한을 추가하지 않는다. B0.4 진단 라이브러리와 Pastel은 Guest namespace에만 읽기 전용으로 배치한다. [Host 실행기](../native/host-frame-p02-launch.c) · [Host 수신기](../native/host-frame-p01.c) · [Guest 송신기](../native/guest-angle-b0.c)

두 준비 시도는 정책을 적용하기 전에 종료됐다. 첫 시도는 ANGLE 원본의 mapped `system_lib_file` 라벨을 허용 목록에 반영해 해결했다. 두 번째는 Guest ext4에 복사한 속성 디렉터리에 `properties_device` 라벨을 붙일 때 거부됐다. 후속 실행에서는 원래 속성 영역과 같은 Guest tmpfs에 진단 fixture를 만들고 기존 라벨을 재사용했다. [파일 라벨 확인](../out/guest-graphics-p02-bridge/preflight2/fixture.txt) · [첫 준비의 회수](../out/guest-graphics-p02-bridge/preflight-worker-cleanup.txt) · [두 번째 준비의 회수](../out/guest-graphics-p02-bridge/preflight2-worker-cleanup.txt)

브리지의 첫 `bind()`는 `frame.sock`을 넘긴 이름 전환이 KernelSU 적용 로그에서 `frame`으로 기록되어 실패했다. 전환이 적용되지 않은 실제 socket inode 대상은 `ssal_p0001_shell_data_file`이었고 브리지에는 이 type의 `sock_file:create`가 없었다. 고정 basename을 파서가 실제 등록한 `frame`으로 맞췄다. Guest 및 기존 type에 권한을 추가하지 않았다. [이름 전환 적용 출력](../out/guest-graphics-p02-bridge/preflight3/policy.txt#L10) · [bind 거부 추적](../out/guest-graphics-p02-bridge/preflight3/trace.txt#L17)

| 관측 항목 | Host 브리지 | Guest 송신기 |
| --- | --- | --- |
| PID / SID | 26699 / `u:r:ssal_p0001_p02_frame_bridge:s0` | 26718 / `u:r:ssal_p0001_shell:s0` |
| UID:GID / capabilities | 2000:2000 / 0 | 2000:2000 / 0 |
| mount / network namespace | `mnt:[4026532493]` / `net:[4026531983]` | `mnt:[4026535494]` / `net:[4026535115]` |

Guest 경로는 `/data/local/ssal-shell/p02-bridge.QokjO3/bridge/frame`이었다. Host 브리지는 별도 루트에서 상대 이름 `frame`으로 바인딩했다. inode mode는 0600, 소유자는 2000:2000, 실제 라벨은 `u:object_r:ssal_p0001_p02_frame_socket:s0`였다. 활성 정책 재조회에서 Guest의 두 허용 비트는 각각 `0x4`와 `0x200000`이었고, `ksu`로의 `connectto` 허용 비트는 0이었다. [양쪽 자격과 소켓](../out/guest-graphics-p02-bridge/identities.txt) · [Host peer 확인](../out/guest-graphics-p02-bridge/receiver.txt#L2) · [Guest peer 확인](../out/guest-graphics-p02-bridge/guest.txt#L13) · [활성 AV](../out/guest-graphics-p02-bridge/policy-active.txt)

양쪽 PID로 제한한 감사 추적의 11건은 시작·경로 탐색 중의 거부였다. 브리지의 데이터 파일·자기 프로세스·Unix datagram 접근과 Guest의 디렉터리 조회가 포함됐다. 이 실행에서 pathname inode 또는 연결형 Unix 소켓의 거부 기록은 없었고 프레임 전송은 완료됐다. 관측된 추가 거부에 allow를 삽입하지 않았다. [Luna 감사 요약](../out/guest-graphics-p02-bridge/audit-summary.txt)

Host boot ID, PID 1 mountinfo 해시, `/vendor`·`/odm` mount, SurfaceFlinger PID 1537, HWC PID 1446, Binder 서비스 PID가 시험 전후 같았다. 실험에 추가한 브리지·Guest 허용 규칙을 종료 시 제거했고, Guest의 `write`·전용 브리지 `connectto`가 다시 거부되는 것을 조회했다. 최종 성공 시도 전후 활성 정책 해시는 `5ef45191…f2f`로 같았다. 첫 브리지 시도 전의 `b9a67a24…efb`와 다른 이유는 새 type 선언과 이름 전환이 현재 부팅에 남아 있기 때문이다. 완전 원복에는 규칙을 재적용하지 않는 재부팅이 필요하며 이번 시험에서 재부팅하지 않았다. [첫 선언 전](../out/guest-graphics-p02-bridge/preflight3/host-before.txt) · [성공 시도 전](../out/guest-graphics-p02-bridge/host-before.txt) · [성공 시도 후](../out/guest-graphics-p02-bridge/host-after.txt) · [허용 규칙 회수](../out/guest-graphics-p02-bridge/rollback.txt)

브리지 소켓, 프로세스, 추적 인스턴스와 기기·WSL staging을 제거했다. Guest worker는 rootfs 잔여 마운트가 없고 루프 46개가 해제됐음을 기록했다. 임시 userdata 이미지는 없었다. [Guest 정리](../out/guest-graphics-p02-bridge/worker-cleanup.txt) · [최종 정리](../out/guest-graphics-p02-bridge/cleanup.txt)

## 전용 소켓 쓰기 허용 및 Guest permissive 대조

2026-11-19 KST. 사용자 요청에 따라 이 실험의 소켓 inode에만 붙이는 `u:object_r:ssal_p0001_p02_frame_socket:s0`를 사용했다. 시험 권한은 `ssal_p0001_shell → ssal_p0001_p02_frame_socket:sock_file write` 한 건이다. 첫 실행은 Guest 도메인 Enforcing에서 확인하고, 두 번째는 같은 SID만 잠시 permissive로 전환해 동일 경로를 관측한다. 전역 SELinux는 Enforcing을 유지한다. 마지막에 Guest 도메인 Enforcing을 복구하고, 추가 전 거부였던 정확한 쓰기 비트를 제거해 다시 조회한다. 실험용 type 선언은 재부팅 전까지 남을 수 있으며 부팅 스크립트나 모듈에는 저장하지 않는다.

첫 준비에서는 17:49:10 KST에 Host Toybox `tar`가 Guest 루트 경로에 Pastel을 풀던 중 `dirflush`에서 SIGSEGV를 냈다. 권한 변경 단계 전이었고 활성 정책 해시는 동일했다. 파일만 포함한 아카이브를 기기의 전용 staging에서 먼저 풀어 Guest 디렉터리로 복사하는 방식으로 재시도했다. [준비 실패](../out/guest-graphics-p02-permissive/preflight/fixture.txt) · [크래시 발췌](../out/guest-graphics-p02-permissive/preflight-tar-crash.txt)

| 실행 | 판정 | 관측 |
| --- | --- | --- |
| 17:52:31 · Guest Enforcing, 전용 `sock_file:write`만 허용 | **FAIL** | Guest PID 19466이 `connect()`에서 `EACCES`를 받고 코드 1로 종료했다. 대기 중인 Host 수신기는 종료 신호로 회수했다(143). |
| 17:52:32 · Guest Shell SID만 permissive | **PASS (진단)** | 실제 Guest sender PID 19503과 Host receiver PID 19495가 양쪽 `SO_PEERCRED`/`SO_PEERSEC`에서 각각 UID/GID 2000, `u:r:ssal_p0001_shell:s0`와 UID/GID 0, `u:r:ksu:s0`를 확인했다. ANGLE의 Vulkan SwiftShader에서 GL 오류 0으로 64바이트를 읽고, Host는 72바이트 레코드, 4×4 RGBA8, stride 16, RED 16/16을 검증했다. 양측 종료 코드는 0이다. |

Guest mount namespace `mnt:[4026535494]` 안에서만 Pastel·B0.4 ANGLE 진단 ELF·`ro.hardware.vulkan=pastel` 속성 영역을 읽기 전용 bind로 배치했다. 시험용 `frame-e.sock`, `frame-p.sock`은 모두 2000:2000/mode 0600이었다. [fixture와 ELF 해시](../out/guest-graphics-p02-permissive/fixture.txt) · [정책과 SID](../out/guest-graphics-p02-permissive/policy.txt) · [Guest readback](../out/guest-graphics-p02-permissive/guest.txt#L162) · [Host 프레임](../out/guest-graphics-p02-permissive/receiver-p.txt) · [종료 코드](../out/guest-graphics-p02-permissive/result.txt)

Luna Max가 송신 PID별 `selinux_audited` trace를 분석했다. Enforcing에서 소켓 inode 쓰기 거부는 재현되지 않았고, `connect()`를 끝낸 거부는 `ssal_p0001_shell → ksu:unix_stream_socket connectto`(mask `0x200000`, result `-13`)였다. 그 전에 `vendor_file:dir search` 5건과 Guest data root의 `dir:read` 1건이 거절됐지만 연결 코드는 peer 검사까지 진행했다. [Enforcing trace](../out/guest-graphics-p02-permissive/trace-e.txt#L18) · [Luna Max 분석](../out/guest-graphics-p02-permissive/luna-analysis.txt)

Permissive에서 감사된 거부는 17건이며 호출 결과는 모두 0이었다. Guest SID에서 나온 3건은 앞서 관측한 두 디렉터리 권한과 `connectto`다. 나머지 14건은 실험 실행 준비 중 기존 `ksu` SID의 디렉터리·linker·라이브러리 접근이었다. `connectto` 이후 송신 PID에서 감사된 거부는 없었다. `dontaudit`로 억제된 검사와 다른 PID는 이 trace 범위 밖이다. 두 logcat 발췌는 비어 있었다. 추가 정책 검토는 전용 enforcing 수신 SID의 `connectto`로 한정한다. 디렉터리·라이브러리와 기존 `ksu` 도메인에 대한 추가 allow는 적용하지 않았다. [Permissive trace](../out/guest-graphics-p02-permissive/trace-p.txt#L20) · [Luna Max 분석](../out/guest-graphics-p02-permissive/luna-analysis.txt)

재조회에서 Guest permissive 플래그는 0이고 전용 inode의 `sock_file:write`와 `ksu`에 대한 `connectto`는 거부였다. 전역 Enforcing, Host boot ID, PID 1 mountinfo 해시, SurfaceFlinger·HWC·Binder 서비스 PID는 유지됐다. 정책 SHA-256은 `817b0828…7bce`에서 `b9a67a24…efb`로 바뀌었고 실험용 type 이름은 활성 정책에 남아 있다. 기본 정책 해시까지의 복구는 실험 규칙을 재적용하지 않는 재부팅이 필요하다. 이번에는 재부팅하지 않았다. [복구 명령 기록](../out/guest-graphics-p02-permissive/restore.txt) · [독립 재조회](../out/guest-graphics-p02-permissive/restored-av.txt) · [Host 전](../out/guest-graphics-p02-permissive/host-before.txt) · [Host 후](../out/guest-graphics-p02-permissive/host-after.txt)

시험 소켓, 추적 인스턴스, 기기·WSL staging을 제거했다. Guest worker는 rootfs 잔여 mount가 없고 loop 46개가 모두 해제됐음을 기록했다. [worker 정리](../out/guest-graphics-p02-permissive/worker-cleanup.txt) · [최종 정리](../out/guest-graphics-p02-permissive/cleanup.txt)

## SOCK_SEQPACKET 재검증 — 2026-11-19 17:34:29 KST

**FAIL — 최초 차단은 SELinux의 socket inode `sock_file:write`다.** Lenovo TB320FC의 실제 `y702` Guest에서 Host 수신기가 같은 유형의 pathname 소켓을 열었다. 송신 PID 14777의 `connect()`만 포함하도록 제한한 별도 tracefs 인스턴스에 `requested=0x4 denied=0x4 audited=0x4 result=-13 tclass=sock_file` 한 건이 기록됐다. 송신 호출도 errno 13을 반환했다. `SOCK_SEQPACKET` pathname 연결은 디렉터리를 탐색하고 소켓 inode에 쓰기 권한을 확인한 다음 peer에 대한 `connectto` 검사로 진행한다. 이번 호출은 inode 검사에서 끝났다. [Guest syscall](../out/guest-graphics-p02-access-check/guest.txt#L11) · [PID 제한 추적](../out/guest-graphics-p02-access-check/connect-trace.txt#L12) · [Android 공통 커널의 pathname 검사](https://android.googlesource.com/kernel/common/%2B/138e9097f7e9d71f502c6b4f926c54d09d6c54e7/net/unix/af_unix.c) · [peer 검사](https://android.googlesource.com/kernel/common/%2B/138e9097f7e9d71f502c6b4f926c54d09d6c54e7/net/unix/af_unix.c#1435)

| 경계 | Guest 송신기 | Host 수신기 |
| --- | --- | --- |
| PID, SID, UID:GID | 14777, `u:r:ssal_p0001_shell:s0`, 2000:2000 | 14619, `u:r:ksu:s0`, 0:0 |
| mount / network | `mnt:[4026535494]` / `net:[4026535123]` | `mnt:[4026532493]` / `net:[4026531983]` |
| 소켓 경로 | `/data/local/ssal-shell/p02-access.Gc2Q4P/frame.sock` | `/proc/14613/root/data/local/ssal-shell/p02-access.Gc2Q4P/frame.sock` |

Host의 자체 루트에서 Guest 경로를 그대로 조회하면 `ENOENT`였다. Guest 루트를 통해서는 dev `0x100750`, inode `294923`, 2000:2000, mode `0600`, 라벨 `u:object_r:ssal_p0001_shell_data_file:s0`를 읽었다. socket inode의 POSIX ACL xattr은 없었다. Host proc-root와 Guest에서 상위 디렉터리들의 dev/inode가 일치했다. Guest의 `faccessat(X_OK)`는 `/`(0:0/0755), `/data`(0:0/0755), `/data/local`(0:0/0751), shell 홈과 실험 디렉터리(2000:2000/0700)에서 모두 성공했다. 송신기의 UID/GID는 각각 2000이고 supplementary groups와 capability는 비어 있었다. 소켓 owner의 쓰기 비트와 실제 SELinux 거부 기록으로 DAC를 최초 차단으로 볼 근거가 없다. [Host 경로](../out/guest-graphics-p02-access-check/host-paths.txt) · [Guest 경로](../out/guest-graphics-p02-access-check/guest.txt#L13) · [프로세스 자격](../out/guest-graphics-p02-access-check/identities.txt)

| 활성 정책 조회 | 결과 |
| --- | --- |
| Guest → 실제 상위 라벨의 `dir:search` | 모두 허용. Host KSU의 실제 탐색도 성공했다. KSU의 Guest data 라벨 일부는 AV에서 거부 비트가 나왔으나 KSU 도메인 permissive 플래그는 1이었다. 전역 SELinux는 Enforcing이었다. |
| Guest → 실제 소켓 라벨의 `sock_file:write` | 거부. `connect()` 구간의 실제 trace와 일치한다. |
| Guest → 실제 소켓 라벨의 `sock_file:getattr` | 거부. 연결 시도 뒤 별도로 실행한 Guest `stat()`가 `EACCES`였다. 연결에 필요한 수정 후보에는 포함하지 않는다. |
| Guest → 자기 소켓 `unix_stream_socket:{ create connect }` | 허용. |
| Guest → Host 소켓 `unix_stream_socket:connectto` | 현재 SID 조합에서 거부. 이번 syscall의 최초 차단보다 뒤에 있는 검사다. |

두 거부 비트는 정책 응답의 `auditdeny=ffffffff`에 포함됐고, 직접 관측한 inode 거부의 `audited=0x4`도 설정돼 있었다. 따라서 이 inode 거부를 `dontaudit`가 억제했다는 설명은 배제된다. 동일 PID·경로·시각으로 좁힌 logcat과 dmesg에서는 해당 AVC 및 rate/backlog 경고를 찾지 못했다. 읽기 전용 `AUDIT_GET`에서 `enabled=0`, `rate_limit=5`, backlog 0을 관측했고, connect 구간에 전역 `lost`가 282223에서 282224로 증가했다. 전역 카운터에는 이벤트 식별자가 없으므로 이번 AVC 또는 이전 P0.2의 누락을 특정한 rate-limit 판정으로 귀속할 수 없다. [활성 AV 원문](../out/guest-graphics-p02-access-check/av.txt) · [감사 조회 및 로그 검색](../out/guest-graphics-p02-access-check/audit-search.txt) · [커널 감사 카운터 구현](https://android.googlesource.com/kernel/common/%2B/16a2d602244f/kernel/audit.c)

현재 빌드는 적용된 Guest 계획 v29를 v34로 다시 해석하지 않아 첫 시도가 socket 생성 전에 중단됐다. v29 리비전 `f1daa3d`의 임시 빌드에 이미 적용된 계획만 읽는 기존 검증 경로를 이식해 다시 실행했다. 활성 정책·장치의 정책 장부·enforcing 상태는 그대로 유지했다. 수신기와 송신기 종료 코드는 각각 143과 1이며, 소켓과 전용 trace 인스턴스는 제거됐다. `SO_PEERSEC`/`SO_PEERCRED`, 렌더링, 4×4 RGBA8 전송과 수신 검증은 연결이 성립하지 않아 실행하지 못했다. 전후 활성 정책 해시, PID 1 mountinfo 해시, SurfaceFlinger·HWC·Binder 서비스 PID가 일치했다. [첫 시도의 준비 실패](../out/guest-graphics-p02-access-check/preflight/guest.txt) · [종료·회수](../out/guest-graphics-p02-access-check/result.txt) · [Host 전](../out/guest-graphics-p02-access-check/host-before.txt) · [Host 후](../out/guest-graphics-p02-access-check/host-after.txt)

Guest worker의 rootfs 잔여 마운트 부재와 loop 46개 해제를 확인했다. 기기와 WSL의 시험 staging을 제거했고 임시 userdata 이미지는 없었다. [worker 정리](../out/guest-graphics-p02-access-check/worker-cleanup.txt) · [최종 정리](../out/guest-graphics-p02-access-check/cleanup.txt)

## 원 P0.2 관측 — 2026-11-19 16:25 KST

2026-11-19 · **원인 범위: SELinux 접근제어 거부 확인, connect()의 개별 차단 hook 미특정.** 실제 Guest 송신기 PID 532가 `AF_UNIX/SOCK_SEQPACKET` pathname `connect()`에서 `EACCES`를 받았다. Guest SID는 `u:r:ssal_p0001_shell:s0`, 소켓 라벨은 `u:object_r:ssal_p0001_shell_data_file:s0`, 수신기 SID는 `u:r:ksu:s0`였다. 원 실행 결과는 [P0.2 재현 기록](guest-graphics-p02-isolated-frame-transfer.md) 참조.

## 증거와 특정 한계

| 증거 | 결과 | 해석 |
| --- | --- | --- |
| 실제 syscall | `connect()` → `EACCES` | 최초 실패는 pathname socket 연결 호출이다. |
| 활성 정책 질의: Guest → 실제 socket label, `sock_file:write` | 거부 (`av.txt`, 요청 mask `4`) | 연결에 필요한 socket inode 접근 권한이 허용되지 않았다. |
| 활성 정책 질의: Guest → `ksu`, `unix_stream_socket:connectto` | 거부 (`av.txt`, 요청 mask `0x200000`) | 수신 socket SID로 연결할 권한이 허용되지 않았다. |
| 활성 정책 질의: Guest → `ksu`, `unix_stream_socket:write` | 거부 (`av.txt`, 요청 mask `4`) | Host SID가 붙은 소켓 객체에 대한 결정이다. pathname 클라이언트는 자신의 소켓을 생성하므로 이 결과만으로 송신 권한을 추가할 근거는 없다. |
| 활성 정책 질의: Guest → `ksu`, `fd:use` | 허용 (`av.txt`) | 이 조회에서는 해당 권한이 차단 요인으로 보이지 않는다. |
| PID·comm·경로·SID·시간으로 제한한 logcat 및 dmesg AVC 검색 | 일치 항목 없음 (`avc-search.txt`; 실행 AVC 파일도 비어 있음) | 로그에 AVC가 남지 않아 여러 거부 중 커널이 먼저 반환한 권한 검사를 선택할 수 없다. |

따라서 **SELinux가 관여한 접근제어 실패**까지는 활성 정책 조회와 syscall 결과가 뒷받침한다. 다만 `sock_file:write`와 `connectto`가 모두 거부 상태이며 대응 AVC가 없으므로, 어느 검사가 이 `connect()`를 직접 `EACCES`로 끝냈는지는 미특정이다. `unix_stream_socket:write`는 활성 정책에서 확인한 후속 송신 차단 후보이며, 아직 연결/전송 시점에 관측된 거부는 아니다. UID/GID DAC만으로 실패를 설명한다는 증거는 없지만 이번 자료는 모든 비-SELinux 커널 거부 경로를 배제하지 않는다.

## 최소 수정 후보와 원복 조건

현재 `ksu` 수신 SID와 `ssal_p0001_shell_data_file` 라벨은 여러 소켓에 쓰인다. 두 type 전체에 권한을 추가하면 이번 프레임 채널보다 범위가 커진다. 시험을 계속할 때는 이 채널의 socket inode에만 전용 type을 붙이고, Host 수신기에 전용 enforcing SID를 사용한다. 기존 경로와 DAC는 유지한다.

첫 변경 후보는 Guest 송신 SID에서 이 채널 전용 socket inode type으로의 `sock_file:write` 한 건이다. 실제 endpoint에서 `unix_stream_socket:connectto`가 다음 차단으로 확인되면 전용 수신 SID에 한해 그 권한을 검토한다. 전용 type 선언·프로세스 전환과 소켓 생성에 필요한 기본 권한은 그러한 실행 경로를 준비한 뒤 따로 검증해야 한다. 이 조사에서는 해당 정책을 정의하거나 적용하지 않았다.

실험용 정책 적용이 별도로 승인되면 시험 기기의 한 부팅에서만 적용한다. 실행 전 기준 정책 해시와 대상 AV를 기록하고, 부팅 스크립트나 모듈 정책에는 실험 규칙을 저장하지 않는다. KernelSU의 동적 추가는 세션 종료로 제거할 수 없으므로 원복은 실험 규칙을 재적용하지 않는 정상 재부팅으로 한다. 재부팅 후 동일한 기본 정책과 Guest 구성에서 다시 해시와 대상 AV를 비교한다. 정책을 적용하기 전 이 원복 조건을 확보한다.

## 검증 순서

1. 전용 endpoint의 실제 inode 라벨과 양쪽 SID를 기록하고 `connect()`를 검증한다.
2. 연결이 성립하면 양쪽 `SO_PEERCRED`/`SO_PEERSEC`로 기대 UID/GID/SID와 대조한다.
3. B0.4 진단 렌더링과 64바이트 readback을 실행한다. Host가 72바이트 레코드, 4×4 RGBA8, stride 16, RED 16/16과 양측 종료 코드 0을 확인해야 통과다.
4. `send()`나 `recv()`에서 거부되면 해당 호출의 실제 객체 SID와 AV만 확인하고 중단한다. Android 공통 커널의 `sendmsg` SELinux hook은 호출자가 사용하는 소켓 객체의 SID에 대해 `write`를 검사한다. [SELinux 소켓 hook](https://android.googlesource.com/kernel/common/%2B/7bbf48947605d6ccef21a896c4b44dc356dc8726/security/selinux/hooks.c#4302)

원 P0.2 실패 뒤 정책은 변경하지 않았다. 원 전송 시험은 연결 실패로 종료됐고, peer SID 인증 및 렌더링 결과는 미도달 상태다.

## 추가 실기기 AVC 조사 — 2026-11-19

현재 연결된 Lenovo TB320FC에서 `y702` Guest를 다시 시작했다. Host는 ZUI 17.0.313, Enforcing이었고 Guest shell은 다시 `u:r:ssal_p0001_shell:s0`, UID/GID 2000으로 실행됐다. 별도 mount/network namespace에서 pathname Unix socket에 `toybox nc -U`로 연결을 시도한 결과 `connect: Permission denied`, 종료 코드 1이었다. 이번 보조 재현은 원 P0.2의 `SOCK_SEQPACKET` 대신 `SOCK_STREAM`을 사용했고, 수신기 bind도 stale socket 때문에 실패했다. 따라서 이것은 원 P0.2 전송 재현의 대체 PASS/FAIL 판정이 아니라, Guest에서 pathname Unix socket 연결이 계속 EACCES라는 보조 관측이다.

실시간 logcat에서 **실제 AVC denied**를 확보했지만, 정확한 Guest `connect()`와 일치하는 AVC는 다시 찾지 못했다. 확인된 인접 거부는 다음과 같으며 원 연결 실패의 권한 근거로 사용하지 않는다.

| 시각 / AVC | 판정과 관련성 |
| --- | --- |
| 16:42:22.225, PID 5379 `mkdir`: Guest shell → `vendor_file:dir search`, `permissive=0` | 실제 enforcing denial. 테스트 디렉터리 준비 시각이며 socket `connect()` 거부가 아니다. |
| 16:43:16.413, PID 5566 `toybox`: KSU → Guest data 경로의 `dir { search write add_name }`, `sock_file create`, `permissive=1` | Host 수신 소켓 생성 과정에서 나온 permissive 기록이다. Guest의 연결 요청이 아니다. |
| 16:43:32.717, PID 5616 `chown`: KSU → Guest `sock_file setattr`, `permissive=1` | 수신 소켓 소유권 조정 기록이며 연결 거부가 아니다. |
| 16:43:37.477–16:44:46.629, `logd.auditd`: logd → Guest PID 5348의 proc 디렉터리 `search`, `permissive=0` | Guest 프로세스 정보 접근 거부다. pathname socket 권한과 무관하다. |

연결 재시도 시각을 포함한 수집 구간에서 `scontext=u:r:ssal_p0001_shell:s0`의 `sock_file:write` 또는 `unix_stream_socket:connectto` AVC는 없었다. `dmesg`에서는 AVC/audit-loss/rate-limit 근거를 추가로 확인하지 못했다. 이 보조 실행에서 확보한 AVC는 Guest 실행 중 주변의 독립 거부를 설명한다. 이 실행의 `connect()`에서 어느 SELinux 검사가 EACCES를 반환했는지는 특정하지 못했다.

보고서에는 AVC만 추려 [추가 조사 기록](../out/guest-graphics-p02-avc-investigation/avc-filtered.txt)에 저장했다. 원시 logcat 캡처는 `out/guest-graphics-p02-avc-investigation/logcat-capture.txt`에 남아 있다. 캡처 프로세스를 중단했지만 Windows 파일 잠금으로 삭제하지 못했고, 잠금 소유 프로세스도 확인되지 않았다. 같은 재현에서 테스트 socket과 directory를 제거했고, Guest worker는 rootfs 잔여 mount 없음 및 loop 46개 회수를 기록했다. 정책은 변경하지 않았다.
