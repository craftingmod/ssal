# SSAL Graphics P0.3 — Android SurfaceView Presenter

2026-11-19 KST · Lenovo TB320FC, Android API 35, SSAL Guest 프로필 `y702`.

| 단계 | 판정 | 실기기 증거 |
| --- | --- | --- |
| P0.3a · 앱 단독 | **PASS** | 앱이 4×4 RED Bitmap을 SurfaceView 전체에 nearest-neighbor로 표시했다. 사용자 육안 확인과 가로·홈 복귀·세로 캡처의 중앙 픽셀 `#FF0000`이 일치했다. [가로](../out/guest-graphics-p03/a-landscape.png) · [복귀](../out/guest-graphics-p03/a-resume.png) · [세로](../out/guest-graphics-p03/a-portrait.png) · [수명주기 로그](../out/guest-graphics-p03/a-lifecycle.txt) |
| P0.3b · 브리지 테스트 프레임 | **PASS** | 브리지와 앱이 72바이트, 4×4 RGBA8, stride 16, RED 16/16을 기록했다. 사용자가 빨간 화면을 확인했고 캡처 중앙도 `#FF0000`이었다. 앱은 잘못된 72바이트 헤더를 거부했다. [브리지](../out/guest-graphics-p03/b-receiver.txt) · [앱](../out/guest-graphics-p03/b-presenter.txt) · [대기 화면](../out/guest-graphics-p03/b-before.png) · [표시 화면](../out/guest-graphics-p03/b-presented.png) |
| P0.3c · 실제 Guest 프레임 | **PASS** | ANGLE의 Vulkan SwiftShader가 읽은 4×4 RGBA8 프레임을 표시했다. 18:50:09 KST 캡처의 중앙 50% 영역 전체가 `#FF0000`이었고 사용자가 화면에서 확인했다. [대기 화면](../out/guest-graphics-p03/c-before.png) · [표시 화면](../out/guest-graphics-p03/c-presented.png) · [앱 로그](../out/guest-graphics-p03/c-presenter.txt) |

## 전달 경로와 접근제어

저장소의 P0.2 Host 브리지는 `native/host-frame-p01.c`의 C 구현이다. Guest 송신기, 72바이트 레코드, pathname `AF_UNIX/SOCK_SEQPACKET`, 소켓 mode 0600 및 양방향 `SO_PEERCRED`·`SO_PEERSEC` 검사를 재사용했다. 브리지는 검증된 RED 레코드의 원본 바이트를 기존 전용 `state/receiver.txt`에 16진수 한 줄로 기록한다. `--presenter-test`는 같은 브리지 실행기, SID, 검증 및 출력 함수를 사용해 로컬 RED 레코드 한 개를 만든다. [P0.2 브리지 실행](guest-graphics-p02-selinux-access-report.md) · [검증과 출력](../native/host-frame-p01.c) · [실행기](../native/host-frame-p02-launch.c)

브리지에서 앱으로 오는 시험 경로는 디버그 전용이다. 인증된 ADB 연결(`ro.adb.secure=1`)에서 시험 컨트롤러가 로그를 읽고, Android `run-as alyac.android.ssalsurface`로 전환해 앱의 비공개 캐시에 0600 파일을 원자적으로 배치한다. 관측된 ADB 데몬은 기존 root/`ksu` 세션이며, relay `run-as`는 앱 UID 10059와 동일한 MCS 범주의 `runas_app`이었다. 앱은 `untrusted_app` SID를 유지했다. 이 구간의 쓰기 권한은 앱 데이터 파일의 소유권과 SELinux 라벨로 제한된다. relay와 앱 사이에는 소켓 listener가 없고 Guest의 socket inode는 앱에 공개되지 않는다. [relay](../scripts/publish-presenter-frame.ps1) · [파일 소유권·라벨·SHA-256](../out/guest-graphics-p03/b-inbox.txt)

앱과 브리지는 Host network namespace `net:[4026531983]`에 있고 앱의 mount namespace는 별도다. 읽기 전용 SELinux 질의에서 앱 SID의 브리지 `connectto` 및 전용 socket inode `write`가 모두 거부됐다. Guest와 브리지의 SELinux 접근 응답 flags는 0이었다. [앱·ADB namespace](../out/guest-graphics-p03/b-boundary.txt) · [SELinux 조회](../out/guest-graphics-p03/c-policy-queries.txt)

디버그 Activity는 32자리 세션명으로 파일을 선택한다. 수신 스레드가 최대 73바이트만 읽어 길이·매직·width·height·stride·format을 검사하고 RGBA8을 Android ARGB 픽셀로 변환한다. UI 스레드가 현재 Surface에 Bitmap을 그린다. pause 때 observer와 스레드를 종료하고, Surface 파괴 때 렌더링을 중단한다. 입력 파일은 파일 감시를 시작하기 전에 도착하거나 앱이 잠들어 있는 동안 도착해도 다음 resume에서 읽는다. [수신 및 표시](../android-surface/app/src/main/java/alyac/android/ssalsurface/MainActivity.kt) · [프레임 검증 테스트](../android-surface/app/src/test/java/alyac/android/ssalsurface/FrameRecordTest.kt)

## P0.3a와 P0.3b 실행 기록

- 앱은 기존 Gradle 프로젝트에서 `:app:assembleDebug :app:testDebugUnitTest`를 빌드했다. 첫 Kotlin 빌드 도구 다운로드 후 오프라인 재빌드와 프레임 단위 테스트도 통과했다. P0.3a 앱 PID 29844, P0.3b 캡처 앱 PID 31621, 둘 다 UID 10059 및 SID `u:r:untrusted_app:s0:c59,c256,c512,c768`이었다. 앱 단독 모드에는 프레임 IPC가 없다. 홈 복귀와 회전에서 Surface 생성·파괴, Activity 재생성, callback 해제와 Bitmap 해제를 기록했다. [수명주기 로그](../out/guest-graphics-p03/a-lifecycle.txt)
- P0.3b C 브리지와 실행기를 ARM64 NDK로 `-Wall -Wextra -Werror -static` 빌드했다. 브리지 PID 31369, UID/GID 2000, 실행 전환 SID `u:r:ssal_p0001_p02_frame_bridge:s0`, 종료 코드 0이었다. 첫 fixture 실행은 chroot 루트에 P0.2의 mapped 디렉터리 라벨을 붙이기 전이라 종료 코드 1이었다. 동일 라벨로 재시도한 뒤 표시를 검증했다. 시험용으로 재적용한 기존 P0.2 허용 규칙을 회수하고 전후 Enforcing 및 활성 정책 SHA-256 일치를 확인했다. 브리지 프로세스, 임시 stage, 세션 inbox를 회수했다. [종료 코드](../out/guest-graphics-p03/b-exit.txt) · [정책 전](../out/guest-graphics-p03/b-policy-before.txt) · [정책 후](../out/guest-graphics-p03/b-policy-after.txt) · [정리](../out/guest-graphics-p03/b-cleanup.txt)

## P0.3c 실행 기록

Guest 송신기와 브리지의 ARM64 빌드는 WSL NDK r30에서 통과했다. Guest 실행기는 기기에 적용된 v29 계획과 일치하는 `f1daa3d` 스냅샷에 기존 `load_applied_for_probe` 검증 경로를 이식해 빌드했다. v34 계획 생성이나 적용은 수행하지 않았다. P0.2와 동일한 SHA-256의 ANGLE B0.4 진단 ELF와 Pastel을 기존 Guest 전용 읽기 전용 bind에 사용했다. [Guest fixture와 해시](../out/guest-graphics-p03/c-fixture.txt)

| 프로세스 | PID | UID/GID | SID | Network namespace |
| --- | ---: | --- | --- | --- |
| Guest shell | 5312 | 2000/2000 | `u:r:ssal_p0001_shell:s0` | `net:[4026535123]` |
| Guest 송신기 | 5433 | 2000/2000 | `u:r:ssal_p0001_shell:s0` | Guest shell 상속 |
| Host 브리지 | 5399 | 2000/2000 | `u:r:ssal_p0001_p02_frame_bridge:s0` | `net:[4026531983]` |
| Android Presenter | 5650 | 10059/10059 | `u:r:untrusted_app:s0:c59,c256,c512,c768` | `net:[4026531983]` |

Guest와 브리지는 `/data/local/ssal-shell/p03c.jbwpvC/bridge/frame`의 0600 Unix 소켓에서 상대 UID/GID와 SID를 확인했다. SwiftShader의 `glReadPixels`는 GL 오류 0으로 RGBA8 64바이트를 읽고 송신기는 72바이트를 보냈다. 브리지가 검증한 레코드와 앱 inbox의 SHA-256은 모두 `b6799d6f60b63432887f2106d5b9f2dc815cd84a86d3a8d1fb9ce16c55143131`이다. 송신기와 브리지 종료 코드는 0이었다. [Guest 송신](../out/guest-graphics-p03/c-sender.txt) · [브리지 수신](../out/guest-graphics-p03/c-receiver.txt) · [PID·SID·소켓](../out/guest-graphics-p03/c-identities.txt) · [앱 식별](../out/guest-graphics-p03/c-app-identity.txt) · [inbox](../out/guest-graphics-p03/c-inbox.txt) · [종료 코드](../out/guest-graphics-p03/c-exit.txt)

초기 시도에서는 Guest 속성 tmpfs에 직접 푸는 Toybox `tar`가 실패해 Host stage에서 먼저 푼 뒤 복사했다. Toybox의 `/proc/<pid>/root` 경유 remount 경로 조회 실패는 Guest mount namespace 내부에서 해당 bind를 읽기 전용으로 remount하는 작은 시험 도구로 해결했다. 이후 송신기의 기존 `--bridge` 옵션이 빠진 시도에서는 소켓 연결 뒤 송신기가 전용 SID를 거부했고 브리지는 EOF를 받았다. 이 인수를 복구한 최종 실행이 통과했다. [인증 실패 로그](../out/guest-graphics-p03/c-attempt2-sender.txt) · [재시도 전 정리](../out/guest-graphics-p03/c-attempt2-cleanup.txt)

시험 전후 SELinux Enforcing, 활성 정책 SHA-256, 부팅 ID, PID 1 mountinfo, `/vendor`·`/odm` mount와 서비스 PID가 일치했다. SurfaceFlinger는 1537, HWC는 1446, Android servicemanager·hwservicemanager·vndservicemanager는 714·717·721이었다. 기존 P0.2 허용 규칙만 시험 중 재적용했고 종료 시 회수했다. [Host 전](../out/guest-graphics-p03/c-host-before.txt) · [Host 후](../out/guest-graphics-p03/c-host-after.txt)

## Presenter 재현

`android-surface`에서 `.\gradlew.bat :app:assembleDebug :app:testDebugUnitTest`를 실행하고 `app/build/outputs/apk/debug/app-debug.apk`를 설치한다. `alyac.android.ssalsurface/.MainActivity`를 기본 실행하면 앱 단독 RED를 그린다. 브리지 모드에서는 저장소 루트에서 새 세션을 사용한다. `$bridgeLog`는 종료 코드 0의 새 브리지 실행에서 가져온 전용 로그 경로다.

```powershell
$session = [guid]::NewGuid().ToString('N')
adb -s $serial shell am start -W -S -n alyac.android.ssalsurface/.MainActivity --es presenter_session $session
.\scripts\publish-presenter-frame.ps1 -Serial $serial -Session $session -BridgeLog $bridgeLog
adb -s $serial logcat -d -s SsalPresenter:I
```

P0.3b 로그는 [P0.2 전용 브리지](guest-graphics-p02-selinux-access-report.md)의 기존 실행기 인수 뒤에 `--presenter-test`를 추가해 만든다. P0.3c는 같은 실행기에서 테스트 인수 없이 브리지를 시작하고 Guest에서 실제 [B0.4 ANGLE/SwiftShader 송신기](guest-graphics-p01-frame-transfer.md#재현)를 `angle vulkan "$guestDir/bridge/frame" --bridge`로 실행한다. 앱에서 `Received SSAL 72 bytes, 4x4 RGBA8 stride=16 RED=16/16`을 확인하고 실기기 화면을 캡처한다. 검증 후 `adb -s $serial shell run-as alyac.android.ssalsurface rm -f "cache/ssal-frame-$session"`으로 inbox를 정리한다.
