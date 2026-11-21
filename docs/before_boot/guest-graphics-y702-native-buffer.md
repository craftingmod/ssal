# Y702 Concurrent 그래픽 버퍼 실험

Y702의 Android 15 Host는 Qualcomm Adreno 730, Gralloc4 HIDL allocator와 QTI Mapper 4.0을 사용한다. 패널의 Host Composer는 HIDL 2.4다. Guest가 만들 Primary Display는 GSI용 Composer3로 별도 구성하는 설계다. Y702에서 Host Gralloc5 AIDL을 전제로 한 경로는 적용할 수 없다.

## Host 기준선

`ssal-graphics-buffer-probe`는 서로의 UID·GID·SELinux SID를 확인한 두 프로세스가 16×16 RGBA8 `AHardwareBuffer`를 Unix 소켓으로 넘긴다. Producer가 같은 버퍼에 8번 번갈아 빨강·초록을 그리고 EGL native acquire fence를 보낸다. Host가 sync-file 신호를 확인하고 EGLImage를 4×4 pbuffer에 blit한 뒤 16픽셀을 검증한다. 동기 readback 완료 ACK가 도착해야 Producer가 다음 프레임을 그린다.

| 용도 | usage | Producer 할당 | Host 할당 |
|---|---:|---|---|
| 앱용 render/sample | `0x300` | PASS | PASS |
| Composer client target 후보 | `0x1b00` | PASS | PASS |

두 프로세스 모두 Y702 Host에서 `u:r:ksu:s0`로 실행했고 EGL renderer는 Adreno 730이었다. 예상 SID가 다른 연결은 버퍼 전송 전에 거부했다. 마지막 초록색 프레임은 기존 앱의 디버그 픽셀 릴레이로 전달했고 `SurfaceView` 화면 캡처에서 중앙 RGB `0,255,0`을 확인했다. Host SurfaceFlinger 및 system_server PID는 각각 1537, 2280으로 유지됐고 기기는 전역 Enforcing이었다. 이 기준선에는 Guest namespace, Guest HAL, 실시간 Presenter 경로가 포함되지 않는다.

## 재현

WSL에서 NDK로 빌드한다. 기존 Y702 실험 환경의 ADB 셸 UID·GID·SID가 예시와 일치하는지 먼저 확인한다.

```sh
ANDROID_NDK_HOME=/path/to/android-ndk bash scripts/build-rust/build-graphics-buffer-probe.sh
adb shell id
stage=$(adb shell mktemp -d /data/local/tmp/ssal-native-graphics.XXXXXXXX)
adb push out/bin/ssal-graphics-buffer-probe "$stage/probe"
adb shell "chmod 700 '$stage/probe'"
# 두 터미널에서 순서대로 실행한다.
adb shell "$stage/probe host host-alloc client-target $stage/frame 0 0 u:r:ksu:s0" > host.log
adb shell "$stage/probe producer host-alloc client-target $stage/frame 0 0 u:r:ksu:s0"
```

`host-alloc`에서는 Host가 할당한 버퍼 하나를 Producer에 먼저 전달한다. `producer-alloc`은 Producer가 할당한 버퍼를 Host로 전달하는 대조다. `check app` 또는 `check client-target`은 소켓 없이 현재 프로세스의 EGL 초기화, 로컬 할당 및 EGLImage FBO를 확인한다. 빌드 스크립트는 선택적으로 출력 경로를 인수로 받는다. Host 로그의 마지막 검증 프레임 한 건은 기존 `scripts/publish-presenter-frame.ps1`로 앱에 전달할 수 있다.

## Guest 결과

기존 `ssal exec y702` 경로에서 같은 바이너리의 `check client-target`을 실행했다. 첫 준비에서 남은 세션 전용 OverlayFS로 인해 Guest ext4에서 `ENOSPC`가 발생했다. 해당 세션의 overlay만 제거한 후 재시도는 APEX 44개를 준비하고 Android 16 Guest 셸(`u:r:ssal_p0001_shell:s0`)에 도달했다.

Guest libEGL은 OpenGL ES 구현을 찾지 못해 종료됐다. 같은 셸에서 `/vendor/lib64/egl` 조회는 `EACCES`였고 `/dev/kgsl-3d0`과 `/dev/hwbinder`는 없었다. Host는 `ro.hardware.egl=adreno`, `ro.board.platform=taro`이며 Mapper 4.0 파일은 `android.hardware.graphics.mapper@4.0-impl-qti-display.so`다. Guest에서의 EGL 실패가 driver ABI 불일치인지는 확인되지 않았다. 기기 로그 `/data/local/ssal/logs/shell-22659.log`는 151행에 마지막 APEX 준비, 2996–2999행에 cgroup·마운트·세션 loop 회수를 기록했다.

Y702에서 다음 관문은 Guest 그래픽 프로세스에 필요한 Adreno EGL 라이브러리와 KGSL 접근을 구성한 뒤 QTI Mapper 4.0으로 Host 할당 버퍼를 import하는 것이다. Guest Composer3, Guest SF 기동, 실시간 Presenter는 이 실험에서 구현되지 않았다.

### SELinux 후속 실험

Guest PID 24679의 전용 `/dev` tmpfs에 Host `kgsl-3d0` 문자 장치 하나를 임시 bind했다. 기본 Guest에서는 경로가 `ENOENT`였고, bind 직후 기존 정책으로 Guest 셸의 읽기·쓰기 open이 성공했다. Host `hwbinder`는 연결하지 않았다.

Guest SID로 필터링한 `selinux_audited`에서 vendor 디렉터리의 `search`/`getattr`와 `same_process_hal_file:file`의 `read`/`open`이 순차적으로 거부됐다. [Y702 프로브 정책](../scripts/guest-graphics-y702.rule)에 확인된 규칙을 기록하고 활성 정책에 가산했다. 같은 Guest 셸이 Adreno EGL·GLES와 QTI Mapper의 ELF 헤더를 읽었고, 재시험에서 위 대상의 AVC는 없었다.

### 후속 실험에서 재사용

Y702에서 아래처럼 새 Guest Shell 세션을 시작한다. 이미 열린 세션에 접속하려면 그 세션과 같은 설정을 사용한다.

```sh
SSAL_Y702_GRAPHICS=1 ssal shell y702
SSAL_Y702_GRAPHICS=1 ssal exec y702 -- /system/bin/sh -c 'ls -lZ /dev/kgsl-3d0'
```

이 옵션은 GPU 노드의 장치 번호, 소유권과 SELinux 라벨을 확인한 뒤 Guest의 `/dev`에만 연결한다. 기존 읽기 전용 `/vendor`에서 필요한 네 규칙의 유효 권한을 조회하고 빠진 규칙을 Guest 셸 도메인에 적용한다. KGSL 마운트는 Guest 세션 종료 시 정리된다. KernelSU가 추가한 권한은 해당 부팅 동안 유지된다. EGL 초기화, GPU ioctl, Guest SF 기동은 별도 검증이 필요하다.

Y702의 별도 시험 빌드에서 KGSL 읽기·쓰기 open, Adreno EGL·GLES 및 QTI Mapper ELF 헤더 읽기, 동일 옵션 접속 성공과 다른 옵션 접속 거부를 확인했다.

### Guest SurfaceFlinger 재시험 (2026-11-19)

앞선 [재시험 로그](../out/guest-y702-graphics/sf-retest-y702.txt) 18–21행에서 `ssal_p0001_surfaceflinger`가 KSU 소유 상속 FD에 `fd:use`를 요청했으나 거부된 기록 네 건을 확인했다. Guest 정책 생성기에 `surfaceflinger → ksu:fd use`를 추가하고 `/system/bin/surfaceflinger` 실행 파일을 Guest `surfaceflinger` 도메인에 매핑했다. Host 정책은 변경하지 않았다.

수정한 정책으로 다시 계측한 [결과 로그](../out/guest-y702-graphics/sf-retest-y702-fd-use.txt)에서 SurfaceFlinger가 UID 1000, `u:r:ssal_p0001_surfaceflinger:s0`로 시작했다(233–236행). 이번 trace에는 `fd:use` AVC가 없어서 앞서 관측한 거부는 해소됐다. 이 변경이 이전 `SIGSEGV`의 원인이었는지는 증명되지 않았다.

이번 프로세스는 SELinux가 아닌 `/dev/hwbinder` 부재로 `SIGABRT` 종료됐다(241–245행). Host hwbinder는 Guest에 연결하지 않았으며, SurfaceFlinger의 HIDL 경로가 이를 열려다 실패했다. 따라서 SurfaceFlinger 서비스 등록 여부는 아직 확인하지 못했다. Guest의 Binder 조회 명령도 spawn/root setup `EACCES`로 실행되지 않았다(237–238행). 추가 AVC는 `vendor_file:dir` 거부 12건과 abort 뒤 crash-dump 실행 파일 거부 한 건이 남았지만, 이번 종료 원인으로 확인되지는 않았다(3102–3114행).

계측은 [재시험 스크립트](../out/guest-y702-graphics/run-sf-retest-y702.sh)로 수행했다. 전역 SELinux는 Enforcing, Host SurfaceFlinger와 system_server PID는 각각 1537, 2280으로 유지됐고, Guest loop 장치는 회수됐다.
