# SSAL Graphics Experiment B · Guest buffer round-trip

Gralloc 없이 ANGLE을 직접 초기화한 후속 실험은 [B0 런타임 보고서](guest-graphics-b0-angle-swiftshader-20261119.md)에 기록했다.

2026-11-19 KST · **BLOCKED — Guest 전용 allocator/mapper와 사용할 소프트웨어 Vulkan 드라이버를 확보하지 못했다.** GSI에는 플랫폼 EGL/GLES와 ANGLE이 있다. 현재 SSAL 프로필은 Guest 준비 중 Host vendor 전체를 읽기 전용으로 bind하므로 이번 실험에 사용할 수 없다. 선행 조건에서 중단했고 A/B 프로그램은 작성하거나 실행하지 않았다. 실제 픽셀·fence·FD 수명은 미측정이다. [Astra 실험 B](surfaceflinger-astra-architecture.md#L74) · [마운트 프로필](../module/profiles/concurrent/mounts/initial.json#L20) · [bind 호출](../src/guest/mount/mod.rs#L292)

## 실측 환경과 근거

- 기기에 연결된 Host는 **Lenovo TB320FC, Android 15/ZUI, SELinux Enforcing**이다. `y702`의 등록 이미지 `/data/local/ssal/images/1794661103681-12276/system.img`와 로컬 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img`에 각각 SHA-256을 계산했고 둘 다 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`였다. 이미지 크기는 2,733,260,800 bytes, GSI는 LineageOS 23.2, Android 16 SDK 36, fingerprint는 `google/lineage_arm64_bvN4/generic_arm64:16/BP4A.251205.006/eng.andrew:userdebug/release-keys`이다. 삼성 기기에서의 상태는 **UNKNOWN**이다.
- 이미지의 파티션 경로와 APEX/CAPEX 44개의 ext4 payload에서 표준 바이너리·라이브러리 디렉터리, HAL/VINTF 후보, APK 디렉터리 이름을 읽었다. `readelf`로 후보의 ELF class·machine·build ID·SONAME·직접 `DT_NEEDED`·RPATH/RUNPATH를 읽었다. APK 내부, 비표준 경로와 런타임에 설치되는 패키지는 조사 범위 밖이다. [전체 인벤토리](../out/guest-graphics-buffer-preflight-20261119.txt) · [재현 스크립트](../scripts/probe-guest-graphics-image.py)

| 경계 | 판정 | 근거 |
| --- | --- | --- |
| 플랫폼 EGL/GLES 및 ANGLE ELF | **PASS** (파일 검사) | `/system/lib64`에 `libEGL.so`, `libGLESv1_CM.so`, `libGLESv2.so`, `libGLESv3.so` 및 `libEGL_angle.so`, `libGLESv1_CM_angle.so`, `libGLESv2_angle.so`가 있다. 모두 AArch64 ELF64이다. 플랫폼 `libGLESv2.so`는 `libEGL.so`에 의존하고, 플랫폼 EGL은 `libgraphicsenv.so`, `libnativewindow.so`, `libvndksupport.so` 등을 사용한다. ANGLE EGL은 같은 디렉터리의 `libGLESv2_angle.so`와 `libnativewindow.so` 등에 의존한다. 주요 build ID는 플랫폼 EGL `f5e13db29b37a8bf81ee0d6084b6af9d`, ANGLE EGL `b8db46c33713eb706ab28de73521fe0c`, ANGLE GLESv2 `60c0726b2430edab766ce66f768963b4`이다. |
| SwiftShader / 소프트웨어 EGL 백엔드 | **BLOCKED** | `libvulkan.so`와 ANGLE은 있다. 표준 경로와 APEX에서 `vulkan.pastel.so`, `libvk_swiftshader.so` 또는 다른 Vulkan 드라이버 모듈을 찾지 못했다. ANGLE GLESv2 ELF에서 `EGL_ANGLE_platform_angle_device_type_swiftshader`, `SwiftShader Device`, `VK_ANDROID_external_memory_android_hardware_buffer`, `EGL_ANDROID_native_fence_sync` 문자열을 확인했다. 이 ELF의 `DT_NEEDED`에는 별도 SwiftShader 또는 Vulkan ICD가 없다. 동적 로드·내장 백엔드 사용 가능성 및 EGL 확장 광고는 **UNKNOWN**이다. 확인된 ELF만으로 동작하는 소프트웨어 ICD를 지정할 수 없다. |
| Android allocator/mapper 구현 | **BLOCKED** | 플랫폼 `libui.so`의 직접 의존성에 allocator AIDL V2, allocator HIDL 2.0/3.0/4.0, mapper HIDL 2.0/2.1/3.0/4.0, `libbinder_ndk.so`, `libgralloctypes.so`, `libsync.so`가 있다. `libui.so` build ID는 `604dcc7b76bed24d4d5a3bcd22a6a93e`이고 `AIMapper_loadIMapper` 문자열과 `AServiceManager_openDeclaredPassthroughHal@LIBBINDER_NDK35` 참조가 있다. GSI의 `libandroid.so`에서 AHardwareBuffer allocate/send/recv/release export도 확인했다. 이미지 및 APEX의 해당 디렉터리에는 그래픽 allocator 서비스 실행 파일, `mapper.<suffix>.so`, gralloc 구현이 발견되지 않았다. VNDK APEX에도 인터페이스 ELF가 있으나 이 검색에서 대응 구현은 발견되지 않았다. |
| VINTF 선언 | **BLOCKED** | 이미지의 framework manifest/fragment에서 graphics HAL 선언이 발견되지 않았다. Framework compatibility matrix에는 graphics HAL 항목이 있다. 예를 들어 `compatibility_matrix.202504.xml`에는 allocator AIDL 1–2, `compatibility_matrix.6.xml`에는 mapper HIDL 2.1/3.0/4.0이 있다. GSI의 `/vendor/etc/vintf`에 device manifest가 없으며 SSAL에 Guest용 graphics device VINTF 공급 경로도 확인되지 않았다. |
| 기존 Guest device VINTF 호출 | **FAIL** (이전 실행) | Guest servicemanager PID 6749의 `getDeviceHalManifest()`가 `/vendor/etc/vintf/manifest.xml` 읽기에서 `-13/EACCES`를 냈다. 기기 로그 시각 `11-18 16:26:14.434` (당시 수집 기록의 KST 환산 11-19 01:26:14.434). 같은 실행에서 framework VINTF를 통한 SystemSuspend 등록은 성공했다. 이번 실험에서 allocator의 `isDeclared`나 service lookup을 호출하지 않았으므로 결과는 **UNKNOWN**이다. [기존 오류 발췌](../out/guest-vintf-20261119/run-1-detail.txt#L10) · [기존 검증 보고서](guest-vintf-system-suspend-20261119.md#오류와-avc) |
| Guest linker namespace | **PASS** (기존 설정 확인), **UNKNOWN** (그래픽 로드) | 이미지의 `/linkerconfig`는 비어 있다. SSAL이 Guest에서 `linkerconfig --target /linkerconfig`로 설정을 생성한다. 11-17에 캡처한 Guest 설정의 `[system]` default는 `/system/${LIB}`, `/system/system_ext/${LIB}`를 검색한다. 별도 격리된 `sphal`은 `/odm/${LIB}`, `/vendor/${LIB}`와 vendor의 `egl`, `hw`를 검색한다. 경로가 있어도 구현 파일, 의존 ELF의 namespace 가시성, SELinux read/map, 로드 성공은 별도다. [생성 코드](../src/guest/runtime/linkerconfig.rs#L27) · [기존 Guest 설정](../out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt#L759) |
| A/B allocate, FD/native_handle 전달, import/free | **BLOCKED** | 실행 전 중단했다. `AHardwareBuffer_allocate`, allocator `allocate`, mapper `importBuffer/freeBuffer` 및 handle 송수신 반환값은 **UNKNOWN**이다. |
| EGLImage, 앱·primary 픽셀, readback | **BLOCKED** | `eglInitialize`, `eglCreateImageKHR`, FBO 및 readback 경로에 진입하지 않았다. 실제 driver/renderer 이름, format/stride 및 픽셀 비교 결과는 **UNKNOWN**이다. |
| acquire/release fence, 반복 재사용, 종료·FD 수명 | **BLOCKED** | buffer round-trip이 없어 sync FD 전달, 지연 검출, 재사용, mapper free 및 프로세스 종료 후 FD 회수를 측정할 수 없었다. |

## 재현

저장소 루트의 Linux/WSL에서 Python 3.11+, `debugfs`(e2fsprogs), `readelf`(binutils)로 실행한다. `--linker-config`는 기존 Guest 캡처를 함께 표시하는 선택 항목이다. 스크립트는 이미지와 APEX payload를 mount하지 않고 읽으며, 임시 추출물은 종료 시 제거한다. 정상 종료는 정적 조사 완료를 뜻한다. A/B 실험의 판정은 위 표를 따른다.

```sh
python3 scripts/probe-guest-graphics-image.py \
  out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img \
  --linker-config out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt \
  > /tmp/guest-graphics-buffer-preflight.txt
```

WSL에서 실제 이미지 전체 조사와 CLI 도움말, ext4가 아닌 입력의 실패 종료를 확인했다. 기기에서는 등록 이미지의 해시와 Guest 프로세스·작업 mount 디렉터리 상태를 읽었다. 관측 시 SSAL 관련 프로세스는 Host의 `ksu` 문맥 `ssald` 데몬뿐이었고 Guest 작업 mount 디렉터리는 비어 있었다. 이번에 Guest worker, 그래픽 서비스 또는 장치 노드를 열지 않았고 userdata 이미지를 만들지 않았다.

## 차단 해제에 필요한 최소 구성

1. **Guest arm64 allocator/mapper 한 쌍.** Gralloc5 경로라면 Guest private Binder에 AIDL `android.hardware.graphics.allocator.IAllocator/default` (interface ≥ 2), 동일 ABI의 stable-C mapper5 `mapper.<suffix>.so`, 이를 선언하는 Guest device VINTF가 필요하다. 먼저 `isDeclared → checkService → getInterfaceVersion/allocator suffix → mapper load`를 두 Guest 프로세스에서 확인한다. GSI가 가진 framework client를 사용한다. [Astra의 Gralloc5 로드 순서](surfaceflinger-astra-architecture.md#L22)
2. **GSI ANGLE과 호환되는 Android arm64 소프트웨어 Vulkan 드라이버.** Guest 전용 경로에서 실제 ELF 및 의존성을 로드할 수 있어야 한다. `eglInitialize`과 GLES context 생성 뒤 `EGL_VENDOR`, `GL_RENDERER`, 확장 및 native-buffer import를 확인한다. Guest 소유 backing과 fence 제공 경로의 장치 요구사항을 먼저 확인한다.
3. **Host vendor 전체 bind를 생략하는 Guest 실행 경로.** 필요한 Guest 소유 파일만 읽기 전용으로 배치하고 VINTF와 mapper/ICD의 linker namespace를 맞춘다. Guest private Binder 및 기존 supervisor, SELinux, namespace·수명 검증과 정리를 유지한다. standalone `ssal exec`만으로는 private Binder 서비스가 시작되지 않으므로 allocator 등록을 위한 Guest ServiceManager와 Guest 전용 HAL의 준비가 필요하다. [SSAL Shell 준비 경로](../README.md#독립-guest-shell) · [Guest 장치 allowlist](../src/guest/mount/devices.rs#L8)

## Runtime 재개 기준

- **버퍼와 픽셀.** RGBA8888, 예를 들어 17×9×1에서 A가 실제 allocator를 써서 할당하고 Unix socket FD 전달 API로 B에 공유한다. 수신 프로세스에서 mapper import 및 descriptor를 확인한다. A는 `eglGetNativeClientBufferANDROID → eglCreateImageKHR → GLES FBO`로 빨강·파랑과 프레임 번호를 기록한다. B는 CPU-readable 대상에 대해 mapper lock 결과의 row stride와 pixel stride, format을 사용해 전체 예상 픽셀을 비교한다. [Android NDK AHardwareBuffer](https://developer.android.com/ndk/reference/group/a-hardware-buffer)
- **Usage 별도 판정.** 앱 texture/render는 `GPU_TEXTURE | GPU_RENDER_TARGET` (`0x300`), primary는 `COMPOSER_CLIENT_TARGET | GPU_RENDER_TARGET | COMPOSER_OVERLAY` (`0x1a00`)를 각각 그대로 할당한다. 앱 CPU read 진단은 `CPU_READ_OFTEN`을 붙인 별도 할당(`0x303`)으로 기록한다. 원본을 CPU로 읽을 수 없으면 B에서 원본 usage로 합법적인 EGLImage/FBO import와 복사를 확인한 뒤 별도 CPU-readable target에서 검증한다. 원본 import·복사가 실패하면 그 usage는 미통과로 기록한다. [Android BufferUsage AIDL](https://android.googlesource.com/platform/hardware/interfaces/%2B/eccb702dab07591c65493e8b7c606c34aaaf2956/graphics/common/aidl/android/hardware/graphics/common/BufferUsage.aidl) · [Astra primary 버퍼 경로](surfaceflinger-astra-architecture.md)
- **Fence와 수명.** A의 draw 완료 fence를 B acquire로, B의 읽기/복사 완료 fence를 A의 다음 재사용 대기로 전달한다. 실제 `sync_file` FD가 신호 전 미완료이고 신호 후 진행하는 것을 두 방향에서 검증한다. 동일 버퍼의 여러 프레임에서 stale/torn 픽셀을 확인하고, 각 프로세스의 import/free와 FD 수를 비교한다. 송신 측 원본 해제 뒤 수신자가 보유한 참조의 수명, 그리고 피어 종료 시 소켓·fence·버퍼 FD 회수도 각각 확인한다. 동기 완료만 제공하는 경로의 픽셀 결과와 실제 fence 결과는 따로 기록한다.

**PASS 조건**은 두 usage의 실제 픽셀, 필요한 readback, 지연 acquire/release, 반복 재사용 및 종료 시 FD 회수의 실측이다. 호출이 실행되어 오류나 불일치를 반환하면 **FAIL**, 선행 조건 때문에 실행에 진입하지 못하면 **BLOCKED**, 관측하지 않은 런타임 세부 결과는 **UNKNOWN**으로 기록한다.
