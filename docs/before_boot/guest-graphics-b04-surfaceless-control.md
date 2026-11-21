# SSAL Graphics B0.4 — ANGLE surfaceless 포맷 조회 대조

2026-11-19 KST · **PASS.** 선택적 surfaceless 포맷 조회를 생략하자 EGL 초기화가 끝났고, SwiftShader/Pastel에서 RGBA8 pbuffer의 16픽셀이 모두 `(255, 0, 0, 255)`로 읽혔다. 원본의 최초 차단은 이 조회가 시작한 Gralloc5 초기화의 `servicemanager.ready` 대기였다. 진단 실행에서는 readback까지 추가 차단이 발생하지 않았다. [원본 스택](../out/guest-vulkan-b04/original.txt#L20) · [진단본 readback](../out/guest-vulkan-b04/diagnostic.txt#L143)

## 변경 지점

GSI의 `libGLESv2_angle.so` Build ID는 `60c0726b2430edab766ce66f768963b4`이며 내장 ANGLE 리비전은 `ab6a82e0ed1425316da0ba9a0b1c715a58a0b725`다. Luna가 같은 이미지에서 ELF를 다시 추출해 B0.3 호출 위치와 일치함을 확인했다. GSI Vulkan Loader, nativewindow, UI의 Build ID도 B0.3과 일치했다. Pastel은 B0.3과 같은 Ika 261111 Android arm64 배포 바이너리를 다시 추출해 원본 SHA-256을 대조했다. [B0.3 ELF 근거](../out/guest-vulkan-b03/elf-calls.txt) · [Pastel 검증](../out/guest-vulkan-b04/pastel-sha256.txt)

실제 호출 경로는 다음과 같다.

```text
eglInitialize → EGL_Initialize → egl::Display::initialize → rx::DisplayVk::initialize
  → initSupportedSurfaceFormatColorspaces → GetSupportedFormatColorspaces(VK_NULL_HANDLE)
  → vkGetPhysicalDeviceSurfaceFormats2KHR(count-only) → GetPhysicalDeviceSurfaceFormatsKHR
  → AHardwareBuffer_isSupported(RGB565, 1×1, 1 layer, usage 0xb00)
  → GraphicBuffer::GraphicBuffer → GraphicBufferMapper::GraphicBufferMapper
  → Gralloc5Mapper::Gralloc5Mapper → waitForAllocator → AServiceManager_isDeclared
  → android::defaultServiceManager → servicemanager.ready 대기
```

대응 ANGLE 소스는 `supportsSurfacelessQueryExtension.enabled && supportsSurfaceCapabilities2Extension.enabled`일 때만 `VK_NULL_HANDLE` 포맷·색공간 조회를 한다. 대조본은 `libGLESv2_angle.so+0x24a014`의 `b.ne 0x24a578` (`21 2b 00 54`)를 `b 0x24a578` (`59 01 00 14`)로 바꿔 기존 캐시 clear 분기를 실행한다. 하나의 AArch64 명령을 교체했고 실제로 다른 바이트는 셋이다. ANGLE의 feature 상태, Vulkan 확장 활성화, 유효한 surface에 대한 포맷 조회 및 모든 Gralloc 구현을 그대로 사용한다. Android의 EGLConfig 생성은 RGBA8을 기본 포맷으로 포함한다. [ANGLE 정확한 리비전](https://android.googlesource.com/platform/external/angle/+/ab6a82e0ed1425316da0ba9a0b1c715a58a0b725/src/libANGLE/renderer/vulkan/DisplayVk.cpp#385) · [Android EGLConfig](https://android.googlesource.com/platform/external/angle/+/ab6a82e0ed1425316da0ba9a0b1c715a58a0b725/src/libANGLE/renderer/vulkan/android/DisplayVkAndroid.cpp#55) · [Loader 소스](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android16-qpr2-release/vulkan/libvulkan/swapchain.cpp#725) · [분기 디스어셈블리](../out/guest-vulkan-b04/angle-branch.txt) · [ELF SHA-256](../out/guest-vulkan-b04/angle-sha256.txt)

## 기기 결과

Lenovo TB320FC의 LineageOS 23.2 GSI (`BP4A.251205.006`, incremental `1779626072`)에서 원본과 진단본에 같은 실행기, linker 설정, Pastel 및 `ro.hardware.vulkan=pastel` 속성 영역을 사용했다. 원본은 10초 제한에서 종료 코드 124였고, 진단본은 두 번 모두 0을 반환했다. 원본 ELF를 복구하자 동일한 AHardwareBuffer/Gralloc 경로에서 다시 124가 나왔다. [Guest fixture](../out/guest-vulkan-b04/guest-fixture.txt) · [복구 SHA-256](../out/guest-vulkan-b04/restored-sha256.txt) · [복구 실행](../out/guest-vulkan-b04/restored.txt)

| 단계 | 원본과 복구본 | 진단본 |
| --- | --- | --- |
| `eglInitialize` | 호출 내부에서 대기, 반환값과 EGL 오류 미관측 | `EGL_TRUE (0x1)`, `EGL_SUCCESS (0x3000)`, EGL 1.5 |
| `eglChooseConfig` | 미도달 | RGBA 채널 각각 8비트를 재조회해 확인 |
| `eglCreatePbufferSurface` | 미도달 | 4×4 surface `0x1`, `EGL_SUCCESS` |
| `eglCreateContext` | 미도달 | GLES2 context `0x1`, `EGL_SUCCESS` |
| `eglMakeCurrent` | 미도달 | `EGL_TRUE`, `EGL_SUCCESS` |
| `glClearColor(1, 0, 0, 1)`, `glClear(GL_COLOR_BUFFER_BIT)` | 미도달 | 둘 다 반환형 `void`, 각 `GL_NO_ERROR (0x0000)` |
| `glReadPixels(GL_RGBA, GL_UNSIGNED_BYTE)` | 미도달 | 반환형 `void`, `GL_NO_ERROR`, 16/16 픽셀 `255,0,0,255` |

원본 스택의 호출 명령 위치는 ANGLE의 `+0x24a038`(null-surface 헬퍼) 및 `+0x24af94`(Vulkan 간접 호출), Loader의 `+0x28878`(count-only 전달) 및 `+0x2794c`(AHardwareBuffer 호출), nativewindow의 `+0x8ed0`(GraphicBuffer 생성), libui의 `+0x3106c`(`AServiceManager_isDeclared`)다. 최초 차단은 allocator 선언 조회의 결과가 나오기 전 `defaultServiceManager` 경로에서 발생했다. [원본 스택](../out/guest-vulkan-b04/original.txt#L27) · [호출 명령 디스어셈블리](../out/guest-vulkan-b03/elf-calls.txt)

진단본은 `/system/lib64/libvulkan.so`와 `/vendor/lib64/hw/vulkan.pastel.so`를 매핑했고 `GL_RENDERER`가 ANGLE Vulkan 1.3.0 SwiftShader를 보고했다. 두 실행 모두 HIDL ConfigStore의 `hasHDRDisplay` 조회는 서비스 매니저 없이 기본값 0으로 진행했다. 진단본에서 B0.3의 Gralloc5 readiness 대기나 mapper fatal은 관측되지 않았다. Vulkan 개별 명령 전체를 계측하는 대신 ELF 호출 위치, blocker 스택, 실제 소프트웨어 렌더러와 픽셀을 대조했다. [원본](../out/guest-vulkan-b04/original.txt) · [진단본](../out/guest-vulkan-b04/diagnostic.txt)

## 재현과 적용 범위

동일 Pastel, GSI와 설정을 사용하는 [B0.2 재현 절차](guest-graphics-b02-swiftshader-pastel.md#재현)에서 probe 빌드에 `-DSSAL_B04 -DSSAL_MAPPER_TRACE -funwind-tables -fno-omit-frame-pointer`를 추가한다. 속성 영역에는 `ro.hardware.vulkan=pastel`만 설정한다. 원본을 먼저 실행하고 [패치 스크립트](../scripts/patch-guest-angle-b04.py)에 staged `root/system/lib64/libGLESv2_angle.so`와 새 출력 경로를 전달한다. 스크립트는 원본 해시와 명령 바이트를 검사한다. Guest staging의 ELF 내용만 교체한 뒤 같은 `timeout -k 3 10 … angle`을 재실행하고, 원본 해시로 복구한 뒤 세 번째로 실행한다. [Probe 소스](../native/guest-angle-b0.c) · [Guest 실행기](../native/guest-pastel-mount.c)

기존 `u:r:ksu:s0` 진단 chroot의 별도 mount·network namespace를 사용했다. Guest의 `/dev`에는 regular-file 속성 영역만 있고, staged 루트와 Pastel에 장치 노드가 없었다. Host Binder, 그래픽 HAL, SurfaceFlinger, 물리 DRM 및 SELinux 정책에 변경을 가하지 않았다. 전후 enforcing, 활성 정책 SHA-256, SurfaceFlinger PID, `/vendor`·`/odm` 마운트가 일치했다. [Host 전](../out/guest-vulkan-b04/host-before.txt) · [Host 후](../out/guest-vulkan-b04/host-after.txt)

원본 ELF의 SHA-256을 확인한 뒤 기기 staging, WSL 속성 fixture, 로컬 임시 추출물을 정리했다. 실험용 프로세스와 마운트는 남아 있지 않았고 보존한 증거 파일 12개의 SHA-256은 정리 전후 일치했다. 이번 실험에서는 userdata 이미지를 생성하지 않았다. [정리 확인](../out/guest-vulkan-b04/cleanup.txt)

이번 판정은 격리된 소프트웨어 RGBA8 pbuffer에 해당한다. 실제 SSAL Guest SID, 앱 프로세스, window/swapchain 및 Android native-buffer 경로는 미검증이다. 해당 경로에서 다음 Gralloc 차단이 발생하는지는 이번 실험으로 판정할 수 없다.
