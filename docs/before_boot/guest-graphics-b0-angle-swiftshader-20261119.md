# 실험 B0 — ANGLE/SwiftShader 단독 초기화

2026-11-19 05:56:56 KST · **FAIL** · Lenovo TB320FC에서 LineageOS 23.2 GSI의 `libEGL_angle.so`를 로드했다. 명시적 SwiftShader 선택은 `EGL_BAD_ATTRIBUTE`로 거부됐다. 일반 ANGLE/Vulkan 경로는 display를 반환한 뒤 `EGL_NOT_INITIALIZED`로 실패했다. 두 경로 모두 pbuffer, GLES 컨텍스트 및 픽셀 검증 단계에 도달하지 못했다. [기기 출력](../out/guest-angle-b0-20261119/device.txt) · [실험 B 사전 조사](guest-graphics-buffer-experiment.md)

## 실행 환경

- GSI는 LineageOS 23.2, Android 16 SDK 36, AArch64다. 사용한 이미지의 SHA-256은 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`다. 이 해시는 실험 B 사전 조사에서 기기 `y702`의 등록 이미지와 일치했다.
- `ssal exec`의 Host vendor bind를 피하기 위해 GSI에서 추출한 런타임 APEX linker64·Bionic과 `/system/lib64` 의존성만 담은 진단용 chroot를 사용했다. `unshare -m -n`으로 격리했고 기기의 기존 `u:r:ksu:s0`에서 실행했다. Guest에 `/vendor`, `/odm`, `/dev`, `/proc`, `/sys`, `/data`, `/linkerconfig` 경로가 없음을 확인했다. GSI linker는 기본 설정과 명시적 `LD_LIBRARY_PATH`를 사용했다. 전체 SSAL Guest 부팅, mapped Guest SELinux 도메인 및 생성된 linkerconfig는 이 실험의 검증 범위 밖이다. [실행 경계와 로그](../out/guest-angle-b0-20261119/device.txt#L2)
- Gralloc allocator/mapper, Composer3 및 SurfaceFlinger를 시작하거나 호출하지 않았다. `/dev`가 없어 Guest에서 Binder 및 디스플레이 장치 노드를 열 수 없었다. Host 그래픽 서비스, vendor 설정, 물리 디스플레이 및 SELinux 정책을 변경하는 명령은 실행하지 않았다. 전후 Host SurfaceFlinger PID `1537`, `/vendor`·`/odm` mount 정보, SELinux `Enforcing`과 활성 정책 SHA-256이 일치했다. userdata 이미지는 생성하지 않았다. [Host 실행 전](../out/guest-angle-b0-20261119/host-before.txt) · [Host 실행 후](../out/guest-angle-b0-20261119/host-after.txt)

## 단계별 판정

| 단계 | 판정 | 실측 |
| --- | --- | --- |
| ANGLE 로드와 client 확장 조회 | **PASS** | `dlopen("/system/lib64/libEGL_angle.so", RTLD_NOW \| RTLD_LOCAL)` 성공. 두 모드에서 `libEGL_angle.so`와 `libGLESv2_angle.so`의 매핑을 확인했다. |
| SwiftShader 명시 요청 | **FAIL** | `eglGetPlatformDisplayEXT` → `EGL_NO_DISPLAY`, `eglGetError()` → `0x3004 EGL_BAD_ATTRIBUTE`. `EGL_KHR_debug` 메시지는 `EGL_ANGLE_platform_angle_device_type_swiftshader is not supported`였다. SwiftShader 실행의 종료 코드는 1이다. |
| 일반 ANGLE/Vulkan 대조 실행 | **FAIL** | SwiftShader device attribute 없이 display 획득 성공. `eglInitialize` → `EGL_FALSE`, `eglGetError()` → `0x3001 EGL_NOT_INITIALIZED`. ANGLE은 `VK_ERROR_INITIALIZATION_FAILED (-3)`를 `external/angle/src/libANGLE/renderer/vulkan/vk_renderer.cpp`의 `initialize:2477`에서 기록했다. GSI `libvulkan.so`가 동적으로 매핑됐다. 종료 코드는 1이다. |
| pbuffer, GLES 렌더링, `glReadPixels` | **BLOCKED** | 준비한 probe는 GLES2 RGBA pbuffer 4×4를 만들고 좌측 빨강·우측 파랑을 그린 뒤 RGBA8 16픽셀 전부를 비교한다. 두 초기화 실패로 이 코드에 도달하지 못했다. GL 호출, GL 오류 코드 및 픽셀 결과는 미측정이다. |
| 공급자·렌더러·확장 | **PASS** (client) / **BLOCKED** (display·GL) | 아래 EGL client 확장은 두 모드에서 같았다. `EGL_VENDOR`, `EGL_DISPLAY_EXTENSIONS`, `GL_RENDERER`, `GL_VERSION`, `GL_EXTENSIONS`는 미측정이다. |

EGL client 확장 전체 목록

```text
EGL_EXT_client_extensions
EGL_EXT_device_query
EGL_EXT_platform_base
EGL_ANGLE_platform_angle
EGL_ANGLE_platform_angle_vulkan
EGL_ANGLE_platform_angle_vulkan_device_uuid
EGL_ANGLE_platform_angle_device_id
EGL_KHR_client_get_all_proc_addresses
EGL_KHR_debug
EGL_ANGLE_feature_control
EGL_ANGLE_no_error
```

## 백엔드 및 ELF 의존성

SwiftShader 선택 확장은 광고되지 않았고 드라이버 초기화 전에 요청이 거부됐다. 명시적 SwiftShader 실행에서는 `libvulkan.so`와 별도 SwiftShader 모듈의 매핑이 관찰되지 않았다. 대조 실행은 ANGLE의 Vulkan 구현과 GSI Vulkan loader까지 진입했으나, 초기화에 성공한 Vulkan 장치나 GLES 렌더러는 확인되지 않았다. 경로와 반환값은 [기기 출력](../out/guest-angle-b0-20261119/device.txt#L9)에 기록했다. [ANGLE SwiftShader 선택 확장](https://chromium.googlesource.com/angle/angle/+/refs/heads/main/extensions/EGL_ANGLE_platform_angle_device_type_swiftshader.txt)

| ELF | Build ID | 직접 의존성 또는 실측 |
| --- | --- | --- |
| `libEGL_angle.so` | `b8db46c33713eb706ab28de73521fe0c` | `libGLESv2_angle.so liblog.so libm.so libnativewindow.so libc.so libdl.so` |
| `libGLESv2_angle.so` | `60c0726b2430edab766ce66f768963b4` | `libz.so liblog.so libm.so libnativewindow.so libc.so libdl.so` |
| `libvulkan.so` | `fcec72ebf9a693aef02c808cf98ef6eb` | 일반 Vulkan 실행에서 매핑. `libhardware.so`, `libgraphicsenv.so`, `libui.so`, `libnativewindow.so`, `libvndksupport.so` 등을 로드하는 플랫폼 Vulkan loader. |

- ANGLE ELF의 `DT_NEEDED`에는 SwiftShader ICD가 없다. GSI와 APEX 표준 경로의 사전 조사에서도 `libvk_swiftshader.so`와 `vulkan.pastel.so`를 발견하지 못했고, 두 실행의 ELF 매핑에도 SwiftShader 모듈이 없었다. 따라서 **별도 SwiftShader 라이브러리가 로드된 증거가 없다**. 실패한 모듈 검색에 대한 시스템 호출 추적은 수행하지 않았다. [ELF 발췌](../out/guest-angle-b0-20261119/elf-backend.txt) · [사전 조사](guest-graphics-buffer-experiment.md#실측-환경과-근거)
- `libGLESv2_angle.so`에는 SwiftShader의 확장명·오류 메시지·장치명 문자열이 있다. 이 문자열은 ICD 구현 포함 여부를 판별할 수 없다. **사용 가능한 내장 SwiftShader 경로는 확인되지 않았다**. 스트립된 ELF에 미사용 구현 코드가 물리적으로 들어 있는지는 미확정이다. 일반 Vulkan의 `-3`만으로 구체적인 ICD 탐색 실패 원인도 확정할 수 없다. [ELF 발췌](../out/guest-angle-b0-20261119/elf-backend.txt)
- `libnativewindow.so → libui.so`를 통해 그래픽 allocator/mapper 인터페이스 라이브러리가 매핑됐다. 실행 루트에는 Gralloc 서비스·mapper 구현 또는 Binder 장치가 없다. [전체 의존성](../out/guest-angle-b0-20261119/dependencies.txt) · [런타임 매핑](../out/guest-angle-b0-20261119/device.txt#L10)

## 재현

Linux/WSL에서 Android NDK, Python 3, `debugfs`, `readelf`로 빌드·추출한다. 저장소 루트에서 실행하며 `ANDROID_NDK_HOME`은 설치된 NDK를 가리킨다.

```sh
work=$(mktemp -d)
image=out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
  -std=c17 -Wall -Wextra -Werror -O2 native/guest-angle-b0.c -ldl -llog -o "$work/b0"
python3 scripts/stage-guest-angle-b0.py "$image" "$work/b0" "$work/root" > "$work/dependencies.txt"
tar -C "$work/root" -cf "$work/root.tar" .
```

root ADB가 가능한 기기에서 새 경로를 만들고 실행한다. 두 모드의 종료 코드는 각각 출력하며 스크립트는 SwiftShader 모드의 종료 코드를 반환한다. 이번 GSI에서는 `1`이다.

```sh
stage=$(adb shell 'umask 077; mktemp -d /data/local/tmp/ssal-angle-b0.XXXXXX' | tr -d '\r')
adb push "$work/root.tar" "$stage/root.tar"
adb push scripts/run-guest-angle-b0.sh "$stage/run.sh"
adb shell "set -e; mkdir '$stage/root'; tar -xf '$stage/root.tar' -C '$stage/root'"
adb shell "unshare -m -n /system/bin/sh '$stage/run.sh' '$stage/root'"
```
