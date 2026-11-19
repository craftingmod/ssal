# SSAL 실험 B0.1 — Vulkan Loader / ICD Discovery

2026-11-19 KST · **Vulkan Loader API PASS, Guest ICD FAIL.** Lenovo TB320FC에서 LineageOS 23.2 GSI의 `libvulkan.so`를 직접 호출했다. instance extension 8개를 읽고 Vulkan 1.0 인스턴스를 만들었다. `vkEnumeratePhysicalDevices`는 `VK_SUCCESS`와 장치 수 0을 반환했다. B0의 `VK_ERROR_INITIALIZATION_FAILED (-3)`는 이 장치 수 0을 처리하는 ANGLE의 분기에서 생성됐다. [직접 호출 결과](../out/guest-vulkan-b01/baseline.txt) · [B0 기기 오류](../out/guest-angle-b0-20261119/device.txt#L63) · [ANGLE ELF 분기](../out/guest-vulkan-b01/angle-error-branch.txt)

## 실행 범위와 판정

B0와 같은 Android 16 AArch64 GSI에서 Loader와 Bionic 및 ELF 의존성을 추출했다. Loader Build ID는 `fcec72ebf9a693aef02c808cf98ef6eb`다. 별도 mount·network namespace의 진단용 chroot에서 기존 `u:r:ksu:s0`로 실행했다. ANGLE은 B0.1 루트에 포함하지 않았다. 기본 실행은 B0와 같은 기본 linker 설정을 사용했다. 재현 실행은 11-17 SSAL Guest에서 캡처한 `ld.config.txt`를 그대로 읽고, Bionic 경로만 `LD_LIBRARY_PATH`로 보충했다. 두 번째 재현에서는 임시 chroot의 regular file로 `ro.hardware.vulkan=pastel` 하나를 공급했다. 두 재현 모두 Guest 소유의 빈 `/vendor/lib64/hw` 및 `/odm/lib64/hw` 디렉터리를 사용했다. [GSI ELF 근거](../out/guest-vulkan-b01/loader-elf.txt) · [전체 ELF 의존성](../out/guest-vulkan-b01/dependencies.txt) · [Guest linker 설정](../out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt#L27)

| 검증 항목 | 판정 | 실측 |
| --- | --- | --- |
| `dlopen("/system/lib64/libvulkan.so")` | **PASS** | 3회 성공. |
| `vkEnumerateInstanceExtensionProperties` | **PASS** | count 및 list 호출 모두 `0 VK_SUCCESS`. 세 실행에서 동일한 확장 8개. |
| `vkCreateInstance` | **PASS** | 레이어와 확장 활성화 없이 API 1.0으로 `0 VK_SUCCESS`, 유효한 핸들 획득. |
| `vkEnumeratePhysicalDevices` | **PASS** (호출) / **FAIL** (장치 발견) | `0 VK_SUCCESS`, count=0. 세 실행에서 동일. |
| physical device 이름·ID·device extensions | **BLOCKED** | 조회할 장치가 없어 device 목록 및 장치별 호출을 생략했다. |
| Guest 소유 Vulkan ICD | **FAIL** | `pastel` 탐색을 실제로 유발했으며, `sphal`의 세 파일 열기 모두 `ENOENT`였다. |
| 완전한 SSAL Guest에서의 Vulkan 실행 | **UNKNOWN** | 캡처된 linker 설정과 현재 커널의 Guest SID 접근 결정을 각각 검증했다. mapped Guest 프로세스에서 Vulkan을 다시 실행하지 않았다. |

세 실행의 probe 종료값 `1`은 장치 0개에 대한 실험 판정이다. Vulkan 호출의 반환값은 위 표와 같다. [기본 실행](../out/guest-vulkan-b01/baseline.txt) · [linker 설정 재현](../out/guest-vulkan-b01/replay.txt) · [Pastel 선택 재현](../out/guest-vulkan-b01/pastel.txt)

전체 instance extensions와 `specVersion`

```text
VK_KHR_surface                          25
VK_KHR_surface_protected_capabilities    1
VK_KHR_android_surface                   6
VK_EXT_swapchain_colorspace               5
VK_KHR_get_surface_capabilities2          1
VK_GOOGLE_surfaceless_query               2
VK_EXT_surface_maintenance1              1
VK_EXT_debug_report                      10
```

## 최초 실패 지점

1. 선택자를 지정한 실행에서 최초 차단은 `vkEnumerateInstanceExtensionProperties(count)` 안의 ICD 검색이다. `android_load_sphal_library`가 `vulkan.pastel.so`를 열지 못해 `library ... not found`를 기록한다. 세 공개 API는 이후에도 성공한다. 이 동작은 HAL 로드 실패 시 Android Loader가 stub HAL을 유지하고, stub이 physical device 수 0을 돌려주는 소스와 일치한다. [선택자 실측 trace](../out/guest-vulkan-b01/pastel.trace#L419) · [AOSP HAL 선택](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/vulkan/libvulkan/driver.cpp#253) · [AOSP stub HAL](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/vulkan/libvulkan/stubhal.cpp)
2. B0의 `-3`는 `vk_renderer.cpp:2477`에서 처음 만들어진다. B0와 같은 Build ID의 ANGLE ELF를 오프라인에서 확인했다. `0x2f2b04`는 Vulkan 호출 자체의 오류를 검사해 2476행으로 보내고, 성공 시 `0x2f2b0c`에서 출력 count를 검사한다. count=0일 때 `0x2f3e74`가 `-3`을, `0x2f3e7c`가 소스 행 2477을 설정한다. 이 흐름은 ANGLE 소스의 physical device 수 검사 및 B0.1의 직접 호출 결과와 일치한다. [ELF 명령어 발췌](../out/guest-vulkan-b01/angle-error-branch.txt) · [ANGLE 초기화 소스](https://android.googlesource.com/platform/external/angle/+/refs/heads/main/src/libANGLE/renderer/vulkan/vk_renderer.cpp#2572)

## ICD 탐색과 Guest 접근 조건

- **Loader 동작.** GSI ELF에는 `ro.hardware.vulkan`, `ro.board.platform`, `ro.vulkan.apex`와 `android_load_sphal_library`, `android_dlopen_ext`, `android_get_exported_namespace`가 있다. 대응 AOSP 소스는 GraphicsEnv가 설정한 업데이트 드라이버 namespace, `ro.vulkan.apex`가 지정한 APEX, 내장 HAL 경로 순으로 선택한다. 후보 파일명은 `ro.hardware.vulkan`, 이어서 `ro.board.platform`으로 `vulkan.<값>.so`를 구성한다. HAL 로드는 `HMI` 모듈 심볼과 `vulkan` ID를 확인한 뒤 모듈의 Vulkan device를 연다. 이번 GSI Loader ELF에 `hw_get_module` 미해결 심볼은 없고, 선택자 재현에서 `sphal` 경로를 실측했다. [GSI ELF](../out/guest-vulkan-b01/loader-elf.txt) · [AOSP 드라이버 탐색](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/main/vulkan/libvulkan/driver.cpp#151) · [AOSP libvndksupport](https://android.googlesource.com/platform/system/core/+/android16-qpr2-release/libvndksupport/linker.cpp)
- **실제로 조회한 파일.** 선택자 없는 실행은 chroot 이후 `libvulkan.so`를 열었으며 `vulkan.<값>.so` 파일 조회는 없었다. `pastel`을 넣자 최초 확장 개수 호출 중 `/odm/lib64/vulkan.pastel.so` → `/vendor/lib64/vulkan.pastel.so` → `/vendor/lib64/hw/vulkan.pastel.so` 순으로 `openat`이 발생했다. 셋 모두 `ENOENT`였다. `/system/lib64/hw/vulkan.pastel.so`, `/vendor/lib64/egl/vulkan.pastel.so`, `/etc/vulkan/icd.d` 및 두 데스크톱 환경 변수에 넣은 `/ssal-b01-sentinel.json`의 파일 조회는 이 trace에 없었다. [무선택 trace](../out/guest-vulkan-b01/empty.trace#L411) · [Pastel trace](../out/guest-vulkan-b01/pastel.trace#L419) · [Khronos의 Android Loader 설명](https://github.com/KhronosGroup/Vulkan-Loader/blob/main/docs/LoaderDriverInterface.md)
- **실제 Guest 설정.** 11-17 캡처의 `[system]`에서 `default`는 `/system/lib64`, `/system/system_ext/lib64`를 검색하고 `/system/lib64/hw`를 permitted path에 포함한다. `sphal`은 isolated·visible이며 `/odm/lib64`, `/vendor/lib64`, `/vendor/lib64/egl`, `/vendor/lib64/hw`를 검색한다. `sphal → default` 링크는 지정된 SONAME만 허용한다. 따라서 default의 permitted path에 파일을 두는 것만으로는 `sphal`의 이름 기반 탐색에 들어가지 않는다. 재현 trace에서 config 열린 뒤 `sphal` 조회까지 확인했다. 기존 SSAL property service의 seed는 `/system/build.prop`과 생성된 `guest_build.prop`이며, 두 입력에 조사한 Vulkan 드라이버 선택자가 없다. 이번 실행에서 실제 Guest property service를 재기동하지 않았다. [default 설정](../out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt#L27) · [sphal 설정](../out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt#L759) · [설정 파일 open](../out/guest-vulkan-b01/empty.trace#L202) · [SSAL seed 코드](../src/guest/environment.rs#L47) · [GSI 파일 목록](../out/guest-vulkan-b01/gsi-property-inventory.txt)
- **파일 출처와 SELinux.** GSI의 `/system/lib64/hw`에는 오디오 모듈 7개가 있고 Vulkan 모듈은 없다. GSI·APEX 표준 경로의 이전 인벤토리에도 SwiftShader ICD가 없었다. 일반 SSAL 프로필은 Host `/vendor`와 `/odm`을 read-only bind한다. Lenovo의 Host `/vendor/lib64/hw/vulkan.adreno.so`는 파일명과 라벨만 조회했다. 현재 커널의 `selinuxfs/access` 질의에서 실제 Guest Shell SID `u:r:ssal_p0001_shell:s0`는 `vendor_file` 및 `vendor_hal_file` 디렉터리의 `search`, Adreno 파일 라벨 `same_process_hal_file`의 `getattr/open/read/map/execute`가 모두 거부됐다. 반면 mapped `system_file` 및 `system_lib_file` 디렉터리의 `search`와 mapped `system_lib_file`의 `open/read/map/execute`는 허용됐다. 이 결과는 커널 정책 질의이며 다른 Guest 앱 SID, 실제 ICD inode의 DAC·SELinux label, mount의 실행 가능 여부, 종속 ELF의 namespace 접근성은 별도 검증 대상이다. [Host 파일 라벨](../out/guest-vulkan-b01/host-before.txt) · [Guest Shell SID 실측](../out/guest-shell-20261117/ATTEMPT114/pty.stdout.txt#L57) · [현재 커널 접근 결정](../out/guest-vulkan-b01/selinux.jsonl) · [마운트 프로필](../module/profiles/mounts/initial.json#L20)

Host GPU/HAL과 디스플레이를 호출하거나 변경하지 않았고, Host 속성·vendor 설정·SELinux 정책도 변경하지 않았다. 전후 SurfaceFlinger PID `1537`, SELinux `Enforcing`, 정책 SHA-256, `/vendor`·`/odm` mount 정보가 일치했다. chroot 이후의 trace에 `/dev/dri`·`/dev/kgsl*` 접근은 없었다. userdata 이미지를 생성하거나 사용하지 않았다. [Host 실행 전](../out/guest-vulkan-b01/host-before.txt) · [Host 실행 후](../out/guest-vulkan-b01/host-after.txt)

## SwiftShader Android arm64 가능성과 다음 최소 실험

**PASS (빌드 경로 확인), UNKNOWN (이 GSI에서의 호환성).** AOSP에 Android vendor HAL용 `vulkan.pastel` Soong 모듈과 `hw` 설치 경로가 있다. generic arm64 소프트웨어 렌더링 제품도 Pastel을 패키지하고 `ro.hardware.vulkan=pastel`로 선택하는 선례가 있다. 해당 빌드는 LLVM Reactor를 사용하며 Subzero는 arm64를 지원하지 않는다. AOSP 모듈에는 버전에 따라 `libnativewindow`, `libsync`, `liblog` 등 Android 의존성과 AHardwareBuffer 관련 소스가 포함된다. GSI와 같은 Android 계열에서 ARM64/Bionic·Android Vulkan HAL ABI의 산출물을 확보하는 경로가 타당하다. 이 단계에서 SwiftShader를 구현하거나 빌드·설치하지 않았다. [AOSP SwiftShader 빌드 정의](https://android.googlesource.com/platform/external/swiftshader/+/refs/heads/main/src/Android.bp) · [generic arm64 SwANGLE 제품](https://android.googlesource.com/device/linaro/dragonboard/+/b2534ba9661d343fbf1e43e93e4e3d4667137a2d%5E%21/) · [Reactor 아키텍처 설정](https://android.googlesource.com/platform/external/swiftshader/+/1045249e0b74fee730736afc5e6752bebc9592dd/src/Reactor/reactor.gni)

다음 실험은 호환되는 `vulkan.pastel.so` 한 개와 필요한 Guest 소유 의존성으로 시작한다. ELF64/AArch64, `HMI` export, `DT_NEEDED` 및 LOAD segment 정렬을 오프라인에서 확인한 뒤, Guest 전용 `/vendor/lib64/hw`와 Guest 속성으로 선택한다. 같은 probe에서 실제 모듈 열기, 세 API의 `VK_SUCCESS`, 1개 이상의 CPU physical device, 장치명 및 device extensions를 확인하면 통과다. mapped Guest SID에서 경로의 `search/open/read/map/execute`도 확인한다. 현재 Guest Shell의 `execmem` 정책 질의는 허용이지만 JIT 실행이나 다른 도메인의 권한은 미검증이다. 이 단계 통과 뒤에 B0의 일반 Vulkan pbuffer 경로를 재검증한다. [현재 커널 접근 결정](../out/guest-vulkan-b01/selinux.jsonl) · [B0 초기화 보고서](guest-graphics-b0-angle-swiftshader-20261119.md)

## 재현

WSL에서 Android NDK r30, Python 3, `debugfs`, `readelf`를 사용했다. 저장소 루트에서 아래처럼 빌드하고 새 디렉터리에 추출한다.

```sh
work=$(mktemp -d)
image=out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img
"$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang" \
  -std=c17 -Wall -Wextra -Werror -O2 native/guest-vulkan-b01.c -ldl -llog -o "$work/probe"
python3 scripts/stage-guest-angle-b0.py --vulkan-only "$image" "$work/probe" "$work/root" \
  > "$work/dependencies.txt"
mkdir -p "$work/root/system/lib64/hw"
tar -C "$work/root" -cf "$work/root.tar" .
stage=$(adb shell 'umask 077; mktemp -d /data/local/tmp/ssal-vulkan-b01.XXXXXX' | tr -d '\r')
adb push "$work/root.tar" "$stage/root.tar"
adb shell "set -e; mkdir '$stage/root'; tar -xf '$stage/root.tar' -C '$stage/root'"
adb shell "unshare -m -n timeout -k 3 25 env -i \
  LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/system/lib64 \
  /system/bin/chroot '$stage/root' /apex/com.android.runtime/bin/linker64 /system/bin/ssal-vulkan-b01"
```

namespace 재현은 chroot에 캡처된 `/linkerconfig/ld.config.txt` 및 Guest 소유 빈 `vendor/lib64/hw`, `odm/lib64/hw`를 만들고 `LD_LIBRARY_PATH`에서 `/system/lib64`를 제외한다. 선택자 대조는 [fixture 소스](../out/guest-vulkan-b01/seed/src/main.rs)의 `rsproperties 0.7.0` 생성물을 root:root로 chroot의 `/dev/__properties__`에 배치한다. 파일 접근은 Alpine arm64 패키지의 `strace 6.13`으로 오직 probe를 실행하는 자식에 대해 `-s 240 -e trace=%file,write`로 수집했다. trace에서 `chroot(".") = 0` 이후가 Guest 실행이다. [tracer 패키지 목록](../out/guest-vulkan-b01/tracer-packages.txt) · [Alpine arm64 패키지](https://pkgs.alpinelinux.org/package/v3.22/main/aarch64/strace)
