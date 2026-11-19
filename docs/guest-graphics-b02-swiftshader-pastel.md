# SSAL 실험 B0.2 — SwiftShader Pastel ICD 이식 및 Vulkan Device 검증

2026-11-19 KST · **Pastel 로드 및 Vulkan Device 생성 PASS.** Lenovo TB320FC의 격리된 LineageOS 23.2 Guest에서 GSI Vulkan Loader가 Guest 전용 `/vendor/lib64/hw/vulkan.pastel.so`를 로드했다. `SwiftShader Device (LLVM 16.0.0)` CPU 장치 1개를 열거했고 `vkCreateDevice`가 `VK_SUCCESS`를 반환했다. [Vulkan 실측](../out/guest-vulkan-b02/vulkan.txt) · [B0.1 보고서](guest-graphics-b01-vulkan-icd.md)

## 산출물 출처와 ABI

- **PASS — Android 16 arm64 산출물 확보.** Ika 261111 공개 Cuttlefish 릴리스의 `ika-lineageos-261111-1-aarch64.pkg.tar.xz`를 사용했다. 게시된 SHA-256 `70d486f62affe9f8c821ba5fef106dc5a454560ab1b524210d2406028b140764`와 다운로드가 일치했다. 소스 태그는 `f4031cfa4f96c91aaf82a69a3a2d3c6e6f9f2501`, manifest의 AOSP SwiftShader 고정 리비전은 `9a22bb9de00f5d8ddf4fc5ba5c2f425c2816e679`다. 공급 이미지의 vendor build ID `BP4A.251205.006`과 SDK 36은 대상 GSI와 같다. 실험은 배포 바이너리를 사용했다. [릴리스 및 게시 체크섬](https://github.com/DesktopECHO/ika/releases/tag/261111) · [소스 manifest](https://github.com/DesktopECHO/ika/blob/261111/src/lineageos/manifests/lineageos-desktop.xml) · [검증 기록](../out/guest-vulkan-b02/provenance.txt)
- **PASS — ELF 및 HAL 인터페이스.** `super.img → vendor_a → /apex/com.google.cf.vulkan.swiftshader.apex → apex_payload.img → /lib64/hw/vulkan.pastel.so`에서 추출했다. SHA-256은 `ad204f1786992a42efa0c0ec0e9873aa20a658d6c9a9de60de5d7fb6c9c393c6`, Build ID는 `702fb145378745c1fd6125ee9ff0a51b`다. ELF64 AArch64 DSO, Android API note 36, SONAME `vulkan.pastel.so`, `PT_LOAD` 정렬 `0x4000`, `HMI` global object 248 bytes를 확인했다. HMI 헤더의 tag `HWMT`, module API `0.1`, ID `vulkan`은 Android HAL 형식과 일치한다. 실제 Loader가 HAL을 열고 장치를 반환해 인터페이스도 런타임에서 검증됐다. [ELF와 직접 의존성](../out/guest-vulkan-b02/pastel-elf.txt) · [HMI 원시 근거](../out/guest-vulkan-b02/provenance.txt) · [SwiftShader HAL 소스](https://swiftshader.googlesource.com/SwiftShader/+/fb632b91110cabce297c34b8c01ec8c931a10933/src/Vulkan/VkGetProcAddress.cpp)
- **PASS — 의존 ELF 해석.** Pastel의 직접 `DT_NEEDED`는 `libnativewindow.so`, `libhardware.so`, `libsync.so`, `liblog.so`, `libc++.so`, `libc.so`, `libm.so`, `libdl.so`다. 같은 APEX에서 꺼낸 `libhardware.so`, `libc++.so`, `libcutils.so`, `libbase.so`를 Guest vendor에 함께 배치했다. `libhardware.so → libcutils.so → libbase.so`까지 실제 파일 열기에 성공했다. 나머지는 GSI library 및 Bionic을 사용했다. 전체 APEX 활성화나 Host vendor 라이브러리 연결 없이 실행했다. [ELF 의존성](../out/guest-vulkan-b02/pastel-elf.txt) · [GSI 의존성](../out/guest-vulkan-b02/gsi-dependencies.txt) · [파일 접근 trace](../out/guest-vulkan-b02/vulkan.trace#L259)

## Guest 배치와 Vulkan 실측

실행기는 새 mount·network namespace를 만들고 `MS_REC|MS_PRIVATE`로 전파를 끊었다. 전용 staging 경로의 Pastel 디렉터리를 진단용 chroot의 `/vendor`로 bind하고 `ro,nodev,nosuid`로 재마운트했다. B0.1에서 확보한 SSAL Guest `ld.config.txt`를 사용했고 Guest의 regular-file property area로 `ro.hardware.vulkan=pastel`을 공급했다. chroot에는 Binder/GPU/display 노드가 없었다. 기존 `u:r:ksu:s0`에서 실행했고, 실제 SSAL mapped Guest SID에서의 로드 및 앱 권한은 **UNKNOWN**이다. [namespace·마운트 실측](../out/guest-vulkan-b02/vulkan.trace#L14) · [실행기 소스](../native/guest-pastel-mount.c)

| 단계 | 판정 | 반환값과 관측 |
| --- | --- | --- |
| 빈 vendor 대조 | **PASS** (대조) | `sphal`에서 Pastel `not found`, Loader API는 성공하고 physical device 0개. |
| GSI Loader의 ICD 탐색·로드 | **PASS** | `/vendor/lib64/vulkan.pastel.so`는 `ENOENT`, 다음 후보 `/vendor/lib64/hw/vulkan.pastel.so`는 `openat → fd 3`. `dl_iterate_phdr`에서도 같은 경로를 확인했다. |
| `vkEnumerateInstanceExtensionProperties` | **PASS** | count/list 모두 `VK_SUCCESS (0)`, 확장 15개. `VK_EXT_headless_surface`, `VK_KHR_android_surface`, `VK_KHR_get_physical_device_properties2` 포함. |
| `vkCreateInstance` | **PASS** | API 1.0 요청, layer/extension 활성화 0개. `VK_SUCCESS (0)` 및 유효한 instance. |
| `vkEnumeratePhysicalDevices` | **PASS** | count/list 모두 `VK_SUCCESS (0)`, 장치 1개. |
| `vkGetPhysicalDeviceProperties` | **PASS** | 반환형은 `void`. `SwiftShader Device (LLVM 16.0.0)`, CPU type `4`, vendor `0x1ae0`, device `0xc0de`, Vulkan API `1.3.0`, driverVersion 원시값 `20971520`. |
| `vkCreateDevice` | **PASS** | queue family 0은 queue 1개와 flags `0x7`을 제공했다. 확장과 optional feature를 활성화하지 않고 `VK_SUCCESS (0)`, 유효한 device, `vkDestroyDevice` 완료. |
| `vkEnumerateDeviceExtensionProperties` | **PASS** | count/list 모두 `VK_SUCCESS (0)`, 장치 확장 84개. `VK_KHR_swapchain` (68), `VK_ANDROID_external_memory_android_hardware_buffer` (5), `VK_KHR_external_semaphore_fd` (1) 포함. 이 호출은 확장을 열거했다. |

양성 실행 종료 코드는 0이다. instance/device 확장 전체 목록과 각 `specVersion`은 원본 로그에 있다. [빈 vendor 대조](../out/guest-vulkan-b02/negative-control.txt) · [ICD 탐색](../out/guest-vulkan-b02/vulkan.trace#L258) · [장치 속성과 확장 전체](../out/guest-vulkan-b02/vulkan.txt#L13)

## ANGLE 재검증과 최초 실패 지점

| 실행 | 판정 | 최초 차단 지점 |
| --- | --- | --- |
| B0 일반 ANGLE/Vulkan, Pastel 선택 | **BLOCKED** | `eglGetPlatformDisplayEXT` 성공. `eglInitialize` 중 Pastel 파일 열기에 성공했다. `/dev/hwbinder` 조회는 `ENOENT`였고 ConfigStore는 기본값을 사용했다. 이후 `libbinder.BackendUnifiedServiceManager`가 `servicemanager.ready`를 반복 대기했다. 45초 timeout으로 종료(124)됐으며 EGL 반환값은 관측되지 않았다. |
| 일반 ANGLE/Vulkan, Guest `servicemanager.installed=false` | **FAIL** | 독립 실행용 속성으로 readiness 대기를 통과했다. `eglInitialize`가 계속 진행되다가 mapper 4.x·3.x·2.x 조회 실패 후 `GraphicBufferMapper`가 `gralloc-mapper is missing`을 기록하고 `SIGABRT (6)`로 종료됐다. EGL 반환값은 관측되지 않았다. 같은 속성에서 직접 Vulkan `vkCreateDevice`는 재차 `VK_SUCCESS`였다. |
| B0 명시적 ANGLE SwiftShader 속성 | **FAIL** | `eglGetPlatformDisplayEXT`가 `EGL_BAD_ATTRIBUTE (0x3004)`로 종료됐다. 설치한 Android Vulkan HAL의 로드 성공과 별개로 현재 GSI ANGLE은 `EGL_ANGLE_platform_angle_device_type_swiftshader`를 광고하지 않는다. |
| pbuffer 및 `glReadPixels` | **BLOCKED** | 두 EGL 초기화 경로에서 초기화 완료 전에 중단됐다. `EGL_VENDOR`, `GL_RENDERER`, GL 확장 및 픽셀은 미측정이다. |

정상 속성에서의 첫 차단은 AIDL 서비스 매니저 readiness 대기이고, 독립 실행 대조에서 드러난 첫 치명 오류는 Guest Gralloc mapper 부재다. 어느 코드가 ANGLE 초기화 중 `GraphicBufferMapper`를 처음 호출했는지는 **UNKNOWN**이다. [ANGLE readiness 대기 trace](../out/guest-vulkan-b02/angle.trace#L265) · [AOSP libbinder 분기](https://android.googlesource.com/platform/frameworks/native/+/db049236e411740fae925f0353ab11e72a99e1ea/libs/binder/BackendUnifiedServiceManager.cpp) · [mapper 치명 오류](../out/guest-vulkan-b02/angle-standalone.txt#L18) · [SIGABRT trace](../out/guest-vulkan-b02/angle-standalone.trace#L297) · [독립 실행 직접 Vulkan 대조](../out/guest-vulkan-b02/vulkan-standalone.txt) · [명시적 선택 오류](../out/guest-vulkan-b02/angle-explicit-swiftshader.txt#L6)

## Host 불변성과 정리

Host GPU/HAL·물리 디스플레이·속성·vendor 설정·SELinux 정책을 변경하는 동작은 수행하지 않았다. 전후 SELinux `Enforcing`, 활성 정책 SHA-256, SurfaceFlinger PID `1537`, Host `/vendor`·`/odm` mount 및 SSAL mount 작업 디렉터리가 일치했다. chroot 이후 Host GPU 장치, Binder 장치 또는 Host 소켓 열기에 성공한 기록은 없다. `/dev/hwbinder`는 Guest에서 존재 확인에 실패했고, 독립 ANGLE의 crash logging 소켓도 `ENOENT`였다. userdata 이미지는 추출·생성·사용하지 않았다. [Host 실행 전](../out/guest-vulkan-b02/host-before.txt) · [Host 실행 후](../out/guest-vulkan-b02/host-after.txt) · [Guest trace](../out/guest-vulkan-b02/angle-standalone.trace#L288)

실행기·probe·tracer의 잔존 프로세스와 실험용 mount가 없음을 확인했다. 기기 staging 경로, WSL에서 받은 패키지와 이미지, 로컬 전송 아카이브를 삭제했다. 보존한 trace 3개의 SHA-256은 기기 원본과 일치했고, 정리 뒤에도 Host 전후 상태가 일치했다.

## 재현

### 배포 산출물 추출

WSL에서 공식 배포 파일을 내려받고 다음 순서로 필요한 항목만 추출했다. 사용한 [lpunpack.py](https://github.com/unix3dgforce/lpunpack)의 SHA-256은 `600d1cab2fc7de5127fb287f4e2791718db54efb1102d0f365db0d3ec1ccf62e`다. 아래 명령은 새 작업 디렉터리에서 실행한다. [Ika 261111 릴리스](https://github.com/DesktopECHO/ika/releases/tag/261111)

```sh
curl -fL https://github.com/DesktopECHO/ika/releases/download/261111/ika-lineageos-261111-1-aarch64.pkg.tar.xz -o ika.tar.xz
printf '%s  ika.tar.xz\n' 70d486f62affe9f8c821ba5fef106dc5a454560ab1b524210d2406028b140764 | sha256sum -c -
tar -Jxf ika.tar.xz --occurrence usr/share/cuttlefish-common/lineageos/super.img
mkdir -p partitions pastel/lib64/hw
python3 lpunpack.py -p vendor_a usr/share/cuttlefish-common/lineageos/super.img partitions
debugfs -R 'dump /apex/com.google.cf.vulkan.swiftshader.apex swiftshader.apex' partitions/vendor_a.img
unzip -p swiftshader.apex apex_payload.img > swiftshader-payload.img
debugfs -R 'dump /lib64/hw/vulkan.pastel.so pastel/lib64/hw/vulkan.pastel.so' swiftshader-payload.img
for lib in libhardware.so libc++.so libcutils.so libbase.so; do
  debugfs -R "dump /lib64/$lib pastel/lib64/$lib" swiftshader-payload.img
done
printf '%s  pastel/lib64/hw/vulkan.pastel.so\n' ad204f1786992a42efa0c0ec0e9873aa20a658d6c9a9de60de5d7fb6c9c393c6 | sha256sum -c -
readelf -Whlnd --dyn-syms pastel/lib64/hw/vulkan.pastel.so pastel/lib64/*.so
```

소스 빌드 재현은 Ika `261111` 태그의 BP4A arm64 빌드 흐름을 사용한다. Ika 소스 루트에서 `BUILD_VARIANT=user ./src/lineageos/scripts/build_lineageos_desktop.sh arm64`는 `lineage_desktop_cf_arm64_pgagnostic-bp4a-user` 제품을 대상으로 한다. manifest에 고정된 SwiftShader와 Cuttlefish 패치를 적용한 빌드 트리의 모듈은 `com.google.cf.vulkan.swiftshader`이며 `vulkan.pastel`을 포함한다. 이번에는 소스에서 Pastel을 다시 빌드하거나 배포 파일의 비트 단위 재현을 검증하지 않았다. [태그의 빌드 안내](https://github.com/DesktopECHO/ika/blob/261111/src/lineageos/README.md) · [APEX 모듈 정의 패치](https://github.com/DesktopECHO/ika/blob/261111/src/lineageos/patches/device-google-cuttlefish-vulkan-driver-apexes.patch)

### Probe 빌드와 기기 실행

SSAL 저장소 루트에서 NDK r30의 `aarch64-linux-android30-clang`를 사용한다. 아래에서 `work`는 새 작업 디렉터리이며 `$work/pastel`은 위에서 추출한 ELF 트리다.

```sh
cc="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
"$cc" -std=c17 -O2 -Wall -Wextra -Werror native/guest-angle-b0.c -ldl -llog -o "$work/angle"
"$cc" -std=c17 -O2 -Wall -Wextra -Werror native/guest-vulkan-b01.c -ldl -llog -o "$work/vulkan"
"$cc" -std=c17 -O2 -Wall -Wextra -Werror -static native/guest-pastel-mount.c -o "$work/guest-pastel-mount"
python3 scripts/stage-guest-angle-b0.py out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img \
  "$work/angle" "$work/root" > "$work/gsi-dependencies.txt"
mkdir -p "$work/root/system/bin" "$work/root/linkerconfig" "$work/root/vendor" "$work/root/odm" "$work/root/dev"
install -m 0755 "$work/angle" "$work/root/system/bin/ssal-angle-b0"
install -m 0755 "$work/vulkan" "$work/root/system/bin/ssal-vulkan-b01"
cp out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt \
  "$work/root/linkerconfig/ld.config.txt"
```

[B0.1의 property fixture](../out/guest-vulkan-b01/seed/src/main.rs)를 해당 `Cargo.toml`로 빌드한 뒤 WSL root로 실행해 `$work/root/dev/__properties__`를 새로 생성한다. 독립 ANGLE 대조에서는 [두 속성 fixture](../out/guest-vulkan-b02/standalone-property-fixture.rs)를 쓴다. 아카이브 소유권은 root:root로 지정한다. Guest 루트와 드라이버 트리에는 문자·블록 장치 노드가 없는지 확인한다.

```sh
tar --owner=0 --group=0 -C "$work/root" -cf "$work/root.tar" .
tar --owner=0 --group=0 -C "$work/pastel" -cf "$work/pastel.tar" .
stage=$(adb shell 'umask 077; mktemp -d /data/local/tmp/ssal-vulkan-b02.XXXXXX' | tr -d '\r')
adb push "$work/root.tar" "$work/pastel.tar" "$work/guest-pastel-mount" "$stage/"
adb shell "set -e; mkdir '$stage/root' '$stage/pastel'; \
  tar -xf '$stage/root.tar' -C '$stage/root'; tar -xf '$stage/pastel.tar' -C '$stage/pastel'; \
  chmod 0755 '$stage/guest-pastel-mount'; \
  test -z \"\$(find '$stage/root' '$stage/pastel' \( -type b -o -type c \) -print -quit)\""
adb shell "timeout -k 3 40 '$stage/guest-pastel-mount' '$stage' vulkan"
adb shell "timeout -k 3 45 '$stage/guest-pastel-mount' '$stage' angle"
```

실측의 파일 및 namespace 추적은 B0.1과 같은 Alpine arm64 `strace 6.13`으로 시작한 자식에만 `-f -ttt -s 220 -e trace=%file,write,connect,mount,umount2,unshare`를 적용했다. `angle-swiftshader` 모드는 B0 명시적 속성을 재현한다. 사용한 임시 bind는 자식 mount namespace의 수명에 따라 해제된다. [tracer 패키지 목록](../out/guest-vulkan-b02/tracer-packages.txt)

## 다음 최소 실험

동일 Pastel과 GSI에서 `GraphicBufferMapper`에 도달하는 첫 호출을 좁히고, Android native-buffer 경로를 쓰지 않는 headless/pbuffer 설정으로 재검증한다. mapper가 여전히 필수라면 Guest 전용 mapper와 private Binder를 갖춘 실행에서만 진행한다. 실제 SSAL mapped SID에서 동일 ELF·의존성의 열기 및 매핑과 Vulkan device 생성을 먼저 재현하고, ANGLE 초기화와 픽셀을 별도로 판정한다.
