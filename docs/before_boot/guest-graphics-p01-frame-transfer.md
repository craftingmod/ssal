# SSAL Graphics P0.1 — Guest RGBA 프레임 전송

2026-11-19 KST · **PASS — `u:r:ksu:s0` 진단 환경, B0.4 진단 ELF.** Lenovo TB320FC의 LineageOS 23.2 GSI (`BP4A.251205.006`, incremental `1779626072`)에서 ANGLE/Vulkan이 Guest Pastel의 SwiftShader로 4×4 pbuffer를 렌더링했다. Guest의 `glReadPixels(GL_RGBA, GL_UNSIGNED_BYTE)`가 반환한 64바이트를 Host 수신 프로세스가 받아 크기, stride 16바이트, RGBA8, RED 16/16을 확인했다. [기기 로그](../out/guest-graphics-p01/diagnostic.txt#L140)

| 실행 | 판정 | 실측 |
| --- | --- | --- |
| 원본 ANGLE, 16:08:15 | **FAIL** | 소켓 쌍 생성과 Guest namespace 진입 성공. `eglInitialize` 안에서 `AHardwareBuffer_isSupported → Gralloc5Mapper → AServiceManager_isDeclared → servicemanager.ready` 대기. 12초 후 종료 124. `glReadPixels`와 IPC `send`에 도달하지 못했다. [최초 차단 스택](../out/guest-graphics-p01/original.txt#L22) |
| B0.4 진단 ANGLE, 16:08:27 | **PASS** | `glReadPixels`의 GL 오류 0, 72바이트 송·수신, 64바이트 payload, 4×4, stride 16, RGBA8, RED 16/16, Guest와 Host 종료 0. [렌더러](../out/guest-graphics-p01/diagnostic.txt#L88) · [송수신](../out/guest-graphics-p01/diagnostic.txt#L149) |
| 실제 SSAL Guest SID | **미실행** | 별도 단계에서 실제 Guest 프로세스의 SID·UID와 namespace를 기록하고 동일 레코드를 수신해 판정한다. |

```text
Host pid=28722 created private AF_UNIX SOCK_SEQPACKET pair
Launcher before unshare pid=28723 mount=mnt:[4026532493] network=net:[4026531983] sid=u:r:ksu:s0
Launcher after unshare pid=28723 mount=mnt:[4026535143] network=net:[4026535145] sid=u:r:ksu:s0
glReadPixels(0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels): return=void GL=0x0000
Guest begin send fd=4 packet=72 payload=64
Host recv packet=72 payload=64 width=4 height=4 stride=16 format=1
Host RED=16/16
Guest send=72
Guest exit=0
SSAL P0.1 PASS
exit=0
```

## IPC 경계

Host 수신기는 `socketpair(AF_UNIX, SOCK_SEQPACKET)`으로 이 실험 전용 연결을 만들고 fork한 Guest 실행기에 송신 FD만 넘긴다. 실행기는 mount·network namespace를 분리한 뒤 chroot하고 Guest linker로 exec한다. 송신 FD는 상속으로 이어진다. 소켓 경로, 이름 조회, 새 연결은 없다. 위 실행에서 namespace 경계를 통과했고 SELinux SID 경계 검증은 실제 Guest SID 단계에 남아 있다. [수신기](../native/host-frame-p01.c) · [실행기](../native/guest-pastel-mount.c) · [Guest 프로브](../native/guest-angle-b0.c)

단일 레코드의 헤더는 8바이트다. `SSAL` 4바이트 다음에 width, height, byte stride, pixel format을 각각 1바이트로 기록한다. format `1`은 RGBA8이고 뒤에 `glReadPixels` 버퍼 64바이트가 그대로 온다. 수신기는 `MSG_TRUNC`로 실제 레코드 크기를 검사한 뒤 헤더와 16개 픽셀의 `ff 00 00 ff` 여부를 검증한다. Linux 수신기 대조에서 71/73바이트, 잘못된 magic·가로·세로·stride·format, RED 15/16, 송신 없이 종료한 경우, 정상 레코드 송신 뒤 Guest가 실패한 경우 모두 종료 코드 1이었다. 정상 레코드와 Guest 종료 0은 통과했다. [프레임 형식](../native/guest-frame-p01.h)

실패 시 마지막 성공 단계 다음의 첫 오류를 기록한다. 수신 전 차단은 Guest의 마지막 EGL/GL 단계와 종료 코드로, IPC 차단은 `socketpair`·`send`·`recv` 중 실패한 호출의 errno와 각 프로세스의 SID·UID·mount/network namespace로 확인한다. 권한을 확대하지 않고 그 실행을 종료한다. 원본 실행의 차단은 IPC 사용 전에 발생했고, 진단본 실행에서는 IPC 오류가 관측되지 않았다.

Host SurfaceFlinger PID 1537, SELinux Enforcing과 활성 정책 SHA-256, `/vendor`·`/odm` 마운트가 전후 일치했다. Guest staging에는 문자·블록 장치 노드가 없었다. Host SurfaceFlinger·HWC·Binder·DRM·SELinux 정책 변경과 화면 표시는 실험 범위에서 제외했다. [Host 전](../out/guest-graphics-p01/host-before.txt) · [Host 후](../out/guest-graphics-p01/host-after.txt) · [Guest fixture](../out/guest-graphics-p01/guest-fixture.txt)

## 재현

WSL의 SSAL 저장소 루트에서 NDK r30을 사용한다. 새 작업 디렉터리 `$work`에 B0.2의 SHA-256 검증을 거친 `pastel/`을 준비한다. B0.2 절차의 linker config를 복사하고 B0.1의 root 소유 property fixture로 `ro.hardware.vulkan=pastel`만 설정한다. [Pastel과 property fixture 준비](guest-graphics-b02-swiftshader-pastel.md#재현) · [B0.4 진단 대조](guest-graphics-b04-surfaceless-control.md#재현과-적용-범위)

```sh
cc="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
"$cc" -std=c17 -O2 -Wall -Wextra -Werror -DSSAL_B04 -DSSAL_MAPPER_TRACE \
  -DSSAL_FRAME_P01 -funwind-tables -fno-omit-frame-pointer \
  native/guest-angle-b0.c -ldl -llog -o "$work/angle"
"$cc" -std=c17 -O2 -Wall -Wextra -Werror -static native/guest-pastel-mount.c -o "$work/guest-pastel-mount"
"$cc" -std=c17 -O2 -Wall -Wextra -Werror -static native/host-frame-p01.c -o "$work/host-frame-p01"
python3 scripts/stage-guest-angle-b0.py out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img \
  "$work/angle" "$work/root"
mkdir -p "$work/root/system/bin" "$work/root/linkerconfig" "$work/root/vendor" "$work/root/odm" "$work/root/dev"
mv "$work/root/b0" "$work/root/system/bin/ssal-angle-p01"
cp out/guest-ashmem-20261117/attempt115/device-stage/attempt115/worker/phase7b/ld.config.txt \
  "$work/root/linkerconfig/ld.config.txt"
python3 scripts/patch-guest-angle-b04.py "$work/root/system/lib64/libGLESv2_angle.so" \
  "$work/libGLESv2_angle.diagnostic.so"
```

B0.1 property fixture를 `$work/root/dev/__properties__`에 생성한 뒤 B0.2의 root:root tar 배치 절차를 따른다. Guest staging 디렉터리 `$stage`에 `root/`, `pastel/`을 풀고 새 실행기 두 개와 진단 ELF를 같이 올린다. `guest-pastel-mount`와 `host-frame-p01`에 실행 권한을 주고, staging에 장치 노드가 없는지 확인한다. ADB 셸에서 `id`의 context가 `u:r:ksu:s0`이고 `getenforce`가 `Enforcing`인지 확인한다.

```sh
# 먼저 원본 대조. B0.4에서 확인된 대기 지점에서 124가 예상된다.
adb shell "timeout -k 3 12 '$stage/host-frame-p01' '$stage/guest-pastel-mount' '$stage'"

# 진단본은 staging의 ELF에만 적용한다. 원본을 복원하고 SHA-256을 출력한다.
adb shell "set -e; cd '$stage'; elf=root/system/lib64/libGLESv2_angle.so;
  cp \"\$elf\" libGLESv2_angle.original.so;
  trap 'cat libGLESv2_angle.original.so > \"\$elf\"; sha256sum \"\$elf\"' EXIT;
  cat libGLESv2_angle.diagnostic.so > \"\$elf\";
  timeout -k 3 12 ./host-frame-p01 ./guest-pastel-mount '$stage'"
```

진단본의 SHA-256은 `6966c7708ae637329906678ea48a44c5d7d1ff8398612d5cdb476ad010e4e614`이었다. 실행 뒤 staging의 ELF를 복구했고 원본 SHA-256 `9114d0748ef743a1d3c4aecf5a51e17cebdec869e369ac3661ba5781af5954fb`와 일치했다. 기기와 WSL의 임시 staging을 제거했고 기기에 관련 프로세스와 마운트가 남아 있지 않음을 확인했다. 이번 실험에서 userdata 이미지는 생성하지 않았다. [ELF 해시](../out/guest-graphics-p01/angle-sha256.txt) · [복구 해시](../out/guest-graphics-p01/restored-sha256.txt) · [정리 기록](../out/guest-graphics-p01/cleanup.txt)
