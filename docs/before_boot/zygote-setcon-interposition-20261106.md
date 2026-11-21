# Guest Zygote `selinux_android_setcon()` interposition — 2026-11-06

## 결론

현재 Android 16 GSI의 `libandroid_runtime.so`에서 `selinux_android_setcon()`은 PLT/GOT 동적 심볼로 호출되므로, Guest Zygote 실행 시 주입한 `LD_PRELOAD` 라이브러리로 선택적으로 가로챌 수 있는 정적 구조다. 다만 **최종 setter만 가로채도 선행 `selinux_android_setcontext()`가 실패하면 system_server fork는 이미 중단된다.** 따라서 startup SID 선택과 transition을 먼저 Guest 전용으로 해결해야 한다. 이 조사는 읽기 전용이며 interposer 구현, GSI 변경, SELinux 정책 변경 또는 Guest system_server 실행은 하지 않았다.

## 대상 ELF와 interposition 지점

대상은 `out/phase7fb/source/libandroid_runtime.so`이며 SHA-256은 `d35220026ef94be6992d8b9b31cd446f937b8e782833813b2ac68140f41fc035`로 기존 [Phase 8B-2 GSI 기록](phase8b2-selinux-transition.md)과 일치한다. AArch64 ELF의 dynamic symbol table에서 두 API 모두 global undefined function import다. 각각 `selinux_android_setcontext@LIBSELINUX_R`와 `selinux_android_setcon@LIBSELINUX_R`로 기록되어 있다.

| API | PLT/GOT relocation (ELF VA) | 직접 caller call VA | ABI |
|---|---:|---:|---|
| `selinux_android_setcontext` | `R_AARCH64_JUMP_SLOT` `0x2ca2c8` | `0x260c78` | `(uid_t, bool, const char *, const char *) -> int` |
| `selinux_android_setcon` | `R_AARCH64_JUMP_SLOT` `0x2ca2d0` | `0x260dd0` | `(const char *) -> int` |

GOT 대상 심볼은 버전 이름이 붙어 있지만, Bionic linker 소스는 version table이 없는 정의 라이브러리의 심볼을 요청 버전과 일치하는 것으로 취급하며 preload 목록을 lookup 후보로 사용한다. 따라서 통상적인 unversioned C export도 이 import를 선점할 수 있는 구조다. 대상 ELF는 `BIND_NOW`/`NOW`라 relocation을 로드 때 즉시 확정하지만, eager binding은 preload 우선 symbol lookup 자체를 막지 않는다. 이 ELF의 linker namespace/실기기 binding 동작을 직접 확인한 것은 아니므로 정적 결론으로 한정한다. [Bionic Android 10 linker](https://android.googlesource.com/platform/bionic/+/android10-c2f2-release/linker/linker_soinfo.cpp), [현재 Bionic symbol version lookup과 lookup 순서](https://android.googlesource.com/platform/bionic/+/master/linker/linker_soinfo.cpp)

SSAL은 Guest Zygote 실행에만 별도의 `LD_PRELOAD` 목록을 설정하는 경로가 이미 있다([`guest_launcher.rs`](../src/guest_launcher.rs#L250)). 따라서 해당 목록에 전용 interposer를 넣으면 주입 범위의 첫 경계는 Guest Zygote가 된다. 다만 fork한 child도 같은 매핑을 물려받고, 후속 exec 프로세스에는 환경 변수가 상속될 수 있다. 구현 시 정확한 `u:r:system_server:s0` 인자, UID 1000 및 Guest 실행 조건을 함께 확인하고, 적용할 child가 아닌 exec 경로에서 preload가 지속되지 않도록 해야 한다. host Zygote 환경은 별도로 구성하지 않는다.

## Android 10~16 흐름과 ABI

AOSP Android 10, 11, 12, 13, 14, 15, 16의 `com_android_internal_os_Zygote.cpp`에서 system_server specialization은 다음 의미 순서를 유지한다.

1. native specialization이 먼저 `selinux_android_setcontext(uid, is_system_server, seinfo, nice_name)`를 호출한다. 실패 시 `fail_fn`으로 fork child가 중단된다.
2. `is_system_server`일 때 system-server post-fork hook을 실행한다.
3. 그 뒤 고정 문자열 `u:r:system_server:s0`를 `selinux_android_setcon()`에 전달하고 실패도 fatal 처리한다.
4. 일반 child post-fork hook을 진행한다.

| Android | ABI / 관측된 분기 차이 |
|---|---|
| 10 | 4인자 `setcontext`, system_server 조건부 `setcon` 흐름 확인. |
| 11 | 같은 함수 ABI와 두 단계 전환 흐름. |
| 12 | 같은 함수 ABI와 두 단계 전환 흐름. |
| 13 | 같은 함수 ABI와 두 단계 전환 흐름. |
| 14 | 같은 함수 ABI와 두 단계 전환 흐름. |
| 15 | 같은 함수 ABI와 두 단계 전환 흐름. |
| 16 | 같은 함수 ABI와 두 단계 전환 흐름. 일부 post-fork 작업 및 함수 주변 코드는 버전별로 달라졌지만 대상 setter 계약은 유지. |

libselinux Android API 선언도 두 함수의 반환형과 인자형을 이 형태로 정의한다. [Android 10 Zygote native source](https://android.googlesource.com/platform/frameworks/base/+/android10-release/core/jni/com_android_internal_os_Zygote.cpp), [Android 11](https://android.googlesource.com/platform/frameworks/base/+/android11-release/core/jni/com_android_internal_os_Zygote.cpp), [Android 12](https://android.googlesource.com/platform/frameworks/base/+/android12-release/core/jni/com_android_internal_os_Zygote.cpp), [Android 13](https://android.googlesource.com/platform/frameworks/base/+/android13-release/core/jni/com_android_internal_os_Zygote.cpp), [Android 14](https://android.googlesource.com/platform/frameworks/base/+/android14-release/core/jni/com_android_internal_os_Zygote.cpp), [Android 15](https://android.googlesource.com/platform/frameworks/base/+/android15-release/core/jni/com_android_internal_os_Zygote.cpp), [Android 16](https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/jni/com_android_internal_os_Zygote.cpp), [`selinux/android.h`](https://android.googlesource.com/platform/external/selinux/+/refs/heads/master/libselinux/include/selinux/android.h). ABI 관점에서는 같은 타입으로 구현 가능하지만, 정책·linker·seapp 설정과 surrounding fork flow는 각 GSI에서 별도 대조해야 하므로 Android 10~16 전체에 검증 없이 단일 바이너리를 적용할 수 있다는 뜻은 아니다.

## 선행 전이와 안전한 가로채기 범위

`selinux_android_setcontext()`는 seapp 규칙으로 현재 SID를 기반으로 한 startup context를 계산하고 `security_check_context()` 후 필요할 때 `selinux_android_setcon(ctx)`를 호출한다. 여기서 실패하면 Zygote native 코드가 즉시 fork를 실패 처리하므로, 뒤쪽 `selinux_android_setcon("u:r:system_server:s0")` interposition은 호출되지 않는다. 현 GSI의 `plat_seapp_contexts`는 system_server startup SID를 `system_server_startup`으로 고르며, 기존 SSAL 조사에서는 일반 app child의 `setcontext`가 `EINVAL`을 반환했다. 이것만으로 system_server 입력도 같은 이유로 실패한다고 단정할 수는 없지만, 성공 여부를 사전 검증해야 한다. [libselinux Android context implementation](https://android.googlesource.com/platform/external/selinux/+/refs/heads/master/libselinux/src/android/android_device.c), [Guest startup/final transition 분석](phase8b2-selinux-transition.md), [app child 실측](zygote-phase7fc-results.md)

대상 GSI의 `libselinux.so` 해시도 기존 기록과 일치한다. 해당 ELF의 `selinux_android_setcontext()` 구현은 startup context 적용 시 `setcon@plt`를 직접 호출한 뒤 `__system_properties_init@plt`를 별도 호출하며, `selinux_android_setcon()`으로 되돌아가지는 않는다. 그러므로 `selinux_android_setcon`만 interpose하면 선행 startup transition은 통과 변경되지 않고, final `libandroid_runtime.so` 호출은 별도로 잡을 수 있다. 이는 현재 GSI ELF에 대한 disassembly 근거이며 모든 Android 버전의 내부 구현을 보증하지 않는다. Final hook은 원본 `selinux_android_setcon(guest_context)`를 호출해 그 함수의 property 재초기화 의미를 보존해야 한다.

전용 Guest SID로 이어지는 최소 설계는 다음 두 seam을 모두 맞춰야 한다.

- `setcontext(..., isSystemServer=true, ...)`가 Guest 전용 startup type을 선택하고, Guest Zygote에서 그 type으로 전이할 수 있어야 한다. 현재 검토 후보는 `ssal_guest_system_server_startup`이다.
- 마지막 `setcon` 인자가 기본 `u:r:system_server:s0`일 때만 Guest final type으로 바꿔 실제 setter를 호출해야 한다. 그 setter가 성공한 뒤 libselinux가 수행하는 property 재초기화 의미도 보존해야 한다.

즉, `setcontext`를 통째로 성공 처리하거나 모든 요청을 우회하는 interposer는 이 설계의 대안이 아니다. 다른 Guest app specialization 호출까지 바꾸면 현재의 `EINVAL` 진단 및 보안 경계를 넓히므로 별도 근거 없이 가로채면 안 된다. 최종 SID가 Guest 전용이어도 UID/GID, capability, namespace, policy allow 및 Host 접근 거부는 따로 검증해야 한다.

## 구현 난이도 평가

| 선택지 | 코드 난이도 | 전체 작업 난이도 | 평가 |
|---|---|---|---|
| Guest Zygote 전용 `LD_PRELOAD` interposer | 낮음~중간 | 중간~높음 | C/C++의 두 함수 ABI와 target gate 자체는 작다. 다만 `setcontext` 선행 성공, 버전 있는 import binding, property 재초기화 보존, child 환경 상속, SELinux label/접근 및 system_server 전체 부팅까지 검증해야 한다. 기존 진단 preload와 이름 충돌 없이 별도 artifact로 연결해야 한다. |
| GSI source patch 후 재빌드 | 낮음~중간 | 중간 | native Zygote의 고정 final label을 Guest target으로 바꾸고 seapp startup 선택을 같이 패치하면 의도가 명확하고 runtime symbol interposition에 덜 의존한다. 정확한 LineageOS source revision 확보, 빌드 재현, GSI 교체 및 회귀 확인이 비용이다. 기존 [Phase 8B-2 patch 후보](../scripts/guest-domain-poc/phase8b2-guest-gsi.patch)는 review candidate일 뿐 재빌드/실행된 결과가 아니다. |

**판단:** 짧은 실험은 interposer가 가장 빠르지만, Guest `setcontext`가 선택한 startup SID와 정책이 이미 맞는 조건에서만 유효하다. 지속 가능한 GSI 동작에는 source patch가 더 단순하고 검증 가능한 최종 변경이다. 특히 선행 `setcontext`가 Guest startup SID로 성공하지 않으면 interposer 작성 전에 그 경로부터 고쳐야 한다.

## 조사 한계

- dynamic symbol/relocation/disassembly 분석은 해시가 맞는 이 Android 16 AArch64 GSI ELF에 한정했다. 32-bit 대응 ELF의 relocation, 다른 GSI 빌드의 ELF, 현 기기 linker 실행 중 실제 바인딩은 검사하지 않았다.
- Android 10~16은 공개 AOSP branch source를 비교한 것이며, 등록 GSI가 각 branch 그대로 빌드됐다는 뜻은 아니다.
- 이 문서에서는 hook, GSI 재빌드, 실제 system_server fork, sepolicy 수정, 부팅/회귀 시험을 하지 않았다. 최종 적합성에는 controlled Guest-only runtime 시험이 필요하다.
