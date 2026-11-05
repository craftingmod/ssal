# LineageOS GSI Hardcoded SELinux Context Audit

감사일: 2026-11-06 (KST)  
범위: 기존 GSI의 ELF 바이너리·공유 라이브러리, APEX payload, APK 내 ELF에 대한 읽기 전용 정적 분석. 이미지 재빌드, 기기 정책 변경, Guest 서비스 실행은 하지 않았다.

## 요약

- 대상은 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img` (SHA-256 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`, Android 16 / SDK 36)이다.
- 정확한 프로세스 context 문자열이 SELinux 전환 API의 인자로 전달되는 경로는 `system_server` 최종 전환 1개와 그 밖의 전환 2개다. 즉, **`system_server` 외에 GSI 코드 변경 없이 Guest 전용 domain으로 바꾸기 어려운 경로는 2개**다: init의 `vendor_init` subcontext와 update_engine의 `backuptool` helper.
- 이 두 경로와 `system_server` 최종 전환은 현재 SSAL 실행에서 호출되지 않았다. 현재 런타임에서 확인된 것은 앱 child의 `selinux_android_setcontext()` 호출이며, 기존 기록상 `-1/EINVAL`을 반환했다.
- 정책은 하드코딩된 target을 허용하거나 거부할 수 있지만, 그 target을 별도의 Guest SID로 바꾸지는 못한다. Guest 전용 SID가 필요하면 해당 바이너리의 literal/call 경로를 대체하거나 그 경로를 실행하지 않아야 한다.

## 대상과 분석 방법

대상 이미지의 system filesystem에서 실행 bit 또는 `.so` 확장자를 가진 경로를 조사하고, 18개 APEX payload와 608개 APK 안의 ELF도 별도로 열거했다. ELF byte/string 검색으로 `u:r:`, `u:object_r:`, `setcon`, `setexeccon`, `selinux_android_setcon`, `selinux_android_setcontext` 및 관련 setter를 찾고, LLVM ELF symbol/disassembly로 가능한 경우 문자열 참조와 호출 지점을 확인했다. `setfilecon` 및 `setfscreatecon`은 프로세스 SID 전환과 구별했다.

| 검사 범위 | 결과 |
|---|---:|
| system filesystem 실행 파일·`.so` 후보 | 1,538 regular-file 후보, ELF 1,484개 (공유 라이브러리 1,252개와 실행 ELF 232개); 비-ELF 54개. `.so` symlink 항목 18개는 별도 ELF 인스턴스로 세지 않았다. |
| APEX payload | 18개 payload, ELF 2,682개 |
| APK 내 공유 라이브러리 | APK 608개 검사, ELF 12개 발견 |
| 전체 ELF 인스턴스 | **4,178개** |

7-Zip은 ext filesystem 내용 2,690,048,000 bytes 뒤에 43,212,800 bytes가 더 있다고 보고했다. 이 후행 영역은 ELF 검사 범위에 포함하지 않았다. 이 결론은 열거된 system filesystem/APEX/APK에 대한 것이며 이미지 후행 영역, 기기 vendor 파티션, 정확한 LineageOS 소스 revision의 전체 검증은 포함하지 않는다.

확실성 표기: **높음**은 이미지의 문자열과 정적 setter callsite/xref가 확인된 경우, **중간**은 이미지 literal·symbol과 Android 16 AOSP의 호출 경로가 맞지만 GSI 소스 revision 일치가 증명되지 않은 경우, **참조 확인**은 문자열은 있으나 전환 setter로 전달되는 근거가 없는 경우다. 정적 호출 가능성과 실제 실행 여부는 아래에서 따로 표시한다.

## 프로세스 context 및 전환 호출

| GSI 파일 / literal | 분류 및 호출 경로 | 실제 호출 여부 | 확실성 및 SSAL 영향 |
|---|---|---|---|
| `/system/lib64/libandroid_runtime.so`: `u:r:system_server:s0` (파일 오프셋 `0x948fc`); `selinux_android_setcontext` call VA `0x260c78`, literal을 전달하는 `selinux_android_setcon` call VA `0x260dd0`. 32-bit `/system/lib/libandroid_runtime.so`에도 literal/API가 있다. | **코드에 하드코딩된 강제 전환.** `ZygoteInit.forkSystemServer()` → native specialization의 `selinux_android_setcontext(..., is_system_server=true, ...)` → seapp/policy가 정한 startup SID → `selinux_android_setcon("u:r:system_server:s0")`. AOSP Android 16의 같은 경로와 literal은 [Zygote native 코드](https://android.googlesource.com/platform/frameworks/base/+/aml_tz2_303900102/core/jni/com_android_internal_os_Zygote.cpp#1778)에 있다. 기존 [GSI 전환 분석](phase8b2-selinux-transition.md#source-references)도 binary offset/call 경로를 기록한다. | **미호출.** Guest system_server를 fork하지 않았고 SSAL은 `start_system_server=false`로 실행한다. 앱 child의 앞 단계 `selinux_android_setcontext()`는 기존 런타임 실험에서 호출되어 `-1/EINVAL`을 반환했다([결과](zygote-phase7fc-results.md#selinux-specialization)). | 정적 근거 **높음**; 정확한 GSI 소스 revision은 미확인. `plat_seapp_contexts`로 startup SID를 바꿔도 마지막 명시적 `setcon` target은 남는다. Host와 PID namespace를 공유하는 현재 조건에서 Guest에 이 SID를 재사용하면 Host `system_server`와 같은 domain이므로 격리 증거가 되지 않는다. |
| `/system/bin/init`: `u:r:vendor_init:s0`; ELF에 `setexeccon` 호출이 있다 (VA `0x77b18`). | **코드에 하드코딩된 강제 전환.** Android 16 init은 `kVendorContext`를 `Subcontext`에 넘기고, subcontext child가 `setexeccon(context_)` 후 init worker를 실행한다 ([상수](https://android.googlesource.com/platform/system/core/+/android16-release/init/subcontext.h#37), [fork 경로](https://android.googlesource.com/platform/system/core/+/android16-release/init/subcontext.cpp#219)). GSI binary의 literal과 setter call은 확인했으나 정확한 binary/source revision 일치는 입증하지 못했다. | **미호출.** 현재 SSAL은 Guest init 및 그 init subcontext를 실행하지 않는다. | 정적 근거 **중간~높음**. 정상적인 Guest init이 이 경로를 사용하면 target은 Host와 공용인 `vendor_init`이다. 정책만 추가해도 별도 Guest SID를 선택하지 못한다. |
| `/system/bin/update_engine`: `u:r:backuptool:s0` (파일 오프셋 `0x18e0d`); 해당 문자열을 구성한 뒤 `setexeccon` 호출 VA `0x190a10`, 이후 context를 지우는 `setexeccon(nullptr)` VA `0x190bf8`. | **코드에 하드코딩된 강제 전환.** backuptool postinstall 분기에서 context를 설정하고 `/postinstall/system/bin/backuptool_postinstall.sh`를 실행하는 정적 경로다. 인접 문자열로 `Running backuptool scripts`, `Failed to set backuptool context`, `Skipping backuptool scripts`가 확인된다. 이 xref는 Android AOSP 소스가 아니라 GSI ELF disassembly 근거다. | **미호출.** Guest init/update_engine/postinstall은 실행하지 않았다. | 정적 근거 **높음**. 별도의 Guest domain이 필요하면 update_engine의 target literal/call을 대체하거나 해당 postinstall 경로를 실행하지 않아야 한다. |
| `/system/bin/init`: `u:r:init:s0` | **단순 참조.** 이 literal이 `setexeccon` target인 정적 xref는 찾지 못했다. 일반 init service의 `seclabel`/실행 파일 label 경로는 설정과 file-context/policy에 의존할 수 있다. | setter target으로의 호출 근거 없음. | **참조 확인**. 위의 `vendor_init` hardcoding에 포함하지 않았다. |
| APEX `com.android.os.statsd/bin/statsd`: `u:r:traced_probes:s0` | **단순 참조.** 해당 ELF에서 process context setter symbol/callsite는 확인되지 않았다. | setter 호출 없음(정적 검색). | **참조 확인**. 이 문자열만으로 statsd가 해당 domain으로 전환된다고 결론 내리지 않았다. |
| `/system/bin/vold`: `u:r:mediaprovider_app:` 및 `u:r:mediaprovider:` prefix | **단순 참조/비교.** FUSE daemon 식별 경로에서 context prefix를 판별하는 문자열이다. `setcon`/`setexeccon` target으로 확인되지 않았다. Android 16 [vold의 FUSE 식별 경로](https://android.googlesource.com/platform/system/vold/+/android16-release/Utils.cpp#1043)와 일치한다. | 식별 비교 경로일 뿐 이 문자열을 대상으로 한 전환 호출은 없음. | **참조 확인**. process-domain hardcoding 수에 포함하지 않았다. |

### 설정·정책으로 달라질 수 있는 호출

- `selinux_android_setcontext()`는 API 자체가 호출자의 UID, seinfo, package 및 `isSystemServer` 입력과 Guest가 읽는 `seapp_contexts`/정책으로 SID를 조회한다. 앱 child와 `/system/bin/run-as`, `/system/bin/simpleperf_app_runner`에서 API 호출 경로가 확인됐다. 이들은 API target literal을 직접 고정하지 않은 동적 선택 경로다. run-as의 seapp 기반 호출 형태는 [Android run-as 코드](https://android.googlesource.com/platform/system/core/+/android16-qpr2-release/run-as/run-as.cpp)와 일치한다.
- `/system/bin/toybox`의 `setexeccon` 등은 명령 인자 기반이고, `/system/bin/vold` 및 `vold_prepare_subdirs`의 `setexeccon`은 동적 context 인자를 사용한다. 호출 존재만으로 고정된 Guest process SID를 뜻하지 않는다.
- libselinux의 `setcon`, `setexeccon`, `selinux_android_setcon`, `selinux_android_setcontext`는 API 구현/호출 심볼이다. 함수 이름만 검색된 경우 hardcoded target으로 세지 않았다.
- 정적 호출이 존재하는 run-as/simpleperf/vold 등은 이번 감사에서 별도 런타임 경로를 실행하지 않았다. 앱 child의 `selinux_android_setcontext()` 실행만 기존 SSAL 실험 기록으로 실제 호출을 확인했다.

## `u:object_r:` 문자열

아래 문자열은 파일, socket, filesystem 또는 생성 시 기본 label에 관한 **객체 context**다. 이들은 `setfilecon`, `setfscreatecon`, mount `context=`/`defcontext=` 등의 경로를 통해 객체 label을 설정하거나 참조하며 process SID를 바꾸지 않는다.

| 파일 위치 | 확인된 context | 용도 / 분류 |
|---|---|---|
| `/system/bin/init` | `u:object_r:default_prop:s0`, `u:object_r:ota_metadata_file:s0`, `u:object_r:snapuserd_socket:s0`, `u:object_r:snapuserd_exec:s0` | property, OTA metadata, snapuserd 객체 label 참조/생성 경로. process transition 아님. |
| `/system/bin/update_engine`, `/system/bin/snapshotctl` | `u:object_r:ota_metadata_file:s0`; update_engine에는 `defcontext=u:object_r:postinstall_file:s0`, `context=u:object_r:postinstall_file:s0` | OTA/postinstall filesystem 객체 label. `context`/`defcontext`는 mount 설정이며 process context가 아님. |
| `/system/bin/vold` | `u:object_r:app_fuse_file:s0`, `u:object_r:app_fusefs:s0`, `u:object_r:sdcard_posix:s0` | FUSE mount·filesystem 객체 label. `setexeccon` 동적 호출과 별개. |
| `/system/lib64/libartpalette-system.so` 및 32-bit 대응 라이브러리 | `u:object_r:apex_art_staging_data_file:s0` | **객체 label literal을 사용한 `setfilecon` 호출**이 확인됐다(64-bit VA `0x49c0`, `PaletteCreateOdrefreshStagingDirectory`). 파일 relabel이며 process transition은 아님. |
| `/system/lib64/libfs_mgr.so`, `/system/lib64/libfs_mgr_binder.so` | `u:object_r:overlayfs_file:s0` | overlayfs 관련 객체 생성 경로. `setfscreatecon`은 동적 context 인자를 사용한다. process transition 아님. |
| `/system/bin/adevice_fingerprint`, `/system/bin/bootstrap/linker[64]`, `/system/bin/resetprop_phh`, `/system/bin/snapuserd`, `/system/bin/overlay_remounter`, system libc/bootstrap 및 runtime APEX linker/libc | `u:object_r:properties_serial:s0` | property storage 관련 객체 label reference. process transition 아님. |
| `/system/bin/phh-ota`; `/system/bin/simpleperf` | `u:object_r:phhota_dev:s0`; `u:object_r:simpleperf_boot_data_file:s0` | device node/boot data 파일 관련 객체 label. process transition 아님. |

문자열이 코드에 들어 있어도 실제 label의 유효성·접근은 로드된 policy와 mount/filesystem 조건에 좌우된다. 특히 `libartpalette-system.so`의 직접 `setfilecon`은 literal relabel 동작이지만, 이것을 새 프로세스 domain 전환으로 해석해서는 안 된다.

## SSAL 우회 및 영향 평가

| 경로 | Guest 전용 SID가 필요한 경우 | 현재 SSAL 영향 |
|---|---|---|
| `system_server` | `libandroid_runtime.so`의 final `setcon` target을 Guest 전용 context로 대체하는 GSI 바이너리 변경이 정공법이다. `seapp_contexts`는 앞의 startup SID 선택만 바꾼다. | 현재는 `start_system_server=false`; 이 경로는 실행하지 않는다. [기존 전환 결과](phase8b2-selinux-transition.md#execution-guard) 참조. |
| `vendor_init` | Guest init을 구동하지 않거나 vendor subcontext 경로를 생략한다. 그 경로를 유지하면서 Guest 전용 SID를 쓰려면 init binary의 context target을 바꿔야 한다. | Guest init을 실행하지 않으므로 현재 비활성. Guest init 안전성 자체도 미승인 상태이며 [사전 조사](guest-init-property-preflight-20261031.md)를 따른다. |
| `backuptool` | update_engine postinstall/backuptool 분기를 생략하거나 update_engine binary/호출을 Guest용 context로 대체한다. | Guest init/update_engine을 실행하지 않으므로 현재 비활성. |

SELinux 정책 변경은 위 literal이 가리키는 기존 SID에 대한 transition 허용 여부를 바꿀 수 있지만, `vendor_init`, `backuptool`, `system_server` 문자열을 다른 Guest 전용 type으로 치환하지는 않는다. `seapp_contexts`만 바꾸거나 해당 기존 type에 권한을 더하는 것은 Host/Guest SID 분리를 만들지 않으며, 공유 PID namespace 조건에서 Host domain 재사용 위험을 남긴다. 현재 SSAL 경로에서 가장 안전한 우회는 세 경로를 시작하지 않는 것이다. 이후 기능상 실행이 필요해지면 Guest 전용 target을 선택하는 바이너리 경로와 Guest-only policy를 함께 검증해야 한다.

## 한계

- 43,212,800-byte 이미지 후행 영역은 파싱하지 않았다. 따라서 그 영역에 별도 ELF가 있을 가능성은 배제하지 않는다.
- binary callsite는 정적으로 확인했지만, Guest init/vendor subcontext, update_engine postinstall, Guest system_server의 런타임 호출은 실행하지 않았다.
- Android 16 AOSP 소스는 호출 의미를 설명하는 참고 자료이며, 등록된 LineageOS GSI의 정확한 소스 revision과 일치한다고 증명되지 않았다. 바이너리 문자열·xref·disassembly를 이 이미지에 대한 주 근거로 삼았다.
- APEX payload와 APK 내 ELF에서는 추가 process-domain setter target을 찾지 못했다. 기기 vendor partition과 Host의 전체 활성 policy는 이번 감사 범위가 아니다.
