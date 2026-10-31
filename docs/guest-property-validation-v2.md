# Guest Property 입력 및 AOSP Serializer 검증 v2 — 2026-10-31

**결론:** 수집된 부분 입력을 Android 16 r2 AOSP C++ serializer로 직렬화했고 기존 EINVAL 12개 라벨이 모두 결과에 포함됐다. 기존 기기 정책에서 같은 라벨이 계속 유효하지 않고 표준 Bionic area 생성 시 라벨 설정이 실패한다면 초기화 차단 후보이다. 실제 Guest의 property area 생성과 라벨 적용은 `not_run`, 최종 입력과 순정 삼성 정책에서의 결과는 `unknown`이다.

## 입력 출처와 범위

연결된 SM-S937N에서 ADB 셸(uid 2000)과 이후 승인된 su를 이용해 읽기 전용 수집했다. 현재 Host fingerprint는 `samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`이며 이전 profile 기록과 일치한다. 현재 runtime vendor/odm fingerprint는 Android 15, SDK 35에 해당한다. Runtime 속성만으로 펌웨어 이미지의 출처를 증명할 수는 없다. 펌웨어 이미지 SHA-256은 `unknown`이다.

| 기기 입력 | 읽기 전용 확인 결과 |
|---|---|
| `/vendor/etc/selinux/vendor_property_contexts` | 34,094 bytes, SHA-256 `16ac4a4aa8088819a575bb22aa326ceef7e7b84c0129d1a0e950c1d87159d3df`. 기존 스냅샷과 동일 |
| `/odm/etc/selinux/odm_property_contexts` | 기기에서 해당 경로가 발견되지 않음 |
| `/vendor_dlkm/etc/build.prop` | 860 bytes, SHA-256 `23faa20414aeed7804898fba473d7e9af2a636264dc2a881b4a9fedf4c4fea72`. 속성 후보 15개 추가 |
| `/vendor/build.prop` | root 읽기 성공, 16,042 bytes, SHA-256 `d21efa1066633acea422feee9a8ac4747a90147d6d30349d3f3bf0bea54725e9` |
| `/odm/etc/build.prop` | root 읽기 성공, 1,106 bytes, SHA-256 `af6147378c88ff4a9b617888fc233cb79e2f5569591c3f07fb11c41c978ec66c` |
| `/system_dlkm/etc/build.prop` | root 읽기 성공, 860 bytes, SHA-256 `58c7b42d2fe59c5759a8aa948d299f42f282d1ec138d0c6bc8cb4af118f24c70` |
| `/vendor/default.prop`, `/odm/build.prop`, `/odm_dlkm/etc/build.prop` | 기기에서 해당 경로가 발견되지 않음 |

수집 목록과 상세 관측은 [기기 입력 inventory](../out/guest-property-validation-v2/host/input-inventory.json), 입력별 해시와 후보는 [결과 JSON](../out/guest-property-validation-v2/result.json)에 있다. Guest system·system_ext·product 입력은 기존 GSI 추출본을 재사용했다. 기존 이미지 SHA-256 기록은 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`이며 이번에는 재검증하지 않았다. second-stage 및 debug 입력은 미확인이다. 수집된 system_dlkm은 삼성 Host 파일이므로 Guest에서 이를 사용할지는 별도로 결정해야 한다.

## 실제 AOSP 대조

[AOSP Android 16 r2 텍스트 parser와 serializer](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/property_service/libpropertyinfoserializer/) 및 [직렬화 trie parser](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/property_service/libpropertyinfoparser/)를 호스트에서 메모리만 사용해 실행했다. Windows 호환을 위해 Android 파일 mmap 부분을 제외하고 `android-base` 문자열 함수를 작은 shim으로 제공했다. trie 생성·조회 로직은 AOSP 코드다. 소스 11개는 고정된 SHA-256으로 확인했다. 이는 Android 기기의 실행 파일이나 SELinux를 실행한 시험이 아니다.

| 검사 | 결과 |
|---|---|
| 텍스트 parser | 1,664 항목, 구문 오류 0, JS와 항목별 차이 0 |
| serializer | 부분 입력의 trie 생성 성공, context 523개. 동일 match/name 중복 0 |
| trie lookup | GSI build.prop 후보, 각 context별 probe 및 default 포함 1,982개 조회에서 JS와 context/type 차이 0 |
| 12개 EINVAL 라벨 | 12개 모두 직렬화된 context 목록에 존재 |
| 실제 SELinux 권한, `fsetxattr`, property area, Guest 서비스 | `not_run` |

이 대조는 해당 입력과 probe 집합에 한정된다. 원본 GSI 바이너리의 정확한 구현 동일성, 다른 기기 상태와 접근 조건을 포함한 전체 trie, build.prop에 대한 SELinux 권한과 값 타입 판정은 `unknown`이다. JS build.prop 계산은 권한 검사 전 후보 map이며 실제 AOSP Property Service 실행 결과가 아니다. `ro.*`는 파일들을 map으로 합칠 때 나중 입력이 이기지만, 앞선 boot 단계에서 이미 기록됐다면 최종 쓰기는 거절된다.

수집된 build.prop을 권한 검사 전 후보로 합치면 603개 속성이 나온다. 예를 들어 `ro.control_privapp_permissions`는 system_ext `disable` → 삼성 vendor `enforce` → Guest product `log` 순으로 충돌한다. `ro.config.notification_sound`, `ro.config.alarm_alert`, `ro.config.ringtone`도 삼성 vendor 후보가 Guest product 후보로 덮인다. 이는 파일 순서만 적용한 결과이며 실제 권한·타입 검사, 선행 `ro.*` 기록과 Guest 마운트 구성을 반영한 최종값은 `unknown`이다.

## SELinux 차단과 변경 후보

12개 라벨은 이전 `selinux-check-device-20261031.json`에서 EINVAL로 기록됐고, 각각의 GSI 파일·라인과 실제 직렬화 포함 여부는 결과 JSON의 `context.invalid_12`에 있다. 이전 검사는 KernelSU가 적용된 당시 실효 정책을 대상으로 했으므로 순정 정책의 증거는 아니다. [AOSP Bionic area 초기화 경로](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/system_properties/contexts_serialized.cpp)에서 각 context area를 만들고 라벨을 설정하는 조건에서 라벨 설정이 실패하면 전체 초기화가 실패할 수 있다. GSI 바이너리 동등성과 대상 파일시스템의 동작은 미확인이다.

| 후보 | 필요한 증거와 의미 |
|---|---|
| 전체 context 보존 + 정책 변경 | 12개뿐 아니라 실제 직렬화된 모든 라벨의 대상 정책 유효성, property 파일 생성·라벨링 권한과 각 클라이언트 read/write 권한을 별도 검증해야 한다. EINVAL만으로 특정 allow 규칙이나 타입 추가의 충분성은 증명되지 않는다. |
| Guest 전용 context 필터/축소 | 실제 필요한 property 및 접근 주체를 먼저 확정하고, 제거로 바뀌는 prefix·default 매칭과 접근 통제를 검증해야 한다. 기능 필수성이 unknown인 12개를 일괄 제거하거나 default 라벨로 합칠 근거는 없다. |
| 별도 구현에서 라벨/영역 전략 변경 | AOSP 클라이언트의 property lookup, mmap, DAC와 SELinux 접근 의미를 유지할 수 있는지 미검증이다. |

어느 쪽이 최소 변경인지는 미확정이다. 정책 적용 및 context 필터링은 이번에 수행하지 않았다.

## 다음 구현에 넘길 입력·정책 계약

- **Context:** Guest platform → system_ext → 삼성 vendor → Guest product → 삼성 odm 순서로 입력과 출처를 고정한다. 동일 match/name 중복은 serializer 실패로 취급하고, 파싱 오류와 미수집 파일을 구분한다. 실제 사용할 context 전부에 대해 대상 정책과 접근 주체를 검증한다.
- **초기 identity:** `ro.build.version.sdk`, `ro.build.version.release`, `ro.build.fingerprint`, ABI 관련 값은 Guest 이미지에서 얻은 후보와 AOSP 파생 규칙을 기준으로 한다. build.prop 권한/타입 검사와 누락 파티션 확인 전의 후보값은 확정값이 아니다.
- **Boot:** Host DT/cmdline/bootconfig를 자동 유입하지 않는다. 하드웨어 호환상 필요한 `ro.boot.*`만 출처와 값, 공개 범위를 명시해 검토하고 첫 `ro.*` 기록 전에 결정한다. 허용 목록은 현재 `unknown`이다.
- **Persist:** Host property area와 Host `/data/property`를 사용하지 않고 Guest userdata에 별도 저장한다. 필요한 키와 복원 시점은 `unknown`이다.
- **제어:** `ctl.*`는 Guest 전용 감독자에서만 처리하거나 거부하고, `sys.powerctl`은 Host에 전달하지 않는다. 접근 권한, 호출자 인증 및 종료 동작은 별도 설계가 필요하다.
- **격리:** Guest 소유 property area·socket 및 독립된 핸들을 요구한다. 상속 FD와 대체 접근 경로 차단, 서비스 도메인 접근과 실제 생성은 `not_run`이다. `ro.property_service.version`, `servicemanager.ready`는 서비스 구현/준비 신호 후보이며 전체 최소 property 목록은 `unknown`이다.

다음 단계는 펌웨어 provenance와 Guest에 실제 제공할 파티션을 확정하고, 실제 타깃 정책에서 전체 라벨 유효성 및 필요한 주체별 접근을 오프라인으로 대조하는 것이다. 그 결과로 보존과 축소 중 선택할 근거를 마련한다.

## 재실행

기존 추출본과 스냅샷, Bun, clang-cl 및 Visual Studio C++ 환경이 필요하다. AOSP 원본이 없으면 고정 버전 소스를 다운로드하고 해시를 확인한다. 빌드 스크립트의 Visual Studio 경로는 이 환경 기준이다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/property-aosp/run.ps1
bun test scripts/validate-guest-properties.test.js
```

첫 명령은 `out/guest-property-validation-v2/result.json`과 진단 파일을 다시 작성한다. 테스트는 중복·충돌, 누락 상태, 우선순위·write-once, context 타입 오류, type 상속, 제어 속성 및 실제 AOSP fixture를 다룬다.
