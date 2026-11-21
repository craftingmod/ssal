# Android 16 Guest Property 입력 검증 — 2026-10-31

**결론: 표준 AOSP 방식의 초기화는 조건부 차단 후보가 확인됐고, 최종 입력은 아직 확정할 수 없다.** 저장된 4개 context 파일의 1,664개 항목에는 동일한 match 종류와 이름을 가진 중복이 없었다. ODM 파일과 여러 build.prop이 수집되지 않았으므로 전체 병합과 실제 초기화 결과는 `unknown`이다. 기존 기기 EINVAL 12개는 아래 GSI context 파일에서 모두 발견됐다. 이 기기 관측은 KernelSU가 적용된 당시 실효 정책에 대한 것이며 순정 정책의 판정이 아니다.

## 재실행

저장된 `out/init-preflight-extract`, `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef`, `docs/selinux-check-device-20261031.json`이 필요하다. `out`은 생성물이라 다른 체크아웃에는 없을 수 있다. 입력 경로 및 SHA-256과 누락 상태는 JSON에 기록한다. 원본 GSI의 해시와 추출 한계는 [기존 사전 조사](guest-init-property-preflight-20261031.md)에 기록돼 있다. 이번에 원본 이미지 해시나 추출 완전성은 다시 검증하지 않았다.

```powershell
bun test scripts/validate-guest-properties.test.js
bun scripts/validate-guest-properties.js docs/guest-property-input-validation-20261031.json
```

검증기는 읽은 파일만으로 후보를 계산한다. 입력은 고정 경로이며 누락된 파일은 `unknown_not_collected`로 표시한다. 검사 대상 라벨은 기존 EINVAL 결과와 대조한다. 관측되지 않은 라벨은 유효하다고 가정하지 않는다. 모델은 Android의 SELinux 권한/값 타입 검사, import 확장, legacy fallback, derived property, 실제 직렬화 및 런타임 동작을 실행하지 않는다. 따라서 JSON의 후보 값과 context 매칭은 확정된 실행 결과가 아니다. 실제 구현과 다른 부분은 별도 대조가 필요하다.

## 병합과 차단 후보

[AOSP Android 16 r2 property service](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/init/property_service.cpp)는 platform → system_ext → vendor → product → odm context를 연결한다. 동일 이름의 동일 match 종류 중복은 라벨이 같아도 [trie 생성 실패](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/property_service/libpropertyinfoserializer/trie_builder.cpp)를 일으킨다. exact와 prefix는 별도이며 lookup은 exact와 더 구체적인 prefix를 고려한다. 개별 context 구문 오류는 로그 후 건너뛴다. 파일의 부재와 직렬화 성공은 별개의 문제다.

build.prop은 권한 및 타입 검사에 통과한 값들을 먼저 map에 합친다. 정상 경로의 순서는 second-stage resources → system → system_ext → system_dlkm → vendor/default → vendor/build → vendor_dlkm → odm_dlkm → odm → product → debug ramdisk다. 나중 값이 `ro.*`까지 덮어쓰지만 map을 property area에 쓸 때 기존 `ro.*`가 있으면 write-once로 거절된다. DT, cmdline, bootconfig와 boot export가 이보다 먼저 쓰는 값은 별도로 고려해야 한다. 선택된 세 GSI 파일에서는 `ro.cp_system_other_odex` 1→0, `ro.control_privapp_permissions` disable→log의 후보 충돌이 있다. 권한 검사와 빠진 입력 때문에 최종값은 unknown이다.

| 이전 EINVAL 타입 | GSI context 출처 | 표준 area 초기화 가능성 |
|---|---|---|
| `native_binder_stats_prop` | plat:348 | 조건부 차단 후보 |
| `persist_sysui_ranking_update_prop`, `persist_sysui_builder_extras_prop` | plat:1838–1839 | 조건부 차단 후보 |
| `sf_hs_mode_prop`, `vendor_hwc_prop`, `odm_cast_prop` | system_ext:28–29, 35 | 조건부 차단 후보 |
| `legal_url_prop`, `custom_version_prop`, `vendor_persist_nfc_prop` | system_ext:45, 48–52, 55–56 | 조건부 차단 후보 |
| `recovery_update_prop`, `xtra_control_prop`, `usb_uvc_config_prop` | system_ext:71, 74, 80–81 | 조건부 차단 후보 |

조건은 이 항목이 성공적으로 직렬화되고, 해당 실행 시점의 정책에서 라벨의 `fsetxattr`이 실패하며, GSI가 조사한 AOSP 방식으로 모든 context area를 생성하는 것이다. 이 조건이면 기능 사용과 무관하게 초기화가 실패할 수 있다. 실제 Guest area 생성과 해당 GSI 바이너리의 동일성은 `not_run`/`unknown`이다. 12개의 기능적 필수성 역시 unknown이다. `custom_version_prop`에 연결되는 `ro.lineage.*` 후보는 product build.prop에서 확인된다. 정책을 추가하거나 default 라벨로 치환하라는 뜻이 아니다.

## Guest 최소 입력과 Host 유입

현재 확정된 완전한 최소 속성 목록은 없다. 다음은 검증 대상 후보이며 필수성이나 값의 실효성을 입증하지 않는다.

| 후보 | 출처 / 상태 |
|---|---|
| `ro.build.version.sdk`, `ro.build.version.release`, `ro.build.fingerprint` | GSI build.prop 후보. Guest identity 및 호환성 검토용 |
| `ro.product.cpu.abilist` | GSI build.prop 후보 또는 AOSP 파생값. 실제 최종값 unknown |
| `ro.property_service.version` | AOSP property service 시작 시 설정. 구현과 접근 검증 not_run |
| `servicemanager.ready` | servicemanager의 준비 상태 기록 후보. 실행과 정확한 필요성 not_run/unknown |
| `persist.*` | Guest userdata의 별도 저장소에서 후속 로드할 후보. 필수 키와 시점 unknown |

Host의 DT/cmdline/bootconfig를 그대로 읽으면 `ro.boot.*`와 export 값이 먼저 고정될 수 있다. Host property area, 상속 FD, vendor/odm build.prop 및 Host persist 저장소도 유입 경로다. boot 정보는 명시적 허용 목록과 provenance를 정한 뒤 첫 기록 전에 결정하고, Guest 소유 property area/socket 및 userdata를 사용해야 한다. `ctl.*`와 `sys.powerctl`은 Host 제어로 전달하지 않도록 별도 처리해야 한다. 격리 시험은 `not_run`이다.

다음 최소 단계는 누락된 삼성 vendor/odm 입력의 출처와 버전을 읽기 전용으로 확보하고, 초기 boot 입력의 허용 목록 및 각 후보에 대한 권한·값 타입 결과를 결정하는 것이다. 그 뒤 격리된 오프라인 fixture에서 실제 Android serializer 및 property 파서와 차이를 대조한다. Guest init, servicemanager, 인증 HAL 실행과 SELinux 정책 적용은 수행하지 않았다.
