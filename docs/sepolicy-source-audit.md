# SELinux 정책 소스·도구 점검 — 2026-10-31

현재 서브모듈, 빌드 정의, 기존 기기 시험 JSON과 공개 upstream 소스를 대조했다. 연결된 기기에서는 버전·파일 목록·이미지 manifest·ksud 도움말만 읽었다. 정책 적용, 라벨 변경, 서비스 기동, 이미지 마운트는 수행하지 않았다.

`vendor/README.md`는 vendor 소스를 코드 수정 참고용으로 두고 빌드하지 않는다고 명시한다. 아래 추가 권장도 정책 정의·차이 추적용이다. 전체 vendor 소스를 모듈 빌드에 연결하라는 의미가 아니다.

## 추가할 소스

| 구분 | 소스 | 필요한 이유 |
|---|---|---|
| 우선 추가 | `TrebleDroid/device_phh_treble`, `android-16.0` | 기존 시험에서 누락된 `fingerprint_hidl_service`, `qcrilam_service`의 정의와 서비스 이름 매핑이 있다. |
| 재현성 자료 | `MisterZtr/treble_manifest`, `lineage-23.2` | 사용 GSI의 추가 프로젝트·브랜치를 추적한다. manifest 자체는 각 프로젝트의 고정 커밋을 보장하지 않는다. |
| 재현성 자료 | `MisterZtr/LineageOS_gsi`, 릴리스 `v2026.05.24-lineage23.2`에 연결된 소스 | Lineage 원본에 없는 GSI 정책·빌드 패치가 있다. 전체 저장소 또는 해당 릴리스의 패치와 해시를 보관한다. |
| 필요할 때 고정 보관 | `diabl0w/KernelSU`, `samsung-v2.2` | 현재 기기의 정책 패처 구현을 확인할 기준이다. 관련 소스는 이미 `.cache/private-binder-research/`에 있으며, 기존 조사에 커밋이 기록돼 있다. 지금 별도 서브모듈이 필수인 것은 아니다. |

첫 항목을 추가하는 명령은 다음과 같다. 이번 점검에서는 서브모듈을 추가하지 않았다.

```powershell
git submodule add -b android-16.0 https://github.com/TrebleDroid/device_phh_treble.git vendor/device_phh_treble
```

GSI의 [빌드 안내](https://github.com/MisterZtr/LineageOS_gsi/tree/7bf212f)는 별도 manifest와 패치 적용을 요구한다. 릴리스 시점 이전 manifest 커밋 [565a797840c5aace0a7c6e3d52773af80fee2802](https://github.com/MisterZtr/treble_manifest/blob/565a797840c5aace0a7c6e3d52773af80fee2802/manifest.xml)에서도 `device/phh/treble`의 위 저장소·브랜치를 확인했다. 이것은 등록된 이미지의 정확한 소스 커밋을 입증하는 빌드 manifest는 아니다.

## 기존 누락 context 9개 대응

기준은 [기존 Enforcing 시험](enforcing-binder-device-20261031.md)과 [원시 결과](enforcing-binder-device-20261031.json)의 `runtime.checks.service_contexts_compatibility`다. 519개 고유 context 중 9개가 blocked였다.

| 타입 | 정의 위치 |
|---|---|
| `adbroot_service` | `android_device_lineage_sepolicy/common/private/service.te` |
| `lineage_globalactions_service` | 동일 |
| `lineage_hardware_service` | 동일 |
| `lineage_health_interface_service` | 동일 |
| `lineage_livedisplay_service` | 동일 |
| `lineage_profile_service` | 동일 |
| `lineage_trust_service` | 동일 |
| `fingerprint_hidl_service` | `device_phh_treble/sepolicy/service.te` |
| `qcrilam_service` | `device_phh_treble/sepolicy/service.te` |

Lineage 쪽은 현재 로컬 파일을 확인했다. Git 인덱스 gitlink는 `0a9e75292f0ed1a83c31a311b1b32367a9faff75`다. TrebleDroid 쪽은 조회 시 `android-16.0`의 커밋 [ad694645eb591f00b3acced10b546397812435ec](https://github.com/TrebleDroid/device_phh_treble/blob/ad694645eb591f00b3acced10b546397812435ec/sepolicy/service.te)을 확인했다. 등록 이미지와 이 커밋의 일치는 미확인이다.

TrebleDroid의 [service_contexts](https://github.com/TrebleDroid/device_phh_treble/blob/ad694645eb591f00b3acced10b546397812435ec/sepolicy/service_contexts)에서 다음 매핑도 기존 기기 시험과 일치했다.

- `android.hardware.biometrics.fingerprint.IFingerprint/defaultHIDL` → `fingerprint_hidl_service`
- `me.phh.qcrilam` → `qcrilam_service`

따라서 **현재 확인된 서비스 타입 9개의 정의를 추적하는 데 필요한 추가 정책 저장소는 TrebleDroid 하나**다. 모든 프로세스·파일·property·앱·HAL 정책의 의존성이 해결됐다는 뜻은 아니다. `QcRilAm` 앱 저장소에는 이 두 타입의 정책 정의가 없었으며, 두 타입 때문에 앱 소스 전체를 추가할 필요는 없다.

## 소스 확보 이후 남은 작업

1. **실제 이미지 기준 고정.** 기기 등록 manifest의 이미지 SHA-256은 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`, 크기는 2,733,260,800바이트다. `android_version`은 null이다. `GSI.md`의 릴리스 링크만으로 이 이미지의 정확한 빌드 출처가 증명되지는 않는다. 실제 이미지의 build 정보, 각 partition의 CIL·mapping·contexts·앱 서명 매핑과 해시가 필요하다. Host vendor/odm도 같은 방식으로 기준을 확보해야 한다.
2. **SSAL 전용 정책 설계.** 서비스 계약은 `ssal_property` 도메인과 전용 property 실행 파일을 요구하지만, 현재 프로젝트·추가한 두 정책 저장소에서 해당 도메인 정의를 찾지 못했다. private property 영역·소켓·userdata 라벨과 접근 주체는 별도 구현·정책이 필요하다. upstream 저장소 추가로 제공되는 부분이 아니다.
3. **최소 정책 확장 산출·검증.** 현재 빌드에는 vendor 정책 소스를 읽는 단계가 없고 모듈은 `module/sepolicy.rule`만 패키징한다. 타입 존재, attribute, 등록 주체의 add, 클라이언트의 find, Binder 접근을 나누어 검증해야 한다. 기존 servicemanager 주체의 AV 검사 결과를 실제 각 서비스의 등록 권한으로 대체할 수 없다.
4. **Enforcing·복구 조건 유지.** GSI 패치에는 permissive 도메인 허용과 userdebug 정책 선택 관련 변경도 있다. [릴리스의 정책 패치 디렉터리](https://github.com/MisterZtr/LineageOS_gsi/tree/7bf212f/patches/personal/platform_system_sepolicy)를 참조하되, Host에 전체 적용하는 입력으로 사용하지 않는다. 게스트 정책도 공유 커널에 영향을 준다. 일회성 적용과 부팅 자동 재적용을 구분해야 한다.

9개 타입 정의를 전부 확보하더라도 PID/proc, private property, cgroup/task profile, HAL 중계 및 독립 userdata 조건은 남는다. 서비스 계약의 `launch_enabled=false`는 유지됐다.

## 도구 점검

- 기기에서 `ksud samsung-v2.2 (uapi: 5)`와 `sepolicy patch/apply/check` 명령 제공을 확인했다. `check`의 도움말은 구문 지원·유효성 검사라고 설명한다. 실제 커널 반영과 권한 증명은 별도다.
- 전역 상태는 `Enforcing`, `/sys/fs/selinux/policyvers`는 `33`, `/vendor/etc/selinux/plat_sepolicy_vers.txt`는 `202404`였다. 바이너리 정책 형식 버전과 vendor 정책 API 버전은 서로 다른 값이다. Host Android 버전은 `17`, SDK는 `37`이었다. Guest의 실제 버전·CIL과 별도로 대조해야 한다.
- 오프라인 CIL 조합·비교를 위해 `secilc`, `checkpolicy`, `m4`, SETools의 `seinfo`·`sesearch`·`sediff`를 빌더 도구로 준비하는 것을 권장한다. `containers/builder/Containerfile`에는 이 도구들이 명시돼 있지 않다. 실행 컨테이너는 `wslc`의 `E_ACCESSDENIED`로 확인하지 못했다. 이 도구 전체가 현재 ksud 기반 일회성 시험의 필수 조건인 것은 아니다.
- 도구 소스를 전부 서브모듈로 추가할 필요는 없다. 패키지/버전을 고정하거나, Android 특화 동작이 필요할 때 해당 버전의 `external/selinux`를 고정하면 된다. [AOSP 정책 빌드 설명](https://source.android.com/docs/security/features/selinux/build), [SETools](https://github.com/SELinuxProject/setools).

## 저장소 정합성

- `.gitmodules`는 `android_system_sepolicy`, `android_device_lineage_sepolicy`, `freesam`의 현재 경로로 정리돼 있다.
- 점검 초기에 있던 `vendor/third_party/android_system_sepolicy` gitlink는 최종 재검사 시 정리돼 있었다.
- 최종 `git ls-files --stage vendor FreeSam`에는 `.gitmodules`에 없는 **루트 `FreeSam` gitlink가 남아 있다**. 현재 `vendor/freesam`과 같은 커밋 `f70fc2a23415a32d607e82b497147beaf4f35c08`을 가리킨다. 새 checkout의 서브모듈 초기화 전에 정리가 필요하다. 이번에는 사용자 staging 상태를 변경하지 않았다. 일반 `git diff --check`도 이전 FreeSam 관리 경로에 접근하다 실패했으며, `diff.ignoreSubmodules=all`을 지정한 작업 트리·인덱스 whitespace 검사는 통과했다.
- `docs/architecture.md`와 `docs/freesam-master-prepare-mounts.md`는 루트 `../FreeSam/...` 경로를 참조한다. 현재 루트 디렉터리도 존재하므로 링크가 모두 깨졌다고 판정하지 않는다. 루트 항목을 제거할 때 `../vendor/freesam/...`으로 함께 갱신해야 한다.

정책 소스·모듈·빌드 파일·Git 인덱스·기기는 변경하지 않았고, 점검 결과 문서만 추가했다. 실제 GSI 정책 산출물 추출·컴파일·live patch·서비스 실행 시험은 이번 점검 범위에 포함하지 않았다.
