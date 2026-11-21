# Guest Property SELinux Feasibility — 2026-10-31

**판정: 조건부 구현 후보는 있으나, 필요한 최소 정책과 실제 적용 가능성은 아직 확정되지 않았다.** 저장된 삼성 실효 정책 검사와 GSI·삼성 입력을 합친 AOSP serializer 결과를 대조하면, 직렬화된 523개 고유 context 중 당시 유효 509개, EINVAL 12개, 당시 미조회 2개다. 설치된 `ksud samsung-v2.2`는 12개 각각에 대한 타입 선언 후보의 **구문**을 수용한다. 타입의 실제 추가, 권한, Guest enforcing 도메인 실행 및 Property Area 생성은 검증하지 않았다.

## 범위와 근거

- 대상 context는 [Property 입력 검증 v2](guest-property-validation-v2.md)의 GSI platform/system_ext/product와 삼성 vendor, 그리고 AOSP serializer 기본 context다. 삼성 기기의 `/odm/etc/selinux/odm_property_contexts`는 수집 당시 발견되지 않았다. 1,664개 매핑에서 AOSP trie가 생성한 context 집합이며 전체 GSI 부팅 정책이나 모든 서비스 context가 아니다.
- [기존 기기 검사](selinux-check-device-20261031.md)는 2026-10-31 06:07 KST의 KernelSU가 이미 반영된 실효 정책을 대상으로 했다. 당시 전역 Enforcing이었고 live context 2,686개 중 37개가 EINVAL이었다. SELinux policy 전체 export가 EINVAL로 실패해 현재 정책의 완전한 해시는 없다. 그 정책을 현재 또는 순정 삼성 정책과 동일하다고 단정하지 않는다.
- 이번에 연결된 SM-S937N에서 읽은 전역 `getenforce`는 Enforcing, root 셸은 `u:r:ksu:s0`, `ksud`는 `samsung-v2.2 (uapi: 5)`였다. `ksu` permissive 도메인의 동작을 Guest enforcing 성공으로 해석하지 않는다. 이번에는 context 유효성/AV를 재조회하지 않았다.
- 전체 523개와 과거 검사 결과, 12개 구문 검사 결과는 [기계 판독 결과](../out/guest-property-validation-v2/selinux-feasibility.json)에 있다. 원본 context별 매핑·라인은 [v2 JSON](../out/guest-property-validation-v2/result.json)의 `context.invalid_12`와 입력 파일에서 추적할 수 있다. 원본 GSI·Host 파일과 정책은 변경하지 않았다.

## Context 전체 분류

| 분류 | 개수 | 의미 |
|---|---:|---|
| 과거 실효 정책의 context 유효 | 509 | 지정된 전체 라벨에 대한 유효성 확인만 통과. 속성 의미, attribute, 생성·읽기·쓰기 권한과 현재 유효성은 unknown |
| 과거 EINVAL | 12 | 해당 전체 `u:object_r:…:s0` 라벨을 당시 정책이 거부. 누락 타입 후보이지만 EINVAL만으로 타입 부재와 user/role/MLS 제약 중 원인을 확정할 수 없음 |
| 당시 미조회 | 2 | `vendor_ctl_port-bridge_prop`, `vendor_ipacm-diag_prop`. 각각 유효/무효 및 원인은 unknown. 이름에 하이픈이 있다는 이유만으로 invalid로 판정하지 않음 |
| 동일 name+match 충돌 | 0 | 수집된 context 입력을 기준으로 AOSP trie 생성 성공. exact와 prefix가 다른 규칙은 허용되며 중첩 정책의 의미 충돌이나 Host 접근 동등성을 증명하지 않음 |

과거 EINVAL 12개는 `custom_version_prop`, `legal_url_prop`, `native_binder_stats_prop`, `odm_cast_prop`, `persist_sysui_builder_extras_prop`, `persist_sysui_ranking_update_prop`, `recovery_update_prop`, `sf_hs_mode_prop`, `usb_uvc_config_prop`, `vendor_hwc_prop`, `vendor_persist_nfc_prop`, `xtra_control_prop`이다. 이들 모두 실제 AOSP serializer 출력의 context 테이블에 있다. 별도 serial area의 `u:object_r:properties_serial:s0`, `property_info` 파일 라벨과 socket·디렉터리 라벨도 context 테이블 외에 따로 검증해야 한다.

기존 감사의 GSI system_ext와 삼성 vendor 간 `iso9660 /`, `udf /` genfscon 충돌은 **전체 SELinux 정책 조합 충돌**이다. Property Context 동일 키 충돌과는 별개이며, 그 충돌 제거만으로 다른 정책 오류가 해소된다고 볼 수 없다. 과거 재구성 정책은 `-N`에서만 Host 컴파일이 성공했고 실효 정책 완전 복제도 아니므로, 그 결과로 live 정책의 의미 충돌·권한 전부를 판정할 수 없다.

## KernelSU 타입 선언 가능성

설치된 `ksud sepolicy check`에 12개 각각 `type <이름> property_type` 문장을 전달해 모두 exit 0을 확인했다. `typeattribute custom_version_prop property_type`, `type ssal_property domain`의 구문도 수용했으며 의도적으로 잘못된 문장은 거부됐다. `check`는 파서 검사다. 정책에 문장을 로드하지 않았고, attribute 존재·실제 타입 부재·커널 반영 또는 권한 검증을 수행하지 않았다.

기존 조사에서 설치 버전과 연결된 [삼성 KernelSU 포크의 고정 소스](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/kernel/selinux/sepolicy.c)는 타입 생성 후 attribute를 부여하는 경로와 별도의 `typeattribute` 경로를 구현한다. [userspace 파서](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/userspace/ksud/src/sepolicy.rs)는 해당 명령을 처리한다. 이것은 **소스상 지원과 현재 파싱 가능성**이지 이 기기의 정확한 빌드가 성공적으로 새 타입을 추가한다는 증거는 아니다. 이름 충돌, role/MLS, attribute의 존재와 확장, 오류의 부분 반영, 정책 용량 및 기존 SID·AV 영향을 별도 확인해야 한다. 포크의 attribute 추가는 기존 constraint와 attribute 기반 규칙에도 영향을 주므로 단일 타입 선언을 무해하다고 볼 수 없다. `property_type`이나 `domain`은 예시 입력이지 적용할 규칙의 승인이나 최소 attribute 확정이 아니다.

## Property Area 생성 경로와 권한

[AOSP Bionic](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/system_properties/prop_area.cpp)은 각 context 파일을 `O_CREAT|O_EXCL`로 열고 `security.selinux`를 `fsetxattr`한 뒤 크기를 설정하고 공유 writable mmap한다. [contexts_serialized](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/system_properties/contexts_serialized.cpp)는 직렬화된 각 context와 별도의 `properties_serial`에 area를 만든다. [초기화 API](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/bionic/system_property_api.cpp)는 라벨 설정 실패 flag가 있으면 실패를 반환한다. 이는 참조 AOSP 경로이며 등록 GSI 바이너리의 동일성은 unknown이다.

| 단계 | 검사 대상과 필요한 권한/조건 | 현재 증거 |
|---|---|---|
| Guest 전용 디렉터리와 파일 생성 | 작성자 → 부모 `dir`: `search`, `add_name`, 필요 시 `write`; 작성자 → 생성될 초기 라벨의 `file`: `create`; 초기 라벨 → filesystem: `associate`. DAC/소유권·읽기 전용 여부도 충족 | 대상 Guest 도메인·초기 라벨·mount SID와 AV unknown |
| 열기·크기·mapping | 작성자 → 파일 `open`, `read`, `write`, `getattr`, 크기 변경에 `setattr`, mmap에 `map` 등 실제 syscall에 해당하는 권한; 충돌 없는 새 파일과 충분한 tmpfs 자원 | 기존 파일, DAC, filesystem 및 SELinux 실제 결과 not_run |
| `fsetxattr(security.selinux)` | 기존 inode 라벨에 대한 작성자의 `relabelfrom`, 새 라벨에 대한 `relabelto`, 유효 context, 유효 transition, 새 라벨 → 실제 filesystem SID의 `filesystem:associate`; 소유자 또는 적절한 capability와 SELinux 라벨링을 지원하는 mount 필요 | 해당 주체·쌍의 AV와 파일시스템 동작 unknown; `fsetxattr`은 별도 SELinux permission 이름이 아님 |
| 공유 읽기 | 클라이언트별 디렉터리 탐색과 `property_info`, serial, 해당 context area의 `open/read/getattr/map`, DAC 및 mmap 접근 | 각 Guest 클라이언트 도메인·권한 unknown |
| property 설정 | 소켓 DAC/SELinux 연결 및 호출자 context → 목적지 타입의 `property_service:set`, 이름·값 타입과 `ro.*` write-once 검사 | 기존 유효 라벨 확인만으로 허용 여부를 알 수 없음; `ctl.*`·`sys.powerctl`은 Host에 전달 금지 |
| persist 저장 | Guest userdata 전용 property 저장 디렉터리/파일의 생성·읽기·쓰기·rename 및 라벨, 내구성 | 데이터 라벨·도메인·정확한 권한 unknown |

`setattr`은 일반 파일 속성·크기 변경과 관련되며 `security.selinux` 설정의 `relabelfrom`/`relabelto`/`associate`를 대신하지 않는다. 위 접근 벡터는 경로별 후보이며 모두 현재 거부됐거나 모두 추가해야 한다는 뜻이 아니다. 검사 대상은 **실제 enforcing 주체 SID, 이전 파일 SID, 새 SID, filesystem SID와 class**를 지정해야 한다.

[Android 공통 커널의 SELinux setxattr 경로](https://android.googlesource.com/kernel/common/+/refs/tags/android15-6.6-2024-10_r2/security/selinux/hooks.c)는 `SBLABEL_MNT`, inode 소유권, relabel 및 filesystem associate 등을 확인한다. 참고 소스에는 invalid context에 대해 `CAP_MAC_ADMIN`이 있을 때 별도 force 경로도 있다. 따라서 EINVAL은 적절한 조건에서의 차단 **후보**이지 모든 자격에서 `fsetxattr`이 반드시 같은 errno로 실패한다는 증거가 아니다. 이 예외를 우회 설계로 채택하거나 올바른 라벨·접근 통제로 취급하지 않는다. 삼성 실행 커널의 정확한 동작은 unknown이다.

새 tmpfs는 Host property area와 inode를 분리하는 후보지만, tmpfs라는 이름만으로 개별 보안 라벨 설정과 `associate`가 보장되지는 않는다. `context=` 같은 단일 라벨 mount는 per-context 라벨링을 제한할 수 있으므로 mount 옵션과 실제 filesystem SID를 검증해야 한다. 반대로 mount namespace만으로 열린 FD, `/proc` 경로, 상속 socket 또는 공유 커널 정책을 분리할 수 없다.

## 구현 선택과 Host 영향

| 선택지 | 장점 | Host 영향 및 미해결 조건 |
|---|---|---|
| 원본 context 보존 + 최소 정책 확장 | 이름·prefix와 접근 구분을 유지할 수 있음. GSI 표준 클라이언트와의 호환성 검증에 유리 | 12개 라벨과 나머지 권한을 실제 enforcing 정책에서 재검증해야 한다. KernelSU 정책은 커널 전역이며 기존 도메인과 attribute가 받는 권한이 늘 수 있다. 새 타입 선언만으로 area 생성과 클라이언트 접근이 끝나지 않는다. 전체 AV 차분과 Host 인증 자원 음성 시험은 unknown |
| Guest 전용 context 축소 | 입증된 제한된 서비스 범위에서 context·권한 집합을 줄일 가능성 | 어떤 이름/서비스가 필요한지 unknown. 제거된 exact/prefix가 다른 prefix 또는 `default_prop`에 매칭될 수 있어 읽기·쓰기 경계가 바뀐다. Guest 전용 전체 매핑과 클라이언트별 권한, 기능 누락을 검증해야 한다. 재매핑만으로 Host와 같은 SID의 기존 권한을 분리할 수 없다 |

어느 선택이 최소인지 현재 결정할 수 없다. 특히 `property_type` 등 공유 attribute 또는 Host와 동일한 `init`·`system_server` SID에 allow를 추가하면 다른 Host 프로세스에도 영향을 줄 수 있다. 포괄적 allow, permissive 도메인, 무조건적인 default 라벨 치환은 안전한 최소 방안으로 입증되지 않았다. Live 변경은 전역이며 재부팅 후 자동 재적용되는 모듈 규칙은 One UI 복구 목표와 별도로 평가해야 한다.

## 다음 최소 구현 단계와 검증 조건

1. **읽기 전용 기준 고정:** 현재 실효 정책에서 523개와 `properties_serial`, 두 미조회 라벨 및 필요한 Guest domain/socket/filesystem context를 다시 유효성 검사하고 정책 identity/시각을 기록한다. 현재 policy export가 막혀 있으므로 전후 AV 차분의 한계를 명시한다. 최초 12개는 타입 부재와 role/MLS 불일치를 분리한다.
2. **Guest 계약을 오프라인으로 확정:** Guest property 작성자·클라이언트별 도메인, 파일/serial/socket/저장소 타입, tmpfs mount 옵션과 실제 inode·superblock SID, 읽기/설정 대상 property를 표로 만든다. Host Binder/FD/socket, 인증 저장소 및 `ctl.*`/`sys.powerctl`의 음성 경로를 포함한다.
3. **정책 후보 비교:** 보존과 축소 각각에 대해 원본·후보 property 매칭 변화, attribute가 기존 Host 도메인에 주는 AV 변화, SELinux constraint와 필요 permission을 비교한다. 별도 정책 복사본에서 도구 호환성 및 충돌을 검증하고, 정책 적용 없이도 해결 불가능한 부분은 unknown으로 둔다.
4. **후속 시험의 통과 조건:** Guest 전용 enforcing 도메인에서 개인 tmpfs와 socket의 실제 label·inode·mount SID, 모든 필요 area의 생성·mmap 및 권한 검사를 확인한다. Host area/FD/제어 경로 차단과 정책 미변경·One UI 복구를 별도로 검증한다. 이번 작업에서는 이 시험, 정책 적용, Property Area 생성, Guest 서비스 및 인증 HAL 실행을 하지 않았다.
