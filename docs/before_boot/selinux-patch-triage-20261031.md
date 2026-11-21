# SELinux 패치 후보 선별 — 2026-10-31

결론: **적용하거나 오프라인 패치로 만들 수 있는 후보는 아직 없다.** 37개를 검토했지만 boot 필수성, 실행 파일 존재, Host 인증 격리를 입증할 자료가 없다. 아래 분류는 기능과 위험에 따른 잠정 검토 우선순위이며 적용 승인이나 사용 여부의 판정이 아니다.

기준은 `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/patch-plan.json` (SHA-256 `843d97ae962b88a67a09da3e8e08d176bbb66ecc8eb0d68402f5de8e9f57ec01`) 및 이 파일이 지정한 `report.json`이다. Guest 이미지 manifest의 SHA-256은 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`다. 보고된 Guest 빌드 정보는 Android 16, SDK 36이다. 정책 소스와 이미지의 정확한 빌드 일치는 입증되지 않았다.

## 분류 기준

- `security_sensitive`: 인증·보안 저장소·특권 실행·업데이트·통신·공유 Host 자원에 직접 또는 잠재적으로 닿거나 설계가 미완성인 항목. 자동 적용 제외. 민감 분류가 실제 접근을 증명하지는 않는다.
- `optional` **검토 후보**: 이름과 바인딩상 특정 기능에 연결되는 것으로 보이나, 실제 부팅에서 선택 사항임은 미검증. 기능을 끄고 부팅 가능하다는 뜻이 아니다.
- `boot_required`, `unused`: 실측 근거가 없어 현재 어느 항목에도 부여하지 않는다. `unused`는 파일 부재만으로 확정하지 않는다.

| 타입 | 잠정 분류 | 검토 근거 / 다음 확인 |
|---|---|---|
| `adbroot_data_file` | security_sensitive | `/data/adbroot`; 특권 상태와 접근 주체 확인 |
| `adbroot_exec` | security_sensitive | `adb_root` 실행 경로; 파일·init 서비스와 권한 확인 |
| `adbroot_service` | security_sensitive | `adbroot_service`; 등록 주체와 클라이언트 확인 |
| `ashmem_compat_memfd_context_file` | optional | 호환성 context 파일; 파일 및 사용 주체 확인 |
| `custom_version_prop` | optional | Lineage 버전 속성; 읽기·쓰기 주체 확인 |
| `dmd_device` | security_sensitive | `/dev/dsm`; 실제 장치와 공유 Host 접근 확인 |
| `fingerprint_hidl_service` | security_sensitive | 지문 HAL 서비스 매핑; Host 생체 인증과의 경계 확인 |
| `gatekeeper_vendor_data_file` | security_sensitive | `/data/vendor/gatekeeper`; Host 인증 데이터 경계 및 접근 주체 확인 |
| `hal_audio_sysbta_exec` | optional | Bluetooth 오디오 HAL 실행 경로; 파일·서비스 확인 |
| `hal_fingerprint_oppo_compat_exec` | security_sensitive | 지문 호환 HAL 실행 경로; 파일과 인증 경계 확인 |
| `legal_url_prop` | optional | 법적 고지 URL 속성; 사용자 확인 |
| `lineage_globalactions_service` | optional | `lineageglobalactions`; 등록 주체·기능 의존성 확인 |
| `lineage_hardware_service` | security_sensitive | `lineagehardware`; 실제 하드웨어 접근 범위 확인 |
| `lineage_health_interface_service` | optional | `lineagehealth`; 등록 주체·의존성 확인 |
| `lineage_livedisplay_service` | optional | `lineagelivedisplay`; 등록 주체·의존성 확인 |
| `lineage_profile_service` | optional | `profile`; 등록 주체·의존성 확인 |
| `lineage_trust_service` | security_sensitive | `lineagetrust`; 보안 관련 기능과 접근 주체 확인 |
| `mkfs_exec` | security_sensitive | 파일시스템 생성 도구 경로; 블록 장치 접근과 호출자 확인 |
| `native_binder_stats_prop` | optional | Binder 통계 속성; 사용자 확인 |
| `odm_cast_prop` | optional | cast 관련 속성; 사용자 확인 |
| `persist_sysui_builder_extras_prop` | optional | System UI 알림 속성; 사용자 확인 |
| `persist_sysui_ranking_update_prop` | optional | System UI 알림 속성; 사용자 확인 |
| `phhsu_exec` | security_sensitive | `phh-su`, `rw-system.sh`; 특권 실행 및 Host 영향 확인 |
| `qcrilam_service` | security_sensitive | `me.phh.qcrilam`; 모뎀 서비스 및 Host 경계 확인 |
| `recovery_update_prop` | security_sensitive | recovery 업데이트 속성; 쓰기 주체와 Host 영향 확인 |
| `sf_hs_mode_prop` | optional | 화면 구성 속성; 사용자 확인 |
| `smcinvoke_device` | security_sensitive | `/dev/smcinvoke`; secure world 및 인증 관련성 확인 |
| `teecd_data_file` | security_sensitive | `/sec_storage`; TEE 저장소 및 Host 경계 확인 |
| `usb_uvc_config_prop` | optional | USB 카메라 속성; 사용자 확인 |
| `vendor_hwc_prop` | optional | vendor 디스플레이 속성; 사용자 및 Host 영향 확인 |
| `vendor_persist_nfc_prop` | security_sensitive | 지속 vendor NFC 설정; 쓰기 주체 및 Host 영향 확인 |
| `vndk_detect_exec` | optional | `vndk-detect` 실행 경로; 파일·호출자·부팅 의존성 확인 |
| `xtra_control_prop` | optional | 위치 보조 데이터 데몬 속성; 사용자 확인 |
| `mediashell_app` | security_sensitive | 특권 앱 도메인과 attribute 영향 확인 |
| `qcrilam_app` | security_sensitive | 모뎀 관련 앱 도메인과 권한 확인 |
| `ssal_property` | security_sensitive | SSAL 전용 도메인 설계 미완성; 격리 설계 선행 |
| `updater_app` | security_sensitive | 업데이트 앱 도메인; Host 파티션·부팅 관련 영향 확인 |

## 증거의 빈칸과 실행 순서

1. 저장된 Guest 추출물은 SELinux 정책 및 contexts 자료다. `file_contexts`의 정규식과 `service_contexts` 또는 `seapp_contexts`의 매핑은 파일, 서비스, 앱이 이미지에 실제 존재하거나 실행된다는 증거가 아니다. 현재 37개 모두 해당 실행 파일·서비스의 존재와 런타임 사용은 미확인이다. 속성·파일 타입은 실행 파일 자체가 없을 수도 있으므로 각 접근 주체를 확인한다.
2. 이미지 해시를 다시 확인한 뒤, 이미지의 읽기 전용 오프라인 파일 목록과 init rc, VINTF manifest, APK 목록을 확보한다. 경로를 실제 파일과 대조하고 서비스 이름을 선언·바이너리·호출자에 연결한다. 존재와 부재를 구분하되 조건부 서비스·동적 등록을 별도로 조사한다. 그 다음 SSAL의 실제 부팅 경로에 대한 증거로 `boot_required` 또는 `unused`를 판단한다.
3. Host FBE, KeyMint, Gatekeeper, Weaver, TEE 및 공유 vendor 데이터·장치에 대한 접근 경로를 주체, Binder 서비스, 마운트와 DAC/SELinux 권한까지 분석한다. 특히 `system_server`의 Host 인증 상태 접근 차단은 현재 보장되지 않는다. 이름만 필터링하는 것은 충분한 격리 근거가 아니다.
4. 필수성이 입증되고 보안 검토를 통과한 타입만 별도 후보로 기록한다. 타입 선언과 attribute 부여가 기존 Host 규칙에서 부여할 수 있는 권한을 분석하고, 인증·공유 자원에 대한 기존 및 추가 접근을 비교한다. 재구성 정책은 live 정책의 완전한 사본이 아니다. 현재 `Unknown extended permission: 3`으로 baseline 분석이 실패했으므로 영향 분석은 미완료이며, 이 오류를 해결하고 도구 호환성과 결과를 확인하기 전에는 안전성을 판정하지 않는다.
5. 검토 통과 후보가 생기면 설치된 Samsung KernelSU 구현에 맞는 구문을 확인하고 **오프라인 복사본**에서 컴파일 및 전후 권한 차이 검사를 한다. 구문 성공은 권한 안전성이나 live 적용 성공을 증명하지 않는다. Host `genfscon`을 유지하고 충돌하는 Guest `iso9660`, `udf` 선언은 증분 이식에서 제외한다.
6. 그 후에만 일회성 기기 시험을 별도로 설계한다. 자동 재적용 없이 Enforcing 유지, 적용 전후 상태 기록, 실패 시 하드 재부팅 및 One UI 복구 확인을 포함한다. 부팅·잠금 해제·인증과 독립 userdata의 실제 검증은 여전히 필요하다.

이번 검토는 저장된 파일만 읽었고 기기 접근, 정책 변경, 실행 가능한 규칙 생성은 하지 않았다.
