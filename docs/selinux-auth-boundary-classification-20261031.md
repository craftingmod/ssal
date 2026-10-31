# SSAL SELinux 및 인증 경계 분류표 — 2026-10-31

37개 모두 최초 부팅 필수성 및 불필요성은 unknown이다. optional_candidate는 기능상 선별 후보이며 제거 가능하다는 뜻이 아니다. security_sensitive는 격리 검토 우선순위다. 파일·선언의 존재는 실행의 증거가 아니다. 상세 근거는 [기존 분석](../out/selinux-check/2026-10-31-offline-guest/analysis-report.md), 선언과 attribute는 [patch-plan](../out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/patch-plan.json)을 참조한다.

| 타입/도메인 | 검토 분류 | 최초 부팅 / 불필요 | 이미지 단서 |
|---|---|---|---|
| `adbroot_data_file` | security_sensitive | unknown / unknown | `/system/system_ext/bin/adb_root`, `/system/system_ext/etc/init/adb_root.rc` |
| `adbroot_exec` | security_sensitive | unknown / unknown | `/system/system_ext/bin/adb_root`, `/system/system_ext/etc/init/adb_root.rc` |
| `adbroot_service` | security_sensitive | unknown / unknown | `/system/system_ext/bin/adb_root`, `/system/system_ext/etc/init/adb_root.rc` |
| `ashmem_compat_memfd_context_file` | optional_candidate | unknown / unknown | `/system/etc/selinux/ashmem_compat_memfd_context.txt` |
| `custom_version_prop` | optional_candidate | unknown / unknown | 미확인 |
| `dmd_device` | security_sensitive | unknown / unknown | 미확인 |
| `fingerprint_hidl_service` | security_sensitive | unknown / unknown | `/system/bin/adevice_fingerprint`, `/system/bin/hw/android.hardware.biometrics.fingerprint@2.1-service.oplus.compat`, `/system/bin/hw/android.hardware.biometrics.fingerprint@2.1-service.oppo.compat` |
| `gatekeeper_vendor_data_file` | security_sensitive | unknown / unknown | 미확인 |
| `hal_audio_sysbta_exec` | optional_candidate | unknown / unknown | `/system/bin/hw/android.hardware.bluetooth.audio-service-system`, `/system/etc/init/android.hardware.bluetooth.audio-service-system.rc` |
| `hal_fingerprint_oppo_compat_exec` | security_sensitive | unknown / unknown | `/system/bin/hw/android.hardware.biometrics.fingerprint@2.1-service.oplus.compat`, `/system/bin/hw/android.hardware.biometrics.fingerprint@2.1-service.oppo.compat` |
| `legal_url_prop` | optional_candidate | unknown / unknown | 미확인 |
| `lineage_globalactions_service` | unknown | unknown / unknown | 미확인 |
| `lineage_hardware_service` | security_sensitive | unknown / unknown | 미확인 |
| `lineage_health_interface_service` | unknown | unknown / unknown | 미확인 |
| `lineage_livedisplay_service` | unknown | unknown / unknown | 미확인 |
| `lineage_profile_service` | unknown | unknown / unknown | 미확인 |
| `lineage_trust_service` | security_sensitive | unknown / unknown | 미확인 |
| `mkfs_exec` | security_sensitive | unknown / unknown | `/system/bin/mkfs.exfat`, `/system/bin/mkfs.ntfs` |
| `native_binder_stats_prop` | unknown | unknown / unknown | 미확인 |
| `odm_cast_prop` | unknown | unknown / unknown | 미확인 |
| `persist_sysui_builder_extras_prop` | unknown | unknown / unknown | 미확인 |
| `persist_sysui_ranking_update_prop` | unknown | unknown / unknown | 미확인 |
| `phhsu_exec` | security_sensitive | unknown / unknown | `/system/bin/asus-motor`, `/system/bin/phh-on-boot.sh`, `/system/bin/phh-on-data.sh` |
| `qcrilam_service` | security_sensitive | unknown / unknown | `/system/app/QcRilAm`, `/system/app/QcRilAm/QcRilAm.apk`, `/system/app/QcRilAm/oat` |
| `recovery_update_prop` | security_sensitive | unknown / unknown | 미확인 |
| `sf_hs_mode_prop` | unknown | unknown / unknown | 미확인 |
| `smcinvoke_device` | security_sensitive | unknown / unknown | 미확인 |
| `teecd_data_file` | security_sensitive | unknown / unknown | 미확인 |
| `usb_uvc_config_prop` | unknown | unknown / unknown | 미확인 |
| `vendor_hwc_prop` | unknown | unknown / unknown | 미확인 |
| `vendor_persist_nfc_prop` | security_sensitive | unknown / unknown | 미확인 |
| `vndk_detect_exec` | optional_candidate | unknown / unknown | `/system/bin/vndk-detect` |
| `xtra_control_prop` | unknown | unknown / unknown | 미확인 |
| `mediashell_app` | security_sensitive | unknown / unknown | 미확인 |
| `qcrilam_app` | security_sensitive | unknown / unknown | `/system/app/QcRilAm`, `/system/app/QcRilAm/QcRilAm.apk`, `/system/app/QcRilAm/oat` |
| `ssal_property` | security_sensitive | unknown / unknown | 미확인 |
| `updater_app` | security_sensitive | unknown / unknown | `/system/system_ext/etc/init/init.lineage-updater.rc` |

## 기존 정책 및 추가 검토

| 항목 | 판정 및 범위 |
|---|---|
| binder_device, servicemanager | 기존 정책으로 제한된 enforcing private IPC passed. 정식 서비스와 인증 HAL은 미실행 |
| system_file, system_server | v5에서 관련 AV 허용. Guest system_server 실제 read not_run |
| ssal_image_file | v5 실효 정책의 kernel read 허용. 순정 삼성 정책에서도 존재하는지는 unknown |
| 9개 invalid service context | blocked. context 검증 EINVAL; 서비스별 필수성과 add/find 주체는 unknown |
| system_file filesystem associate | context tmpfs에만 추가 후보. 검증된 ext4 방식에는 불필요; 전역 영향 미평가 |
| 별도 Guest 도메인·라벨 | 설계 후보. 전이, 의존성, 전역 정책 영향 미검증 |
| 기타 allow/type/mapping | unknown. invalid context 자체는 추가 권한의 필요성을 증명하지 않음 |
