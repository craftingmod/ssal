# Samsung Host / LineageOS 23.2 Guest SELinux 재사용성 검토 — 2026-11-04

## 결론

**전체 Guest 정책을 Host에 병합하거나 Guest 규칙을 그대로 재사용하는 것은 권장하지 않는다.** Samsung Host의 활성 정책을 기준으로 유지하고, 실제 첫 부팅 경로에 필요한 Guest 전용 타입·context·transition·allow만 단계적으로 더하는 방향이 최소 변경 후보다. 기존 Host 정책 파일은 수정하지 않는다.

이번 조사에서 `/sys/fs/selinux/policy` binary를 기기에서 읽어 보관했다. Android 16 GSI의 CIL과 file/service/property/seapp context도 이미지에서 추출한 자료로 대조했다. 활성 binary에 대한 SETools 수준의 전체 역분석은 아직 수행하지 않았으므로, 아래 규칙 수와 타입명 차이는 추출 CIL 원문에 대한 정적 비교이며 binary와의 완전한 동등성 증명은 아니다.

## 수집 자료와 기준

### Samsung Host

- 기기: `SM-S937N`; build fingerprint `samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`.
- 수집 시점 상태: `getenforce=Enforcing`, boot ID `f7900911-c061-4570-8f65-900571a55c11`, selinuxfs `policyvers=33`. `policyvers`는 커널 지원 버전 정보이며 로드된 정책 버전의 독립 확인값으로 취급하지 않는다.
- 활성 binary는 `adb pull /sys/fs/selinux/policy`로 읽었다. 보관 경로는 `out/selinux-check/2026-11-04-host-active-policy.bin`, 크기 `3,140,889` bytes, SHA-256 `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723`다. 기기에는 정책·라벨·서비스 변경을 하지 않았다.
- 함께 비교한 Host CIL/context 파일은 `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/` 아래에 있다. 핵심 입력 CIL 해시는 `plat_sepolicy.cil` `425aba8b73da746a6338a3d42f6dfd20b5bfdd02163928f1aee0b7b333ab03c9`, `system_ext_sepolicy.cil` `3ea88731ec5753c3d6803c9cf85cdaeae507bfbb6d64ecdca650438575736b5c`, `product_sepolicy.cil` `7b25f3b8af6373c43ade1725a7cee70b97a81d34c15ff146f473940fc8c01aa4`, `vendor_sepolicy.cil` `a06d7a774089c364a9ba33a177e35000d9ce0ea83ed351251ce06567eba2f3d1`, `plat_pub_versioned.cil` `32f3a336016d2b76733291942e97ecc193d830e88fa95e1bc48d381d091ec9b0`다. Vendor policy API는 `202404`다.
- 기존 CIL 재구성 기록에서는 Android 기기의 `secilc -N`으로 Host 입력을 컴파일해 타입 4,983개, permissive 도메인 0개를 얻었다. 이는 `-N`으로 neverallow 검사를 생략한 정적 재구성이지, 위에서 새로 수집한 활성 binary 자체에 대한 분석 결과는 아니다. `/odm/etc/selinux/precompiled_sepolicy`는 정책 버전 30이고 Host system/system_ext/product component hash가 모두 불일치해 현재 활성 정책의 대용으로 사용하지 않았다.

### LineageOS 23.2 Android 16 Guest

- 등록된 GSI 이미지 SHA-256 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`, 크기 `2,733,260,800` bytes. 이미지 fingerprint `google/lineage_arm64_bvN4/generic_arm64:16/BP4A.251205.006/eng.andrew:userdebug/release-keys`, SDK `36`, release `16`이다.
- CIL과 context 파일은 해당 이미지에서 읽기 전용으로 추출한 `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/`의 복사본이다. 주요 해시:

| Guest 파일 | SHA-256 |
|---|---|
| `system/etc/selinux/plat_sepolicy.cil` | `be4eb2bcc7c1fe5bec30ec686b8ac1df28eec0eefcc48b9f541fd2f8cfffa167` |
| `system_ext/etc/selinux/system_ext_sepolicy.cil` | `74dd0be2cbcf599baede7e1cd5d25529cdb72976b5ab8f880b498c8cdf55ef60` |
| `system/etc/selinux/plat_file_contexts` | `bde583ce3e1643536807d12308cb53f3c2ce9adbbb1044fd34d81a4e23144e24` |
| `system/etc/selinux/plat_service_contexts` | `f50794b6a89e6be5cf1d2e8300d777d0ea60c618d98c1e34233e556c754f1865` |
| `system/etc/selinux/plat_property_contexts` | `f4b41c3f807c948a5f437bc8605c0af5340335e96b95a3028e32d7c02b9a8221` |
| `system/etc/selinux/plat_seapp_contexts` | `7a4d14a898fb234d87cd49ae106e245324ad365d9029230d2a6306e6d4aa7a7a` |
| `system_ext/etc/selinux/system_ext_file_contexts` | `3d2836b16dc0c861b5ce3381516466818c1f7aed0daadc9f8329a0cb16719945` |
| `system_ext/etc/selinux/system_ext_service_contexts` | `9c5e9d0a06cc72743d04e3dbb452a91321e52848cf107b2c6f285ebfe82efc56` |
| `system_ext/etc/selinux/system_ext_property_contexts` | `bfadf3d5f1de14b2b052974156950953fefe29f36e6af3840fbd56666d72bb3e` |
| `system_ext/etc/selinux/system_ext_seapp_contexts` | `3b4b2ee6b46063625312530f1d12f82510318cbe892810dbe7058a19a93709b` |

Product CIL은 추출 이미지에서 1-byte 파일이었다. 공개 GSI 릴리스 안내는 이 배포물을 unofficial LineageOS 23.2, Android 16 QPR2로 설명한다. 등록 이미지와 해당 공개 빌드 소스의 정확한 commit 일치는 입증되지 않았다.

## 정책 비교

추출 CIL 원문의 선언을 세어 비교했다. 수치는 attribute 확장과 컴파일 후 효과가 아니라 직접 등장한 CIL 문장 수다.

| 비교 입력 | type 선언 | `allow` | `allowx` | `typetransition` |
|---|---:|---:|---:|---:|
| Host platform/system_ext/product/vendor 및 202404 mapping | 4,983 | 37,289 | 604 | 1,175 |
| Guest system/system_ext/product | 2,043 | 13,121 | 331 | 346 |

정확한 타입명 비교에서는 **Guest에만 있는 type 96개와 attribute 이름 21개**가 나왔다. 타입 예로 `adbroot_*`, `lineage_*_service`, `qcrilam_*`, `fingerprint_*`, `smcinvoke_device`, `teecd_data_file`, `vndk_detect_exec`가 포함된다. 21개 Guest-only attribute는 `hal_lineage_{health,livedisplay,powershare,touch,trust}`와 각각의 client/server 변형, `hal_mms_server`, `opengl_sphal_domain`, `vulkan_sphal_domain`, `sdcard_posix_contextmount_type`, `smcinvoke_device_29_0`, `sysfs_backlight_attr`다.

타입이 Guest CIL에 정의되어 있다는 사실은 Host에서 같은 권한을 복사해도 된다는 뜻이 아니다. Attribute membership은 기존 Host `allow`와 constraint에 새 타입을 포함시킬 수 있다. 예를 들어 기존 분석은 Guest `core_data_file_type`에 270개 타입과 231개 정책 참조가 있음을 기록했다. `domain`, `appdomain`, `file_type`, `data_file_type`, `property_type`, `core_data_file_type` 같은 공용 attribute에 새 Guest 타입을 붙이는 결정은 개별 type 이름보다 Host 영향이 클 수 있으므로 `REVIEW`로 둔다.

| 항목 | 판정 | 근거와 Host 격리 위험 |
|---|---|---|
| 기존 Host의 공용 SELinux class와 의미가 일치하는 최소 primitive | **REUSE** | 기존 커널 class·권한 이름을 중복 정의하지 않는다. `system_file`, `tmpfs` 같은 Host type은 Guest의 읽기 전용 파일과 의미가 정확히 맞고, Host subject가 Guest mount나 FD를 볼 경로가 없음을 확인한 경우에만 재사용한다. 같은 label은 mount namespace가 달라도 같은 전역 SID/권한을 뜻한다. |
| Guest-only type 및 attribute | **EXTEND / REVIEW** | 96개 type·21개 attribute 이름 차이는 source-level 차이다. 필요한 runtime object만 새 이름으로 추가하고, 공용 attribute에 넣기 전 기존 Host rule의 확장 효과를 확인한다. 임의로 Guest type을 Host의 비슷한 type에 alias하지 않는다. |
| Guest `allow` | **ISOLATE** | Guest 전체의 13,121개 literal `allow`를 Host에 이식하지 않는다. 필요한 권한만 전용 Guest source type에서 전용 Guest target type으로 제한해야 한다. Guest process를 기존 Host `system_server`, `init` 또는 `servicemanager` domain에 두면 Host 권한을 그대로 받는다. |
| Guest `type_transition` | **REVIEW** | 346개 전이를 가져오면 공용 source domain과 실행 파일 label이 맞는 Host 프로세스에도 적용될 수 있다. 전용 Guest launcher/init source와 Guest 전용 exec label에 한정해 설계하고, Host `init`·`zygote`·`system_server`를 source로 한 규칙은 피한다. |
| Guest file contexts / userdata | **ISOLATE** | 전체 Guest file_contexts를 Host에 전역 등록하지 않는다. Guest가 소유한 system image와 userdata에만 Guest label을 적용한다. Host `/data`, FBE key, firmware, credential 및 TEE 상태에 Guest data label이나 Host의 넓은 `data_file_type` 권한을 공유하지 않는다. |
| service contexts | **EXTEND / ISOLATE** | 이전 Host context 검사에서 9개 서비스 context가 유효하지 않았다. 이름별 Guest service type만 정의하고 Guest의 private Binder registry에 한정한다. private binderfs가 Binder registry를 분리해도 SELinux type과 Host 정책은 분리하지 않는다. |
| property contexts / Property Area | **ISOLATE** | 이전 검사에서 Guest property type 12개가 EINVAL이었고 독립 property namespace는 아직 성립하지 않았다. Host init/property area를 재사용하지 말고 Guest 전용 property area·저장소·서비스 주체로 분리한다. `ctl.*` 및 `sys.powerctl`은 Host로 전달하지 않는다. |
| Guest와 Samsung Host의 `genfscon` 조합 | **REVIEW** | 기존 전체 조합 검증에서 `iso9660 /`는 Guest `iso9660` 대 Host `vfat`, `udf /`는 Guest `udf` 대 Host `vfat` 충돌이 났다. Host 선언을 유지하고 이 Guest 선언은 증명된 필요가 없으면 increment에 넣지 않는다. 전체 Guest CIL 조합은 현재 통과하지 않는다. |

`out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/patch-plan.json`의 37개 context-invalid 항목 분류는 아래와 같다. EINVAL은 전체 context가 당시 거부됐다는 결과이지, 단독으로 해당 type이 binary에 없다는 증명은 아니다. 필수성도 대부분 `unknown`이므로 생성 계획과 boot 필수 목록을 동일시하지 않는다.

| 판정 | 항목 | 권장 처리 |
|---|---|---|
| **EXTEND** | `lineage_globalactions_service`, `lineage_health_interface_service`, `lineage_livedisplay_service`, `lineage_profile_service`, `ashmem_compat_memfd_context_file`, `hal_audio_sysbta_exec`, `vndk_detect_exec` | 실제 첫 부팅에서 필요한 서비스·파일임을 확인한 뒤 고유 Guest type/context와 정확히 좁은 권한만 추가한다. |
| **ISOLATE** | `ssal_property`; property 12개 (`custom_version_prop`, `legal_url_prop`, `native_binder_stats_prop`, `odm_cast_prop`, `persist_sysui_builder_extras_prop`, `persist_sysui_ranking_update_prop`, `recovery_update_prop`, `sf_hs_mode_prop`, `usb_uvc_config_prop`, `vendor_hwc_prop`, `vendor_persist_nfc_prop`, `xtra_control_prop`); `mediashell_app`, `qcrilam_app`, `updater_app`; `fingerprint_hidl_service`, `lineage_hardware_service`, `lineage_trust_service`, `qcrilam_service`; `adbroot_data_file`, `dmd_device`, `gatekeeper_vendor_data_file`, `hal_fingerprint_oppo_compat_exec`, `smcinvoke_device`, `teecd_data_file` | Host service, property area, app data, biometric/radio/TEE/credential device label을 재사용하지 않는다. 필요성이 입증된 항목만 Guest 전용 경계에서 연다. |
| **REVIEW** | `adbroot_service`, `adbroot_exec`, `mkfs_exec`, `phhsu_exec` | root·파일시스템 변경 가능성이 있는 항목이다. 첫 부팅에 필요하다는 증거가 없으면 추가하지 않고, 별도 기능 검토 대상으로 둔다. |
| **REUSE** | 해당 37개 중 없음 | 모두 기존 Host에서 유효하다고 입증되지 않은 Guest context다. |

37개 context 항목 외 Guest-only type 59개는 모두 현재 **REVIEW**다. 이로써 CIL에서 찾은 96개 Guest-only type은 EXTEND 7개, ISOLATE 26개, REVIEW 63개로 나뉘며 REUSE는 없다.

`adbroot`, `apex_test_prepostinstall_devpts`, `ashmem_compat_memfd`, `asus_motor_device`, `backuptool`, `boot_prop`, `camera_prop`, `crosvm`, `crosvm_tmpfs`, `default_hisi_hwservice`, `hal_aguiledbelt`, `hal_aguiledbelt_hwservice`, `hal_aidl_agolddaemon_default`, `hal_audio_sysbta`, `hal_ext_fingerprint_hwservice`, `hal_fingerprint_oplus`, `hal_fingerprint_oppo`, `hal_fingerprint_oppo_compat`, `hal_gesturewake_default`, `hal_gesturewake_hwservice`, `hal_tp_default`, `hostapd`, `ipacm`, `iso9660`, `mediashell_app_userfaultfd`, `mkfs`, `mtk_hal_audio`, `mtk_hal_light`, `mtk_hal_mms_hwservice`, `mtk_hal_power`, `mtk_hal_rild_hwservice`, `mtk_vilte_support_prop`, `oeminfo_nvm`, `oeminfo_nvm_device`, `omapi_service`, `phhota_dev`, `phhsu_daemon`, `phhsu_daemon_tmpfs`, `proc_ged`, `qcrilam_app_userfaultfd`, `rpmb_device`, `sdcard_posix`, `sensitivity_sysfs`, `shell_devpts`, `su_userfaultfd`, `sys_block_mmcblk0`, `sys_block_sdd`, `sysfs_board_properties`, `sysfs_perdev_minors`, `sysfs_tp`, `sysfs_tp_fodstatus`, `sysfs_usb_supply`, `tkcore`, `udf`, `updater_app_userfaultfd`, `vendor_sysfs_displayfeature`, `vmlauncher_app_devpts`, `vnd_qcril_audio_hwservice`, `vnd_qcrilhook_hwservice`, `vndk_detect`.

21개 Guest-only attribute의 판정도 명시한다. `opengl_sphal_domain`, `vulkan_sphal_domain`, `sdcard_posix_contextmount_type`, `smcinvoke_device_29_0`, `sysfs_backlight_attr`는 **ISOLATE**다. 나머지 `hal_lineage_{health,livedisplay,powershare,touch,trust}`와 client/server 변형 및 `hal_mms_server`는 실제 Guest HAL 의존성이 확인되기 전까지 **REVIEW**다. 어느 attribute도 현재 Host rule에 재사용할 이유는 확인되지 않아 REUSE로 두지 않는다. REVIEW 목록 중 `oeminfo_nvm*`, `rpmb_device`, `sys_block_*`, `sysfs_*`, `tkcore`, `vnd_qcril*`, `hal_fingerprint_*`는 나중에 필요하더라도 Host 하드웨어·radio·secure storage endpoint와 분리해야 한다.

## 최소 변경 계획

1. Host 활성 binary를 기준 정책으로 유지한다. Guest의 13,121 `allow`와 346 transition을 전체 복사하거나, 버전 30 ODM `precompiled_sepolicy`로 교체하지 않는다.
2. 첫 부팅에 실제 필요한 프로세스 경로만 선택한다. Guest `init`에서 private `servicemanager`와 `zygote`/`system_server`로 이어지는 전환을 Guest 전용 source/domain/exec type으로 제한한다. 기존 Host `init`, `servicemanager`, `zygote`, `system_server` label을 Guest 프로세스에 재사용하지 않는다.
3. SSAL property 실행 주체·실행 파일·property area·userdata에 필요한 전용 `ssal_property` 도메인 및 Guest 전용 label만 후보로 둔다. 이 도메인의 실제 필요한 권한·mount SID·transition은 아직 미검증이므로 추측성 `allow`를 작성하지 않는다.
4. private Binder와 독립 userdata 경계를 유지한다. Guest service context는 실제 등록되는 이름만 정의하며, service add/find와 Binder 접근은 전용 Guest domain 사이로 좁힌다. Host Binder/property/socket/FD와 KeyMint·Gatekeeper·TEE·radio·fingerprint HAL은 첫 부팅 기본 경로에 연결하지 않는다.
5. 공용 attribute membership, exact allow/transition 차이와 neverallow를 동일 Host binary·현재 Android CIL 기준으로 오프라인 비교한 후, 필요한 Guest-only delta만 별도 승인 단계에서 검토한다. 이번 조사에서는 정책 적용이나 도메인 생성, permissive 변경을 하지 않았다.
6. 향후 실행 세션 정책은 Host source/vendor/odm 파일에 영구 반영하거나 부팅 자동 재적용하지 않는다. SSAL Guest 실행 중에만 동적 추가를 검토하고, 하드 재부팅 후 정책이 재적용되지 않으며 One UI와 Enforcing 상태가 정상 복귀하는지 별도 확인한다.

## 조사 한계와 기존 자료

- 2026-10-31 기존 기기 검사에서는 2,686 context 중 2,649 유효, 37 EINVAL이었고 37개는 service 9, file 12, property 12, seapp 3, `ssal_property` 1로 나뉘었다. 이 과거 결과는 2026-11-04 binary에 대해 재실행한 context 검사 결과가 아니다.
- Host binary는 이번에 수집했지만 현재 Windows 작업 환경에 binary policy용 `seinfo`/`sesearch`가 없어, 해당 binary의 type/attribute/rule table 전체를 역분석하지 않았다. CIL rule count 및 name diff와 앞선 Android `secilc`/SETools 재구성 결과를 binary 분석 결과로 과장하지 않는다.
- 등록 이미지와 upstream build commit의 일치, 37개 context의 최신 커널 유효성, 전체 GSI service 등록/실행, 필수 attribute membership, Guest Enforcing 첫 부팅은 미확인이다.
- 이전 자료: [SELinux source audit](sepolicy-source-audit.md), [device context check](selinux-check-device-20261031.md), [patch triage](selinux-patch-triage-20261031.md), [Guest property feasibility](guest-property-selinux-feasibility.md), [Enforcing Binder results](enforcing-binder-device-20261031.md).

참조: [LineageOS GSI 2026-05-24 release](https://github.com/MisterZtr/LineageOS_gsi/releases/tag/v2026.05.24-lineage23.2), [AOSP SELinux compatibility](https://source.android.com/docs/security/features/selinux/compatibility), [AOSP CIL type statements](https://android.googlesource.com/platform/external/selinux/+/android-9.0.0_r33/secilc/docs/cil_type_statements.md).
