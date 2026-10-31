# SSAL Guest init 및 Property Service 사전 조사 — 2026-10-31

**결론: 현재 Android 16 `init second_stage`를 실행할 수 있는 안전한 환경이 아니다.** Host PID 1을 보며, 원본 init은 `/proc/1/oom_score_adj`에 쓰고 전역 커널 설정·서비스 제어·재부팅 경로를 가진다. 별도 Property Service도 아직 구현되지 않았다. 이 문서의 최소 범위는 **Guest property 초기화와 private Binder의 servicemanager 준비**이며 Android 부팅 전체가 아니다. 실제 실행 가능성은 미검증이다.

## 근거와 범위

등록 이미지 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img`의 SHA-256은 기존 기록과 같은 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`다. 이미지에서 파일을 읽기 전용으로 추출해 `system/etc/init/hw/init.rc`, `system/etc/init/servicemanager.rc`, `apexd.rc`, `logd.rc`, system 및 system_ext property contexts와 build.prop를 확인했다. runtime APEX와 statsd APEX의 payload를 오프라인 열거했다. runtime payload에는 rc가 보이지 않았고 statsd의 `etc/init.rc`는 main class `statsd`를 선언한다. 다른 모든 APEX의 rc까지 완전 열거한 결과는 아니다. 7-Zip은 이미지에 경고를 출력했으므로 누락 가능성을 배제하지 않는다. Guest 바이너리와 정확히 일치한다고 증명되지 않은 코드는 Android 16 r2 AOSP 기준으로 표시한다.

참고 vendor 구현인 `vendor/freesam/app/src/main/assets/switch_to_lineage.sh:571–574`는 mount namespace만 지정하고 `master_inner.sh:6–16`은 pivot_root와 proc mount를 수행하며 Guest init을 실행하지 않는다. `vendor/freesam/docs/engineering/HANDOFF.md:206–208`은 servicemanager 공유와 Host 기준의 stale property를 기록한다. 이는 SSAL의 격리 증거가 아니다. `vendor/LineageOS_gsi/patches/trebledroid-staging/platform_system_core/0004-init-tolerate-EROFS-on-restorecon-of-system-bin-init.patch:6–19,38–47`는 read-only init restorecon의 EROFS와 fatal reboot 위험을 다루지만, 이 패치가 등록 이미지에 적용됐는지는 미확인이다.

기존 [실행 환경 결과](servicemanager-execution-environment.md), [SELinux 결과](selinux-check-device-20261031.md), [초기 mount 구성](initial-mount-profile.md), [서비스 계약](../module/profiles/services/initial.json)을 재사용했다. 기존 실제 기기 결과는 KernelSU가 적용된 실효 정책에 대한 관측이지 변경 전 순정 정책의 증명이 아니다. 이번에는 기기 접근, Guest init/서비스/인증 호출, 정책 적용 또는 설치 모듈 변경을 하지 않았다.

## 서비스 의존성 표

| 구성 요소 | 이 단계의 필요성 및 근거 | 현재 상태 / 경계 |
|---|---|---|
| Property area 및 Property Service | **필수 기능**. AOSP [PropertyInit / StartPropertyService](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/init/property_service.cpp)는 init 내부 기능과 스레드이며 독립 rc 서비스가 아니다. servicemanager의 ready property 기록도 필요하다. | SSAL 계약의 `/run/ssal/property-service`는 계획이며 실제 구현·domain transition 미검증. Guest 전용 area와 두 socket 필요. |
| servicemanager | **목표 서비스**. 실제 `servicemanager.rc:1–13`은 system:system, readproc, `/dev/kmsg` FD 및 `ProcessCapacityHigh`를 지정한다. [AOSP main](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r2/cmds/servicemanager/main.cpp)은 Binder context manager와 ready property를 설정한다. | private Binder 및 property가 선행. 실제 exec 미실행; rc의 재시작 액션을 그대로 실행하면 apexd, audioserver, gatekeeperd 및 main/hal class에 영향. |
| apexd / apexd-bootstrap | **서비스 자체는 이 제한된 범위에서 필수로 입증되지 않음**. 실제 `apexd.rc:1–20`은 disabled, root, SYS_ADMIN 및 실패 시 reboot를 선언한다. | 기존 SSAL은 APEX payload를 RO로 준비하고 linkerconfig를 생성하지만 정식 activation·서명 검증을 대체하지 않는다. 필요한 runtime APEX/링커 파일은 필요; 완전성 unknown. |
| logd | **필수로 입증되지 않음**. `logd.rc:1–12`는 `/proc/kmsg`, `/dev/kmsg`, SYSLOG/AUDIT_CONTROL을 요구한다. | Host 커널 로그를 넘기지 않을 대체 logging 경로 필요. 로깅 대체 시 실제 바이너리 호환성은 unknown. |
| hwservicemanager, vndservicemanager, statsd 및 다른 HAL/프레임워크 서비스 | **이 단계의 직접 필수성 미입증**. system_ext의 hwservicemanager rc와 statsd APEX rc는 별도 서비스 선언이다. | 추가 등록이나 전체 부팅에서 필요할 수 있어 전체적으로 불필요하다고 판단하지 않는다. 인증 HAL과 Lock Compatibility v5는 조사·변경 대상에서 제외. |

## second_stage와 Host 보호

[Android 16 second_stage](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/init/init.cpp)는 PropertyInit 전 `/proc/1/oom_score_adj`를 직접 쓰며, 이후 mount, SELinux restorecon, property socket, vendor overlay, cgroup 설정과 rc 로딩, `early-init`/`init`/`late-init` 트리거를 진행한다. 현재 기기에서 PID 및 IPC namespace `unshare`는 EINVAL이었고 Host PID 1이 그대로 보인다. 원인이 커널 설정인지 다른 제한인지는 확정하지 않았다. 새 mount namespace나 chroot만으로 PID 1을 Guest init으로 만들 수 없다. 빈 proc 대조군은 Host 경로를 가리지만 기능하는 Android proc가 아니다.

실제 GSI `init.rc:15–22, 325–340`은 `/proc/sys/kernel`과 VM 설정에 쓰고, 266–280행은 configfs/Binder mount와 symlink를 다룬다. 설정 값이 우연히 같거나 쓰기가 거부될 가능성은 안전성 증명이 아니다. rc의 exec·mount·setprop 및 service restart는 프로세스와 공유 커널에 영향을 줄 수 있다. `sys.powerctl`, 치명적 서비스, apexd의 `reboot_on_failure` 및 init shutdown 경로는 재부팅 위험이다. 소켓·mount만 격리해도 커널 전역 설정과 권한 있는 FD, Host PID 접근이 자동 차단되지 않는다. Guest PID 1 부재 시 원본 init의 기능적 동작도 보장되지 않는다. 따라서 현재 조건에서 원본 second_stage 실행은 금지 상태로 유지한다.

## Property 초기화와 격리 조건

AOSP `PropertyInit`은 contexts를 병합·직렬화한 뒤 `/dev/__properties__` 영역을 만들고, DT → kernel cmdline → bootconfig, boot property export, partition build.prop 및 파생값 순으로 초기화한다. build.prop들은 일단 map으로 합쳐 뒤에 읽은 partition 값이 우선하며 그 후 기록한다. 이미 기록된 `ro.*`는 write-once다. 따라서 Guest 값과 허용할 boot 정보, 중복 우선순위를 **첫 기록 전** 결정해야 한다. Host 커널 cmdline/DT/bootconfig를 그대로 읽으면 Host 값이 Guest에 유입될 수 있다. persist 값은 별도 후속 로딩과 Guest `/data/property`를 사용해야 한다. 정확한 전체 Guest 값과 접근 정책은 미확정이다. [AOSP property_service.cpp](https://android.googlesource.com/platform/system/core/+/android-16.0.0_r2/init/property_service.cpp)

전제는 새 Guest 전용 tmpfs의 `/dev/__properties__` 및 `/dev/socket`, Guest 소유 `property_info`/serial/개별 context 영역, Guest userdata의 persist 저장소다. 일반 `property_service`와 권한이 다른 `property_service_for_system` 양쪽을 다뤄야 한다. 직렬화는 platform, system_ext, vendor, product, odm contexts를 읽으며 이름·타입·접근 권한의 충돌 및 실제 정책의 유효성을 확인해야 한다. Host와 다른 dev/inode 확인만으로 충분하지 않다: 상속 FD, `/proc/<pid>/root`, 대체 bind 경로, 추상 socket 및 공유 mount를 차단하고 대상 자격에서 음성 검증해야 한다. `ctl.*`는 Guest 감독자에만 연결하거나 거부하고 `sys.powerctl`은 Host 종료·재부팅 경로에 전달하지 않아야 한다. SELinux 권한 검사는 socket DAC의 대체물이 아니다.

기존 시험에서 Host property area 제거와 경로 차단은 **시험 뷰**에서만 통과했다. 기존 composed root에서는 Host property area와 kmsg가 공유됐고, 빈 proc 뷰는 Guest property 생성 성공의 증거가 아니다. 실제 서비스 도메인에서의 영역 생성, mmap, SELinux 검사, persist 순서, 통신과 우회 차단은 미검증이다.

## 최소 파일시스템 및 커널 의존성

- `/proc`: 정확한 서비스·라이브러리의 self 정보와 필요한 proc 항목은 추가 식별이 필요하다. Host PID 1 및 타 프로세스 root/FD, 쓰기 가능한 전역 sysctl은 노출하지 않아야 한다. 빈 proc를 완성된 대안으로 취급하지 않는다.
- `/sys` 및 cgroup: 원본 init의 sysfs/커널 전역 쓰기는 허용할 수 없다. servicemanager의 `ProcessCapacityHigh`는 Guest task profile에서 `JoinCgroup(cpuset, foreground)`로 해석됐지만 독립 목적지는 준비되지 않았다. Host cgroup/BPF 메타데이터 노출도 기존 시험에서 관찰됐다. 최소 읽기 항목과 안전한 Guest 소유 cgroup 또는 명시적 대체 정책은 unknown.
- `/dev/socket`, `/dev`: 전용 socket 디렉터리와 property socket, 독립 Binder 및 최소 장치가 필요하다. Host Binder fallback, kmsg와 상속 FD를 차단한다. 기존 private binderfs의 `binderfs` 라벨에 대한 servicemanager AV는 거부됐고, 실제 대상 도메인 실행은 검증되지 않았다.
- `/apex`, `/linkerconfig`: Guest runtime APEX와 Guest 링커 설정 및 실제 필요한 라이브러리를 RO 제공해야 한다. 기존 생성 linkerconfig 파일 라벨 시험은 제한적으로 통과했으나 전체 loader 의존성·정식 APEX activation은 검증되지 않았다.

## 기존 37개 invalid context 판정

기준은 저장된 2,686개 context 중 EINVAL 37개다. 원본의 전체 contexts와 AOSP 표준 property 구현을 그대로 사용할 경우, 다음 **12개는 기능 사용 여부와 무관하게 property area 초기화의 직접 차단 후보**다: `custom_version_prop`, `legal_url_prop`, `native_binder_stats_prop`, `odm_cast_prop`, `persist_sysui_builder_extras_prop`, `persist_sysui_ranking_update_prop`, `recovery_update_prop`, `sf_hs_mode_prop`, `usb_uvc_config_prop`, `vendor_hwc_prop`, `vendor_persist_nfc_prop`, `xtra_control_prop`.

근거: 실제 GSI `plat_property_contexts:348,1838–1839`, `system_ext_property_contexts:28–81`에 이 12개가 있다. [AOSP bionic contexts_serialized.cpp](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/system_properties/contexts_serialized.cpp)는 직렬화된 모든 context의 writable area를 열고, [prop_area.cpp](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/system_properties/prop_area.cpp)는 각 SELinux 라벨을 `fsetxattr`한다. [system_property_api.cpp](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/bionic/system_property_api.cpp)는 라벨 설정 하나라도 실패하면 초기화를 실패로 반환하며 init은 fatal 처리한다. 이는 AOSP 코드 기반의 조건부 결론이며 정확한 GSI 바이너리의 구현과 실제 파일시스템 라벨 동작은 미검증이다. 특히 `custom_version_prop`은 실제 product `etc/build.prop:49,92–95`의 `ro.lineage.*`와 연결된다. 다른 11개의 **기능적 필수성**은 unknown이다. 필터링 또는 별도 구현을 택하면 이 12개 모두가 반드시 필요한지는 다시 검증해야 하며, 임의로 default 라벨로 합치는 것은 접근 제어 의미를 바꾼다.

`u:r:ssal_property:s0`는 기존 SSAL 서비스 계약이 지정한 도메인이고 현재 invalid다. 독립 SSAL 구현에서 그 계약을 유지할 때만 필요한 **조건부 차단**이며, 원본 init 내 property 기능의 필수 도메인이라는 증거는 없다. 나머지 24개는 이 단계에서 필요하거나 불필요하다는 직접 근거가 부족해 **unknown**으로 둔다. 목록은 [기존 결과 JSON](selinux-check-device-20261031.json)의 invalid_contexts를 따른다. 이 판정은 새 정책·권한 추가의 승인이나 안전성 결론이 아니다.

## 다음 단일 실행 가능 검증 단계

**오프라인 property 초기화 입력 검증기 한 개를 작성·실행한다.** 등록 GSI의 system/system_ext/product contexts와 build.prop, 이미 저장된 vendor/odm contexts 및 기존 37개 결과를 읽어 Android 16의 context 병합·중복/타입·partition 우선순위를 모사하고, 12개 invalid context와 초기 `ro.*` 후보의 출처를 결정적으로 출력한다. 합성 fixture로 중복, write-once, invalid context를 검증하며 실제 이미지·모듈·정책을 수정하지 않는다. 저장된 vendor/odm 입력이 없거나 버전이 불명확하면 해당 부분을 unknown으로 출력한다. 이 검사는 영역 생성·SELinux 라벨 적용·서비스 실행 또는 격리 통과를 증명하지 않으며, 그 결과를 바탕으로 별도의 안전한 구현 설계를 할 수 있다.

