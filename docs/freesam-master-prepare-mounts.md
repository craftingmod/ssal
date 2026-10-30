# FreeSam `master_prepare.sh` 마운트 목록

이 문서는 [`master_prepare.sh`](../FreeSam/app/src/main/assets/master_prepare.sh)의 **실행 가능한 마운트 명령 전체**를 정적으로 정리한 것이다. 조건, 반복문, 함수 및 생성된 헬퍼 스크립트의 명령을 포함한다. 실제 기기의 mountinfo나 모든 명령의 성공을 확인한 목록은 아니다. 명령 다수는 `|| true` 등으로 실패를 무시한다. `mount` 출력 조회, `dumpsys mount`, 주석은 마운트 생성 명령이 아니므로 제외했다. `master_inner.sh`, `switch_to_lineage.sh` 등의 별도 파일은 범위 밖이다.

## 경로와 실행 맥락

- `STAGE` = `/data/local/tmp/lineage_stage`; `ROOTFS` = `$STAGE/rootfs`.
- 아래 `$ROOTFS/...`는 준비 시점의 staging 경로다. 이후 다른 스크립트의 `pivot_root` 이후에만 게스트 경로가 된다.
- 일반 명령은 이 스크립트가 실행된 프로세스의 mount namespace에서 작동한다. 스크립트 자체는 새 namespace를 생성하지 않는다. MediaProvider 헬퍼의 `nsenter`는 별도의 대상 프로세스 namespace에서 실행된다.
- bind 명령은 별도의 `ro` 재마운트를 지정하지 않는다. 최종 읽기 가능 여부는 원본 마운트와 런타임 상태에 따라 확인해야 한다.
- 목적은 소스의 의도를 설명하기 위한 잠정 분류다. **필수**는 FreeSam의 준비 절차 기준이며 SSAL에서 필수라는 검증 결과가 아니다. **호환성**은 호스트와 게스트 구성의 연결, **기기별 우회**는 특정 문제 대응을 뜻한다.

## 시스템 이미지와 기본 마운트

| 위치 | 원본 → 대상 | 종류·옵션 | 조건 및 목적 |
|---|---|---|---|
| [L35–56](../FreeSam/app/src/main/assets/master_prepare.sh#L35) | `$STAGE/system.raw`를 연결한 `$LOOP` → `$ROOTFS` | loop-backed ext4, `ro` | 기존 유효 rootfs mount가 없으면 연결. 필수. |
| [L64](../FreeSam/app/src/main/assets/master_prepare.sh#L64) | `proc` → `$ROOTFS/proc` | proc | 대상이 마운트되어 있지 않을 때. 필수. |
| [L65](../FreeSam/app/src/main/assets/master_prepare.sh#L65) | `sysfs` → `$ROOTFS/sys` | sysfs | 대상이 마운트되어 있지 않을 때. 필수 후보. |
| [L67–69](../FreeSam/app/src/main/assets/master_prepare.sh#L67) | `binder` → `/dev/binderfs` | binderfs (`-t binder`) | `/dev/binderfs/binder`가 없을 때. staging 밖의 `/dev/binderfs`에 실행하며 실패를 무시한다. 호환성. |
| [L74–76](../FreeSam/app/src/main/assets/master_prepare.sh#L74) | `/dev` → `$ROOTFS/dev` | 재귀 bind | 대상이 마운트되어 있지 않을 때. 이후 해당 트리를 재귀 private으로 변경. 호환성; 호스트 장치 노출 범위 검토 필요. |
| [L79](../FreeSam/app/src/main/assets/master_prepare.sh#L79) | `/linkerconfig` → `$ROOTFS/linkerconfig` | 재귀 bind | 대상이 마운트되어 있지 않을 때. 호환성. |
| [L80–82](../FreeSam/app/src/main/assets/master_prepare.sh#L80) | `/vendor`, `/odm`, `/vendor_dlkm` → 각각 `$ROOTFS/vendor`, `$ROOTFS/odm`, `$ROOTFS/vendor_dlkm` | bind | 각각 대상이 마운트되어 있지 않을 때. 호환성. |
| [L89–90](../FreeSam/app/src/main/assets/master_prepare.sh#L89) | `/system_ext/apex` → `$ROOTFS/system_ext/apex` | bind | 호스트 원본 디렉터리가 있고 대상이 미마운트일 때. 호스트 apexd가 보고하는 경로와 맞추기 위한 호환성. |
| [L92](../FreeSam/app/src/main/assets/master_prepare.sh#L92) | `/mnt` → `$ROOTFS/mnt` | 재귀 bind | 대상이 미마운트일 때. 호환성; 하위 호스트 mount가 함께 노출될 수 있다. |

## 파일 패치 bind

다음 항목은 대응하는 `$STAGE` 파일이 있으면 기존 대상 mount를 lazy unmount한 후 bind한다. 원본 파일이 없으면 건너뛴다. [L93–125](../FreeSam/app/src/main/assets/master_prepare.sh#L93)

| 위치 | 원본 → 대상 | 목적 |
|---|---|---|
| [L95](../FreeSam/app/src/main/assets/master_prepare.sh#L95) | `$STAGE/services_patched.jar` → `$ROOTFS/system/framework/services.jar` | 기기별 우회 |
| [L100](../FreeSam/app/src/main/assets/master_prepare.sh#L100) | `$STAGE/framework_patched.jar` → `$ROOTFS/system/framework/framework.jar` | 기기별 우회 |
| [L105](../FreeSam/app/src/main/assets/master_prepare.sh#L105) | `$STAGE/libaudio_aidl_conversion_common_cpp_patched.so` → `$ROOTFS/system/lib64/libaudio_aidl_conversion_common_cpp.so` | 오디오 호환성 우회 |
| [L110](../FreeSam/app/src/main/assets/master_prepare.sh#L110) | `$STAGE/libaudioclient_aidl_conversion_patched.so` → `$ROOTFS/system/lib64/libaudioclient_aidl_conversion.so` | 오디오 호환성 우회 |
| [L115](../FreeSam/app/src/main/assets/master_prepare.sh#L115) | `$STAGE/framework-res_patched.apk` → `$ROOTFS/system/framework/framework-res.apk` | 기기별 우회 |
| [L124](../FreeSam/app/src/main/assets/master_prepare.sh#L124) | `$STAGE/PermissionController_patched.apk` → `$ROOTFS/apex/com.android.permission`에서 찾은 첫 `PermissionController.apk` | 파일과 검색 결과가 있을 때. 기기별 권한 호환성 우회. APEX 준비 후 별도로 재시도한다. |

## userdata 및 호스트 데이터 브리지

| 위치 | 원본 → 대상 | 조건 및 목적 |
|---|---|---|
| [L295–300](../FreeSam/app/src/main/assets/master_prepare.sh#L295) | `$STAGE/data/$d` → `/data/$d`, `$d`는 `app`, `app-staging`, `user`, `user_de`, `dalvik-cache`, `misc/profiles` | 각 호스트 대상 디렉터리가 있고 대상이 미마운트일 때 bind. 호스트 `installd`·`artd`가 게스트 데이터 트리에 쓰도록 하는 호환성 우회. **게스트에서 호스트로 향하는 역방향 bind다.** |
| [L303](../FreeSam/app/src/main/assets/master_prepare.sh#L303) | `$STAGE/data` → `$ROOTFS/data` | 대상이 미마운트일 때 bind. 게스트 userdata 연결. 필수 후보. |
| [L304](../FreeSam/app/src/main/assets/master_prepare.sh#L304) | `/data/adb` → `$ROOTFS/data/adb` | 대상이 미마운트일 때 bind. 호스트 데이터 공유; SSAL 제외 대상. |
| [L305](../FreeSam/app/src/main/assets/master_prepare.sh#L305) | `/data/apex` → `$ROOTFS/data/apex` | 대상이 미마운트일 때 bind. 호스트 APEX 데이터 공유; SSAL 제외 대상. |
| [L307](../FreeSam/app/src/main/assets/master_prepare.sh#L307) | `/data/media` → `$ROOTFS/data/media` | 대상이 미마운트일 때 bind; 실패 무시. 호스트 미디어 공유; SSAL 제외 대상. |

## tmpfs와 APEX

| 위치 | 원본 → 대상 | 조건 및 목적 |
|---|---|---|
| [L1425–1431](../FreeSam/app/src/main/assets/master_prepare.sh#L1425) | `tmpfs` → `$ROOTFS/system/xbin` | 대상이 미마운트일 때 tmpfs를 마운트하고 그 안에 `su`를 복사. KernelSU 접근 호환성. |
| [L1434–1455](../FreeSam/app/src/main/assets/master_prepare.sh#L1434) | `tmpfs` → `$ROOTFS/apex` | 기존 APEX mount 정리 후 새 tmpfs 생성. 실패 시 중단. APEX 구성에 필요한 준비 단계. |
| [L1506–1578](../FreeSam/app/src/main/assets/master_prepare.sh#L1506) | `$STAGE/${NAME}_payload.img`를 연결한 `$LOOP` → `$ROOTFS/apex/$TARGET` | `mount_payload` 함수에서 ext4 `ro`. 캐시 이미지 검증 및 재추출, 실패 시 재시도; 노출된 `apex_manifest.pb` 확인. APEX 호환성. |
| [L1572–1576](../FreeSam/app/src/main/assets/master_prepare.sh#L1572) | 같은 `$LOOP` → `$ROOTFS/apex/${TARGET}@*` | 일치하는 버전 디렉터리 각각에 ext4 `ro`; 실패 무시. 버전 경로 호환성. |
| [L1668–1670](../FreeSam/app/src/main/assets/master_prepare.sh#L1668) | 호스트 `/system/apex` → `$ROOTFS/system/apex` | 호스트 디렉터리가 있고 대상이 미마운트일 때 bind. 게스트 payload 추출 후 호스트 apexd가 보고한 경로를 맞추기 위한 호환성. |
| [L1673–1700](../FreeSam/app/src/main/assets/master_prepare.sh#L1673) | 호스트 `/apex/*`의 각 디렉터리 → `$ROOTFS/apex/$base` | Samsung 이름과 GSI 자체가 제공하는 `com.android.*` 모듈을 제외하고, 대상이 미마운트일 때 bind. 실패 무시. 호스트 APEX 공유를 통한 호환성. |
| [L1712–1717](../FreeSam/app/src/main/assets/master_prepare.sh#L1712) | `$STAGE/PermissionController_patched.apk` → `$ROOTFS/apex/com.android.permission` 아래의 각 `PermissionController.apk` | 패치 파일이 있을 때 APEX 마운트 후 재적용. 기존 대상 lazy unmount 후 bind; 실패 무시. 기기별 권한 호환성 우회. |
| [L1736–1769](../FreeSam/app/src/main/assets/master_prepare.sh#L1736) | `$STAGE/extservices_permissions` (`$OV`) → `$ROOTFS/apex/com.android.extservices/etc/permissions` | 대상 디렉터리가 있고 해당 권한이 없으면 패치 디렉터리를 만들어 bind; 실패 무시. 권한 allowlist 호환성 우회. |
| [L1786–1802](../FreeSam/app/src/main/assets/master_prepare.sh#L1786) | `$STAGE/linkerconfig/ld.config.txt` → `$ROOTFS/linkerconfig/ld.config.txt` | 호스트 설정과 게스트 APEX 디렉터리가 있고 생성한 파일이 비어 있지 않을 때 bind; 실패 무시. 게스트 APEX 라이브러리 경로 보완. |

`mount_payload`의 [고정 호출](../FreeSam/app/src/main/assets/master_prepare.sh#L1581)은 `art`, `i18n`, `runtime`, `sdkext`, `nfcservices`, `tethering`, `crashrecovery`, `cellbroadcast`, `extservices`, `permission`, `wifi`, `appsearch`, `mediaprovider`, `adservices`, `rkpd`, `healthfitness`, `ondevicepersonalization`, `configinfrastructure`, `bt`다. 각각 대상은 `com.android.<이름>`이다. 이후 [GSI의 나머지 `.apex`·`.capex` 탐색](../FreeSam/app/src/main/assets/master_prepare.sh#L1607)과 [누락 재시도](../FreeSam/app/src/main/assets/master_prepare.sh#L1643)도 같은 함수를 호출한다. 따라서 마운트 수는 이미지 내용과 실제 디렉터리 상태에 따라 달라진다.

## 생성된 헬퍼에서 실행되는 마운트

아래 명령은 `master_prepare.sh`가 즉시 실행하는 것이 아니라 파일로 작성하는 셸 코드다. 헬퍼가 시작되고 조건이 충족될 때 MediaProvider의 mount namespace에 `nsenter`하여 실행한다. 경로는 **그 namespace에서 보이는 경로**이며, 단순히 모두 호스트 경로라고 단정할 수 없다.

| 헬퍼와 위치 | 원본 → 대상 | 조건 및 목적 |
|---|---|---|
| `ensure_app_storage.sh` [L1092–1100](../FreeSam/app/src/main/assets/master_prepare.sh#L1092) | `/data/media` → `/storage/emulated`, `/mnt/user/0/emulated` | MediaProvider PID와 marker 조건을 확인하고 각 대상의 inode가 원본과 다르면 bind. MediaProvider 저장소 뷰 보정; 기기별 우회. |
| `media_bind_loop.sh` [L1399–1407](../FreeSam/app/src/main/assets/master_prepare.sh#L1399) | `/data/media/0` → `/data/local/tmp/media_root/0` | MediaProvider가 살아 있고 재적용 조건을 만족할 때. 순회 가능한 미디어 루트 구성; 기기별 우회. |
| 같은 블록 | `/data/local/tmp/media_root` → `/data/media` | 위 staging 루트를 MediaProvider의 `/data/media`에 덮어 bind. 기기별 우회. |
| 같은 블록 | `/data/media` → `/storage/emulated` | 위 재구성 뒤 bind. 미디어 저장소 뷰 보정; 기기별 우회. |
| 같은 블록 | `/data/media` → `/mnt/user/0/emulated` | 위 재구성 뒤 bind. MediaProvider FUSE 경로 보정; 기기별 우회. |

## mount 전파 변경과 해제

다음은 새 파일시스템을 붙이는 명령은 아니지만 마운트 수명과 범위에 영향을 준다.

- [L72](../FreeSam/app/src/main/assets/master_prepare.sh#L72): `$ROOTFS`를 재귀 private으로 변경한다. 실패는 무시한다.
- [L76](../FreeSam/app/src/main/assets/master_prepare.sh#L76): 새로 재귀 bind한 `$ROOTFS/dev`를 재귀 private으로 변경한다.
- [L36–52](../FreeSam/app/src/main/assets/master_prepare.sh#L36): rootfs mount가 유효하지 않으면 lazy unmount를 반복하고 `system.raw`에 연결된 loop 장치를 분리한다.
- 파일 패치와 APEX 항목은 기존 대상 mount를 lazy unmount하고 교체한다. APEX 트리 정리는 [L1434–1450](../FreeSam/app/src/main/assets/master_prepare.sh#L1434)에 있다.

이 목록은 SSAL의 mount manifest가 아니다. 특히 호스트 `/data` 공유, 호스트 `/data`에 대한 역방향 bind, `/dev`·`/mnt` 재귀 bind, 호스트 APEX 공유는 SSAL의 격리 목표에 맞게 별도 판단해야 한다.
