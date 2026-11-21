# Guest 무잠금 호환성 계층

2026-10-31 기준 **오프라인 준비 코드와 검증 체계**다. 기본값은 `enabled=false`, 실제 실행 판정은 `blocked`, `launch_enabled=false`다. Framework 부팅이나 정책 적용은 수행하지 않았다.

## 구현 범위

`guest-compat/lockscreen/`에 Sysconfig XML, RRO 소스 및 manifest를 제공한다. `src/guest_lock_compat.rs`는 설정과 Guest 상대 경로의 주입 계획을 관리한다. 새 프로필 생성 시 `profile.json`에 아래 기본 설정 및 `guest_lock_compat_creation` 계약을 함께 기록한다. 기존 프로필에서 필드가 없으면 비활성화로 처리한다.

```json
{
  "guest_lock_compat": {
    "enabled": false,
    "disable_secure_lockscreen": true,
    "disable_weaver_on_unsecured_users": true,
    "require_fresh_userdata": true
  }
}
```

계획 생성은 신규 생성 계약과 비어 있는 독립 userdata를 모두 요구한다. `require_fresh_userdata=false`도 거부한다. 생성 당시 기록만으로 현재 userdata가 안전하다고 판단하지 않는다. 기존 인증 보호자 검색이나 마이그레이션은 구현하지 않으며, 이미 사용한 프로필은 자동 적용하지 않는다. 설정을 직접 바꿔도 `prepare::check`와 rootfs 준비 단계의 `runtime_gate()`가 활성화된 구성을 무조건 거부한다. 계약 필드는 보안 인증서가 아니다.

## 원본 GSI와 소스 대조

원본 이미지 SHA-256:

`7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`

읽기 전용 `debugfs`로 두 파일을 다시 추출하여 기존 분석 대상과 바이트 해시가 같은지 확인했다. 이미지 전체 해시도 재계산했다. `out/guest-lock-compat/evidence/image-binding.json`에 결과가 있다.

| 파일 | SHA-256 |
|---|---|
| services.jar | `81a66ff7d7e6a736332e34d602ab3c4e7e5adc06aec858b2fc19b220d7395b9d` |
| framework-res.apk | `ff0e7f3982c69a9d6ae87719c4bdd6539bcf118b637364850b340081c22b67f5` |

`docs/lock-research.md`, 기존 `analysis-report.md`와 `patch-plan.json`, Mount rootfs 코드와 Enforcing Binder 결과를 검토했다. Private Binder IPC 성공은 확인됐지만 service_contexts 9개의 부적합과 Vendor HAL 격리 미증명 조건을 유지한다. 자세한 근거는 `docs/enforcing-binder-device-20261031.md`와 `out/selinux-check/2026-10-31-offline-guest/analysis-report.md`에 있다.

調査ソース:

- [AOSP android16-release LockSettingsService](https://android.googlesource.com/platform/frameworks/base/+/android16-release/services/core/java/com/android/server/locksettings/LockSettingsService.java)
- [LineageOS 23.2 LockSettingsService](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/java/com/android/server/locksettings/LockSettingsService.java)
- [LineageOS SystemConfig](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/java/com/android/server/SystemConfig.java)
- [LineageOS SyntheticPasswordManager](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java)
- [LineageOS OverlayConfig](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/java/com/android/internal/content/om/OverlayConfig.java)
- [LineageOS idmap2 ResourceMapping](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/cmds/idmap2/libidmap2/ResourceMapping.cpp)
- [Android RRO 문서](https://source.android.com/docs/core/runtime/rros)

브랜치 소스와 실제 빌드가 동일한 커밋이라고 가정하지 않는다. 실제 GSI의 `services.jar`와 `framework.jar`를 JADX 1.5.3으로 별도 역분석했다. 소스와 분석 파일의 SHA-256은 `provenance.json`에 저장한다. `SystemConfig.readPermissionsFromXml`은 일반 역컴파일에 실패하여 fallback 명령 흐름에서 `unavailable-feature` → `readUnavailableFeature` dispatch를 확인했다. 역컴파일의 실패 stub을 Android 실행 코드로 오인하지 않는다.

## Sysconfig 판정

- 실제 SystemConfig는 `/system/etc/sysconfig`를 `ALLOW_ALL`로 읽는다.
- 모든 파티션 XML과 환경 기반 기능 계산을 끝낸 뒤 누적 `mUnavailableFeatures`를 제거한다. 따라서 다른 파티션의 같은 기능 선언도 최종 제거 대상이다.
- `removeFeature`는 컴파일 시 고정된 enabled 기능이면 제거를 생략한다. 하지만 이 이미지의 `RoSystemFeatures.maybeHasFeature()`는 항상 `null`이고 readonly enabled 목록도 비어 있어 해당 예외가 발견되지 않았다.
- 실제 LockSettingsService 생성자는 PackageManager에서 `android.software.secure_lock_screen`을 조회한다. 일반 `setLockCredential`은 기능이 없고 credential type이 NONE(-1)이 아니면 `UnsupportedOperationException`을 던진다. 토큰 경로는 `LocalService.setLockCredentialWithToken` 진입점에서 같은 제한을 적용한다. 내부 helper 자체에 모두 검사가 있는 것은 아니다.

이것은 **정적 검증**이다. `pm list features`에서 실제 제거되었는지, 일반·토큰 API에서 PIN/패턴/비밀번호가 거부되는지는 **not_run**이다. 기능 목록에서 제거되지 않으면 `blocked`로 유지해야 한다. 설정 UI 숨김은 검증 기준이 아니다.

## Weaver RRO 판정

실제 framework 리소스는 `bool/config_disableWeaverOnUnsecuredUsers`, ID `0x01110148`, 기본값 `false`다. 실제 LockSettingsService와 SyntheticPasswordManager는 `mContext.getResources().getBoolean(17891656)`을 읽는다. 무잠금 신규 LSKF protector에서 Weaver 사용을 줄이는 분기와 기존 protector 마이그레이션 분기가 모두 존재한다.

실제 ARSC에는 overlayable chunk가 0개다. 따라서 현재 후보 APK는 `targetPackage=android`, `targetName` 생략, `hasCode=false`, `isStatic=true`, priority 999로 빌드한다. overlayable 선언이 생기는 다른 GSI에는 그대로 적용할 수 없다. 대상에 선언이 전혀 없으면 idmap2 소스의 기본 정책은 preinstalled system/product/vendor/odm/oem 또는 signature/config-signature 등을 허용한다. 이는 실제 fulfilled policy나 서명이 검증됐다는 뜻은 아니다.

현재 GSI에는 `/system/overlay`가 없고 `/system/product/overlay`에는 APK 494개가 있다. 기존 Guest 경로 해석을 사용해 `/product/overlay/SSALWeaverOverlay.apk`를 후보로 잡았다. 해당 파티션의 `config/config.xml`은 없으므로 실제 OverlayConfig의 static → enabled/immutable fallback이 후보 조건이다. config가 추가되면 manifest의 static/priority만으로 활성화를 보장할 수 없다. 명시적 `enabled=true`, `mutable=false`와 구성 순서가 필요하며 기존 config를 자동 덮어쓰지 않는다.

494개 APK의 리소스와 manifest를 검사한 범위에서 대상 Weaver 리소스 및 SSAL 패키지 충돌은 0개였다. Host vendor/odm 등 다른 파티션과 런타임 property 조건, qualifier별 최종 우선순위는 미검증이다. priority 999만으로 모든 파티션보다 우선한다고 주장하지 않는다.

실제 `AssetManager.createSystemAssetsInZygoteLocked()`는 `OverlayConfig.getZygoteInstance().createImmutableFrameworkIdmapsInZygote()`의 결과를 시스템 assets에 추가한다. `ZygoteInit.preload` → `Resources.preloadResources` → `getSystem` 경로와 system_server fork 전 preload 경로를 확인했다. 따라서 첫 리소스 초기화 **이전**의 파일 노출이 필요하다. 지연 preload 등의 전체 실행 조건을 부팅 성공으로 판정하지 않았다. [공식 문서](https://source.android.com/docs/core/runtime/rros)도 `Resources.getSystem()`에는 android 대상 immutable overlay만 영향을 준다고 명시한다.

APK 링크와 컴파일된 manifest/boolean 검사는 성공했다. 제공 APK는 **unsigned 오프라인 산출물**이며 설치용 릴리스가 아니다. 서명된 APK의 scan, host-native idmap2 생성, 실제 immutable 활성화, system_server가 읽은 최종값은 **not_run**이다. 따라서 RRO 전체 판정은 **blocked**다. framework-res 직접 교체로 우회하지 않는다.

## Mount 통합과 정리

기존 `prepare::worker`의 `unshare(CLONE_NEWNS)`와 `/`의 `MS_REC|MS_PRIVATE`, `guest_path`, `Mounts` 역순 정리를 재사용한다. 새로운 VFS/NoMount 후킹은 추가하지 않았다.

`guest_mounts::prepare_lock_compat` 호출 위치는 읽기 전용 system 구성 직후, Guest 데이터와 서비스 준비 전이다. 비활성 상태는 주입 목록이 비어 기존 mount 동작을 유지한다. 활성화는 현재 gate에서 중단된다.

Sysconfig 주입 후보 구현은 기존 디렉터리 FD를 유지한 채 그 위치에 Guest namespace 전용 tmpfs를 구성하고, 원본 각 항목을 읽기 전용 bind한다. symlink는 링크 문자열을 보존한다. 그 뒤 신규 XML 하나만 추가한다. 원본 GSI 디렉터리에 파일을 생성하지 않는다. 같은 파일명은 내용이 같거나 dangling symlink여도 충돌로 중단하므로 중복 적용을 허용하지 않는다. 지원하지 않는 특수 파일, 예상과 다른 디렉터리 DAC, shared/slave 전파, 라벨 불일치와 mount 오류는 모두 중단한다.

실제 이미지의 sysconfig 디렉터리는 root:root 0755, `u:object_r:system_file:s0`다. 신규 파일은 root:root 0644와 같은 타입을 요구한다. 라벨은 새 namespace tmpfs의 context mount로 요청하고 새 파일에서 읽어 확인한다. Host 파일 `chcon`이나 정책 적용을 하지 않는다. 기존 파일은 원본 inode 및 라벨을 유지한다. enforcing 커널이 context mount를 허용하는지, system_server가 새 tmpfs와 파일을 읽는지는 **not_run**이다.

모든 신규 mount는 기존 `Mounts.paths`에 즉시 등록되며 실패 시에도 기존 cleanup 경로로 역순 unmount한다. 파일은 tmpfs 안에만 있어 unmount 시 사라진다. 기존 cleanup은 잔여 mount도 검사한다. 실제 주입 성공·중간 실패 rollback·Host mountinfo 불변성 검사는 이번에 실행하지 않았다. 오프라인 충돌 테스트는 mount 전에 실패시키고 원본 바이트, mount stack, 테스트 프로세스 mountinfo 불변을 확인했다. 이를 실기기 namespace 불변성 증거로 확장하지 않는다.

RRO는 주입 계획에 독립 항목으로 나오지만 현재 installer는 idmap/immutable 인증 전 명시적으로 거부한다. XML만 적용하고 전체 성공으로 처리하지 않는다. 새 기능의 gate를 해제하는 작업은 이번 범위에 포함되지 않는다.

## 검증 재실행

준비된 빌드 컨테이너에서 실행한다. 아래 명령은 기기에 접속하지 않는다.

```sh
cargo fmt --check
cargo test --locked --lib --bin ssald
python3 -m unittest discover -s scripts -p test_guest_lock_compat.py
python3 scripts/validate-guest-lock-compat.py \
  --aapt2 out/guest-lock-compat/aapt2-linux --test-rust
cargo build --locked --release --bin ssald --target aarch64-linux-android
```

검증기는 `--framework`, `--services`, `--out`을 받을 수 있다. 기본 실제 GSI 파일은 기존 `out/selinux-check/2026-10-31-guest-v3/`를 사용한다. AAPT2는 Apktool 2.11.1 jar에 포함된 Linux/Windows 바이너리를 작업 폴더로 추출해 사용했다. 생성한 Framework decode는 분석 복사본이며 GSI에 반영하지 않는다.

정적 코드 검증에는 `out/guest-lock-compat/evidence/`의 `SystemConfig-guest.java`, `SystemConfig-guest-fallback.java`, `RoSystemFeatures-guest.java`, 실제 services.jar 옆의 `LockSettingsService.java`가 필요하다. 없으면 해당 검사는 `blocked`다. 원본 Overlay 검사를 재현하려면 읽기 전용 debugfs `rdump /system/product/overlay` 결과를 evidence/product-overlay에 준비한다. 494개 수는 이 이미지에 한정된다. 이미지 해시와 각 원본 추출 해시를 image-binding.json에 보존한다. 단순히 증거 JSON을 가져오는 것은 새 이미지의 인증을 대신하지 않는다.

산출물은 `out/guest-lock-compat/`의 요청된 세 JSON과 report.md, XML, unsigned APK, compiled.zip, overlay-inventory.json, provenance.json, manifest.json 및 로그다. `out/`은 저장소의 기존 ignore 대상이며 배포 모듈에 자동 포함하지 않는다.

이번 검증에서는 Rust 27개와 Python 4개가 통과했다. Rust의 기존 권한 필요 테스트 3개는 ignored다. 호스트 대상 `cargo clippy --all-targets -- -D warnings`와 Android release 빌드는 성공했다. Android 대상 strict Clippy는 기존 `src/selinux_probe/enforcing.rs:317`와 `src/selinux_probe/runtime_preflight/environment.rs:85`의 동일 타입 cast 경고 2개로 실패했다. 이 작업과 무관한 코드는 변경하지 않았다. 상세 명령 결과는 `build-validation.json`과 로그에 기록한다.

## 인증 경계와 후속 조건

Sysconfig는 PIN/패턴/비밀번호 **설정 제한**, RRO는 **무잠금 사용자의 Weaver 의존성 축소**다. 둘 다 Host 인증 HAL을 완전히 차단하지 않는다. KeyMint, Keystore2와 FBE는 무잠금 사용자에게도 필요할 수 있다.

Gatekeeper, Weaver, KeyMint, StrongBox, TEE뿐 아니라 AuthSecret/RebootEscrow, Binder/HwBinder/VndBinder, vendor socket, 장치 노드 및 상속 FD 경로의 Host 접근 차단은 별도 필수 조건이다. Private Binder와 독립 `/data`만으로 해당 격리를 증명했다고 보지 않는다. `ro.gsid.image_running`을 설정하거나 `/metadata/gsi/dsu/booted`를 만들지 않으며 Guest Property Service도 새로 사용하지 않는다. KernelSU는 신뢰 기반 allowlist 제어 계층이며 KernelSU root 권한 자체는 이번 위협 모델 밖이다.

다음 오프라인 단계는 릴리스 서명·idmap2 검증과 다른 파티션의 최종 overlay 우선순위 분석이다. 그 이후 별도 승인된 namespace mount/SELinux 읽기 실험이 필요하다. **현재 실제 Guest Framework 실행은 준비되지 않았고 승인되지 않았다.** Host 시스템·userdata·정책·인증 HAL·설치 모듈과 데몬을 변경하거나 One UI 종료/재부팅을 수행하지 않았다.

## v3 검증 갱신

`out/guest-lock-compat-v3/report.md`와 각 JSON에 후속 결과를 기록했다. 원본 Guest의 Android 16 `idmap2`를 QEMU 사용자 모드로 실행해, overlayable 검사를 유지한 조건에서 `product|public` 정책을 지정했을 때 Weaver 리소스 ID 매핑을 확인했다. 이는 CLI에 입력한 Product 정책을 실제 기기의 사전 설치 분류가 충족한다는 증거가 아니다. Guest namespace 주입 및 Enforcing 접근은 아직 실행하지 않았고 별도 안전 probe가 필요하다. Framework 실행 gate는 해제하지 않았다.
