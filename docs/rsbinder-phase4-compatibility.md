# SSAL rsbinder Phase 4 호환성 조사

- 조사일: 2026-11-04
- 대상: LineageOS 23.2 / Android 16 Guest의 Private Binder 기반 `installd`, `artd` 의존성
- 결과: 호환성 표의 실기기 검증은 SM-S937N Android 17 Host 안의 Android 16 / SDK 36 Guest 이미지에서 수행했다. Android 16 Host 단말 결과로 일반화하지 않는다.
- 범위 제한: 실제 Guest `installd`와 `artd`는 실행하지 않았다. Host 서비스도 종료하거나 재시작하지 않았다.

## 요약

Phase 2와 3에서 고정한 `rsbinder 0.12.0`의 `android_16_plus` 설정은 Android 16 Guest의 Private Binder에서 실제 `IServiceManager.checkService2`, descriptor 조회, 동기 AIDL 호출, Binder callback 객체 전달, death 알림과 재연결까지 동작했다. Android Binder protocol 8, Guest SDK 36, SELinux Enforcing에서 확인했다.

이 결과는 `IInstalld` 또는 `IArtd` 메서드 호환성을 증명하지 않는다. 두 서비스는 userdata와 ART artifact를 변경하며, 실제 Guest 인스턴스 실행은 Phase 4 계획상 금지되어 있다. 이 단계에서는 Binder 구현을 추가하지 않았다. 실제 서비스 호출, FD 전달, Java framework 호출, 대형 Parcel, oneway 경로에서 확인된 결함이 없기 때문이다.

## Binder 및 ServiceManager 호환성 표

상태는 `실기기 검증`, `코드 존재·미검증`, `미검증`, `현 인터페이스에서 미사용`으로 구분한다. 코드가 있다는 사실은 실기기 호환성 증명으로 계산하지 않았다.

| 기능 | Android 16 요구사항과 근거 | 현재 지원 / 구현 위치 | 실기기 검증 | 후속 조치 |
|---|---|---|---|---|
| 동기 Binder transaction 및 Parcel | `IServiceManager.checkService2`와 AIDL 메서드 호출·응답이 필요하다. | `rsbinder` AIDL Proxy/Stub 및 `Parcel`; Phase 2 probe source removed, [Phase 3 service](../tools/rsbinder/src/android.rs) | 통과. `BBinder` descriptor, `add(17,25)=42`, `echo` 응답 | 사용 메서드별 타입·오류를 다음 단계에서 검증 |
| oneway | Android 16 Binder는 oneway transaction을 제공한다. 조사한 `IInstalld`와 `IArtd` AIDL 선언에는 oneway 메서드가 없다. | rsbinder 의존성에는 `FLAG_ONEWAY` 경로가 있으나 SSAL 실험에서 쓴 적은 없다. | 미검증 | Phase 5에서 호출할 메서드에 oneway가 없으면 구현 범위에 넣지 않는다. 추가 interface를 사용할 때만 별도 시험 |
| Binder 객체 및 handle 전달 | AIDL callback/cancellation Binder를 인수로 주고받을 수 있어야 한다. | `Strong<dyn IPhase3Callback>` 및 생성된 AIDL Proxy/Stub 사용 | 통과. 동기 callback 객체 전달과 두 번 호출 성공 | `IArtd`의 callback/cancellation 사용 지점을 실제 메서드 선정 뒤 확인 |
| File Descriptor 전달 | `IInstalld.createFsveritySetupAuthToken`은 `ParcelFileDescriptor`를 받고, `IArtd`의 dexopt 계열은 로그 FD를 받을 수 있다. | rsbinder의 Parcel/AIDL 경로는 의존성으로 포함되어 있으나 SSAL 실험 코드에는 FD 메서드가 없다. | 미검증 | FD 소유권·복제·닫힘·취소 동작을 격리된 AIDL 시험으로 확인하기 전에는 대상 메서드 호출 금지 |
| Large Transaction 및 Binder buffer | Binder transaction 크기와 비동기 버퍼는 커널 한도에 묶인다. AIDL에는 경로/배열/메타데이터가 있다. | 별도 크기 제한 코드는 추가하지 않았다. | 미검증. 작은 문자열과 정수만 시험 | 큰 파일 본문은 Binder로 보내지 말고 파일/FD 계약을 사용한다. 실제 metadata 크기만 필요한 경우 별도 경계 시험 |
| 상태 코드, 예외, 오류 복구 | 서비스 없음, 원격 오류, Binder death를 구분해야 한다. | rsbinder 상태 코드 및 death API; [Phase 3 client](../tools/rsbinder/src/android.rs) | 부분 통과. 미등록 서비스의 `NameNotFound`, 죽은 객체 오류, death 통지 확인. 전체 Android 서비스 예외 호환성은 미검증 | 실제 target AIDL 오류 매핑은 메서드 시험에서 확인 |
| Death recipient 및 객체 수명 | 서비스 재시작 시 stale Binder 참조를 버리고 재조회해야 한다. | `link_to_death`, `DeathRecipient`, ServiceManager 재조회 | 통과. 서버 종료, 서비스 미등록, 재시작 후 재연결 | 서비스별 재등록·lazy lifecycle은 별도 확인 |
| Binder thread pool | Native 서비스는 Binder 요청을 처리할 thread pool이 필요하다. | Phase 3 서버에서 `ProcessState::start_thread_pool()` 및 join 사용 | 기본 동기 요청·callback은 통과. 동시성/부하/장시간 요청 미검증 | 초기 Guest 서비스는 낮은 동시성으로 시작하고 별도 부하 시험 |
| Calling UID/PID 및 SELinux context | 커널 Binder caller identity와 SELinux 정책이 실제 서비스 경계다. | 커널 UID/GID 및 SELinux 프로세스 context를 runner가 기록. `rsbinder::get_calling_uid/pid/sid` 사용 코드는 없음 | 프로세스 identity와 SELinux Enforcing은 확인. AIDL 처리 중 `getCallingUid/Pid/Sid` 전달 의미는 미검증 | Guest `system_server`→Guest 서비스 호출 identity와 정책을 서비스별로 시험 |
| `addService` / `checkService` | 서비스 등록·조회에 Android 16 ServiceManager transaction 규약을 사용한다. | Phase 3의 `hub::add_service`, `hub::default().check_interface`; Phase 2의 Android 16 `IServiceManager.checkService2` | 통과. C++ Test B, Rust 서비스 등록·조회, descriptor 확인 | 대상 서비스 호출 권한은 별도. Test B의 synthetic service label을 재사용하지 않는다. |
| `getService`, `listServices`, 알림 | 대기 조회, 목록, 등록 알림을 일부 Android 코드가 사용할 수 있다. | 대상 서비스 사용 코드 확인 전까지 추가하지 않음 | 미검증 | Guest framework의 실제 호출 지점 확인 뒤 필요한 API만 시험 |
| Lazy service 수명주기 | `artd`는 lazy AIDL service로 등록·시작된다. | Phase 3는 명시적으로 시작한 test server만 사용 | lazy 등록/시작/종료 미검증 | `artd` 실행은 Phase 5 이후 private ServiceManager와 init lifecycle을 갖춘 뒤 검증 |
| 서비스 이름·ServiceManager 접근 제어 | 서비스 이름은 SELinux service context와 find/add 권한에 연결된다. | 로컬 [`service_contexts`](../vendor/android_system_sepolicy/private/service_contexts), [`installd.te`](../vendor/android_system_sepolicy/private/installd.te), [`artd.te`](../vendor/android_system_sepolicy/private/artd.te) | synthetic `aidl_lazy_test_1`의 Host 비가시성 및 Guest 격리 통과. 대상 service context 정책은 정적으로 확인 | Host service registry에 Guest 이름을 등록하지 않는다. Guest framework caller의 최소 권한만 별도 검토 |
| Native C++ AIDL / Rust Binder | Android 16 native ServiceManager와 기존 C++ Binder endpoint가 호환되어야 한다. | `rsbinder 0.12.0`, `android_16_plus`; C++ `BBinder`와 Rust AIDL 시험 | 부분 통과. C++ `BBinder` descriptor 조회 및 synthetic Rust AIDL 통과 | 실제 `IInstalld`/`IArtd` AIDL 호출 미검증 |
| Java Binder | Android system_server의 Java client가 Binder endpoint를 사용한다. | 이 저장소 Phase 3에는 Java client나 Guest system_server가 없다. | 미검증 | Guest system_server 자체가 Private Binder/Guest ServiceManager를 고르는지 검증해야 함 |
| Stable AIDL / VINTF | Stable AIDL은 버전·stability 계약과 VINTF 선언이 필요한 interface에서만 적용한다. | `IInstalld`는 native AIDL source group을 쓰며 `aidl_interface` 안정 계약이 아니다. `IArtd`의 `artd-aidl`은 `unstable: true`; 둘은 내부 platform service다. | target interface stability/VINTF 실행 확인은 미검증 | Stable AIDL 변환은 필요성 증거가 없다. 서비스가 요청하는 VINTF/HAL 의존성은 Guest image에서 별도 확인 |

## 대상 서비스 의존성

### `installd`

- Init은 `/system/bin/installd`를 `class main`, `user root`로 시작하고 여러 capability를 부여한다. `early-boot`에서 `/config/sdcardfs/extensions/...`도 만든다. 따라서 mount namespace가 Guest `/data`와 `/config`를 확실히 격리하지 않으면 단순 service registration 시험도 Host 범위 변경 위험이 있다. [Android 16 `installd.rc`](https://android.googlesource.com/platform/frameworks/native/+/android16-release/cmds/installd/installd.rc)
- 서비스 이름은 `installd`; interface는 hidden `android.os.IInstalld`다. AIDL은 user/app data 생성·삭제, restorecon, dexopt, profile, package 경로와 artifact 변경 메서드를 포함한다. FD 인수도 있다. 서버는 C++ `libbinder`의 `BinderService` 경로로 등록된다. [AIDL](https://android.googlesource.com/platform/frameworks/native/+/android16-release/cmds/installd/binder/android/os/IInstalld.aidl), [service implementation](https://android.googlesource.com/platform/frameworks/native/+/android16-release/cmds/installd/InstalldNativeService.cpp), [Android.bp](https://android.googlesource.com/platform/frameworks/native/+/android16-release/cmds/installd/Android.bp)
- 로컬 policy에서 service label은 `installd_service`다. `system_server.te`는 `system_server`의 find/call을 허용하고 `installd.te`의 neverallow는 다른 domain의 find/call을 막는다. `installd`는 다시 `system_server`를 호출한다. Shell/`ksu`가 `installd`를 직접 호출하는 형태를 Phase 5의 검증으로 삼으면 안 된다. [local service_contexts](../vendor/android_system_sepolicy/private/service_contexts), [installd.te](../vendor/android_system_sepolicy/private/installd.te), [system_server.te](../vendor/android_system_sepolicy/private/system_server.te)
- Guest 데이터 변경 가능 범위는 `/data/user*`, `/data/app*`, `/data/misc*`, `/data/dalvik-cache`, profiles 및 volume 경로다. Host와 같은 커널을 쓰더라도 경로별 mount/FD 전달로 경계를 넘지 않는다는 보장은 아직 없다.

### `artd`

- `/apex/com.android.art/bin/artd`는 `interface aidl artd`, `disabled`, `oneshot`, `user/group artd`로 선언된 lazy service다. 별도 `artd_pre_reboot`는 chroot 실행과 추가 capability를 사용한다. [Android 16 `art.rc`](https://android.googlesource.com/platform/art/+/android16-release/build/apex/art.rc), [artd README](https://android.googlesource.com/platform/art/+/android16-release/artd/README.md)
- Interface는 hidden `com.android.server.art.IArtd`다. `isAlive` 외에 profile, dexopt artifact, 삭제·정리 메서드가 있고, 일부 메서드는 `ParcelFileDescriptor`를 인수로 쓴다. AIDL build target은 `artd-aidl`, `unstable: true`이며 Java/NDK backends를 만든다. 서버는 NDK Binder thread pool을 사용하고 Java `system_server` 쪽 `ArtdRefCache`가 death 후 참조를 다시 얻는다. [AIDL](https://android.googlesource.com/platform/art/+/android16-release/artd/binder/com/android/server/art/IArtd.aidl), [AIDL build](https://android.googlesource.com/platform/art/+/android16-release/artd/binder/Android.bp), [server](https://android.googlesource.com/platform/art/+/android16-release/artd/artd_main.cc), [client cache](https://android.googlesource.com/platform/art/+/android16-release/libartservice/service/java/com/android/server/art/ArtdRefCache.java)
- artd는 Guest ART APEX, Guest properties/boot class path와 `/data/dalvik-cache`, app dex 및 profile 경로에 의존한다. dex2oat 등 자식 실행은 file descriptor와 파일 경로를 전달한다. service label은 `artd_service`이며 로컬 policy의 `system_server`만 service를 찾도록 허용한다. [local service_contexts](../vendor/android_system_sepolicy/private/service_contexts), [artd.te](../vendor/android_system_sepolicy/private/artd.te), [system_server.te](../vendor/android_system_sepolicy/private/system_server.te)
- artd의 lazy 시작/죽음 복구와 `artd_pre_reboot` chroot는 Guest에서 실행하지 않았다. Host의 lazy `artd`는 Phase 4 동안 시작하거나 종료하지 않았다.

## Phase 5 진입 조건

아래 조건을 실행 증거로 남긴 후 별도 Phase에서만 실제 Guest 서비스를 시작한다.

1. Guest `/data`, `/mnt/expand`, `/config`, ART APEX data/profile/artifact 경로가 Guest 전용 mount namespace에 있고 Host 경로로 alias되지 않는지 확인한다. symlink, bind mount, inherited FD, `/proc` magic link를 함께 검사한다.
2. Guest Private Binder device와 ServiceManager가 service process 및 모든 client에서 동일하게 선택되는지 확인한다. `/dev/binder` 열기 실패가 Host Binder fallback으로 이어지지 않도록 한다.
3. Guest property service, property area, `ANDROID_DATA`, boot class path 및 `com.android.art` APEX가 독립적으로 준비되어야 한다. `ctl.*` 요청이 Host init으로 전달되지 않아야 한다.
4. Guest `system_server`가 예상 SELinux context와 UID로 실행되고, 대상 service의 find/call 권한이 Guest 정책에서만 필요한 최소 범위로 허용되는지 확인한다. Phase 3 시험용 `aidl_lazy_test_server → shell` runtime allow를 영구/Guest 서비스 정책으로 복사하지 않는다.
5. `installd`와 `artd`의 입력·출력 경로, file descriptor, child process, pre-reboot chroot를 service별로 제한하고 증명한다. 먼저 disposable Guest userdata에서 선택한 읽기 전용/작은 테스트 메서드만 실행한 뒤 변경 메서드는 별도 승인된 시나리오로 시험한다.
6. Host의 `installd`, `artd`, ServiceManager, Binder registry 및 userdata에 대한 전후 snapshot이 동일해야 한다. Host daemon은 종료/재시작하지 않는다.

