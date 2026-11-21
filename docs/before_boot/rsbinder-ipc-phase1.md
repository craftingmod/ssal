# rsbinder IPC Gateway — Phase 1 조사 보고서

- 조사일: 2026-11-03
- 범위: 공개 rsbinder API/소스, 저장소의 Binder·SELinux 실기기 보고서, Host/Guest 다중 Binder Context 가능성
- 저장소 정책: `vendor/` 소스는 읽지 않음
- 조사 방식: 정적 문서·소스 조사. 이 보고서 작성 중 빌드, 테스트, 실기기 rsbinder 실행은 하지 않음

## 요약

**Phase 1 조사 판정: PASS — 분리 프로세스 기반 설계가 가능하다.**

같은 프로세스에서 Host `/dev/binder`와 Guest Private Binder를 함께 초기화하는 방식은 공개 `ProcessState` API의 프로세스 단위 singleton 제약에 걸린다. Host와 Guest 각각 한 프로세스에서 하나의 Kernel Binder를 사용하고, 두 Gateway를 Android 16 RPC v2의 Unix Domain Socket으로 연결하는 구조가 적합하다.

공개 문서는 Android AArch64 빌드, Android 14~16, AIDL 생성 및 Android 16 RPC 호환성을 지원한다고 설명한다. 그러나 **삼성 기기에서 rsbinder 자체를 빌드·실행한 결과는 아직 없다.** 저장소의 기존 실기기 Binder 및 ServiceManager 시험은 C++ AOSP `libbinder`를 사용했으므로 이를 rsbinder 검증으로 간주하지 않는다.

2026-11-03 기준 docs.rs 최신판은 `rsbinder` 0.12.0, `rsbinder-aidl` 0.12.0, `rsbinder-tools` 0.11.0이다. rsbinder는 pre-1.0이므로 PoC는 버전을 고정해 재현성을 확보하는 편이 낫다. [rsbinder 0.12.0](https://docs.rs/crate/rsbinder/0.12.0), [rsbinder-aidl 0.12.0](https://docs.rs/crate/rsbinder-aidl/0.12.0), [rsbinder-tools 0.11.0](https://docs.rs/crate/rsbinder-tools/0.11.0)

## 조사 항목

### 1. Android AArch64 크로스 컴파일 — PASS (문서상)

rsbinder README는 `cargo-ndk`를 이용해 `aarch64-linux-android` 대상으로 API 29 이상에서 빌드하는 방법을 안내한다. 저장소의 `rust-toolchain.toml`도 Rust 1.90.0 및 `aarch64-linux-android` target을 선언한다. 문서상 빌드 경로는 맞지만 이 저장소의 rsbinder 의존성·NDK 조합으로 실제 빌드하지 않았다.

예시:

```sh
cargo ndk -t aarch64-linux-android --platform 29 build --release
```

출처: [rsbinder README](https://github.com/hiking90/rsbinder)

### 2. Android 14~16 호환성 — PASS (upstream 지원), 실기기 미검증

프로젝트 호환성 표는 Android 14~17을 지원하며, Android 14~16 범위에는 `android_14_plus` 설정이 포함된다. Android 15는 `android-15.0.0_r6`부터 ServiceManager transaction 번호가 바뀌므로 API level만으로 세부 프로토콜을 가정하면 안 된다. 여러 버전을 지원할 경우 upstream 문서가 안내하는 호환 feature 조합으로 실행 중 ServiceManager variant를 판별해야 한다.

Kernel Binder 초기화는 장치를 열고 `BINDER_VERSION`을 읽어 rsbinder의 컴파일된 Binder 프로토콜 버전과 일치하는지 검사한다. 저장소의 기존 Private Binder 보고서는 Samsung Android 16 기기에서 arm64 Binder protocol 8과 C++ `libbinder` IPC 성공을 기록한다. 이는 커널 측 선행 근거지만 **rsbinder runtime 호환성의 증명은 아니다.**

출처: [Android 호환성 및 feature 안내](https://moru.rs/rsbinder/android.html), [ProcessState 소스](https://docs.rs/rsbinder/0.12.0/src/rsbinder/process_state.rs.html), [저장소 Binder probe 결과](binder-probe.md)

### 3. `ProcessState::init()`의 장치 선택 및 singleton — FAIL (한 프로세스의 두 Kernel Binder Context)

`ProcessState::init(driver_name, max_threads)`는 명시한 Binder 장치를 여는 API다. 성공한 초기화 상태는 프로세스 내 singleton으로 보관되며, 후속 `init()` 호출은 다른 장치 경로를 넘겨도 기존 상태를 반환한다. 따라서 한 프로세스에서 Host Binder를 초기화한 뒤 Guest Binder로 바꾸거나 두 Context를 동시에 사용하는 방식은 지원되지 않는다.

`init_default()`는 `/dev/binderfs/binder`가 존재하면 그 경로를, 없으면 `/dev/binder`를 선택한다. 실험에서는 기본 경로 자동 선택에 맡기지 말고, 초기화 전에 예상 장치의 경로와 inode/rdev를 확인한 뒤 `init()`에 경로를 명시하는 것이 안전하다.

이 제한은 Kernel Binder의 두 Context에 관한 것이다. RPC 상태는 Kernel `ProcessState`와 별개여서, 프로세스가 Kernel Binder 하나와 `RpcSession` 또는 `RpcServer`를 함께 쓰는 것은 가능하다.

출처: [ProcessState API](https://docs.rs/rsbinder/0.12.0/rsbinder/struct.ProcessState.html), [ProcessState 소스](https://docs.rs/rsbinder/0.12.0/src/rsbinder/process_state.rs.html), [rsbinder 아키텍처](https://github.com/hiking90/rsbinder/blob/master/book/src/architecture.md)

### 4. `rsb_hub` 사용자 지정 Binder Device — PASS (옵션 존재), Android 용도 미검증

`rsb_hub --device <path>` 사용자 지정 장치 경로 옵션은 rsbinder 0.5.0 릴리스에 추가됐다. 현재 docs.rs에서 확인되는 `rsbinder-tools` 문서는 0.11.0이다. 이 옵션은 Hub 프로세스가 사용할 장치 경로를 지정할 수 있다는 근거다. Binder Device 생성 권한, 해당 Context Manager 등록 권한, Android SELinux 권한까지 보장하지 않는다.

Android 안내 문서는 Android의 기존 Binder 노드와 시스템 `servicemanager`를 사용하고 `rsb_hub`/`rsb_device`는 Linux용 도구로 다룬다. 따라서 `rsb_hub`의 Private Binder 사용은 PoC로 확인할 수 있지만, Guest Android의 공식 `servicemanager`를 완전히 대체한다고 가정해서는 안 된다.

출처: [v0.5.0 릴리스 노트](https://github.com/hiking90/rsbinder/releases/tag/v0.5.0), [Android 호환성 안내](https://moru.rs/rsbinder/android.html)

### 5. `rsbinder::bridge::Rewrap` — PASS (타입별 객체 래핑), 범용 중계 아님

`Rewrap<I>`는 원격 Binder 객체와 로컬 래퍼를 대응시켜, 같은 callback을 등록·해제할 때 같은 로컬 Binder 객체를 재사용한다. 사용 예는 인터페이스별로 `Rewrap::new(BnCallback::new_binder)`를 보관하는 방식이다. 테이블은 양쪽 객체의 약한 참조를 사용하고, 원격 Binder 사망 시 해당 대응을 정리한다.

이 API는 임의 transaction을 자동으로 전달하는 범용 Binder 터널이 아니다. 각 인터페이스와 callback에 맞는 AIDL 타입 및 `Bn*` 래퍼가 필요하며, 원격 객체가 사망하거나 래퍼 수명이 끝나면 다음 래핑에서 새 객체가 만들어질 수 있다. 또한 두 프로세스를 잇는 Gateway 구조상 Host 서비스에서 관측되는 Binder 호출 주체는 원래 Guest 호출자가 아니라 Host Gateway 프로세스다. 이는 별도 프로세스가 Host Binder 호출을 발생시키는 구조에서 따르는 보안 경계다.

출처: [Rewrap API 및 구현](https://docs.rs/rsbinder/0.12.0/src/rsbinder/bridge.rs.html)

### 6. `RpcServer` / `RpcSession`의 Android 16 — PASS (명시적 wire profile 필요)

RPC 문서의 wire profile 표는 Android 13을 version 0, Android 14/15를 version 1, Android 16을 version 2로 구분한다. 기본 `setup_unix_client()`는 Android 12(r34) profile을 사용하므로 Android 16 피어와의 연결에는 명시적으로 Android 13+ profile을 선택해야 한다. 서버도 Android 16 version 2를 제공해야 한다.

```rust
let server = RpcServer::setup_unix_server(socket_path)?;
server.set_android13plus(2);

let session = RpcSession::setup_unix_client_android13plus(socket_path, 2)?;
```

프로젝트 문서는 RPC client/server가 Android 13~16의 실제 AOSP `libbinder` 피어와 검증됐다고 설명한다. Unix socket 연결에는 peer credentials와, pathname socket을 쓸 경우 파일 권한이 보안 경계로 남는다. Linux/Android의 abstract Unix socket도 지원해 socket 파일 생성·정리 없이 연결할 수 있다. Android 14+ RPC wire를 사용할 경우 Unix socket의 `SCM_RIGHTS`를 통한 FD 전달도 문서화돼 있다. 이 저장소의 Samsung 기기에서 RPC 연결은 아직 시험하지 않았다.

출처: [RPC transport 및 wire profile](https://github.com/hiking90/rsbinder/blob/master/book/src/rpc-transport.md)

### 7. AIDL Proxy/Stub 및 기존 `libbinder` — PASS (upstream 지원), 대상 HAL 미검증

`rsbinder-aidl`은 Android AIDL 파일을 Rust 소스로 변환하며 인터페이스, parcelable, union, enum을 생성한다. 생성 코드의 Proxy/Stub을 Kernel Binder 경로에서 사용해 기존 Android C++/Java `libbinder` 서비스와 통신할 수 있다는 것이 프로젝트의 호환성 설명이다. 같은 AIDL 바인딩을 RPC 경로에서도 쓸 수 있다.

각 Host HAL에 실제 호출하려면 해당 서비스의 AIDL 정의·버전·stability 및 인수/반환 타입이 일치해야 한다. Samsung Vendor HAL의 AIDL 정의나 실제 메서드는 이번 조사에서 읽지 않았고, HIDL 호환성도 확인하지 않았다.

출처: [rsbinder-aidl API](https://docs.rs/rsbinder-aidl/0.12.0/rsbinder_aidl/), [Android Binder/AIDL 호환성 안내](https://moru.rs/rsbinder/android.html)

### 8. SELinux 및 ServiceManager — NOT TESTED (rsbinder 실기기), 저장소의 C++ 선행 시험은 PASS

rsbinder는 Android의 Binder 장치와 ServiceManager에 직접 접근한다. 따라서 장치 open/ioctl, Binder call/transfer, ServiceManager의 `find`/`add`/`list`, 서비스 이름의 context 매핑은 실행 도메인과 정책에 따라 결정된다. `rsbinder`나 `rsb_hub`를 사용한다고 이 정책 경계가 사라지지 않는다.

저장소의 2026-11-03 Android 16 Test B는 Enforcing에서 Guest ServiceManager 등록·조회와 Host/Guest registry 격리를 통과했다. 다만 전용 서버 도메인 및 제한된 SELinux 정책 규칙을 사용했고, 시험 구현은 C++ AOSP `libbinder`였다. 이 결과는 SSAL의 Binder/SELinux 준비 상태에 대한 근거이지, rsbinder로 Host ServiceManager나 HAL을 조회할 권한이 이미 확인됐다는 뜻은 아니다.

출처: [Test B 기기 결과](servicemanager-test-b-device-20261103.md), [Enforcing Binder 선행 결과](enforcing-binder-device-20261031.md)

## 권장 구조

각 프로세스는 Kernel `ProcessState` 하나만 사용한다. 각 Gateway는 그 Binder Context에 붙은 AIDL 인터페이스를 명시적으로 처리하고, 두 Gateway 사이는 Android 16 RPC v2의 Unix Domain Socket으로 연결한다.

```mermaid
flowchart LR
    GC[Guest Client] --> PB[Private Binder]
    PB --> GG[Guest Gateway<br/>Private ProcessState + RpcSession]
    GG -->|UDS · RPC v2| HG[Host Gateway<br/>Host ProcessState + RpcServer]
    HG --> HB[Host /dev/binder]
    HB --> HS[Allowlisted Host Service]
```

Gateway에는 서비스 Allowlist를 적용하고, 원래 Guest 호출자 권한을 Host 서비스가 그대로 보는 것으로 가정하지 않는다. Callback은 타입별 `Rewrap`으로 동일 객체를 재사용하되, 연결 단절·DeathRecipient·wrapper 수명은 Phase 4에서 별도 검증해야 한다.

## Phase 2로 넘길 검증 항목

1. `rsbinder` 0.12.0 및 `rsbinder-aidl` 0.12.0을 Android AArch64로 빌드한다.
2. Host probe는 `/dev/binder`를 명시하고, 초기화 전후 열린 FD가 같은 장치인지 확인한다.
3. Host ServiceManager에서 서비스 조회와 Interface Descriptor 확인만 수행한다. 등록·교체 및 상태 변경 메서드는 호출하지 않는다.
4. 실패를 장치 open, Binder protocol version, Binder transaction, ServiceManager permission, SELinux AVC로 분리 기록한다.
5. Guest Private Binder에서는 별도 프로세스로 private `ProcessState`를 초기화하고, `rsb_hub`의 커스텀 장치 옵션 및 SELinux Context Manager 권한을 검증한다.

## 최종 판정

rsbinder는 **분리 프로세스 + RPC 기반의 타입별 IPC Gateway PoC 후보**로 적합하다. Host와 Guest의 서로 다른 Kernel Binder Context를 같은 프로세스에서 운용하는 기반으로는 적합하지 않다. `Rewrap`은 callback Binder 객체 대응을 돕지만, Gateway 인터페이스 전달·보안 정책·ServiceManager 설정·비정상 종료 복구는 SSAL 실험에서 구현하고 검증해야 한다.

rsbinder 채택 여부는 Phase 2의 Host read-only probe와 Phase 3의 Private Binder 시험이 실제 Samsung Android 16 기기에서 통과한 뒤 판단한다. 현재로서는 upstream 지원 자료만으로 Host HAL 접근 성공을 확정할 수 없다.

## 참고 자료

- [rsbinder README 및 Android 빌드 안내](https://github.com/hiking90/rsbinder)
- [ProcessState API](https://docs.rs/rsbinder/0.12.0/rsbinder/struct.ProcessState.html)
- [ProcessState 구현](https://docs.rs/rsbinder/0.12.0/src/rsbinder/process_state.rs.html)
- [Android 버전·ServiceManager 호환성](https://moru.rs/rsbinder/android.html)
- [rsb_hub `--device` 추가 릴리스](https://github.com/hiking90/rsbinder/releases/tag/v0.5.0)
- [Rewrap 구현](https://docs.rs/rsbinder/0.12.0/src/rsbinder/bridge.rs.html)
- [RPC transport 문서](https://github.com/hiking90/rsbinder/blob/master/book/src/rpc-transport.md)
- [AIDL generator API](https://docs.rs/rsbinder-aidl/0.12.0/rsbinder_aidl/)
- [저장소 Binder probe](binder-probe.md)
- [저장소 Android 16 Test B 결과](servicemanager-test-b-device-20261103.md)
