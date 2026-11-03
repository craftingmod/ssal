# SSAL rsbinder IPC Gateway — Phase 2 실행 계획

- 작성일: 2026-11-03
- 상태: **PLAN / 실행 전**
- 선행 문서: `rsbinder-ipc-phase1.md`, `binder-probe.md`, `servicemanager-test-b-device-20261103.md`, `enforcing-binder-device-20261031.md`
- 목표: **실제 Samsung Android 16 기기에서 rsbinder의 Host Binder 및 Guest Private Binder 호환성을 독립적으로 입증한다.**
- 범위: AArch64 빌드, read-only Host ServiceManager probe, 별도 프로세스의 Guest Private Binder probe, 재현 가능한 결과 및 오류 분류
- 비범위: RPC Gateway 연결, 실제 HAL 메서드 중계, callback/DeathRecipient 복구, system_server·zygote 기동, Host Binder 서비스 등록·교체, SELinux 정책의 광범위한 완화

## 0. Phase 1에서 확정된 전제

1. `rsbinder::ProcessState`는 **프로세스당 하나의 Kernel Binder Context**를 초기화한다. Host `/dev/binder`와 Guest Private Binder를 **동일 프로세스에서 함께 초기화하지 않는다**.
2. Host Gateway와 Guest Gateway는 별도 프로세스로 만들며, 장래에는 UDS를 통한 rsbinder RPC로 연결한다. **Phase 2에서는 서로 연결하지 않는다**.
3. `rsbinder` 0.12.0 및 `rsbinder-aidl` 0.12.0을 고정한다. `Cargo.lock`을 커밋한다. 버전 변경은 별도 기록한다.
4. 기존 C++ `libbinder` 기반 Binder/ServiceManager 성공을 rsbinder 성공으로 취급하지 않는다.
5. Guest에는 앞선 시험에서 검증된 **기존 C++ Private Binder ServiceManager를 우선 재사용**한다. `rsb_hub`는 기존 ServiceManager와 상호운용이 불가능함이 확인된 경우에만 대안으로 평가한다.
6. Host HAL 접근은 Binder, AIDL 버전, ServiceManager 가시성, SELinux 권한을 모두 충족해야 한다. HIDL(`/dev/hwbinder`)은 이번 단계에서 지원된다고 가정하지 않는다.
7. `Delegating`/생성 `IFooDelegate`는 Phase 3의 단순 AIDL method forwarding 후보, `Rewrap`은 callback Binder 객체 중계 후보이다. **Phase 2에 구현을 강제하지 않는다**.

## 1. 안전 및 격리 규칙 — 반드시 준수

- 작업 전 저장소의 현재 구현과 선행 시험의 **문서/코드만** 확인한다. 기존 동작 경로를 대규모 리팩터링하지 않는다.
- `vendor/` **소스 트리는 읽지 않는다**. 필요한 공개 upstream 소스와 기존 SSAL 시험 자료만 사용한다.
- Host는 **읽기 전용 ServiceManager 조회 및 `INTERFACE_TRANSACTION` 기반 descriptor 확인**으로 제한한다. HAL 기능 메서드, `addService`, 서비스 제거/대체, Context Manager 설정은 호출하지 않는다.
- Host `/dev/binder`를 Private Binder로 bind mount하거나 덮어쓰지 않는다. Host Binder 장치와 ServiceManager의 상태를 변경하지 않는다.
- Host `installd`, `artd`, `zygote`, `system_server`, init service를 종료·재시작하지 않는다. `stop`, `start`, `setenforce 0`, 임의 `supolicy` 일괄 적용을 사용하지 않는다.
- 기본적으로 SELinux **Enforcing 유지**. AVC를 수집하고, 필요한 최소 정책 변경은 **제안만** 한다. 새로운 정책 적용 시험은 별도 승인/단계로 구분한다.
- 테스트용 Private Binder 서비스는 별도 Context에서만 등록한다. 기존 Guest ServiceManager와 충돌하거나 중복 Context Manager를 등록하지 않는다.
- 실기기 실행 시 대상 장치·경로·mount namespace·PID·SELinux context를 선검증한다. 잘못된 장치 선택을 막기 위해 `ProcessState::init_default()`를 사용하지 않는다.
- 비파괴적 probe 외에 파일 배포/정책 변경/daemon 기동이 필요한 경우 수행 전 예상 변경점, 종료 방법, 원상복구 방법을 기록한다. 승인이 없으면 빌드와 dry-run까지만 수행한다.

## 2. 산출물

코드 위치는 기존 저장소 관례를 우선하고, 없다면 아래 구조를 제안한다. 실제 경로 결정 이유를 문서화한다.

```text
experiments/rsbinder-phase2/
  Cargo.toml
  Cargo.lock
  src/bin/host_probe.rs
  src/bin/guest_probe.rs
  README.md
  scripts/build-android.sh            # 필요할 때만
  scripts/collect-readonly.sh         # 필요할 때만

docs/rsbinder-phase2-results.md      # 결과 보고서: 빌드/실기기 결과를 구분
```

기존 프로젝트 구조와 상충하면 경로만 조정한다. **Phase 2 도중 SSAL 메인 전환(switch/return) 경로에 프로브를 통합하지 않는다.**

## 3. Phase 2A — 환경 확인 및 재현 가능한 Android AArch64 빌드

### A. 정적 사전 점검

- 현행 Rust toolchain, Android NDK, `cargo-ndk`, target triple, Android API level, `rust-toolchain.toml`을 기록한다.
- upstream rsbinder 0.12.0의 **실제 API 시그니처와 feature 설정**을 고정된 소스 기준으로 확인한다. 문서의 샘플 코드가 그대로 컴파일된다고 가정하지 않는다.
- `android_14_plus` 및 ServiceManager variant 감지 방식 등 Android 16 호환 feature를 확인한다. 필요한 최소 feature만 사용한다.
- `Cargo.lock` 및 빌드 환경을 기록하고 `aarch64-linux-android` release binary를 생성한다.

### B. 빌드 검증

- `cargo check`, 단위 테스트(호스트에서 실행 가능한 부분), Android AArch64 release build를 수행한다.
- 예시(설치 도구/NDK 구성에 따라 조정):

```sh
cargo ndk -t aarch64-linux-android --platform 29 build --release
```

- 생성 ELF에 대해 architecture, dynamic linker 및 공유 라이브러리 의존성을 확인한다. 실행 장치의 Android 버전/ABI와 비교한다.
- 빌드 실패는 `toolchain`, `feature`, `API mismatch`, `linker`, `missing library`, `source API mismatch`로 분류한다.

**2A 통과:** 실제 바이너리가 `aarch64-linux-android` 대상으로 빌드되고, lockfile/버전/빌드 로그가 남아 있다. **실기기 동작 통과를 의미하지 않는다.**

## 4. Phase 2B — Host read-only rsbinder probe

### A. 사전 조건

1. 현재 셸 및 테스트 프로세스의 PID, UID/GID, SELinux domain, mount namespace를 기록한다.
2. `/dev/binder`, `/dev/binderfs/binder`가 존재하는지 `stat`으로 확인하고 `st_dev`, `st_ino`, `st_rdev`, 파일 유형과 실제 사용 경로를 기록한다. **존재 여부만으로 두 노드가 같다고 추정하지 않는다.**
3. 기준선 확보: 기존 Host ServiceManager의 정상 동작과 테스트 전후 Host 상태를 비교할 수 있도록 읽기 전용 정보를 남긴다.
4. Probe는 명시적으로 `ProcessState::init("/dev/binder", ...)` 또는 확인된 정확한 Host 경로를 사용한다. 경로를 조용히 대체하지 않는다.

### B. 최소 작업

- `ProcessState` 초기화 및 Binder 프로토콜 버전 협상 성공 여부 기록.
- **정해진 비민감·읽기 전용 서비스**에 대해 ServiceManager 조회만 수행. 서비스명은 실행 환경의 기존 목록과 접근 권한을 보고 선정하고, 접근 실패가 나면 다른 서비스로 무제한 탐색하지 않는다.
- 조회한 핸들의 **interface descriptor만** 확인한다. 객체가 없거나 descriptor 조회 권한이 없으면 이유를 기록하고 종료한다.
- 서비스 등록, 기능 transaction, HAL 상태 변경은 하지 않는다.
- 실행 전후 프로세스 FD의 Binder 장치 identity를 비교한다. rsbinder 내부 FD를 직접 확인하기 어려우면 `/proc/<pid>/fd` 등 비침습적 방식과 관측 한계를 기록한다.

### C. 로그 형식

최소한 다음 필드를 남긴다.

```text
run_id, timestamp, device_model, android_release, build_fingerprint_redacted
probe_version, rsbinder_version, abi, uid, gid, selinux_context, mount_ns
requested_binder_path, observed_device_identity, binder_protocol
service_name, lookup_result, descriptor_result
error_stage, errno_or_status, avc_excerpt, elapsed_ms
host_state_before, host_state_after
```

민감한 식별자, 토큰, 개인 데이터는 제거한다. 오류는 **`device_open` → `binder_version` → `process_state` → `servicemanager_connect` → `service_lookup` → `interface_descriptor` → `selinux_avc`** 단계로 분류한다. AVC가 없다는 것만으로 SELinux 문제가 없다고 결론 내리지 않는다.

**2B 통과:** Enforcing 상태의 실제 장치에서 rsbinder가 **Host Binder를 명시적으로 초기화하고**, 사전에 선택한 Host 서비스의 Binder 핸들 및 descriptor를 읽는 데 성공한다. 실패 시에는 원인 분류와 증거가 남아야 하며 PASS로 기록하지 않는다.

## 5. Phase 2C — Guest Private Binder 독립 프로세스 probe

### A. 진입 조건

- Phase 2A 완료.
- 선행 C++ Private Binder 및 Guest ServiceManager 테스트 결과를 재확인하고, 해당 테스트의 **정확한 장치 경로·namespace·프로세스 도메인·service registration 조건**을 기록한다.
- Guest Binder와 Host Binder의 실제 장치 identity를 대조해 **서로 다른 Binder Context**임을 확인한다. 단순 경로 문자열 비교만으로 독립성을 확정하지 않는다.

### B. 구현 및 검증

1. `guest_probe`는 `host_probe`와 **별도 프로세스**로 실행한다.
2. 앞서 검증된 Guest Private Binder 장치의 **실제 절대 경로를 명시하여** `ProcessState::init()`을 호출한다.
3. 기존 Guest Private ServiceManager에서 사전 등록된 테스트 서비스의 조회 및 descriptor를 확인한다. 가능하면 Phase 1 이전 C++ 시험의 **기존 안전한 테스트 서비스**를 재사용한다.
4. 필요하고 별도 허용된 경우에만 Guest Private Context에 신규 **테스트 전용** Echo 서비스를 등록·조회한다. 이때 이름 충돌을 방지하고 종료 시 정리 절차를 갖춘다.
5. 동일한 서비스 이름이 Host registry에 나타나지 않는지 확인한다. Host에서는 읽기 전용 조회만 수행한다.
6. 시험 종료 후 Guest 측 임시 테스트 프로세스를 종료하고, Host 서비스 및 Binder 장치가 영향을 받지 않았는지 비교한다.

**`rsb_hub` 판단:** 기존 C++ Guest ServiceManager와 rsbinder가 상호운용되면 `rsb_hub` 도입을 **보류**한다. 실패하더라도 프로토콜/권한/서비스 종류를 먼저 분류한 뒤 `rsb_hub --device`를 **대안 조사**로만 열어 둔다. 기존 Context Manager를 임의로 중단하거나 교체하지 않는다.

**2C 통과:** rsbinder가 별도 프로세스에서 Private Binder를 초기화하고 Guest ServiceManager와 AIDL/Binder 수준의 읽기 전용 조회가 성공하며, Host/Guest registry 독립성이 유지된다.

## 6. 실패 처리 및 게이트

| 결과 | 판정 | 다음 행동 |
|---|---|---|
| 2A 빌드 실패 | BLOCKED | toolchain/API/feature 원인 수정, 실기기 배포 금지 |
| 2A 성공·2B 실패 | PARTIAL | Host 장치·권한·ServiceManager 원인을 분리, rsbinder Host 호환성 미확정 |
| 2B 성공·2C 미실행 | PARTIAL | Host read-only 기능만 검증됨; Guest 독립성 주장 금지 |
| 2B 성공·2C 실패 | PARTIAL | Private Binder·ServiceManager interop 원인 조사; `rsb_hub` 교체는 자동 진행 금지 |
| 2A·2B·2C 성공 | **PASS** | Phase 3의 Echo AIDL/RPC Gateway 실험 설계로 진행 |
| Host 상태 변화·예상 밖 ServiceManager 변경·대량 AVC | **STOP** | 테스트 중단, 영향 범위 수집, 원상복구 확인 후 재평가 |

실행 시간이 오래 걸리거나 장치 접근이 불가능하더라도 **실행하지 않은 항목을 PASS로 표기하지 않는다**. 보고서에서 `DOC-VERIFIED`, `BUILD-PASS`, `DEVICE-PASS`, `NOT-TESTED`, `BLOCKED`를 구분한다.

## 7. 구현 시 금지할 지름길

- 두 Binder 장치를 하나의 rsbinder `ProcessState`로 교차 초기화하려는 우회
- `init_default()`에 의존해 Host/Guest 장치를 묵시적으로 선택
- Host Binder/ServiceManager에 Guest 테스트 서비스 등록
- 광범위 permissive 전환으로 권한 오류를 가리고 PASS 판정
- C++ 사전 검증이나 upstream 성공 사례를 rsbinder 실기기 PASS로 치환
- 아직 검증하지 않은 HIDL/삼성 Vendor HAL을 자동 지원한다고 선언
- Phase 2에 RPC, `Rewrap`, `Delegating`, 실제 HAL 기능 호출까지 한꺼번에 넣는 범위 확장

## 8. Phase 3로 넘길 사전 설계 메모 (구현 금지)

Phase 2에서 확보한 사실을 토대로 다음 단계에서만 진행한다.

1. **먼저 Echo AIDL**: Host HAL 대신 독립적인 테스트 인터페이스를 양측에서 생성해 기본 메서드·오류 처리를 확인한다.
2. **별도 프로세스 + UDS RPC**: Guest `ProcessState` + `RpcSession`, Host `ProcessState` + `RpcServer`. Android 16 `libbinder` 상호운용이 필요한 경우 RPC v2를 명시적으로 설정한다.
3. **전달 추상화**: 생성 `IFooDelegate`/`Delegating`의 실제 사용 가능 여부 확인; Binder 객체가 오가는 경우 `Rewrap` 및 lifetime 관리 별도 구현.
4. **보안**: Host Gateway의 서비스 및 메서드 allowlist, UDS peer credentials/권한, SELinux 도메인, Host에서 관측되는 caller UID가 Gateway UID라는 사실을 전제로 설계.
5. **안정성**: FD 전달, incoming RPC callback, 동시 호출, 재연결, DeathRecipient, 장애 시 Host 상태 불변성 시험.
6. **HAL 선택**: AIDL interface 버전/stability/메서드와 HIDL 여부를 검증한 뒤 안전한 read-only HAL 한 개를 선정한다.

이 메모는 **Phase 2 완료 조건이 아니다**.

## 9. Codex 실행 지시

1. 선행 파일과 관련 코드를 읽어 현재 작업 트리를 파악한다. 기존에 구현된 probe를 중복 작성하지 않는다. `vendor/`는 읽지 않는다.
2. Phase 2A → 2B → 2C 순으로 진행한다. 각 단계의 증거와 실패 지점을 저장한다.
3. Device 접근·테스트가 허용되지 않은 실행 환경에서는 컴파일·단위 테스트·스크립트 dry-run까지만 수행하고, 실기기 검증은 `NOT-TESTED`로 남긴다.
4. 장치의 Host init/SELinux/ServiceManager 상태를 바꾸는 명령은 수행하지 않는다. 추가 권한이나 파괴적 작업이 필요하면 변경 계획과 근거만 제시한다.
5. `docs/rsbinder-phase2-results.md`에 최종 결과, 실행 명령, 환경, PASS/FAIL 근거, 로그/AVC, 미검증 항목, 다음 단계의 blocker를 작성한다.
6. 완료 시 코드를 최소 diff로 유지하며 빌드·테스트를 재실행하고, **검증한 것과 추정한 것을 명확하게 분리**해 보고한다.

## 10. 최종 수락 기준

- [ ] 재현 가능한 `rsbinder` 0.12.0 Android AArch64 binary와 lockfile
- [ ] Host `/dev/binder`를 명시적으로 사용하는 read-only probe
- [ ] Host ServiceManager 조회와 interface descriptor의 실기기 성공 증거
- [ ] 별도 프로세스의 Guest Private Binder 명시적 초기화
- [ ] 기존 Guest ServiceManager와 rsbinder 상호운용 성공 증거
- [ ] Host/Guest Binder Context 및 registry 독립성 관측
- [ ] SELinux Enforcing 유지 및 권한/실패 로그 기록
- [ ] Host 서비스 및 daemon 상태 불변 확인
- [ ] 모든 미검증 및 실패 항목을 구분한 Phase 2 보고서

**Phase 2 최종 PASS는 위 실기기 관측 요건이 전부 충족된 경우에만 부여한다.** 그 전까지는 `PARTIAL` 또는 `NOT-TESTED`로 표기한다.

---

## 근거 문서

- `rsbinder-ipc-phase1.md` (2026-11-03, 본 계획의 주된 기준)
- [rsbinder README](https://github.com/hiking90/rsbinder)
- [rsbinder Android compatibility](https://moru.rs/rsbinder/android.html)
- [rsbinder ProcessState 0.12.0](https://docs.rs/rsbinder/0.12.0/rsbinder/struct.ProcessState.html)
- [rsbinder RPC transport](https://github.com/hiking90/rsbinder/blob/master/book/src/rpc-transport.md)
- [rsbinder Cross-Transport Services](https://github.com/hiking90/rsbinder/blob/master/book/src/cross-transport-services.md)

> 주의: 본 문서는 Phase 1의 조사 결과와 이전 검토에서 도출한 실행 정책을 계획으로 정리한 것이다. 새로운 실기기 실행이나 추가 upstream 검증 결과를 의미하지 않는다.
