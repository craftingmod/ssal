# rsbinder Phase 3

`rsbinder 0.13.0`과 `rsbinder-aidl 0.13.0`으로 만든 Android 전용 진단용 AIDL 서비스/클라이언트입니다. `IPhase3Service`는 `add`, `echo`, 동기 `callCallback`을 제공하고 `IPhase3Callback`은 콜백 문자열을 돌려줍니다. `phase3-ipc`의 모드는 `server`, `client`, `death-client`, `check-absent`, `context-manager`, `inspect-data-service NAME`입니다.

`phase3-ipc`는 Guest Service Launcher 검증 경로에서 Context Manager 조회, synthetic AIDL readiness, `installd`/`artd` 조회에 사용됩니다. 별도로 루트의 `phase3-diagnostic` feature와 `ssald --phase3-rsbinder-runner` 진입점은 C++ Test B와 Phase 2C를 검사한 뒤 같은 Guest 서비스 이름으로 Rust 시험을 수행합니다. 정리 후 이 선택형 진단에는 저장소 밖에서 준비한 Phase 2 probe 바이너리를 인자로 제공해야 합니다. 진단 실행기 자체는 Host Binder 서비스나 SELinux 정책을 수정하지 않습니다.

## Android 빌드

2026-11-04 공통 Guest Service Launcher에서도 기존 server/client를 재사용한다. 새 `inspect-data-service installd|artd` 모드는 Private Binder에서 서비스 조회 및 `INTERFACE_TRANSACTION` descriptor 응답만 검사한다. [공통 런처 결과](../../docs/guest-service-launcher-common-results.md) 참고.

Windows PowerShell과 Android NDK r30 예시:

```powershell
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "V:\workspace\Toy\ssal\.cache\android-sdk-phase2\android-ndk-r30\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android29-clang.cmd"
cargo build --offline --locked --release --manifest-path tools/rsbinder/Cargo.toml --target aarch64-linux-android
```

Guest 시험은 기존 SSAL Private Binder 실행기 안에서만 해야 합니다. 일반 Host namespace에서 `phase3-ipc`를 직접 실행하면 Host Binder를 선택할 수 있습니다. 서버는 명시적으로 추적한 진단 프로세스만 종료하며, 세션 마운트와 loop 장치 정리는 기존 supervisor가 맡습니다.

## 현재 결과

2026-11-04 SM-S937N / Android 17 Host, Android 16 / SDK 36 Guest에서 Phase 3가 PASS했습니다. AIDL 등록·조회·descriptor·`add(17,25)=42`·`echo`, 반복 동기 callback, Binder death, server restart/reconnect, Host registry 격리 및 cleanup이 통과했습니다.

최초 callback 실패는 `u:r:aidl_lazy_test_server:s0 → u:r:shell:s0`의 `binder call` 거부였습니다. 테스트 전용으로 다음 한 규칙을 KernelSU runtime에 적용해 재검증한 뒤 같은 `deny` rule로 원복했습니다. `module/sepolicy.rule`은 변경하지 않았고, policy hash가 적용 전 값으로 복귀했습니다.

```text
allow aidl_lazy_test_server shell binder call
```

상세 AV mask, 프로세스 identity, 회귀 및 cleanup 결과는 [`docs/rsbinder-phase3-results.md`](../../docs/rsbinder-phase3-results.md)에 있습니다. Phase 4 진행은 가능하지만 실제 Guest boot, SSAL switching, HAL proxy runtime은 아직 검증되지 않았습니다.
