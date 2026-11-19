# Concurrent Mode

Concurrent Mode는 Host Framework를 계속 실행하면서 Guest를 별도 mount 환경과 독립 userdata에서 실행한다. [SSAL Core Runtime](../architecture.md)이 Guest Init, Binder, Property, SELinux, mount 및 Lifecycle을 제공한다. Guest 화면은 Virtual Composer를 통해 제공하는 것이 목표이며, HAL은 Guest용 가상 구현과 명시적으로 허용한 인터페이스의 중개로 제한한다.

| 소유 영역 | 현재 위치와 범위 |
| --- | --- |
| 실행 코드 | [Concurrent 어댑터](../../src/guest/concurrent/mod.rs)에 기존 SystemSuspend와 Host Power Broker 연결이 있다. Guest의 `PARTIAL` wakelock을 중개하는 범위는 기기 실험 문서에 기록돼 있다. [SystemSuspend 결과](../guest-vintf-system-suspend-20261119.md) |
| 설정 | [마운트 프로필](../../module/profiles/concurrent/mounts/initial.json)과 [서비스 계약](../../module/profiles/concurrent/services/initial.json)은 현재 Guest worker용이다. Git에서의 소유 경로는 Concurrent 아래에 두고, KernelSU ZIP의 기존 `profiles/mounts/`와 `profiles/services/` 경로를 사용한다. [마운트 구성](../initial-mount-profile.md) · [실행 계약](../service-execution-contract.md) |
| 빌드 의존성 | [SystemSuspend 패키지](../../experiments/system-suspend/Cargo.toml)가 suspend AIDL 생성과 브리지 바이너리를 소유한다. APEX helper는 [독립 패키지](../../experiments/apexservice/Cargo.toml)에서 빌드한다. 두 패키지는 Binder 서비스 기반 코드와 잠금 파일을 공유한다. |
| 그래픽 | Guest composer3 HAL을 Virtual Composer로 사용하는 방안은 설계 단계다. 프레임 전송, Host Presenter, ANGLE·SwiftShader 및 Y702 Host 네이티브 버퍼는 사전 검증에 해당한다. [Virtual Composer 설계](../surfaceflinger-astra-architecture.md) · [프레임 전송](../guest-graphics-p02-isolated-frame-transfer.md) · [화면 표시](../guest-graphics-p03-surface-presenter.md) · [ANGLE·SwiftShader](../guest-graphics-b0-angle-swiftshader-20261119.md) · [Y702 네이티브 버퍼](../guest-graphics-y702-native-buffer.md) |

Guest Binder 인스턴스와 Property 영역은 Host와 분리한다. Host vendor 파티션의 읽기 전용 뷰는 현재 프로필의 마운트 구성이다. 실제 HAL 중개는 인터페이스별 어댑터가 담당한다.

## SystemSuspend

기존 Guest 서비스 워커에서 SystemSuspend는 기본 활성화되고, `SSAL_GUEST_SYSTEM_SUSPEND=0`으로 끌 수 있다. 활성화 시 Guest worker는 private Binder에 `android.system.suspend.ISystemSuspend/default`, `suspend_control`, `suspend_control_internal`을 등록합니다. Guest의 `PARTIAL` wakelock은 이름과 개수에 관계없이 하나의 Host `SSAL:VirtualWakeLock`으로 합쳐집니다. Host broker는 상속된 소켓을 통해 획득·해제만 처리하고, 마지막 Guest 토큰 해제 또는 연결 종료 시 Host 토큰을 반환합니다. 연속으로 잠금을 5분간 보유하면 broker가 토큰을 반환하고 종료합니다. `FULL`, autosuspend, 강제 절전, 콜백 및 Host 통계는 지원하지 않습니다.
