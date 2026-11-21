# SSAL — rsbinder IPC Gateway Feasibility Experiment

## 목표

SSAL 프로젝트에서 `rsbinder`를 활용하여 Host Samsung Android와 Guest LineageOS 사이에 독립적인 Binder IPC Gateway를 구축할 수 있는지 검증한다.

이번 작업은 **독립적인 실험 및 PoC**이며, 기존 SSAL의 부팅·마운트·SELinux·프로세스 관리 구현을 변경하지 않는다.

최종 목표는 Guest의 `servicemanager`, `installd`, `artd`, `system_server`를 Host와 독립적으로 실행하면서 필요한 Host HAL 서비스만 선택적으로 연결하는 것이다.

## 참고 자료

- rsbinder: https://github.com/hiking90/rsbinder
- rsbinder API: https://docs.rs/rsbinder/latest/rsbinder/
- Bridge: https://docs.rs/rsbinder/latest/rsbinder/bridge/
- ProcessState: https://docs.rs/rsbinder/latest/rsbinder/struct.ProcessState.html
- RPC: https://github.com/hiking90/rsbinder/blob/master/book/src/rpc-transport.md
- Cross-transport: https://hiking90.github.io/rsbinder/cross-transport-services.html

## Phase 1 — API 및 구조 조사

현재 공개된 rsbinder 버전과 실제 소스를 확인하고 다음 항목을 조사한다.

1. Android AArch64 크로스 컴파일 지원
2. Android 14~16 Binder 프로토콜 호환성
3. `ProcessState::init()`의 Binder Device 선택 및 Singleton 제약
4. `rsb_hub`의 커스텀 Binder Device 지원
5. `rsbinder::bridge::Rewrap`의 기능과 한계
6. `RpcServer` / `RpcSession`의 Android 16 호환성
7. AIDL Proxy/Stub 생성 및 기존 Android `libbinder`와 상호운용성
8. SELinux 및 ServiceManager 접근 제약

특히 Host와 Guest의 서로 다른 Binder Context를 하나의 프로세스에서 동시에 사용할 수 있는지 확인한다.

불가능하다면 별도 프로세스와 Unix Domain Socket 기반 Binder RPC로 연결하는 구조를 우선한다.

실제 확인한 API만 사용하고, 공개 문서와 설치 버전이 다르면 소스 코드를 우선한다.

## Phase 2 — Host Binder Read-only Probe

삼성 Host Android에서 rsbinder 기반 테스트 클라이언트를 실행한다.

- 기존 `/dev/binder` 사용
- 기존 Host ServiceManager 접근
- 서비스 목록 및 Interface Descriptor 조회
- 가능하다면 부작용 없는 읽기 전용 메서드 호출
- Binder Driver 및 프로토콜 호환성 확인
- 호출 실패 시 SELinux AVC, Binder 오류, 권한 오류 구분

절대로 Host ServiceManager를 교체하거나 기존 서비스를 재등록하지 않는다.

Host HAL의 상태를 변경하는 메서드도 호출하지 않는다.

성공 기준:

- Host Binder 접근 성공
- 기존 AOSP Binder 서비스와 통신 성공
- Host 프로세스 및 서비스에 변경 없음

## Phase 3 — Private Binder 독립 실행

SSAL의 Guest용 Private Binder를 가정한 테스트 환경을 만든다.

먼저 `/dev/binderfs`, `binder-control`, 커널 Binder 지원 여부를 검사한다.

별도 Binder Device 생성이 가능한 경우에만 테스트 전용 디바이스를 생성한다.

기존 Host `/dev/binder`, `/dev/hwbinder`, `/dev/vndbinder`를 변경해서는 안 된다.

다음 항목을 검증한다.

1. Private Binder Device 생성 및 접근
2. 독립 `rsb_hub` 실행
3. 테스트 AIDL 서비스 등록
4. 별도 프로세스의 클라이언트에서 호출
5. Host ServiceManager와 등록 정보가 분리되는지 확인
6. 테스트 프로세스 종료 후 자원 정리

`rsb_hub`가 Guest Android의 공식 `servicemanager`를 완전히 대체할 수 있다고 가정하지 않는다. 이번 단계에서는 독립 Binder Context의 정상 동작만 검증한다.

SELinux Enforcing 상태에서 우선 실행하고, 실패 시 AVC를 수집한다. Permissive 전환이나 정책 변경을 자동 수행하지 않는다.

## Phase 4 — Binder Gateway PoC

다음 구조를 구현한다.

```text
Guest Test Client
        |
        v
Private Binder
        |
        v
Guest Gateway Process
        |
        | Binder RPC / Unix Socket
        |
        v
Host Gateway Process
        |
        v
Host Binder
        |
        v
Host Test Service
```

Phase 4 초기에는 실제 Samsung HAL 대신 테스트 서비스로 검증한다.

구현 및 검증 항목:

- 서로 다른 Binder Context 간 메서드 호출 전달
- AIDL 인수 및 반환값 직렬화
- 오류 및 상태 코드 전달
- Binder 객체 재래핑
- Callback 등록/해제
- `Rewrap`을 사용한 Callback Identity 유지
- DeathRecipient 및 연결 종료 처리
- Gateway 프로세스 비정상 종료 후 복구
- 동시 호출 및 타임아웃 처리

Gateway는 명시적인 서비스 Allowlist를 사용한다.

범용 Binder Transaction을 무조건 전달하는 방식은 구현하지 않는다.

## Phase 5 — 실제 Host HAL Read-only 검증

Phase 4까지 성공한 경우에만 진행한다.

Host에서 실제로 제공 중인 AIDL HAL 가운데 읽기 전용 호출이 가능한 서비스를 선정한다.

후보:

- Health HAL
- Power HAL의 읽기 전용 인터페이스
- 그 밖의 부작용 없는 Vendor HAL 인터페이스

선정 전에 해당 서비스의 AIDL/HIDL 여부, 인터페이스 버전, 권한 요구사항을 반드시 확인한다.

Gateway가 Host Binder를 통해 실제 HAL과 통신할 수 있는지 확인하되, Guest에 실제 HAL을 등록하거나 Android Framework를 부팅하는 작업은 이번 범위에서 제외한다.

HIDL 서비스는 rsbinder가 자동 지원한다고 가정하지 말고 별도 호환성 작업으로 분류한다.

## 안전 제약

- 기존 SSAL 동작 변경 금지
- Host `init`, `zygote`, `system_server` 종료 금지
- Host `servicemanager` 및 `hwservicemanager` 변경 금지
- Host `installd` / `artd` 사용 또는 재시작 금지
- SELinux 정책 수정 금지
- 전역 Permissive 전환 금지
- 실제 HAL 상태 변경 금지
- 기존 Mount Namespace 변경 금지
- Host `/data` 수정 금지
- 커널 Binder Device 및 기존 노드 교체 금지
- 실험 자원은 별도 디렉터리 및 독립 프로세스로 격리

Root 권한은 실험 환경 준비에 한정하여 사용한다.

실험이 실패하더라도 기존 Host Android는 계속 정상 동작해야 한다.

## 산출물

독립적인 `experiments/rsbinder/` 디렉터리에 구현한다.

최소한 다음 자료를 작성한다.

- `README.md` — 실행 및 빌드 방법
- `RESULTS.md` — 단계별 실험 결과
- `ARCHITECTURE.md` — 검증된 IPC 구조
- `LIMITATIONS.md` — 남은 기술적 제약
- Host Binder Probe
- Private Binder 테스트 서버/클라이언트
- Binder Gateway PoC
- 실행 및 정리 스크립트

## 최종 평가

다음 질문에 명확하게 답한다.

1. rsbinder로 삼성 Host Binder에 정상 접근할 수 있는가?
2. Private Binder와 독립 ServiceManager를 구성할 수 있는가?
3. 서로 다른 Binder Context 간 AIDL 호출을 전달할 수 있는가?
4. Callback, Binder 객체 Identity, DeathRecipient를 보존할 수 있는가?
5. Host HAL을 Guest에 선택적으로 노출하는 방식이 실현 가능한가?
6. 어떤 기능은 rsbinder로 재사용하고 어떤 부분은 SSAL에서 직접 구현해야 하는가?
7. 향후 Guest `servicemanager` 및 실제 LineageOS 부팅에 통합할 때 어떤 제약이 남는가?

각 단계는 `PASS`, `FAIL`, `BLOCKED`, `NOT TESTED`로 기록한다.

구현 성공과 실제 기기 검증 성공을 구분한다.

**Phase 1~4를 우선 완료하고, 실제 HAL 연결은 앞선 단계의 검증 결과에 따라 진행한다.**

최종적으로 rsbinder를 SSAL의 IPC Gateway 구현 기반으로 채택할지, AOSP libbinder를 직접 사용하는 편이 나을지 근거를 제시한다.