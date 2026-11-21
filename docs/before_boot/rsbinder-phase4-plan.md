# SSAL RSBinder Phase 4 — Android 16 Service Compatibility

## 목표

Phase 3에서 검증한 Private Binder 기반을 Android 16 LineageOS Guest의 실제 시스템 서비스에서 사용할 수 있는지 조사하고, 필요한 호환성 기능을 구현 및 검증한다.

최종 목표는 Guest `installd`와 `artd`를 Host의 Binder 및 데이터 영역에 의존하지 않고 독립적으로 실행할 수 있는 기반을 확보하는 것이다.

이번 Phase에서는 실제 Guest Android 전체 부팅을 수행하지 않는다.

## 1. 기존 구현 및 의존성 조사

다음 자료를 우선 분석한다.

- `docs/rsbinder-ipc-phase1.md`
- Phase 2 구현 및 결과 문서
- `docs/rsbinder-phase3-results.md`
- 현재 SSAL의 Private Binder 구현
- LineageOS 23.2 / Android 16의 ServiceManager, installd, artd 구현
- AOSP Binder 및 libbinder 동작

현재 구현을 불필요하게 교체하거나 리팩터링하지 않는다.

Android 서비스가 사용하는 Binder 기능을 조사하여 다음과 같이 분류한다.

- 이미 구현 및 검증됨
- 구현되어 있으나 실기기 검증되지 않음
- 구현되지 않음
- 외부 서비스 또는 HAL 의존성으로 인해 별도 작업 필요

## 2. Binder Compatibility Matrix 작성

최소한 다음 항목을 조사한다.

### Binder Transport

- 동기 및 비동기(oneway) 트랜잭션
- Binder 객체 및 핸들 전달
- File Descriptor 전달
- Parcel 직렬화 및 역직렬화
- Large Transaction 및 Binder Buffer 제한
- Binder 오류 코드와 예외 처리
- Death Recipient 및 객체 수명 관리
- Calling UID/PID 및 SELinux Context 전달
- Binder Thread Pool 동작

### ServiceManager

- `addService` / `getService` / `checkService`
- `listServices`
- 서비스 등록 알림
- Lazy Service 등록 및 시작·종료 처리
- 서비스 재등록 및 재연결
- 서비스 이름 및 인터페이스 중복 처리
- ServiceManager 접근 제어

### Android 시스템 서비스 호환성

- Native AIDL / C++ Binder
- Rust Binder
- Java Binder 사용 가능성 및 요구사항
- Stable AIDL 및 VINTF 관련 제약
- 실제 `installd` / `artd` 인터페이스
- 서비스 실행 시 필요한 Binder Context

각 항목에 대해 AOSP 근거, 현재 구현 위치, 테스트 방법, 우선순위를 기록한다.

**중요:** 실제 사용하지 않는 Binder 기능까지 무조건 구현하지 않는다. Android 16 Guest 부팅 및 대상 서비스 실행에 필요한 기능을 우선한다.

## 3. 실제 서비스 의존성 분석

Android 16의 `installd`와 `artd`를 각각 분석한다.

조사 항목:

1. 실행 파일과 초기화 방식
2. Init RC 정의
3. Binder 서비스 등록 이름
4. AIDL 인터페이스 및 메서드
5. 실행 시 필요한 시스템 속성
6. 필요한 파일시스템 및 Mount Namespace
7. 의존하는 Binder 서비스
8. SELinux 도메인과 권한
9. Host 서비스 접근 가능성
10. Guest 데이터 영역 변경 가능성

특히 `installd`와 `artd`가 Host의 `/data`, PackageManager, ART 데이터 또는 시스템 서비스를 잘못 사용하는 상황을 방지한다.

Host의 실제 `installd`와 `artd`는 절대로 종료하거나 재시작하지 않는다.

## 4. 호환성 기능 구현

Compatibility Matrix에서 실제로 필요하다고 확인된 기능만 구현한다.

구현 우선순위:

1. 기존 Binder ABI 호환성 문제
2. 실제 AIDL 인터페이스 호출 문제
3. Binder 객체 및 FD 전달
4. ServiceManager 호환성 문제
5. Calling Identity 및 접근 제어
6. 서비스 수명주기 관리

가능하면 기존 `rsbinder` 및 AOSP 구현을 재사용한다.

독자적인 Binder 프로토콜이나 새로운 IPC 계층을 불필요하게 만들지 않는다.

각 기능은 독립적인 회귀 테스트를 포함한다.

## 5. 실기기 검증

기존 Phase 3 실험 환경을 활용한다.

검증 순서:

1. 기존 Phase 3 테스트 재실행
2. 새로 구현한 Binder 기능의 단위 테스트
3. Native AIDL 테스트 서비스 실행
4. 실제 Android 16 AIDL 인터페이스를 사용하는 격리된 테스트
5. ServiceManager 등록·조회 및 재연결 검증
6. SELinux Enforcing 환경 검증
7. Host Binder 격리 및 시스템 서비스 상태 확인

SELinux 권한 부족이 발견되면 Phase 3에서 검증한 KernelSU Runtime 최소 정책 방식을 사용할 수 있다.

조건:

- 실제 거부 원인을 확인할 것
- 최소 권한만 허용할 것
- 전체 Permissive 전환 금지
- 영구 정책 변경 금지
- 적용 전후 정책 상태 기록
- 테스트 종료 후 정책 원복

정책 변경과 Binder 구현 오류를 구분해서 기록한다.

## 6. 실제 installd/artd 실행에 대한 제한

Phase 4에서는 실제 Guest `installd` 또는 `artd`를 실행하는 작업을 기본 범위에 포함하지 않는다.

먼저 다음 조건을 만족해야 한다.

- Guest Mount Namespace의 경계 확인
- Guest 전용 `/data` 사용 보장
- Host 데이터 변경 가능성 차단
- Host Binder와 Guest Binder 분리 확인
- 서비스 의존성 파악
- SELinux 정책 변경 범위 확인

실제 서비스 실행에 필요한 조건이 충족되더라도, 실행은 후속 Phase로 분리한다.

단, Host 데이터를 변경하지 않는 읽기 전용 바이너리 분석과 격리된 AIDL 호환성 테스트는 허용한다.

## 7. 결과물

다음 문서를 작성한다.

- `docs/rsbinder-phase4-plan.md`
- `docs/rsbinder-phase4-compatibility.md`
- `docs/rsbinder-phase4-results.md`

호환성 문서에는 다음 표를 포함한다.

| 기능 | Android 16 요구사항 | 현재 지원 | 실기기 검증 | 후속 조치 |
|---|---|---|---|---|
| Binder Transaction | 조사 | 조사 | 조사 | TBD |
| Oneway | 조사 | 조사 | 조사 | TBD |
| FD Transfer | 조사 | 조사 | 조사 | TBD |
| Calling Identity | 조사 | 조사 | 조사 | TBD |
| ServiceManager | 조사 | 조사 | 조사 | TBD |
| Stable AIDL | 조사 | 조사 | 조사 | TBD |

문서에는 실제 코드 위치와 근거를 함께 기록한다.

## 8. 완료 기준

다음 조건을 모두 만족하면 Phase 4를 PASS 처리한다.

1. Android 16 대상 서비스의 Binder 의존성 조사가 완료된다.
2. 핵심 Binder 호환성 요구사항이 분류된다.
3. 구현 범위에 포함된 필수 호환성 기능이 검증된다.
4. 실제 AIDL 호환성 테스트가 통과한다.
5. Host Binder 격리가 유지된다.
6. 기존 Phase 1~3 회귀 테스트가 통과한다.
7. SELinux 정책 변경 사항이 원복된다.
8. Phase 5에서 실제 `installd` 또는 `artd`를 실행하기 위한 구체적인 조건이 정리된다.

결과를 `PASS`, `PARTIAL`, `BLOCKED`, `FAIL` 중 하나로 판정한다.

## 작업 원칙

- SSAL의 기존 구조를 최대한 유지한다.
- 검증된 Phase 3 구현을 불필요하게 리팩터링하지 않는다.
- Android 16에서 실제 필요한 기능을 우선한다.
- Host 시스템 서비스 및 데이터 영역을 보호한다.
- SELinux 문제를 Binder 구현 실패로 간주하지 않는다.
- 기능을 추측해서 구현하지 않고 AOSP 근거를 확인한다.
- 실행하지 않은 테스트를 PASS 처리하지 않는다.
- 구현 범위가 지나치게 커지면 후속 Phase로 분리한다.

**핵심 목표는 Private Binder의 기능을 무작정 확장하는 것이 아니라, 실제 Android 16 Guest 서비스 실행에 필요한 호환성의 최소 집합을 확보하는 것이다.**