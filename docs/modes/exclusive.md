# Exclusive Mode

Exclusive Mode의 책임은 실행 중인 순정 커널에서 Host Framework를 중지하고 필수 물리 HAL을 Guest에 인계해 Guest를 독점 실행한 뒤, 반환 시 Host Framework와 장치 상태를 복원하는 것이다. Guest의 Init, Binder, Property, SELinux, mount, userdata, 프로세스 감독은 [SSAL Core Runtime](../architecture.md)이 제공한다.

물리 HAL의 소유권, 시작·중지 순서, 원복 순서는 Exclusive Mode의 기기별 설정에 속한다. Host 측 사용자나 서비스와 충돌하는 인터페이스는 Guest에 넘기기 전에 Host 사용을 종료한다. Guest 종료 시 장치 소유권을 Host에 돌려주고, 변경한 Host 서비스와 전역 상태를 journal에 따라 복원한다.

이 문서는 목표 설계다. 현재 Exclusive Mode의 실행 코드, 기기 프로필, HAL 의존성은 배포물에 없으며, 기존 `switch`와 `return`은 차단돼 있다.

## 전환 상태 머신과 복구

```text
HOST_ACTIVE
    ↓
PREPARING          이미지 검증, userdata mount, guest namespace 구성
    ↓
GUEST_READY        마운트와 서비스 사전 검사
    ↓
SWITCHING          호스트 서비스 정지, 게스트 서비스 시작
    ↓
GUEST_ACTIVE
    ↓
RETURNING         게스트 종료, 호스트 서비스 복원
    ↓
HOST_ACTIVE

실패 → ROLLING_BACK → HOST_ACTIVE
                   └→ RECOVERY_REQUIRED
```

전환 작업은 하나씩 실행하고 각 단계의 완료와 보상 작업을 journal에 기록한다.

1. 이미지 무결성, 기기 프로파일, 저장 공간과 필수 자산을 검증한다.
2. 호스트 Zygote 중지 전에 게스트 준비를 최대한 끝낸다.
3. 호스트 서비스 상태와 변경할 전역 상태를 기록한다.
4. 기기 프로파일의 의존성 순서에 따라 호스트 서비스를 중지한다.
5. 게스트 서비스를 시작하고 제한 시간 안에 프레임워크와 필수 기능의 정상 동작을 확인한다.
6. 실패하면 시작한 게스트 서비스와 mount를 정리하고 호스트 상태를 복원한다.

정상 복귀에서도 게스트의 쓰기를 멈추고 프로세스 종료를 확인한 뒤 mount를 의존성 역순으로 해제한다. 이름 기반 `pkill` 대신 세션에서 추적한 프로세스와 프로세스 그룹을 대상으로 한다. pidfd를 지원하지 않는 커널의 대체 경로는 PID 재사용 검사를 포함해야 한다.

사용 중인 mount를 무조건 lazy unmount하여 정리가 끝났다고 처리하지 않는다. mount 참조와 프로세스가 남으면 원인을 기록하고 loop 장치도 성급하게 해제하지 않는다.

호스트 namespace 보존은 서비스와 전역 상태의 자동 복원을 뜻하지 않는다. 서비스·property·장치 상태 복구는 mount 복구와 별도로 구현한다. 복구할 수 없는 실패는 `RECOVERY_REQUIRED`로 보고하며 반복 전환을 막는다.

다음 재부팅은 기본적으로 OneUI로 시작한다. 실패한 게스트 자동 실행은 해제한다. 초기 구현에서는 게스트 자동 실행을 제공하지 않고 수동 전환부터 검증하는 것이 좋다.

