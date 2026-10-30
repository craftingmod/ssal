# `probe-servicemanager` 구현 계획 — Binder Test B

상태: 계획이며 명령·서비스 런처는 아직 구현되지 않았다. [Test A](binder-probe.md)의 독립 Binder IPC 결과를 기반으로, 새 세션에서 AOSP servicemanager와 서비스 등록·조회·호출을 검증한다.

운영 서비스의 `launch_enabled=false`와 기존 선행 조건은 유지한다. Guest property service 없는 제한 시험은 운영 서비스 기동이나 `properties_ready`의 통과가 아니다. Android init·HAL·다른 운영 서비스는 실행하지 않는다.

## 1. Host property 불변성

- 실행 전에 Guest의 property 쓰기 경로를 검사한다. `servicemanager.ready`, `ctl.*`를 포함한 모든 property 요청이 Host property service로 전달되지 않도록 Guest 소켓 뷰와 상속 FD를 차단한다. 라이브러리의 대체 접속 경로도 확인한다. 환경 변수 변경이나 하나의 소켓 경로 부재만으로 차단을 통과시키지 않는다.
- 차단 검증은 Host에 실제 변경 요청을 보내는 방식으로 수행하지 않는다. Guest에서 관찰한 경로·FD·접속 결과와 대상 이미지의 property 클라이언트 동작을 증거로 기록한다. 차단을 입증할 수 없으면 servicemanager를 실행하지 않는 fail-closed 동작을 적용한다.
- 읽는 property 영역의 출처와 공유 여부도 기록한다. Host 영역을 읽는 제한 시험을 Guest property 초기화 완료로 판정하지 않는다.
- Host namespace에서 시험 전·후 property 상태를 비교한다. 정상 종료뿐 아니라 timeout·비정상 종료·부분 실패 후에도 비교한다. 전후 수집 실패나 차이는 `property_host_unchanged` 통과를 허용하지 않는다. Host의 독립적인 변경 가능성은 실패 상세에 기록하며 임의로 무시하거나 자동 복원하지 않는다.
- `ctl.*`는 일반 property 목록의 전후 비교만으로 전달 여부를 증명할 수 없으므로, 전달 경로 차단 증거를 반드시 별도로 요구한다. 전후 값이 같다는 사실도 중간 변경이 없었다는 증명이 아니다.
- Property 값 원문은 일반 로그에 남기지 않는다. 비교 결과·변경된 이름·수집 및 차단 증거를 기록한다.

## 2. 실행 자격과 SELinux 전환

- 대상 이미지의 AOSP rc를 확인해 UID/GID/보조 그룹을 실행 명세에 고정한다. Android 16 기준은 `user system`, `group system readproc`이며, 실제 적용 결과까지 검사한다. capabilities·환경·FD·rlimit 등 필요한 실행 조건도 명시한다.
- 실행 파일 라벨, 전환 가능성, Binder 노드 접근, SELinux 상태·설정 파일 접근을 사전 검사한다. 파일 라벨만으로 도메인 전환 성공을 판정하지 않는다.
- 실행 후 추적한 servicemanager PID의 실제 `/proc/<pid>/attr/current`가 정확히 `u:r:servicemanager:s0`인지 확인한다. `u:r:ksu:s0` 또는 다른 도메인이면 실패하고 후속 시험을 중단한다.
- UID/GID/보조 그룹, root·namespace identity, 실제 Binder FD가 해당 세션의 private 장치인지 확인한다. 같은 도메인의 Host 프로세스를 Guest 실행 증거로 사용하지 않는다.
- SELinux Enforcing을 유지한다. 정책 변경·타입 추가·allow 규칙·permissive 변경을 별도 사용자 승인 없이 자동 적용하지 않는다. 필요한 정책이 없으면 차단 사유와 필요한 변경안을 보고하고 시험을 중단한다.

## 3. 서비스 권한과 호출 판정

각 단계는 서비스 이름·실행 주체·UID/SID·대상 Binder identity와 연결해 기록한다.

| 판정 | 필요한 구분 근거 |
|---|---|
| `name_mapping_absent` | 실제 사용한 service_contexts에서 이름 매핑을 찾지 못함 |
| `add_denied` | 이름 매핑은 있으나 등록 주체의 `add` 권한이 거부됨 |
| `find_denied` | 조회 주체의 `find` 권한이 거부됨 |
| `not_registered` | 매핑과 `find` 허용, 정상 조회 경로를 확인했으나 서비스가 없음 |
| `transaction_failed` | Binder 통신 또는 조회 후 시험 호출이 실패함 |
| `passed` | 등록·별도 클라이언트 조회·nonce 응답과 서버 identity가 모두 일치함 |
| `unavailable` | 권한·매핑·통신 증거가 부족해 원인을 구분할 수 없음 |

단순 null 반환·일반 오류 코드만으로 `not_registered`나 격리 성공을 판정하지 않는다. 실효 정책·매핑·접근 검사와 필요한 감사 증거를 수집하며, 원인이 불명확하면 통과시키지 않는다. 시험 이름은 세션별 고유 이름을 사용하고 기존 Host 서비스 이름으로 등록하지 않는다.

## 4. 양방향 레지스트리 격리

- Host 조회기는 Host namespace/root의 Host Binder에서, Guest 조회기는 검증한 Guest private Binder에서 각각 fresh exec한다. Binder FD·ProcessState·객체를 두 컨텍스트 사이에서 재사용하지 않는다.
- Guest에서 시험 서비스를 등록하고 Guest 클라이언트의 조회·호출 성공을 양성 대조군으로 확인한다. 이후 Host에서 같은 이름의 `find`가 허용된 것을 확인하고 미등록인지 검사한다.
- Host에서 조회 가능한 정상 서비스를 선택해 Host 조회 성공을 양성 대조군으로 확인한다. 이후 Guest에서 같은 이름의 매핑·`find` 허용을 확인하고 미등록인지 검사한다. 대조군 조회는 읽기 전용으로 수행한다.
- 부재 조회에는 lazy-start를 요청하지 않는 `checkService`를 사용한다. 대조군 실패, 이름 매핑 부재, `find` 거부, 통신 실패는 비노출 증거로 인정하지 않는다.
- 양방향 모두 권한이 확인된 미등록 결과를 얻었을 때만 `host_registry_isolation=passed`로 기록한다. 한 방향이라도 미검증이면 전체 격리를 통과시키지 않는다.

## 5. 프로세스 수명과 정리

- servicemanager, 시험 서버, 각 Guest·Host 클라이언트를 개별 추적한다. PID와 시작 시각 또는 pidfd, 역할, 세션 소유권을 기록하고 이름 기반 종료는 사용하지 않는다.
- 프로세스 생성 직후부터 추적하며 실행 중 종료·준비 timeout·등록 실패·호출 실패를 감지한다. 정상 종료, timeout, 비정상 종료, 부분 실행 실패 모두 같은 정리 경로로 진입한다.
- 새 실행과 요청을 중단하고 클라이언트 → 시험 서버 → servicemanager 순으로 종료한다. 유한한 TERM 대기 후 소유권이 확인된 잔여 프로세스에만 KILL을 적용한다. 시험이 만든 자식도 추적하고 종료·회수 및 namespace/FD 참조 해제를 확인한다.
- 모든 시험 프로세스의 종료가 확인된 다음 Binder FD, alias bind, binderfs와 rootfs mount, 세션 loop backing을 의존성 역순으로 해제한다. 기존 헬퍼의 종료나 그룹에 신호를 보낸 사실만으로 전체 프로세스 종료를 간주하지 않는다.
- 종료를 확인할 수 없으면 정상 mount 해제를 계속하지 않고 `cleanup=failed`와 잔여 소유 자원을 기록한다. lazy unmount로 성공을 만들지 않는다. Host property 사후 비교 등 독립적으로 수행 가능한 검사는 계속한다.
- 정리 실패는 전체 시험 실패이며 `RECOVERY_REQUIRED`로 기록하고 새 시험·전환을 차단한다. 실패 증거와 복구에 필요한 소유 자원 정보를 보존한다.

## 6. 결과와 성공 조건

다음 필드는 `passed/failed/not_run/unavailable`로 독립 기록하고 단계별 사유를 별도로 보존한다.

| 필드 | 통과 조건 |
|---|---|
| `servicemanager` | Guest 바이너리·root·private Binder identity가 확인되고 실제 서비스 등록·조회·호출 성공 |
| `android_service_selinux` | 올바른 실행 자격과 실제 `u:r:servicemanager:s0`, Enforcing 확인 |
| `host_registry_isolation` | 권한·양성 대조군을 확인한 양방향 미등록 |
| `property_host_unchanged` | Host 전달 차단 증명과 시험 전후 Host property 비교 모두 통과 |
| `cleanup` | 모든 시험 프로세스 종료·회수 및 추적한 Binder·mount·loop 자원 해제 확인 |

실행 전 차단 실패는 해당 필드에 `failed`로 기록하고 미실행 단계는 `not_run`으로 남긴다. 실행·검사는 시도했지만 필요한 증거를 얻지 못한 단계는 `unavailable` 또는 확인된 실패로 기록하며 통과로 변환하지 않는다. 전체 성공에는 위 다섯 필드가 모두 `passed`여야 한다.

증거에는 boot ID·세션 ID·이미지 해시·실행 명세 버전·정책 식별 정보를 포함한다. 결과 범위는 제한된 Test B이며 운영 서비스 `launch_enabled=false`와 property/HAL 관련 차단을 해제하지 않는다.

## 구현 순서와 검증

1. 결과 모델과 실행 명세, 사전 차단 판정을 추가한다.
2. Host property 수집·차단 증명과 실행 자격·SELinux 사전 검사를 구현한다.
3. 개별 프로세스 감독·공통 실패 정리 경로를 구현한다.
4. 새 Binder 세션에서 servicemanager와 등록 서버·클라이언트를 실행한다.
5. 권한 원인 구분과 양방향 대조군 검사를 추가한다.
6. 기기에서 정상 경로와 차단 불명·도메인 불일치·권한 거부·timeout·부분 실행·정리 실패 경로를 검증한다. Property 차단 검증을 위해 Host 변경 요청을 실제 전송하지 않는다.

자동 검증은 null/권한 거부의 격리 성공 오판 방지, 일부 필드만 통과한 전체 성공 거부, 실패 단계별 공통 정리 진입과 자원 해제 순서를 포함한다. 정책 변경이 필요한 기기 검증은 변경안에 대한 별도 승인 이후 수행한다.
