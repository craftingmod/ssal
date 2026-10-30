# 게스트 서비스 실행 계약

결정일: 2026-10-31. 계약 이름: `isolated-userspace-v1`.

이 문서는 SSAL의 목표 서비스 실행 방식을 확정한다. [기계 판독 정의](../module/profiles/services/initial.json)는 빌드 시 포함하고 모듈에 참고용으로 배포한다. [검증 코드](../src/service_contract.rs)는 형식·경로·도메인·의존성을 검사하고 prepare에서 기동 차단 사유를 출력한다. 설치된 JSON을 수정해 서비스를 활성화하는 기능은 없다.

**현재 구현은 계약 검증과 진단까지다.** 게스트 property server, private framework Binder 구성, HAL 중계, 서비스 런처와 복구 엔진은 아직 구현하지 않았다. `launch_enabled=false`이며 이를 true로 바꾼 계약도 현재 검증기는 거부한다. shell probe 통과로 서비스를 자동 실행하지 않는다. `switch`·`return`도 계속 거부한다.

## 1. 현재 상태와 목표

| 대상 | 현재 prepare | 서비스 실행에 적용할 목표 |
|---|---|---|
| framework Binder | 호스트 장치 공유 | 세션 전용 Binder 컨텍스트와 guest servicemanager |
| properties | 호스트 영역 공유, 서비스 소켓 가림 | 게스트 전용 영역·서버·초기값·영속 저장소를 한 세트로 구성 |
| HAL | 연결·부작용 미검증 | 인터페이스별 명시적 호스트 중계. 기본 허용 목록은 비어 있음 |
| 프로세스 도메인 | shell probe에서 실제 컨텍스트 관찰 | 서비스별 실행 전이 조건과 실행 후 실제 도메인 검증 |
| 서비스 관리 | 서비스 미기동 | ssald의 전용 supervisor가 명시한 서비스만 감독 |
| Android init | 실행 안 함 | 초기 단계에서는 직접 실행하거나 rc 전체를 자동 import하지 않음 |

이 계약은 framework와 userdata 서비스를 게스트에서 소유하는 방식을 선택한다. 호스트 installd/artd로 우회하거나 게스트 데이터를 호스트 `/data/app`, `/data/user*`에 역방향 bind하지 않는다. 커널·UID 공간·SELinux 정책은 공유하며 적대적인 guest root를 가정한 보안 격리를 보장하지 않는다.

## 2. Property 계약

게스트 property 환경은 다음 네 요소가 모두 준비된 뒤 사용할 수 있다.

- 게스트 전용 `/dev/__properties__` 메모리 영역과 Bionic이 요구하는 property-info·serial 구조.
- 해당 영역에 쓰는 전용 property server와 그 서버의 소켓·프로토콜. 호스트 영역과 게스트 서버를 조합하지 않는다.
- 게스트 이미지 버전에 맞춘 초기 property 파일 로딩·파생 속성 생성 규칙. 각 값의 출처를 기록한다.
- 게스트 `/data/property` 영속 저장소와 property_contexts·접근 권한 정책.

초기값은 게스트 root에서 해석한 system/system_ext/product 등의 property 파일을 사용한다. 이미 선택한 vendor/odm의 정적 property 파일은 파티션별 소유권·호환성을 검증해 반영한다. 구체적인 파일 우선순위·레거시 경로·파생 속성은 대상 이미지 버전의 Android 규칙을 따른다. import 경로가 게스트 root 밖으로 빠지면 거부한다. 호스트의 실행 중 property 영역 전체를 복사하지 않는다.

| 종류 | 처리 |
|---|---|
| framework 빌드·API 속성 | 게스트 이미지에서 초기화. 호스트 Android 버전 값을 기본값으로 사용하지 않음 |
| 장치의 동적·boot 속성 | 기기 프로파일에 정확한 이름·출처·타입·갱신 방식이 있는 값만 명시적 도입. 현재 허용 목록은 비어 있음 |
| 게스트 `ro.*` | 초기화 완료 후 변경 거부. 호스트 read-only 속성은 수정하지 않음 |
| 게스트 `persist.*` | 권한 검사 후 게스트 `/data/property`에만 기록 |
| 게스트 `ctl.*` | 호스트 init으로 전달하지 않음. 향후 guest supervisor의 선언된 서비스 작업에만 로컬 매핑하며 나머지는 거부 |
| `sys.powerctl`·물리 장치 제어 | 호스트 전원 제어로 전달하지 않음. 지원되는 세션 종료 요청은 별도 관리 프로토콜로 처리 |
| 호스트 property 쓰기 | 현재 허용 없음. 향후 지원은 ssald의 정확한 이름별 허용 목록과 사전 journal·복원 검증을 요구 |

서버는 peer UID/GID와 SELinux 컨텍스트를 확인하고 property_contexts에 따른 검사를 수행해야 한다. property 접근용 타입이 공유 커널 정책에 없거나 현재 정책과 불일치하면 기동을 허용하지 않는다. guest init을 실행해 이 문제를 우회하지 않는다.

## 3. Binder·HAL 계약

framework Binder는 별도 binderfs/장치로 만든 독립 컨텍스트를 사용하고 guest servicemanager가 그 컨텍스트만 소유한다. 장치 노드를 복제하거나 이름만 바꾸는 것은 컨텍스트 분리가 아니다. 서로 다른 노드의 stat 값만으로 독립성을 통과 판정하지 않는다. 게스트에서 등록한 시험 서비스가 호스트 레지스트리에 나타나지 않는지와 반대 방향도 별도 검증해야 한다.

호스트 HAL은 호스트가 계속 소유한다. 게스트에 호스트 Binder 장치나 servicemanager를 직접 노출하는 것을 정상 서비스 구성으로 삼지 않는다. AIDL HAL이 호스트 framework Binder에 있을 수 있으므로 `/dev/hwbinder`만 연결해도 해결된다고 가정하지 않는다.

HAL 연결은 인터페이스별 중계로 정의한다. 기기 프로파일에 인터페이스·인스턴스·프로토콜 버전, 필요한 호출·콜백·FD 전달, SELinux 권한, 전역 장치 상태의 변경·복원 방법을 기록해야 한다. 서로 다른 Binder 컨텍스트 사이에서 객체·콜백을 자동으로 투명 전달할 수 있다고 가정하지 않는다. 각 중계의 구현과 시험 결과가 필요하며 현재 허용 목록은 비어 있다.

게스트 서비스의 호스트 Binder 등록은 금지한다. 호스트 HAL·servicemanager를 이름 기반으로 종료하지 않으며 host 서비스 정지를 충돌 회피의 기본 수단으로 사용하지 않는다. 중계에서 요구하는 전역 변경은 ssald가 별도로 소유·기록한다.

## 4. 서비스별 실행 계약

JSON의 목록은 최초 서비스군의 의존성을 정의한 것이다. 모든 Android 부팅 서비스를 나열한 완성된 init.rc가 아니다. 실제 실행에는 해당 이미지·기기에서 검증한 executable, argv, 환경 변수, UID/GID·보조 그룹, capabilities, rlimit, cgroup, socket·FD와 라벨을 포함하는 `execution_spec`이 추가로 필요하다. 현재 이 명세는 미구현이며 값이 없으면 실행할 수 없다.

| 서비스 | 시작 조건의 선행 서비스 | 목표 도메인 | 주요 추가 조건 |
|---|---|---|---|
| property_service | 없음 | `ssal_property` | private area, 프로토콜·접근 정책. `/run/ssal/property-service`는 향후 구현할 경로 |
| servicemanager | property_service | `servicemanager` | private framework Binder |
| installd | servicemanager | `installd` | 게스트 데이터 라벨·암호화 정책 |
| artd | installd | `artd` | 게스트 코드·프로필 쓰기와 dexopt 권한 |
| vold | servicemanager | `vold` | 제한된 fstab·블록 접근·uevent·볼륨 소유권과 metadata 정책 |
| zygote | artd, vold | `zygote` | VINTF·HAL·FUSE/앱 저장소 뷰와 권한 |
| system_server | zygote | `system_server` | zygote의 자식으로만 실행하며 별도 직접 exec하지 않음 |

도메인 표기는 `u:r:<domain>:s0`이다. `ssal_property`는 목표 정책 이름이며 현재 모듈에서 생성·허용한 타입이 아니다. 나머지 Android 도메인도 호스트와 전역 정책을 공유하므로 이름이 존재한다는 사실만으로 실행·데이터 접근이 허용된다고 판정하지 않는다.

실행 전에는 파일 라벨·domain transition 규칙·자격 증명·socket spec을 검증한다. 실행 후에는 실제 서비스 PID의 `/proc/<pid>/attr/current`, UID/GID, namespace/root, 전용 Binder 등록과 상태 검사를 확인한다. `ksu`·`su`·`magisk` 관리 도메인에서 성공한 shell이나 같은 도메인명의 호스트 프로세스를 게스트 서비스의 증거로 사용하지 않는다. 전역 permissive 전환은 허용하지 않는다.

`may_spawn`과 `ready`를 구분한다. 실행 전 조건이 충족되어도 실제 도메인·서비스 등록·상태 검사까지 성공해야 ready다. 실패한 서비스는 게스트 의존 서비스의 시작을 허용하지 않는다. 현재는 모든 서비스가 `may_spawn=false`, `actual_service_domain=not_started`다.

## 5. 데이터·검증 증거

계약의 `write_paths`는 게스트 root 기준 허용 후보이며 현재 쓰기 권한을 부여하는 정책은 아니다. 실제 spec은 이 범위 안에서 더 좁혀야 하고 데이터·장치·SELinux 권한의 별도 검증을 요구한다. `/metadata`는 필요성을 확인해 게스트 전용 저장소 또는 사용하지 않는 정책을 명시해야 한다. 현재의 빈 RO tmpfs를 vold/FBE의 최종 구성으로 간주하지 않는다.

fscrypt 비교는 정책과 키 식별자의 같음·다름만 알려 준다. 해당 키의 CE/DE 소속·잠금 해제 수명주기와 guest vold의 호환성은 별도 증거가 필요하다. VINTF는 guest framework와 선택한 vendor/odm, 기기별 property·kernel 입력을 명시해 검사해야 한다. 현재 prepare의 도구 기본 입력 결과만으로 서비스 기동 조건을 충족하지 않는다.

모든 증거는 boot ID, 세션 ID, 이미지 해시, 프로필, namespace/root identity, 정책·execution spec 버전에 묶는다. 정리된 prepare 세션의 성공 결과를 새 서비스 세션의 권한으로 재사용하지 않는다.

## 6. 종료·실패·호스트 복구 계약

1. 호스트 상태를 변경하기 전에 ssald가 host namespace/root 참조와 변경 대상의 원래 상태·복원 동작을 journal에 확정한다. 기록 또는 복원 가능성 확인에 실패하면 변경하지 않는다. 현재 host property/HAL 허용 목록은 비어 있으므로 그런 변경은 수행하지 않는다.
2. 서비스는 supervisor가 PID·시작 시각/pidfd, 세션과 프로세스 그룹 소유권을 추적한다. 새 작업과 zygote의 추가 spawn을 막은 뒤 의존성 역순으로 정지한다. 이름 기반 pkill은 사용하지 않는다.
3. 먼저 종료 신호와 유한한 대기를 적용한다. 시간 초과 시 추적한 게스트 프로세스만 강제 종료한다. 그룹 전체 종료는 모든 구성원이 해당 세션 소유임을 확인한 전용 그룹에만 사용하며, 공유 그룹이나 zygote 자식은 pidfd/검증한 개별 PID로 처리한다.
4. 앱·ART·미디어 작업과 쓰기를 멈추고 필요한 flush를 확인한다. 프로세스·FD·namespace 참조가 남아 있는 mount를 lazy unmount해서 복구 성공으로 보고하지 않는다. 게스트 mount와 loop는 의존성 역순으로 해제하고 실제 잔여 상태를 확인한다.
5. host 중계·서비스·property·장치 상태는 journal의 변경 항목만 역순으로 복원하고 실제 결과를 검증한다. 호스트 전체 서비스를 일괄 restart하거나 스냅샷에 없는 상태를 덮어쓰지 않는다. namespace 복원이 서비스·전역 상태의 복원을 대신하지 않는다.
6. 정지·해제·복원이 실패하면 `RECOVERY_REQUIRED`로 기록하고 새 전환을 차단한다. userdata와 복구 journal을 보존한다. 재부팅으로 namespace FD가 무효화된 경우 이를 복원된 세션으로 간주하지 않는다.

계약은 단계적 supervisor 기동을 선택하며 일반 Android init 직접 실행은 보류한다. 향후 init 도입은 PID 1·property server·rc trigger·호스트 전역 상태의 소유권을 별도 설계한 뒤 다룬다.

## 7. 적용 범위와 확인 방법

`ssal prepare PROFILE_NAME`은 강화한 진단 뒤 계약 이름, 목표 property/Binder 방식, 서비스 시작·종료 순서, 각 실행 파일의 라벨·목표 도메인·차단 조건을 출력한다. 이는 계약 점검이며 해당 서비스를 시험 기동하는 기능이 아니다. `ssal doctor PROFILE_NAME`은 기본 서비스 차단 상태를 표시한다.

현재 회귀 테스트는 의존성 순서·순환·누락, 관리 도메인 재사용, 경로 이탈과 launch/host ctl 허용의 우발적 활성화를 거부하는지 확인한다. 실제 private property/Binder·HAL·서비스 도메인의 구현 성공을 검증한 것은 아니다.

참고: [AOSP property 초기화](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/property_service.cpp), [VINTF 검사 인자·종료 코드](https://android.googlesource.com/platform/system/libvintf/+/main/check_vintf.cpp), [기존 아키텍처](architecture.md).
