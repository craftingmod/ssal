# SSAL — LineageOS/GSI Hot-Switch Implementation Plan

> **Status:** Proposed · 2026-11-03  
> **Target:** 기존 One UI 커널을 유지한 채 LineageOS 23.2 (Android 16) GSI로 전환하고, 재부팅 없이 One UI로 복귀하는 SSAL  
> **Strategy:** OneOS의 *검증된 부팅 순서와 호환성 처리*는 참고하되, **Private Binder·Guest 전용 `installd`/`artd`·Guest `/data` 격리는 직접 구현**한다. SELinux Enforcing 호환화는 초기 부팅 이후로 미룬다.

## 0. 의사결정 요약

이 계획의 목적은 Android 서비스를 처음부터 완벽하게 격리하려다 첫 부팅이 무기한 지연되는 상황을 피하는 동시에, Guest 프로세스가 Host 앱 데이터에 접근하거나 Host 서비스가 Guest 요청을 Host 데이터에 실행하는 위험을 구조적으로 차단하는 것이다.

**변경할 것**

- OneOS의 `guest_prepare.sh`, `guest_start.sh`, 전환/복귀 스크립트, Framework 패치 카탈로그에서 **부팅 순서·필수 마운트·APEX/링커 구성·Zygote 실행 방법**을 분석해 적용한다.
- Guest 부팅 초기 단계에서는 SELinux **Permissive를 진단용으로 허용**한다. 단, Permissive가 마운트 또는 IPC 격리를 대체하지 않는다.
- 전체를 한꺼번에 구현하지 않고 독립적인 검증 단계와 통과 조건을 설정한다.

**유지할 것(완화 금지)**

- 별도 `binderfs` 인스턴스와 Guest용 `/dev/binder` 및 Guest `servicemanager`.
- Guest 전용 `installd`·`artd`. Host 데몬을 Guest의 PackageManager 요청 대상으로 사용하지 않는다.
- 기존 SSAL의 별도 loop ext4 Guest `/data`; Host `/data/media` 포함 어떠한 Host 사용자 데이터도 Guest에 직접 노출하지 않는다.
- Guest가 Host `Gatekeeper`, `Weaver`, `KeyMint` 등 인증·키 관리 서비스에 직접 쓰기 작업을 하지 않도록 차단한다.
- Host 데이터/서비스/프로세스를 변경하기 전에 검증하고, 실패 시 **중단(fail closed)** 한다.
- 기존 `doctor`, `status`, `logs`, `add`, `create`, `switch`, `return` 인터페이스와 검사·복구 구조를 가능한 한 유지한다.

**첫 부팅 목표에서 제외할 것**

- Guest 전용 모든 HAL 구현, 범용 Vendor AIDL 프록시, 통화·카메라·지문·Bluetooth 등 비필수 주변 기능.
- 완전한 SELinux Enforcing, 모든 Android 버전 및 모든 삼성 기기에 대한 범용 지원.
- 잠금 화면/자격 증명 등록, Host 인증 HAL 공유, 멀티유저 지원, Guest의 Host 저장소 접근.
- LineageOS GSI 자체의 대규모 수정. 먼저 기존 이미지를 유지하고, 필요한 패치는 외부 overlay/bind mount로 제한한다.

## 1. 시스템 경계와 불변식

```text
                    One UI Host (계속 실행되는 커널)
             ┌──────────────────────────────────────┐
             │ Kernel / hardware / Host vendor HAL  │
             │ Host /data + Host installd/artd      │
             │ Host binder + Host servicemanager    │
             └──────────────────────────────────────┘
                       │          │
          HIDL 등 선별 공유       │ 명시적·최소 권한 HAL 브리지
                       │          │ (필요한 경우에만)
             ┌──────────────────────────────────────┐
             │ SSAL Guest mount namespace           │
             │ GSI /system (ro) + Guest /data (ext4) │
             │ Guest binderfs + Guest servicemanager│
             │ Guest zygote / system_server         │
             │ Guest installd / artd                │
             └──────────────────────────────────────┘
```

### 반드시 유지할 불변식

1. **Host 앱 데이터 불변:** Guest 설치·삭제·DEX 최적화·스토리지 작업은 Host `/data/app`, `/data/user*`, `/data/dalvik-cache` 및 사용자 파일을 변경해서는 안 된다.
2. **Binder 서비스 불변:** Guest `PackageManager`/`system_server`가 `installd`·`artd`를 조회하면 Guest 프로세스의 Binder 객체가 반환되어야 한다. Host Binder context의 동명 서비스가 보이면 실패 처리한다.
3. **마운트 전파 차단:** Guest의 마운트 생성·해제·bind가 Host mount namespace에 전파되면 안 된다. `mountinfo`와 propagation 속성으로 검증한다.
4. **실행 대상 식별:** Host/Guest Zygote 및 서비스 종료·시작은 PID만이 아니라 시작 시각, 실행 파일, SELinux context, mount namespace 등으로 식별해 Host 오인 종료를 방지한다.
5. **인증 경계:** Guest는 Host의 암호화 키·잠금 자격 증명·Weaver 슬롯을 소유하거나 변경하지 않는다. 첫 부팅에서는 Guest 잠금 설정을 사용하지 않는다.
6. **복구 가능성:** 실패한 세션에서 Guest 리소스를 해제하고 이전 SELinux 상태를 복원해야 한다. 안전한 in-place 복귀가 불가능하면 임의의 추가 수정보다 하드 재부팅을 선택한다.
7. **기본 차단:** 공유·브리지·패치는 예외 허용 목록으로만 추가한다. 경로 또는 서비스의 소유자가 불명확할 때는 실행하지 않는다.

> **주의:** Private Binder는 Binder 서비스 디스커버리를 분리할 뿐, 공유된 경로·소켓·속성 서비스·HAL을 통한 Host 변경 가능성을 자동으로 막지 않는다. SELinux 전역 Permissive에서도 위 불변식은 따로 검증해야 한다.

## 2. 참조 구현 활용 원칙

| 영역 | OneOS 활용 | SSAL 결정 |
| --- | --- | --- |
| 준비/전환 순서 | `oneos_switch.sh`, `guest_prepare.sh`, `guest_start.sh` 비교 | SSAL state machine에 순서와 사전 조건만 이식 |
| `/system`, APEX, linkerconfig | 마운트 구성 및 호환성 이슈 분석 | 기존 Guest namespace에서 재현·검증 |
| Zygote/Framework | 실제 부팅에 필요한 명령 및 우회 패치 확인 | LineageOS 23.2에 필요한 최소 패치만 적용 |
| Binder | 충돌 서비스·의존성 분석에 참고 | **Host servicemanager 재사용 금지** |
| `installd`/`artd` | 충돌·데이터 경로·보호 사례 참고 | **Host 데몬 재사용/Host `/data` 브리지 금지** |
| `vold`, 스토리지 | Guest 스토리지 서비스 분리 사례 참고 | Host 데이터 접근 경로 차단 후 최소 기능만 시작 |
| 인증 HAL | 피해 사례·차단 패치 참고 | Host Gatekeeper/Weaver/KeyMint 직접 호출·쓰기 금지 |
| SELinux | 초기 부팅 진단 순서 참고 | 초기 Permissive → 도메인별 분석 → Enforcing |
| 복귀 | 서비스 복원·실패 처리 순서 분석 | SSAL의 식별·트랜잭션·롤백 정책 유지 |

**작업 방법:** 각 기능을 가져올 때 `원본 위치 → 가져온 동작 → SSAL 적용 코드 → 차이점 → 검증 테스트`를 PR/커밋 기록에 남긴다. 원본 전체 스크립트의 무검증 이식은 금지하며, 라이선스·저작권 고지 조건을 확인한다.

## 3. 단계별 구현 계획

### Phase 0 — 현재 상태 고정 및 사전 진단

**목표:** 현재 동작 중인 Host에 영향을 주기 전, 복구 가능한 기준선을 확보한다.

- [ ] 기존 SSAL `dev`의 통과 테스트, `doctor`, dry-run, read-only snapshot 결과를 기준선으로 남긴다.
- [ ] 실제 Host 커널의 binderfs 기능, `/dev/binder*` 구성, SELinux 상태, mount propagation, Android/ART/APEX 버전을 수집한다.
- [ ] OneOS 참조 대상 커밋을 고정하고 해당 코드를 사용한 기능별 차이표를 작성한다.
- [ ] Guest GSI 해시/버전, Guest userdata loop ext4의 마운트 경로 및 백업/폐기 방법을 확인한다.
- [ ] Host의 중요 상태에 대한 읽기 전용 비교 기준을 마련한다(데이터 전체 해시가 아니라 테스트용 sentinel 및 선택된 경로의 메타데이터 등).
- [ ] 모든 위험 작업에 `preflight`/`dry-run`/단계별 상태 저장/타임아웃/중단 사유 로깅을 연결한다.
- [ ] 실제 기기에서 시험하기 전 중요한 데이터 백업 및 복구 수단을 확보한다.

**통과 조건:** 준비 단계는 Host 상태를 변경하지 않으며, 실패 시 `switch`가 Host Framework 중지 전에 중단한다.

### Phase 1 — Private Binder 격리 단독 검증 (최우선)

**목표:** Host Framework를 내리지 않은 상태에서 Guest Binder context를 생성·폐기할 수 있다.

- [ ] Guest mount namespace 내부에 **새 binderfs 인스턴스**를 마운트하고 `binder-control`을 통해 Guest 전용 Binder 장치를 생성한다.
- [ ] Guest `/dev/binder`를 새 장치로 연결한다. **Host의 기존 `/dev/binder`를 단순 bind mount하지 않는다.**
- [ ] Guest `servicemanager`를 Guest Binder 장치의 context manager로 시작하고 서비스 등록/조회 테스트를 실행한다.
- [ ] Host와 Guest 각각에서 동일 서비스명을 등록해도 상대 서비스를 조회할 수 없는지 확인한다.
- [ ] Host/Guest의 장치 ID, binderfs 인스턴스, mount namespace, 서비스 조회 결과를 진단에 기록한다.
- [ ] Guest Binder 장치나 `servicemanager` 시작 실패 시 Host와 Guest에 대한 변경을 최소화하고 즉시 중단한다.

**통과 조건:** Guest 서비스는 Guest에서만 조회되며 Host에 등록되지 않는다. Guest 중지 후 Host 서비스 목록과 Binder 기능이 정상이다.

> **검증 포인트:** 새 mount namespace와 새 Binder context는 별개다. 실제로 독립된 binderfs 인스턴스 및 Binder 장치가 생성되었음을 확인해야 한다.

### Phase 2 — Guest 데이터 및 `installd`/`artd` 독립

**목표:** 앱 설치·삭제와 ART 파일 생성 경로가 Host로 향하지 않음을 입증한다.

- [ ] Guest loop ext4 `/data`를 mount namespace 내부에만 마운트하고 필수 `data` 하위 경로/권한/라벨을 준비한다.
- [ ] Guest에서 보이는 `/data`의 실제 mount source를 확인한다. Host `/data` 또는 그 하위 사용자 데이터 경로가 우회 노출되지 않게 한다.
- [ ] Guest 전용 `installd`와 Android 16에 맞는 `artd` 실행 경로, APEX 의존성, UID/GID 및 서비스 등록 방식의 호환성을 확인한다.
- [ ] 두 프로세스가 Guest Binder에만 등록되는지 확인한다. Host `installd`/`artd` PID 및 서비스 등록은 그대로여야 한다.
- [ ] PackageManager, dexopt, 프로필/캐시 경로가 **Guest loop ext4 내부**에 속하는지 검증한다.
- [ ] Guest `/data`에서만 생성되는 sentinel과 설치·삭제·컴파일 테스트를 자동화한다.
- [ ] Host 경로 접근이 필요한 미해결 의존성을 발견하면 Host bind로 임시 해결하지 말고 명시적 이슈로 남긴다.

**통과 조건:** Guest 앱 설치·삭제 및 DEX 최적화 후에도 Host sentinel과 지정된 Host 경로의 상태가 변하지 않는다. Host `installd`/`artd`는 Guest IPC 요청을 수신하지 않는다.

> **중요:** Private Binder만 검증했다고 Phase 2 완료로 간주하지 않는다. 공유 UNIX 소켓, property service, volume 경로, 기타 Binder/HAL 진입점도 별도로 확인한다.

### Phase 3 — OneOS 기반 Mount/APEX/Zygote 경로 정렬

**목표:** 기존 LineageOS GSI를 가능한 한 그대로 사용하여 최소 Framework 부팅을 시도한다.

- [ ] OneOS의 준비·실행 순서를 SSAL의 `prepare → activate → start → validate` 상태 전이와 대응시킨다.
- [ ] Guest `/system`, `/system_ext`, `/product`, 필요한 `/vendor`/`/odm`, `/apex`, `/linkerconfig`, `/proc`, `/sys`, `/dev`를 **공유/격리/읽기 전용**으로 분류한다.
- [ ] Host Vendor 환경을 재사용하되 Host mount namespace의 `/system`/`/data`를 교체하지 않는다.
- [ ] APEX 및 linker 경로가 Guest `app_process`/`artd`/`system_server`와 호환되는지 검증한다.
- [ ] OneOS의 Zygote 기동 방식과 기존 SSAL의 Zygote PID/starttime/context/exe 동일성 검증을 결합한다.
- [ ] Host Framework 중지 전에 Guest 측 파일·프로세스·Binder·userdata 준비가 완료되었는지 재확인한다.
- [ ] LineageOS GSI 수정이 필요하면 원본 이미지를 유지하고 외부 overlay로 적용 가능한 **최소 패치**만 사용한다.
- [ ] Guest `zygote`, `system_server`, 필수 서비스의 생성 여부와 크래시/재시작 원인을 단계별로 기록한다.

**통과 조건:** Host Framework로부터 Guest Framework로 전환되어 Guest `system_server`가 시작되고 필수 서비스가 Guest Binder에서 조회된다. Host 데이터 격리 불변식이 유지된다.

### Phase 4 — HAL 의존성 해결 (필수 기능에 한정)

**목표:** 실제 부팅에 필요한 Vendor HAL만 선별적으로 연결한다.

- [ ] `system_server` 및 Native 서비스가 요청하는 HAL을 수집해 **HIDL(`hwbinder`) / Stable AIDL(`binder`) / socket / 직접 장치**로 분류한다.
- [ ] 공유 가능한 HIDL 서비스는 실제 영향 범위를 검토해 최소한으로 사용한다.
- [ ] Host 일반 Binder에 등록된 AIDL HAL은 Guest Private Binder에서 자동으로 보이지 않음을 전제로 한다.
- [ ] 필요한 AIDL HAL만 Host 측 어댑터 + Guest 측 프록시 등 **명시적 인터페이스 브리지**로 연결한다. Binder 핸들을 서로 다른 context에 직접 전달하는 방식은 사용하지 않는다.
- [ ] 브리지는 서비스·메서드·요청 방향별 allowlist를 적용한다. Host 데이터/인증 상태를 변경할 수 있는 메서드는 기본적으로 거절한다.
- [ ] Gatekeeper, Weaver, Host KeyMint, 계정·잠금·사용자 관리 호출은 첫 부팅에서 비활성화하고, 호출 시 추적 가능한 오류를 반환한다.
- [ ] GPU/디스플레이/입력 등 부팅 필수 HAL부터 해결하고 나머지는 후속 단계로 미룬다.

**통과 조건:** 필수 HAL이 연결되어 Guest UI가 표시되고 입력 가능하다. Host 인증·데이터 변경 경로가 추가되지 않는다.

### Phase 5 — 최초 완전 부팅 및 Host 복귀

**목표:** LineageOS 홈 화면 도달, 테스트 앱 설치, SSAL `return`으로 원복한다.

- [ ] 초기 시험에 한해 전역 SELinux Permissive를 허용한다. 단, 전환 전에 상태를 저장하고 별도의 실험 옵션으로 명시한다.
- [ ] Permissive에서도 Guest IPC/마운트/데이터 분리는 그대로 유지한다.
- [ ] Guest 부팅 후 홈 화면, 입력, 테스트 앱 설치/실행/제거, Guest 데이터 재진입 보존을 확인한다.
- [ ] `return`에서 Guest Zygote·서비스 종료 → Guest 마운트/브리지 정리 → Host Framework 복원 → SELinux 원상복구를 검증한다.
- [ ] 자동 복귀가 불안전할 때는 실패한 중간 상태를 계속 조작하지 말고 하드 재부팅 경로를 제공한다.
- [ ] 전환/복귀를 연속 반복하고 Host 앱·설정·저장소·서비스 무결성을 비교한다.

**통과 조건:** `Host → Guest → Host`가 최소 1회 재부팅 없이 완료되며, 이후 재진입도 가능하다. Guest 앱 데이터는 Guest loop ext4에만 남는다. 실패 시 안전한 복구 수단이 작동한다.

### Phase 6 — SELinux 정책 단계적 강화 (부팅 이후)

**목표:** Permissive 상태에서 수집한 AVC를 바탕으로 Host 정책을 최대한 유지하며 Enforcing으로 전환한다.

- [ ] 전역 `getenforce`와 Guest 프로세스별 SELinux domain을 기록한다. mount namespace가 SELinux domain을 자동 분리하지는 않는다는 점에 주의한다.
- [ ] Permissive 부팅 중 `avc: denied`/서비스 실패 로그를 수집하고 실행 도메인·대상 타입·클래스·권한별로 분류한다.
- [ ] AVC뿐 아니라 **누락된 Binder 서비스/미구현 HAL/잘못된 경로/속성 문제**를 별도 분류한다. SELinux 규칙 추가로 해결하려 하지 않는다.
- [ ] 가능하면 Guest 전용 domain만 permissive로 지정하고 Host Enforcing은 유지하는 중간 단계를 실험한다. 이를 위해 Host의 실제 sepolicy 수정 가능 범위를 먼저 검증한다.
- [ ] 필요한 `allow`/`type_transition`/`file_contexts`/`service_contexts` 등을 최소 범위로 작성하고 정적 검사·회귀 테스트를 수행한다.
- [ ] `audit2allow` 또는 AVC 일괄 허용 결과를 검증 없이 적용하지 않는다. `neverallow`, 서비스 이름 충돌, Host 데이터 경계는 별도 검사한다.
- [ ] 마지막으로 Guest/Host 모두 Enforcing 상태에서 부팅·복귀 시험을 반복한다.

**통과 조건:** SELinux Enforcing에서 필수 Guest 서비스가 정상 작동하고, Host 데이터 격리 및 복구 불변식이 유지된다. 전역 Permissive는 실험용 옵션으로만 남는다.

## 4. 개발 우선순위 및 의존성

```text
Phase 0 (기준선 / 복구 / preflight)
  └─► Phase 1 (Private Binder)
       └─► Phase 2 (Guest /data + installd/artd)
            └─► Phase 3 (OneOS 부팅 경로 + Zygote)
                 └─► Phase 4 (필수 HAL만 브리지)
                      └─► Phase 5 (첫 부팅 / 복귀)
                           └─► Phase 6 (SELinux Enforcing)
```

**우선순위 규칙**

- Phase 1~2의 격리 검증을 통과하기 전에는 Host Framework를 중지하는 실제 `switch`를 활성화하지 않는다.
- Phase 3~4는 필요한 종속성만 구현한다. 미구현 주변 기능 때문에 첫 부팅을 지연시키지 않는다.
- SELinux AVC는 처음부터 기록하지만, Enforcing을 맞추기 위한 대규모 정책 작업은 Phase 6까지 연기한다.
- 단계에서 실패한 경우 그 단계의 **최소 재현 테스트**를 우선 추가하고 재시도한다. 부팅 전체를 반복 실행하며 무작정 수정하지 않는다.

## 5. 구현·테스트 인터페이스

기존 CLI를 유지하며 다음과 같은 **개발용 진단 기능**을 논리적으로 추가한다. 실제 명령명은 현재 CLI 구조에 맞춰 결정한다.

| 기능 | 검증 내용 |
| --- | --- |
| `doctor` 확장 | binderfs, mount propagation, loop ext4, 커널 기능, SELinux, APEX/ART 호환성 |
| `switch --dry-run` | 단계별 계획 출력, Host/Guest 경로 충돌·부족 조건 검출, 실제 변경 금지 |
| Binder isolation test | Guest context manager 독립성, 동명 서비스 등록·조회·제거 |
| Daemon isolation test | Guest `installd`/`artd` PID·namespace·Binder 등록·데이터 경로 |
| Mount isolation test | Host mountinfo 변화 여부, Guest `/data`의 실제 backing source |
| Data contamination test | Guest 앱 설치/삭제/DEX 처리 후 Host sentinel 불변 |
| `logs` 확장 | 단계, PID identity, namespace ID, Binder 서비스, AVC, HAL 요청, 복구 결과 |
| `return` 검사 | Guest 종료·리소스 회수, Host Framework 및 SELinux 상태 복원 |

**CI / 정적 검사**

- Rust 단위 테스트와 기존 회귀 테스트 유지.
- 상태 전이, preflight 실패, 부분 적용 후 롤백, 경로 검증, PID 재사용, namespace 식별에 대한 자동 테스트 추가.
- OneOS 참조 코드의 변경 추적은 별도 파일/주석으로 관리하고 특정 버전을 pin 한다.
- 실제 Host 데이터를 수정하는 테스트는 CI 및 기본 dry-run에서 실행하지 않는다.

**실기기 시험 원칙**

- 첫 실기기 실행은 Host 서비스가 정상 실행 중인 **읽기 전용 진단 → 독립 Binder 실험 → Guest 데이터 실험** 순서로 진행한다.
- 소실 가능성이 있는 개인 데이터가 포함된 상태를 첫 격리 시험의 테스트 대상으로 사용하지 않는다. 완전한 백업·복구 경로를 확보한다.
- Host 데이터 오염 징후, Host Binder 서비스 변경, 마운트 전파, 인증 HAL 접근 또는 예상치 못한 전역 상태 변경이 발생하면 즉시 테스트를 중단한다.

## 6. 주요 리스크와 대응

| 위험 | 대응 원칙 |
| --- | --- |
| Guest 요청이 Host `installd`·`artd`에 도달 | Private Binder + Guest 데몬 + service identity 검증. Host 브리지 금지 |
| Guest `/data`가 Host 경로를 참조 | loop ext4 실제 마운트 확인, propagation 검증, Host 사용자 데이터 경로 미공유 |
| Host AIDL HAL이 Guest에서 보이지 않음 | 필수 서비스만 분류·allowlist 프록시 구현; 무조건 Host Binder 공유하지 않음 |
| Host/Guest `zygote`·`system_server` 오인 종료 | PID/starttime/exe/context/namespace 검증, 부분 실패 시 중단 |
| Permissive가 Host 보호를 약화 | 제한된 실험에만 사용, 상태 저장·복원, 데이터/IPC 격리는 별도 유지 |
| Android 16 GSI와 Host APEX/ART 버전 충돌 | 버전·ABI를 사전 비교, OneOS의 호환 패치 중 필요한 것만 적용 |
| `vold`, KeyMint, Gatekeeper, Weaver가 Host 상태를 변경 | 인증 쓰기 경로 차단, Guest 잠금 없음, 별도 스토리지 서비스 우선 |
| in-place 복귀 실패 | 유한한 단계별 롤백; 안전 불확실 시 하드 재부팅 |

## 7. 완료 정의(Definition of Done)

### Milestone A — 격리 런타임

- [ ] Private Binder + Guest servicemanager 독립 실행
- [ ] Guest loop ext4 `/data` 및 mount namespace 검증
- [ ] Guest `installd`·`artd` 독립 실행과 경로 검증
- [ ] Host 서비스/데이터 오염 테스트 통과

### Milestone B — 최초 부팅

- [ ] 기존 LineageOS 23.2 GSI 기반 Guest `zygote`/`system_server` 시작
- [ ] 필수 HAL과 UI 작동
- [ ] Guest에서 테스트 앱 설치/실행/삭제
- [ ] One UI로 재부팅 없이 정상 복귀, Host sentinel 보존

### Milestone C — 안정화

- [ ] 실패 경로/강제 재부팅 복구 검증
- [ ] 반복 전환 테스트와 로그 검증
- [ ] Guest 도메인 중심 SELinux 정책 정리
- [ ] 가능한 범위에서 Host 및 Guest Enforcing 달성

**최초 성공의 정의는 Milestone B다.** 모든 HAL 호환성, 범용 기기 지원, 완전한 SELinux Enforcing은 최초 부팅의 완료 조건이 아니다.

## 8. 다음 에이전트에게 줄 즉시 작업 지시

1. **현재 SSAL 코드와 OneOS 부팅 관련 파일을 읽고 차이표부터 작성한다.** 먼저 기존 SSAL이 이미 구현한 mount, Zygote 식별, state machine, 복구 코드를 보존할 대상을 확정한다.
2. **Phase 1만 구현한다.** Host Framework를 내리지 않고 Private Binder 생성·Guest servicemanager 실행·격리 검증·완전한 정리를 수행하는 테스트 가능한 최소 기능을 추가한다.
3. 이번 변경에서는 Guest `installd`/`artd`, HAL 브리지, SELinux 정책 대량 변경, GSI Framework 패치를 동시에 구현하지 않는다.
4. Phase 1 결과를 로그와 테스트로 제시한다. **Host Binder context가 그대로라는 증거가 없으면 다음 단계로 진행하지 않는다.**
5. 이후 Phase 2에서 Host `/data` 경로 오염 여부를 먼저 검증하고, 그때서야 OneOS 부팅 경로 통합을 시작한다.

## 9. 참고 자료

- SSAL (dev): https://github.com/craftingmod/ssal/tree/dev
- OneOS: https://github.com/fahadalijaved/OneOS
- OneOS guest preparation: https://github.com/fahadalijaved/OneOS/blob/main/switcher/assets/guest_prepare.sh
- OneOS guest startup: https://github.com/fahadalijaved/OneOS/blob/main/switcher/assets/guest_start.sh
- Linux binderfs: https://docs.kernel.org/admin-guide/binderfs.html
- Android Binder domains: https://source.android.com/docs/core/architecture/hidl/binder-ipc
- Android SELinux validation: https://source.android.com/docs/security/features/selinux/validate

---

**한 줄 원칙:** *부팅 호환성은 OneOS에서 배우고, Host 데이터와 Binder 격리는 SSAL이 직접 책임진다. SELinux는 측정하면서 나중에 강화한다.*
