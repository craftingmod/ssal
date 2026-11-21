# Experimental Guest ctl.* support — 2026-11-18

Guest Property Service에 명시적으로 등록한 foreground 서비스만 제어한다. Host init, Host Property Service, Host 서비스 레지스트리로 전달하는 경로는 없다. Android init 전체나 SystemServer 부팅 완료를 구현한 것은 아니다.

## 조사와 변경 범위

- `src/guest/properties/server.rs`: 기존 V1/V2 wire 파서, SO_PEERCRED/SO_PEERSEC, 요청 deadline, 응답 코드를 재사용했다. 기존 `ctl.*` 저장 우회 지점에 실제 dispatcher를 연결했다.
- `src/guest/properties/mod.rs`: control 권한 조회와 일반 property 권한 조회를 분리했다. 일반 start/stop/restart는 `ctl.<service>`를 먼저 검사하고, 거절되면 `ctl.<action>$<service>`를 검사한다. `interface_*`는 원래 명령과 인터페이스를 사용한 `ctl.interface_<action>$<interface>`만 검사한다. 외부 `init.svc.*` 쓰기는 거절한다. 일반 property/persistent 처리와 rsproperties `=0.7.0` 고정은 유지한다.
- `src/guest/properties/services.rs`: 등록 정의, 자식 PID 소유권, 상태, dispatcher, polling/reap, 종료 cleanup을 담당한다. 기존 supervisor의 서비스 PID를 가져오거나 프로세스를 이름으로 검색해 채택하지 않는다.
- `src/guest/launcher/mod.rs`의 기존 cgroup 진입·확인 함수를 `src/platform/process.rs`로 이동해 두 실행 경로에서 재사용한다. 기존 launcher 테스트도 같은 함수를 검증한다.
- 기존 `init::Service`의 unreaped leader → process group kill → wait 패턴을 사용한다. 이 타입 자체는 ssald 실행 파일의 진단·로그·런처에 묶여 있으므로 라이브러리 Property Service로 옮기지 않았다.
- 기존 세션 supervisor는 subreaper와 pidfd 기반 `cleanup_descendants`를 보유한다. 새 서비스도 exec 전에 기존 Guest 전용 cgroup mount들에 진입하므로 세션 종료 시 이 cleanup 경계에 포함된다.

## AOSP 비교

조사한 upstream은 2026-11-18의 main이다. 소스별 확인 내용은 다음과 같다.

| 소스 | AOSP 동작 | SSAL 적용/차이 |
|---|---|---|
| [property_service.cpp](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/property_service.cpp) (`CheckControlPropertyPerms`, `CheckPermissions`, `SendControlMessage`; blob `83e9a0da35c3ac14a9ed772bf419116135888ec3`) | 서비스별 legacy/명령별 MAC 검사 후 control message를 init에 queue하고 일반 저장을 우회 | 같은 권한 조회 순서와 저장 우회. Guest dispatcher에 직접 전달하며 Host init 연결 없음 |
| [init.cpp](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/init.cpp) (`HandleControlMessage`, `HandleControlMessages`; blob `920b926dcd26f3dd8661e869168d552c5db7170e`) | 서비스명 또는 interface로 registry 조회, 명령 dispatch, 처리 결과 응답 | 명시적으로 등록된 Guest 서비스명/인터페이스만 조회. 별도 queue/thread 없이 기존 직렬 property loop 사용 |
| [service.cpp](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/service.cpp) (`Start`, `Restart`, `StopOrReset`, `Reap`, `NotifyStateChange`; blob `56300205d293d346627a20fe2158bf9992b5b023`) | 서비스 수명주기, 종료 후 restart, init.svc 상태 발행 | start/stop/명시적 restart 및 상태 발행. crash 자동 재시작, rc 옵션과 재시작 지연은 미지원 |

## 등록 인터페이스와 동작

기존 `ssal-property-service --config GUEST_CONFIG.json` 설정에 아래 선택 필드를 추가한다. 나머지 isolation/property 설정은 기존과 동일하다.

```json
{
  "services": [
    {
      "name": "ssal-mock",
      "executable": "/system/bin/sleep",
      "args": ["600"],
      "interfaces": [
        "aidl/dev.ssal.IMock/default",
        "dev.ssal.mock@1.0::IMock/default"
      ],
      "uid": 1000,
      "gid": 1000,
      "domain": "shell"
    }
  ]
}
```

`domain`은 해당 세션의 `selinux_types`에서 Guest 타입으로 매핑되어야 한다. 예시의 shell 실행과 control 권한이 실제 정책에서 허용되는지는 기기에서 별도로 확인해야 한다. 설정은 신뢰된 세션 생성자가 작성하며 property 요청으로 명령행이나 실행 경로를 등록·수정할 수 없다. 기존 `start_property_service`는 이 필드를 생략하므로 기본 registry는 비어 있다. 새 서비스를 사용하려는 호출자는 worker 시작 전에 `Config.services`/JSON에 정의를 제공해야 한다. 공개 `ServiceDefinition`을 추후 init.rc parser의 출력으로 사용할 수 있다.

서비스명은 1–64자의 ASCII 영숫자, `_`, `-`만 허용한다. 중복 이름, 상대 경로, `..`, NUL, 미매핑 domain, init domain은 거절한다. 실행 시에는 기존 Guest 입력 경로 검사로 실제 경로가 Guest partition 또는 `/run/ssal` 아래인지 확인한다.

`interfaces`는 선택 필드이며 기본값은 빈 목록이다. [AOSP init 문서](https://android.googlesource.com/platform/system/core/+/refs/heads/main/init/README.md)의 `interface <interface name> <instance name>`을 합친 exact key를 등록한다. AIDL은 `aidl/<등록명>`이고 `aidl/apexservice`처럼 slash 없는 등록명도 가능하다. HIDL 예시는 `dev.ssal.mock@1.0::IMock/default`이다. 이는 실제 Binder 서비스 등록을 수행하지 않으며 서비스 실행 대상으로의 매핑만 제공한다.

SSAL은 안전한 ASCII 토큰(영숫자, `_-. /@:` 중 공백 제외), 비어 있지 않은 slash 구간, 기존 wire value 길이 제한을 적용한다. 빈 구간, `.`/`..` 구간, 공백, `$`, NUL, 비ASCII는 거절한다. AIDL/HIDL 문법 전체를 해석하거나 버전/상속/이름을 추정하지 않는다. 같은 인터페이스의 중복 등록은 동일 서비스 안에서도 거절해 모호한 소유권을 방지한다. 하나의 서비스가 여러 인터페이스를 제공하는 것은 지원한다.

| 요청/사건 | 동작과 Guest 상태 |
|---|---|
| 초기 등록 | `init.svc.<name>=stopped` |
| `ctl.start` | 자식 생성 후 `running`; 실행 중 중복 start는 기존 PID 유지 |
| `ctl.stop` | 소유 그룹에 SIGKILL 후 `stopping`; 다음 reap에서 `stopped`. 이미 정지한 서비스에는 성공 |
| `ctl.restart` | 실행 중이면 `restarting` → 종료/reap → 새 PID의 `running`. 정지 중이면 즉시 start |
| `ctl.interface_start/stop/restart` | 등록 인터페이스를 소유 Guest 서비스로 exact 조회 후 동일한 start/stop/restart 처리. 상태는 인터페이스가 아닌 서비스명의 `init.svc.<name>`에 반영 |
| 중복 restart | 진행 중인 종료에 restart 의도 한 개 유지 |
| 비정상 종료 | 그룹의 잔여 자식 정리 후 `stopped`; 자동 restart 없음 |
| exec 실패 | control 실패 응답, `stopped`; 서버는 다음 요청 처리 가능 |
| Property Area 기록 실패 | 서버 오류로 전파, registry drop에서 소유 서비스 정리 |

성공 응답은 명령 처리/종료 요청 수락을 뜻하며 서비스 readiness를 보장하지 않는다. 상태 회수는 평상시 100ms polling이며 요청 처리 중에는 기존 2초 wire deadline만큼 늦어질 수 있다. V1은 기존대로 응답 없이 닫고 V2는 status를 반환한다. 잘못된 control, 미등록 서비스, 권한 거절은 `PROP_ERROR_HANDLE_CONTROL_MESSAGE`로 응답한다. 어느 경우에도 `ctl.*`는 area/persistent store에 기록하지 않는다.

`ctl.interface_start=aidl/dev.ssal.IMock/default`처럼 Guest property socket에 요청한다. 매핑 조회 전에 원래 interface 명령에 대한 MAC 검사를 수행하며, 서비스명 권한으로 재검사해 우회하지 않는다. 미등록 인터페이스는 서비스명이나 Host로 fallback하지 않는다. `interface_start`에 `ssal-mock`만 전달하거나, `start`에 인터페이스 key를 전달해도 거절한다.

## 보안과 cleanup 경계

실제 socket에서 kernel이 제공한 PID/UID/GID와 SID를 읽는다. control caller SID는 현재 설정의 매핑된 Guest SID여야 하며, 이어서 기존 selinuxfs `property_service:set` allowed/decided 검사를 통과해야 한다. Guest permissive domain도 명시적 allow 없이는 통과하지 않는다. Host SID는 control 경로에서 거절한다. SELinux 정책이나 enforcing 상태를 변경하지 않았다.

자식은 Guest root/mount namespace를 상속하고 전용 process group에서 실행된다. 불필요한 FD는 기존 helper로 CLOEXEC 처리하고, 환경을 비우고 최소 Android 환경을 지정하며, 보조 그룹을 지우고 등록 UID/GID 및 매핑된 exec SID를 적용한다. 기존 Guest cgroup mount 전부에 진입·확인한 뒤 실행한다. parent-death SIGKILL과 부모 PID 재확인도 적용한다.

신호 대상은 registry가 직접 spawn한 `Child`의 그룹뿐이다. `waitid(WNOWAIT)`로 소유권을 확인하고 leader를 zombie로 남겨 PID/PGID가 재사용되지 않는 동안 그룹을 정리한 후 회수한다. ECHILD이면 신호를 보내지 않는다. 정상 오류 반환 시 registry drop이 모든 소유 그룹을 정리한다. worker가 강제 종료되면 직접 자식은 parent-death signal을 받고, 세션 teardown의 기존 subreaper가 Guest 자손을 처리한다.

**제한:** 서비스는 foreground로 실행하고 자손을 같은 process group에 유지해야 한다. 별도 세션/그룹으로 이탈하는 daemon의 서비스별 stop은 보장하지 않는다. 해당 지원 전에는 서비스별 cgroup 수명주기가 필요하다. 세션 cleanup 실패 시 기존 supervisor의 Guest 자원 보존·오류 보고 규칙을 따른다. Host 전체 PID sweep이나 Host cgroup kill은 추가하지 않았다.

## 검증 결과

WSLc `ssal-dev`, `/src`, root에서 실행했다. WSL/WSLc 명령은 저장소 지침대로 sandbox 밖에서 실행했다.

| 검사 | 결과 |
|---|---|
| `cargo test --locked -- --test-threads=1` | 173 passed, 0 failed, 7 ignored (interface 확장 후 모든 binary/CLI/doc test 포함) |
| `cargo test --locked --lib -- guest_properties --test-threads=1` | 22 passed, 0 failed |
| `cargo clippy --locked --lib --bin ssal-property-service -- -D warnings` | 통과 |
| `cargo clippy --locked --all-targets -- -D warnings` | 기존 타 영역 경고로 실패: guest-domain-poc 인자 수/map_or/test 배치, cgroup memory iterator/test 배치, diagnostics 상수 assert, cgroup layout clone. 이번 범위에서 수정하지 않음 |
| `cargo build --locked --release --target aarch64-linux-android` | 모든 기본 binary 링크 통과. 산출물은 컨테이너 `/build/target/aarch64-linux-android/release/` |
| `cargo check --locked --tests --target aarch64-linux-android` | Android 전용 기존 device test를 포함한 Rust 컴파일 통과 |
| 실제 삼성 기기 / Guest enforcing MAC / Host 상태 snapshot 비교 | 미실행. 기기 payload 설치 및 Host 서비스 제어 실험 없음 |

새 테스트는 실제 Unix socket pair의 V2 wire 요청, 실제 Linux mock 자식, rsproperties mmap area로 start → stop → restart, 실행 중 restart, 중복 요청, 비정상 종료, exec 실패, 잘못된 이름/미등록 서비스/권한 거절을 확인한다. Android 전용 spawn 단계만 Linux mock spawn 함수로 대체하므로 실제 SELinux transition이나 cgroup mount 검증을 대신하지 않는다. 권한 단위 테스트는 legacy 우선순위와 명령/서비스별 fallback, 모든 SID 거절, `init.svc.*` 위조 거절을 확인한다.

인터페이스 확장 테스트는 AIDL/HIDL 별칭이 동일 PID와 상태를 공유하는지, 세 interface 명령의 수명주기 및 권한 거절, 중복 start/restart, 미등록/잘못된 key, 서비스명 fallback 금지, 중복 등록 거절, 이전 JSON의 기본값 호환을 검증한다. MAC 테스트는 세 명령 각각의 `ctl.interface_<action>$<interface>`만 조회하며 legacy 허용이 있어도 interface 권한 거절을 우회할 수 없는지 확인한다. 각 wire 요청 후 해당 `ctl.*`가 Property Area에 없는지도 확인한다.

별도 Host 대역 프로세스와 별도 Property Area의 sentinel이 보존되고 `ctl.*`가 양쪽 area에 없는지 확인했다. 이는 실제 기기의 Host init/property 무변경을 입증하는 device snapshot 검증과 구분한다. PID 재사용 방지는 이미 회수된 자식의 ECHILD 거절로 검증했고, 종료된 leader가 남긴 같은 그룹 자식도 정리되는지 확인했다.

기존 snapshot fixture 2개 및 privileged mount 관련 테스트 5개는 기존대로 ignored이다. 실제 기기 후속 검증은 disposable Guest의 `ssal-mock`만 등록하고 Guest socket을 통해 수행해야 한다. Host 서비스 이름으로의 제어 실험은 하지 않는다. Luna cleanup 검사에서 `.userdata-*.img`는 없었고 생성한 테스트 결과 임시 파일은 제거했다.

## 미지원

APEX control, init.rc parsing/import, class/trigger, servicemanager/hwservicemanager의 자동 lazy-service 요청 연계, 자동 crash restart/backoff, onrestart, capabilities/rlimits/socket 상속/추가 그룹, 서비스 readiness 및 완전한 Android init 동작은 구현하지 않았다. `sys.powerctl`의 기존 Guest 세션 종료 경로는 유지한다.

AOSP의 나머지 확장도 조사했다. `oneshot_on/off`는 자동 재시작 정책, `sigstop_on/off`는 exec 디버깅 동작을 전제로 하므로 해당 기능을 아직 갖추지 않은 SSAL에서는 지원하지 않는다. `apex_load/unload`는 APEX mount/rc/linker lifecycle을 다루므로 이번 서비스 제어 확장에 포함하지 않는다. 알 수 없는 명령은 interface 접두사가 있어도 동일하게 거절한다.
