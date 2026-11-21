현재 코드 기준으로는 **`guest/` 아래에 실행 책임을 모으고, 데몬 관리·공통 시스템 기능·진단 코드는 별도로 구분하는 구조**를 권합니다. 파일 이동이나 수정은 하지 않았습니다.

특히 [guest_mounts.rs](V:/workspace/Toy/ssal/src/guest_mounts.rs), [guest_launcher.rs](V:/workspace/Toy/ssal/src/guest_launcher.rs)를 먼저 나누되, 이름이 `probe`인 파일 안에 있는 실제 실행 기능도 함께 분리해야 합니다.

**1. 권장 디렉터리 구조**

아래 트리는 최종 배치안입니다. 한 번에 모두 만들지 않고, 기존 코드가 있는 책임부터 옮깁니다. `mod.rs`는 모듈 선언과 외부 진입점 위주로 유지합니다.

```text
src/
├── lib.rs
├── ssal.rs                       # 기존 CLI 진입점 유지
├── ssald.rs                      # 데몬·worker 진입점과 인자 처리
├── bin/                          # 기존 보조 바이너리 이름 유지
│
├── daemon/
│   ├── mod.rs                    # 데몬 시작 및 요청 처리
│   ├── images.rs                 # 시스템 이미지 등록·목록·검증
│   ├── profiles.rs               # Guest 프로필 생성·목록·삭제
│   └── session.rs                # worker 실행, 세션 경로·결과 관리
│
├── guest/
│   ├── mod.rs
│   ├── prepare.rs                # 사전 검사와 준비 단계 조율
│   │
│   ├── mount/
│   │   ├── mod.rs                # Guest 마운트 구성 순서
│   │   ├── profile.rs            # 마운트 프로필 파싱·검증
│   │   ├── namespace.rs          # unshare, private 전파, namespace 검사
│   │   ├── filesystem.rs         # 시스템 rootfs 구성과 경로 연결
│   │   ├── devices.rs            # /dev, 장치 연결, ashmem
│   │   └── apex.rs               # APEX 식별·추출·마운트
│   │
│   ├── init/
│   │   ├── mod.rs                # 현재 서비스 기동 순서 조율
│   │   ├── service.rs            # Service 수명·출력·종료 관리
│   │   ├── readiness.rs          # 서비스별 준비 상태 확인
│   │   └── contract.rs           # 서비스 실행 계약 검증
│   │
│   ├── process/
│   │   ├── mod.rs
│   │   ├── command.rs            # root 전환, 실행 환경, pre_exec
│   │   └── supervision.rs        # signal, subreaper, 자손 회수
│   │
│   ├── properties/               # 기존 guest_properties/ 구조 활용
│   │   ├── mod.rs
│   │   ├── server.rs
│   │   ├── policy.rs
│   │   ├── persistent.rs
│   │   └── device_test.rs
│   │
│   ├── cgroup/
│   │   ├── mod.rs                # v1/v2 선택, 경로·소속 확인
│   │   ├── layout.rs             # Guest 계층 생성·마운트·해제
│   │   ├── memory.rs             # 메모리 제한·사용량·계층 관리
│   │   └── task_profiles.rs      # processgroup 설정 생성·검증
│   │
│   ├── binder.rs                 # private binderfs·장치 수명 관리
│   ├── userdata.rs               # 이미지 생성·잠금·파일시스템 검사
│   │
│   ├── runtime/
│   │   ├── mod.rs
│   │   ├── linkerconfig.rs       # Guest linkerconfig 생성
│   │   ├── classpath.rs          # derive_classpath 실행·결과 검증
│   │   └── zygote.rs             # Zygote 인자·소켓·system_server 기동
│   │
│   ├── compat/
│   │   ├── mod.rs
│   │   ├── patches.rs            # 기존 패치·코드 브리지 적용
│   │   └── lockscreen.rs         # 기존 Guest 잠금 호환성 처리
│   │
│   └── selinux/                  # 기존 guest_policy 모듈 활용
│       ├── mod.rs                # 정책 생성 진입점·공개 타입
│       ├── runtime.rs
│       ├── native.rs
│       └── symbols.rs
│
├── platform/
│   ├── mod.rs
│   ├── fd.rs                     # 상속 FD·CLOEXEC·FD 정리
│   └── mount.rs                  # mount syscall, Mounts, 경로 검증
│
├── ipc.rs                        # CLI↔데몬 요청·응답·FD 전달
│
└── diagnostics/
    ├── mod.rs
    ├── guest.rs                  # Guest 환경·링커·VINTF 진단
    ├── data.rs                   # userdata 격리 진단
    ├── binder.rs                 # Binder 격리·통신 진단
    ├── memory.rs                 # 메모리·cgroup 실험
    ├── zygote.rs                 # Zygote 출력·상태 수집
    ├── lock_namespace/            # 기존 lock_namespace_probe
    ├── selinux/                   # 기존 selinux_probe
    └── launcher/                  # fork·system_server preflight/SID 실험
```

`init/`은 현재 런처의 서비스 관리 역할을 가리킵니다. **범용 Android init 구현을 추가한다는 의미는 아닙니다.** `parser.rs`와 `control.rs`는 이번 분리 대상에서 제외합니다. 현재 제한적인 rc 분석은 진단 코드에 남기고, `ctl.*`의 기존 처리·차단 동작을 유지합니다.

**2. 현재 파일을 나누는 기준**

| 현재 위치 | 분리 방향 |
|---|---|
| `ssald.rs` 내부 `daemon` | 이미지·프로필 관리, 세션 실행을 `daemon/`으로 분리 |
| `prepare.rs` | `check()`·준비 조율은 `guest/prepare.rs`, namespace 설정은 `mount/namespace.rs`, loop 장치 처리는 `mount/` 내부 하위 모듈로 분리 |
| `guest_mounts.rs` | 프로필, 장치, rootfs 구성, APEX, linkerconfig, cgroup, 호환성 패치를 각각 해당 모듈로 분리 |
| `namespace_mounts.rs` | 공통 mount·`Mounts`·경로 검증은 `platform/mount.rs`, 호환성 파일 주입은 `guest/compat/`으로 분리 |
| `guest_launcher.rs` | `command()`는 `process/`, `Service`는 `init/`, classpath·Zygote는 `runtime/`, 실험 분기는 `diagnostics/`로 분리 |
| `guest_probe.rs` | `root_command()`·프로세스 그룹 설정 등 실행 기능은 `process/`, 관찰·검사 코드는 `diagnostics/guest.rs`로 분리 |
| `memory_cgroup.rs` | backend·제한·소속 확인은 `cgroup/`, signal·subreaper·자손 회수는 `process/supervision.rs`로 분리 |
| `binder_probe.rs` | `Session`의 장치 생성·해제는 `guest/binder.rs`, 검증·보고는 `diagnostics/binder.rs`로 분리 |
| `guest_properties/`, `guest_policy/` | 기존 내부 구성을 활용하며 각각 `properties/`, `selinux/`로 편입 |
| `unix.rs` | IPC 프로토콜과 범용 FD 처리를 분리 |

처음부터 모든 큰 파일을 세분화할 필요는 없습니다. 예를 들어 SELinux 정책 생성 코드는 우선 기존 구조로 편입하고, 별도 작업에서 파서·생성기를 나누는 편이 변경 범위를 줄입니다.

**3. 의존성과 정리 책임**

목표 의존성은 다음과 같습니다.

```text
ssal ──→ ipc

ssald ──→ daemon ──→ guest
                  └→ diagnostics ──→ guest

guest ──→ platform
ipc   ──→ platform::fd
```

현재는 실제 실행 코드가 진단 모듈을 참조하는 부분이 있습니다. 이를 해소하려면 다음 경계를 먼저 잡아야 합니다.

- `process::command`가 `guest_probe::root_command`의 실행 기능을 소유합니다.
- 공통 실행 명세는 `selinux_probe` 내부가 아닌 실제 서비스 실행 모듈에 둡니다.
- 복구 필요 상태의 기록·확인은 진단 모듈에서 세션 관리 쪽으로 추출합니다.
- 준비·실행 조율 코드가 필요한 진단을 호출하고, 저수준 mount·process 코드는 진단 결과 형식에 의존하지 않게 합니다.

또한 **모든 정리를 `mount/cleanup.rs`에 모으는 방식은 피하는 것이 좋습니다.** 현재 자원의 소유권을 따라 책임을 유지해야 합니다.

| 자원 | 해제 책임 |
|---|---|
| mount·loop FD | 해당 mount·loop 소유 객체 |
| Guest cgroup 디렉터리 | `cgroup/layout.rs` |
| 서비스·자손 프로세스 | `init/service.rs`, `process/supervision.rs` |
| 세션 임시 디렉터리·복구 상태 | `daemon/session.rs` |

호출 측은 종료 순서와 오류 취합을 담당합니다. 기존 `Drop`, 명시적 해제, 잔여 자원 검사 순서를 그대로 보존하는 것이 핵심입니다.

**4. 실제 분리 순서**

1. **진입점과 공유 코드 경계 정리**  
   `ssald.rs`의 데몬 코드를 추출하고, 여러 바이너리가 사용하는 코드는 `lib.rs`를 통해 접근하도록 정리합니다.

2. **`guest_mounts.rs` 분리**  
   프로필·APEX·장치·linkerconfig부터 추출합니다. 마운트 순서와 자원 소유권은 유지합니다.

3. **cgroup과 프로세스 관리 분리**  
   `memory_cgroup.rs`의 자손 회수 기능을 이동하고, Guest 계층 구성 코드를 합칩니다.

4. **`guest_launcher.rs` 분리**  
   command → Service → readiness → classpath·Zygote → 실험 코드 순으로 추출합니다. 큰 `verify()` 조율 함수는 마지막에 줄입니다.

5. **기존 모듈 편입과 진단 정리**  
   properties·SELinux·userdata를 배치하고, 실제 실행 코드에서 진단 모듈로 향하는 의존성을 제거합니다.

각 단계는 **동작 변경 없이 추출 → 기존 검사 → 관련 worker 하나로 런타임 확인**까지 끝내고 다음 단계로 넘어갑니다. 전체 재구조화를 첫 부팅의 선행 조건으로 만들지는 않습니다.

이동 시에는 `crate::` 참조뿐 아니라 `#[path]`, `include_str!`, 소스 문자열을 검사하는 테스트, `src/bin`의 공유 모듈 참조도 함께 수정해야 합니다. CLI 명령·worker 옵션·환경변수·프로필 형식·배포 바이너리 이름은 유지합니다.

이번에는 코드 이동·테스트·기기 실행·`vendor` 열람을 하지 않았습니다.  
실제 분리의 주요 위험은 mount·loop·프로세스의 수명과 종료 순서가 바뀌는 것이므로, 해당 경계는 단계마다 확인해야 합니다.