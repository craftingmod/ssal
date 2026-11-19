# SSAL rsbinder Phase 5A — Runtime Boundary 조사

- 조사일: 2026-11-04 (Asia/Seoul)
- 대상: SM-S937N Android 17 Host 안의 Android 16 / SDK 36 Guest 경로
- 방법: `vendor/`를 제외한 SSAL 코드 조사, 기존 Phase 2~4 기기 결과 검토, 현재 Host의 읽기 전용 상태 확인
- 이번 단계에서는 Guest `installd`/`artd`를 실행하거나 Host `/data`, property, SELinux 정책을 변경하지 않았다.

상태는 **관찰한 정확한 범위**에만 적용한다. 과거 테스트 결과는 현재 실행 결과로 표시하지 않는다.

## 요약

| 경계 | 상태 | 판정 범위 |
|---|---|---|
| 전용 profile을 Guest `/data`로 연결 | PASS | 2026-11-03 Phase 2 기록에서 source가 Host `/data` 루트와 다른 새 userdata directory였고, mount가 `rw,nosuid,nodev`, private propagation이었다. Guest write/read 왕복과 정리가 확인됐다. |
| Host가 Guest userdata에 접근할 수 없음 | PARTIAL | profile은 `/data/local/ssal/guests/<profile>/userdata`에 있고 Host와 같은 filesystem·kernel·UID 공간을 쓴다. privileged Host 경로 접근을 막는 경계는 아니다. |
| `/data/user`, `/data/system`, `/data/dalvik-cache` | PARTIAL | `/data/user`와 `dalvik-cache` 동작은 과거 disposable 시험에서 확인됐다. `/data/system`은 별도 mount가 아니며 해당 directory/file 동작은 관찰되지 않았다. |
| Guest property read/write | PARTIAL | 시험용 세션은 별도 minimal read-only area와 차단된 socket을 썼다. 기본 `initial-shared-dev` profile은 `/dev/__properties__`를 Host `/dev`에서 상속하고 Guest property service는 없다. |
| 기본 `/dev/binder` | FAIL | 일반 profile은 Host `/dev`를 recursive bind한다. private Binder는 Binder/ServiceManager probe 세션에서만 덮어 쓴다. |
| Probe 세션의 Private Binder 및 ServiceManager 분리 | PASS | 과거 Enforcing Test B에서 Guest `rdev=507:5`, Host `rdev=507:1`, protocol 8, 양방향 registry 격리가 확인됐다. |
| `/dev/hwbinder`, `/dev/vndbinder`의 Guest identity | UNKNOWN | Host node는 현재 각각 `507:2`, `507:3`이다. private binderfs 세션에서 symlink가 어디에 도달하는지 또는 node 부재 여부를 Guest 안에서 stat하지 않았다. |
| Mount namespace 및 propagation | PASS | Worker가 mount namespace를 만들고 재귀적으로 private 처리한다. 과거 Guest mountinfo에서 Host와 다른 namespace 및 private `/data` propagation이 확인됐다. |
| PID / IPC namespace 분리 | FAIL | PID namespace 미지원이며 IPC namespace 생성 시 `EINVAL`이 기록됐다. `/proc`의 self-only view는 PID namespace 분리와 다르다. |
| SELinux Enforcing 및 정책 원복 | PASS | 현재 Host는 Enforcing. 현재 policy hash는 Phase 4 baseline/final hash와 같고, 영구 module rule hash도 기록된 값과 같다. |
| 전체 Guest runtime이 Phase 5B 준비 완료 | FAIL | 기본 device/property 노출, Host path/FD 격리, Guest property service, Guest 전용 SELinux 실행 정책이 완결되지 않았다. |

## Filesystem 및 namespace

### `/data`와 하위 경로

`src/prepare.rs::worker`는 `CLONE_NEWNS`만 unshare하고 `/`에 `MS_REC|MS_PRIVATE`를 적용한다. 이후 profile userdata directory를 Guest rootfs의 `/data`에 bind한다. `src/guest_mounts.rs`에서 이 bind는 `rw,nosuid,nodev`로 remount되며 별도 ext4 image가 아니다. `src/guest_data_probe.rs`는 userdata source 경로의 `.`/`..` 및 symlink/non-directory 구성요소를 거부하고, Guest `/data`와 source의 `(dev, inode)`를 비교한다.

Phase 2 기기 결과(2026-11-03)는 Guest `/data`가 `/data/local/ssal/guests/phase2-20261103-r32/userdata`에서 왔고 Host `/data` root inode와 달랐음을 기록한다. Mountinfo는 `rw,nosuid,nodev`, propagation은 private, profile 경유 marker write/read/delete는 성공했다. Guest `installd`의 CE/DE app-data 생성·삭제와 Guest `artd`의 verify compile 산출물(OAT/VDEX)도 이 disposable profile 안에서 확인됐다. 해당 Phase 2 시험은 당시 Permissive를 사용했으므로 Enforcing 서비스 쓰기 증거가 아니다.

`/data/user`, `user_de`, `app`, `misc`, `misc/profiles`, `dalvik-cache`의 mode·UID/GID·label 적용 결과는 그 시험 report에 기록돼 있다. `/data/system`은 별도 mount가 아니므로 존재한다면 같은 profile userdata에 놓이지만, Phase 2 layout의 생성 목록에는 없고 해당 경로에 대한 실기기 동작은 확인되지 않았다. 현재 mount profile에서는 `/data/user`, `/data/system`, `/data/dalvik-cache`를 각각 별도 volume으로 분리하지 않는다.

이는 Host의 일반 `/data` 앱 디렉터리와 Guest profile을 경로상 분리하는 근거다. Host root는 backing profile의 Host 경로에 접근할 수 있고, user namespace도 없다. 따라서 적대적인 Host root나 Guest root에 대한 저장 매체 접근 격리를 뜻하지 않는다. Test B에서 제한한 `/proc`와 FD 규칙은 해당 테스트 세션에만 적용됐다.

### 경로, FD 및 Host mount 노출

`src/platform/mount.rs::guest_path`는 절대 symlink를 Guest root 안에서 해석하고, 입력 경로의 absolute/`.`/`..`, 누락된 symlink target 및 loop를 거부한다. `guest_data_probe::real_directory`는 userdata source의 각 구성요소를 symlink 없이 검사한다. 기존 unit tests는 이 경로 조건과 symlink escape를 다룬다. Phase 5A에서 새로운 adversarial Guest 경로/FD 검사는 하지 않았다.

기본 profile은 `/dev`를 Host `/dev`에서 recursive bind한다. `/dev/socket`, `/dev/block`은 Guest tmpfs로 가리고 `/mnt`, `/storage`, `/data_mirror`, `/apex`, `/linkerconfig`, `/run`도 Guest tmpfs로 시작한다. `/vendor`, `/odm`, `/vendor_dlkm`은 Host read-only bind다. 반면 `/sys/fs/cgroup` 및 `/sys/fs/bpf`는 Host 경로를 read-write bind한다. 따라서 mount namespace가 있다고 Host kernel resource가 모두 분리된 것은 아니다.

일반 worker는 fresh procfs를 mount하지만 PID namespace를 만들지 않는다. Phase 2 결과는 커널이 PID namespace 생성을 거부한다고 기록하고, 실제 daemon에는 자기 PID의 proc 디렉터리만 보여 줬다. Phase 2 artd compile child의 `unshare(CLONE_NEWIPC)`는 `EINVAL`; 같은 child에서 `CLONE_NEWNET`/`CLONE_NEWUTS`는 성공했다. 이는 compiler helper 결과이며 일반 Guest daemon의 network/UTS 분리를 증명하지 않는다.

Test B는 `/proc/1/root` 및 Host `/proc/<pid>/fd` 경로를 Guest에서 차단하고 process별 현재 SID만 보이게 했으며, exec 시 상속 FD를 닫았다. 과거 daemon 실행 report에는 각 daemon의 초기 FD 목록이 있고 Guest `/dev/binder` private FD만 보인다. 그러나 일반 runtime에서 Host `/data`의 열린 FD나 `/proc/1/root/data`를 실제로 열어 보는 음성 시험은 없다. 이 경계는 아직 UNKNOWN이다.

## Binder 및 ServiceManager

현재 Host에서 읽기 전용으로 확인한 `/dev` symlink 대상은 BinderFS node다.

| Host node | 현재 Host `rdev` | Guest 처리 |
|---|---:|---|
| `/dev/binder` | `507:1` | 일반 profile은 Host `/dev` bind로 공유. Binder/ServiceManager probe에서는 private binderfs node로 교체 |
| `/dev/hwbinder` | `507:2` | 기본 profile은 Host `/dev`에서 상속. private 세션에서의 최종 Guest identity는 미측정 |
| `/dev/vndbinder` | `507:3` | 기본 profile은 Host `/dev`에서 상속. private 세션에서의 최종 Guest identity는 미측정 |

`src/binder_probe.rs::Session::provision`은 Guest root의 `/dev/binderfs`에 새 binderfs를 mount하고 `binder` node를 준비한다. Node `rdev`, mount ID, alias path와 protocol을 검사하고 Host `/dev/binder`와 같으면 실패한다. Phase 2C/4 보고서에서 Guest `/dev/binder`와 rsbinder process FD는 같은 private device(`rdev=507:5`); Host Binder는 `507:1`; protocol 8이었다. Probe-only `src/binder_wire.rs`도 예상 identity와 열린 FD를 확인하며 실패 시 Host Binder fallback을 하지 않는다.

이것은 private Binder가 설치된 시험 세션의 증거다. `module/profiles/concurrent/mounts/initial.json`의 기본 `initial-shared-dev` profile만으로는 `/dev/binder`가 private하지 않다. private binderfs 세션의 `/dev/hwbinder`·`/dev/vndbinder` symlink는 `/dev/binderfs` 아래로 다시 해석되지만, 해당 Guest node가 실제 있는지 또는 어떤 identity인지 기록하지 않았다.

Android 16 Guest SDK 36의 Test B는 private `servicemanager`에서 `aidl_lazy_test_1` 등록/조회 및 nonce transaction을 수행했다. Host에서는 시험 이름이 보이지 않았고 Host의 `package`/`activity` 서비스는 계속 보였다. Phase 3은 Private Binder의 Rust AIDL 동기 호출, callback Binder object 전달, death/restart/reconnect를 Enforcing에서 통과했다. `ParcelFileDescriptor`/Binder FD 전달과 실제 production `IInstalld`/`IArtd` AIDL caller 호환성은 Phase 4에서 미검증이다.

## Property Service 및 Property Area

기본 Guest mount profile은 `/dev` 전체를 Host에서 bind한 다음 `/dev/socket`만 Guest tmpfs로 덮는다. 따라서 Host `/dev/socket/property_service` 경로는 가려지지만 `/dev/__properties__` area는 기본 profile에서 Host area를 상속한다. 현재 Android 17 Host snapshot에서 `/dev/__properties__`는 `(dev=18, ino=118, properties_device)`, `property_info`는 `(18,119, property_info)`, `properties_serial`은 `(18,764, properties_serial)`이었다. `/dev/socket/property_service`와 `_for_system`도 `property_socket` label로 존재했다. 이 Host 측 identity는 Guest identity로 오해하지 않는다.

Phase 2C/Phase 2의 diagnostic override는 Guest 이미지 `/system/build.prop`의 SDK 36에서 값을 만들고, Host area와 다른 Bionic pre-split read-only area(`dev=132, ino=7` 대 Host `dev=18, ino=118`)를 사용했다. 해당 다섯 값과 default context만 있는 최소 area라 full init-populated Android 16 property set이 아니다. Test B의 별도 경로는 빈 Guest property directory를 제공하고 모든 `connect`를 seccomp로 `EPERM` 차단했다. 두 경로 모두 Host property 값을 복사하지 않았다.

따라서 일반 Android property read는 Host area를 읽을 수 있는 구성이고, 정상 property write endpoint는 Guest에 없으며 시험 세션에서는 연결도 막혔다. “Guest property가 Host에 쓰이지 않는다”는 보장은 시험용 seccomp/빈 socket 구성의 정상 API 경로에 한정된다. 기본 profile에서 Guest property area를 Host와 분리하지 않고, 열린 Host property FD/direct write를 대상으로 한 테스트도 없어 전체 경계는 PARTIAL이다. Host property 값 변경 시도는 하지 않았다.

Android 16의 read path는 Bionic `property_info` trie로 이름별 property context/area를 선택한다. Write path는 Guest property service가 Unix socket 요청의 peer UID/GID와 SELinux context를 확인하고 property 이름에 매핑된 type에 `property_service:set` 접근을 검사해야 한다. `ro.*` write-once, 타입 검증, `persist.*`의 Guest 전용 저장, `ctl.*` 및 `sys.powerctl`의 Host 전달 금지도 포함한다. 필요한 area 파일은 `properties_device`, `properties_serial`, 이름별 property context, `property_info`에 맞는 directory/file labels와 DAC/SELinux 권한을 가져야 한다.

저장소의 기존 Android 16 context 조사 결과는 수집된 부분 입력 523개 중 당시 실효 정책에서 509 valid, 12 EINVAL, 2 미조회였다. 전체 정책 export에 실패했고 이 결과는 2026-10-31 기준의 부분 자료다. 필요한 타입이 현재 Host policy에서 유효하다는 점, 실제 Guest enforcing domain의 create/open/read/write/map/relabel 및 `property_service:set` 권한은 확인되지 않았다. Property label 유효성만으로 AV 권한을 추론할 수 없다.

참고: [Android 16 private property contexts](https://android.googlesource.com/platform/system/sepolicy/+/android16-release/private/property_contexts), [Bionic serialized property contexts](https://android.googlesource.com/platform/bionic/+/0b27d314d6d7e66427af7354c05919a0ca8be6bc/libc/system_properties/contexts_serialized.cpp), [Android 16 property service](https://android.googlesource.com/platform/system/core/+/android16-release/init/property_service.cpp), [기존 property SELinux 조사](guest-property-selinux-feasibility.md), [서비스 실행 계약](service-execution-contract.md).

## Identity, capabilities 및 SELinux

과거 Phase 2 disposable daemon probe에서 실제 context/credential은 다음과 같았다. 이 시험은 SELinux Permissive였고 Phase 5A에서는 재실행하지 않았다.

| daemon | Guest UID/GID | context | 기록된 `CapEff` | 제한 |
|---|---:|---|---|---|
| `installd` | `0/0` | `u:r:installd:s0` | `0x000000ff` | 제한 capability set, `NoNewPrivs=1`, seccomp mode 2 |
| `artd` | `1082/1082` | `u:r:artd:s0` | `0x0020000f` | 시험 전용 compiler namespace shim에 명시 승인한 `CAP_SYS_ADMIN` 포함. stock `art_exec` 전 제거 및 NNP 확인 |

Guest와 Host는 동일 커널, UID namespace, SELinux policy를 사용한다. 위 SELinux type은 Host daemon과 같은 `installd`/`artd` type이며 별도 Guest type/policy boundary가 아니다. Phase 2의 실제 daemon 동작은 permissive 결과이므로 enforcing 권한 증거로 계산하지 않는다. Enforcing으로 통과한 Test B/Phase 3 domain은 시험 전용 manager/server/client domain에 한정된다. Guest production service의 enforcing 실행/최소 capability와 AVC는 아직 검증되지 않았다.

## 근거 문서 및 코드

- Mount/data: [prepare.rs](../src/prepare.rs), [guest_mounts.rs](../src/guest_mounts.rs), [guest_data_probe.rs](../src/guest_data_probe.rs), [namespace_mounts.rs](../src/platform/mount.rs), [기존 Phase 2 data 결과](phase2-data-isolation.md), [기기 JSON](phase2-data-isolation-device-20261103.json)
- Binder: [binder_probe.rs](../src/binder_probe.rs), [binder_wire.rs](../src/binder_wire.rs), [Phase 2 결과](rsbinder-phase2-results.md), [Phase 3 결과](rsbinder-phase3-results.md), [Phase 4 결과](rsbinder-phase4-results.md)
- Property/Test B: [servicemanager-test-b-device-20261103.md](servicemanager-test-b-device-20261103.md), [Phase 2C 진단 JSON](rsbinder-phase2c-diagnostics-20261103.json)
