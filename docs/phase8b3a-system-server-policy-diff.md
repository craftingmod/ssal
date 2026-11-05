# Phase 8B-3A — system_server SELinux 정책 차분

## 판정

**정적 비교: PARTIAL.** 저장된 Host binary와 분석용 Guest composite에서 system_server의 확장된 access-vector 집합을 비교했다. Guest의 비교 가능한 source allow 튜플 중 Host와 문자열이 일치하는 비율은 99.17%다. 이 수치는 초기화 성공이나 격리 호환성의 PASS가 아니다. Guest 전체 정책을 neverallow 및 genfs 검증까지 통과시켜 구성하지 못했고, 실제 Guest system_server도 실행하지 않았다.

Stock GSI의 최종 SID u:r:system_server:s0는 Host와 공유된다. Guest 독립성을 요구하는 현재 목표에서는 이 SID로 실행을 허용하지 않는다.

## 입력 및 분석 방법

| 입력 | SHA-256 |
|---|---|
| Host active binary out/selinux-check/2026-11-04-host-active-policy.bin | 577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723 |
| LineageOS 23.2 GSI image | 7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff |
| Guest plat_sepolicy.cil | be4eb2bcc7c1fe5bec30ec686b8ac1df28eec0eefcc48b9f541fd2f8cfffa167 |
| Host plat_sepolicy.cil | 425aba8b73da746a6338a3d42f6dfd20b5bfdd02163928f1aee0b7b333ab03c9 |
| Guest API mapping 202404.cil | 43db2e1852dc8b2e15e8f1efabcfd73c963626814c8dd7bf111b41ecfb97a6a7 |

Host was parsed from the saved active binary. Guest was compared as an offline composite of Guest platform, system_ext, product, API 202404 mappings, and Samsung Host vendor CIL. The generated comparison JSON records the full tuple sets and additional input metadata. The SHA-256 manifest lists all 65 selected image, policy, context, and triage inputs: [phase8b3a-inputs.sha256](phase8b3a-inputs.sha256).

The analyzer expands source and target attributes, then normalizes active unconditional and enabled conditional records as (source type, target type, class, permission); all matched rules in these policies were unconditional. allowxperm is kept separate. These are TE allow-vector grants, not a complete access decision: constraints and neverallow validation are evaluated separately, and a matching tuple does not prove a runtime object can be reached. Source-direction results measure rights requested by system_server; target-direction results measure other domains' access to system_server objects and are not counted as Guest server requests.

The binary's matched source allow rule objects were Host 2,838 (1,932 literal system_server source, 906 attribute source) and Guest 2,078 (1,612 literal, 466 attribute source). Matched source allowxperm rule objects were Host 72 (26 literal, 46 attribute source) and Guest 70 (22 literal, 48 attribute source). At the source-CIL level, literal statement counts were Host 1,476 and Guest 1,194 for allow, and 30 and 24 for allowx. Rule-object counts, source statements, and expanded tuples are different measures.

## 실효 집합 차분

Coverage is COMMON / comparable Guest tuples. Guest tuples whose opposite type name is absent from the Host binary are kept in the uncomparable count; they are not silently treated as denied Host permissions. Exact label equality does not establish that the underlying Host and Guest objects are the same.

| 방향 / rule | Host effective | Guest effective | Common | Host-only | Guest-only | Guest records uncomparable | Host coverage |
|---|---:|---:|---:|---:|---:|---:|---:|
| Source allow | 45,622 | 34,557 | 33,425 | 12,197 | 1,132 | 853 | 99.17% |
| Source allowxperm | 31,385 | 26,046 | 25,292 | 6,093 | 754 | 708 | 99.82% |
| Target allow | 8,013 | 3,910 | 3,616 | 4,397 | 294 | 183 | 97.02% |
| Target allowxperm | 16,339 | 12,345 | 11,825 | 4,514 | 520 | 480 | 99.66% |

The source allow set has 51 Guest target type names absent from Host. Of the 1,132 Guest-only tuples, 853 target those absent names; 279 remain on Host-present target names. In the allowxperm source set, 57 target names are absent. For target-direction comparisons, 24 Guest source type names are absent. No tuple was uncomparable because its class or permission symbol was missing from the Host binary; the unresolved portion here is primarily missing type names.

### Host-present source allow differences by class

The 279 Guest-only tuples on Host-present target names fall into these classes:

| Class | Tuples | Notes |
|---|---:|---|
| file, dir, lnk_file, chr_file, block_file, fifo_file, fd | 234 | Files, directories, device nodes, pipes, and descriptor access; names alone do not identify the boot call sites. |
| tcp_socket, udp_socket, unix_stream_socket, unix_dgram_socket, vsock_socket | 24 | Network/socket permissions; no evidence here that early framework initialization calls them. |
| process | 12 | Targets include su and virtualizationmanager; child capabilities and runtime use are not established. |
| binder | 6 | Does not prove access to Host Binder; Phase 8A uses a private Guest binderfs device. |
| service_manager | 2 | Does not establish that either service is required during bootstrap. |
| property_service | 1 | Does not override the separate Guest property-area boundary. |

The category counts total 279. Permissions involving Binder, property, file, process, and sockets are included in the normalized set, but the comparison does not map individual tuples to an observed framework call sequence.

## 전이, attributes 및 정책 조건

- system_server source type_transition: Host 13 records, Guest 12; 12 common and one Host-only transition for system_server_wrapfd. No type_change or type_member records were found in this direction.
- No type_transition whose default type is system_server exists in either policy. The startup path is expressed through process permissions: both policies allow system_server_startup to setcurrent and dyntransition to system_server.
- The Guest GSI selects system_server_startup before its hard-coded final setcon("u:r:system_server:s0"). The saved Host binary contains both Host types, but not ssal_guest_probe, ssal_guest_system_server_startup, or ssal_guest_system_server. The initial transition from the actual SSAL Guest zygote therefore cannot be checked against this snapshot.
- The compiled policy name comparison contains 96 Guest-only types and 32 Guest-only attributes. The source-CIL inventory previously counted 21 Guest-only attribute names; the source and compiled policy universes differ and these counts should not be merged. None of the compiled Guest-only attribute names is used literally as a source/target attribute in the Guest system_server source allow rules. Attribute membership among expanded target types includes sdcard_posix_contextmount_type on sdcard_posix, and keystore2_key_type on keystore, locksettings_key, resume_on_reboot_key, and wifi_key.
- The Host binary has 90 constraints and no typebounds; the analysis Guest candidate has 97 constraints and no typebounds. dontaudit is not a grant: source-direction effective dontaudit records are Host 1,147 and Guest 1,821; target-direction records are 31 and 1,482.
- The JSON reports zero unresolved symbols within the compiled candidate. That does not make the candidate a complete or valid runtime policy: its compilation deliberately bypassed neverallow checks and removed genfs declarations, as documented in [results](phase8b3a-results.md).

## 기능별 호환성

| 범주 | 정적 관찰 | 판정 |
|---|---|---|
| Framework Core / ART / JNI | Source allow 문자열 튜플의 comparable coverage는 99.17%. 초기 클래스 로딩이나 ART/JNI 호출 시점은 정책 집계에 포함되지 않음. | **UNKNOWN** — 실행 호출 및 첫 AVC가 없음. |
| Binder / service registration | Host-present type에 Guest-only binder 6개, service_manager 2개. | **UNKNOWN** — private Binder 경계는 유지되지만 대상 타입 의미 및 등록 순서 미검증. |
| Property | Host-present type에 Guest-only property_service 1개; 관련 Guest context 일부는 이전 context 검사에서 invalid. | **UNKNOWN** — Guest property area 경계 유지 여부와 실제 초기 읽기/쓰기는 런타임 시험 필요. |
| Filesystem / runtime | Host-present type의 Guest-only file/directory/device/pipe 클래스 234개; 추가로 Host에 없는 Guest target type이 51개. | **UNKNOWN** — /system, private /data, APEX, runtime file 및 JIT의 실제 의존성을 구분하지 못함. |
| Process / cgroup / capability | Host-present type에 process 12개; SELinux capability 튜플은 함께 비교했으나 child의 실제 capability set은 관찰하지 않음. | **UNKNOWN** — signal/ptrace/cgroup 경계와 실제 child credentials 미검증. |
| Vendor HAL / Lineage extensions | 빠진 type 이름에 Guest HAL 및 Lineage 서비스·앱 label이 포함됨. 정책상 존재만으로 필요성이 입증되지는 않음. | **UNKNOWN / 후순위 후보** — 선택 기능인지 bootstrap 의존성인지 코드 호출로 확인 필요. |

## 실행 가능성 결론

1. Stock GSI를 수정하지 않고 실행하면 최종 SID가 Host system_server와 같다. 저장된 Host 정책에는 그 Host 전이 권한이 있지만, 초기 source가 실제 Guest zygote인지 확인되지 않았고 공통 SID는 Host/Guest SELinux 격리를 깨뜨린다. 따라서 이는 실행 승인 근거가 아니다.
2. 정적 차분만으로 가장 먼저 실패할 framework 호출이나 필수 권한을 특정할 수 없다. Guest-only 권한과 missing type이 보이지만 required_for_boot와 실제 호출 시점은 UNKNOWN이다.
3. 유효한 SID/권한에 대한 거부는 enforcing 실행에서 EACCES 계열 AVC로 나타날 수 있다. permissive는 일부 권한 거부를 우회할 수 있지만 유효하지 않은 type/context SID에서 발생하는 EINVAL을 새 type/context 정의 없이 해결하지 못한다. 과거 37개 context-invalid 자료는 이번 binary에 대한 재검사가 아니다.
4. Phase 8A에서 private Binder, Guest property area, private userdata 경로는 관찰됐으나 /proc은 PID-shared였고 system_server의 Host 경계 negative test는 남아 있다. 이 비교는 그 경계를 보증하지 않는다.
5. 보완 후보는 Phase 8B-2의 Guest-specific startup/final SID 전환 설계를 이어가는 것이다. Host system_server allow를 추가하는 것은 제안하지 않는다. 실제 필요한 Guest-only allow 목록은 부팅 AVC 없이는 만들지 않는다.

다음 단계는 Guest-specific 전환과 Host 경계를 검증하는 통제된 8B-3B 준비로 제한한다. Stock shared SID 아래에서 SystemServer.main()/run() 진입을 허용하지 않는다.
