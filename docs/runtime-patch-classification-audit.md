# SSAL Runtime Patch Classification Audit

감사일: 2026-11-16 KST. 기준 HEAD: `e08482355da3494eabeaa33666b38135fc472fc8`와 감사 시점의 미커밋 작업 트리. **READ-ONLY 정적 감사**이며 이 문서만 생성했다. 코드 수정, 빌드/테스트 실행, WSL/WSLc, adb, 정책 생성·주입, 실기기 실행 및 정리는 수행하지 않았다.

## 1. 결론과 판정 기준

SSAL은 Guest Android init을 실행하지 않고, 독립 userdata·mount view·property service·Private Binder 위에서 일부 서비스를 직접 실행하는 단계다. 예상 사용 규모는 단말 한 대의 disposable Guest 세션 하나이며, 다중 Guest 동시 운용이나 완성된 hot-switch를 가정하지 않았다. 누적 수정에는 정상 Android 초기화를 대신하는 처리, 공유 커널 때문에 필요한 처리, 특정 이미지/플랫폼 대응, 진단 코드가 혼재한다.

가장 먼저 정리할 후보는 **실행 도메인 선택의 불완전한 서비스 목록**, **프로필 매핑 위에 남은 고정 SID fork probe**, **생성·캐시·실제 적용 정책의 차이**다. 반대로 private property 저장소, 명시적 SELinux 전환, socket 생성 라벨, 실제 kernel에 대한 AV 조회, private Binder identity 검증을 단순한 임시 패치로 삭제하면 기존 진행 경로가 깨진다. 지금 필요한 것은 첫 부팅 이전의 대규모 재작성보다 현재 성공 범위를 보존하는 작은 정리다.

분류는 코드의 존재 이유를 뜻하며 품질이나 삭제 가능 여부를 뜻하지 않는다.

| 기호 | 의미 |
|---|---|
| A | Android 기본 요구사항: init/서비스가 통상 제공해야 하는 환경·권한·초기화 |
| B | SSAL 구조적 요구사항: Userspace Guest, init 대체, namespace, Private Binder, 공유 커널 |
| C | Host 호환성: KernelSU, Samsung 및 실제 Host 커널/컨트롤러 구성 |
| D | GSI 종속성: Android/LineageOS 버전, 특정 이미지의 파일·ABI·정책·바이너리 구성 |
| E | 임시 코드: 진단, 시험 fixture, 우회, 단계별 bring-up gate |
| UNKNOWN | 분류 또는 원인·현재 필요성의 근거가 부족함. 추측으로 확정하지 않음 |

복합 항목은 주분류를 먼저 적었다. 예: `B+C`는 SSAL 구조가 주원인이고 Host 구현에 의존한다. 아래의 “필요”는 현재 구현의 의존성이지 Android 전체 부팅 성공을 보증하는 표현이 아니다. “도입 이유”는 코드 주석·실제 호출 경로·기존 결과 문서에서 확인한 목적이며, 항목별 최초 도입 커밋을 모두 역추적했다는 뜻은 아니다. 문서에 기록된 과거 실행 결과는 이번에 재현하지 않았다.

## 2. 범위와 현재 경로

직접 확인한 범위는 `src/prepare.rs`, `guest_mounts.rs`, `guest_probe.rs`, `guest_launcher.rs`와 하위 모듈, `guest_policy.rs`와 runtime/native/symbols, `guest_properties/{mod,server,policy,persistent}.rs`, `binder_probe.rs`, `memory_cgroup.rs`, `service_contract.rs`, 관련 module profile·policy·build/run/patch/test script, `native/binder-probe`의 매핑·FD·진단·전환 코드와 phase3 IPC다. README/Cargo/package 설정과 연결된 결과 문서도 확인했다. 전체 저장소·모든 probe·모든 테스트를 전수 감사한 것은 아니다.

`vendor/` 소스와 submodule 내용, 원본 GSI/Host 바이너리 및 raw logcat/dmesg는 읽지 않았다. 로그 관련 판단은 기존 요약 문서의 경로·행·관측을 인용한다. Git 상태 조회는 `--ignore-submodules`로 제한했다. 최초 기본 Git 상태 조회는 KernelSU submodule 접근 제한으로 실패했으며 해당 소스를 열지 않았다.

현재 작업 트리에는 런처, 정책, property, memory cgroup 및 phase3 등의 기존 미커밋 수정이 있다. 감사에는 이 수정도 포함했고 보존했다. 특히 AIDL 전용 실행 파일·도메인 준비는 HEAD 이후 수정이다. 파일·라인은 감사 당시 작업 트리 기준이며 후속 변경 시 달라질 수 있다.

실행 경로:

1. `prepare::worker` (`src/prepare.rs:487–639`): mount namespace 분리, private propagation, userdata 잠금/검사와 ext4 RW·system RO mount.
2. `guest_mounts::verify` (`:1090–1155`): prepare에서는 정책 준비/적용, 일부 launcher worker에서는 기존 `selinux/plan.json` 존재 시 정책 준비/적용. Guest system/APEX를 private overlay로 복제·재라벨한다.
3. Guest `/dev`, `/data`, cgroup view, contexts와 APEX를 준비한다. 일반 prepare의 linkerconfig/동적 shell probe와 서비스 런처는 서로 다른 helper 경로다.
4. `guest_launcher::verify` (`:1258`): Property Service → 초기 property/격리 검사 → Private Binder → linkerconfig → shell probe → ServiceManager의 실제 ready property → Context Manager 응답 → AIDL 등록/호출 → 선택적 Zygote 또는 6A/6B 시험.
5. Zygote 기본 시험에는 `--start-system-server`가 없다. 8B-5 옵션은 `system_server_runtime_sid::enabled`에서 무조건 오류로 종료한다. 서비스 계약의 `launch_enabled=false`와 `switch/return` 차단은 이 disposable worker와 별개다.

**주의:** 저장소의 `prepare`는 순수 조회 명령이 아니다. `prepare_mounted`가 active kernel policy에 추가 규칙을 적용할 수 있다(`src/guest_policy/runtime.rs:597–632`). 이번 감사에서는 실행하지 않았다.

## 3. 수정 분류 원장

각 행은 함께 제거/변경될 가능성이 높은 처리 단위다. 수정된 모든 줄을 별개의 패치로 세지는 않았다. 위치 열은 관련 함수와 실제 근거 구간을 함께 적었다.

### 3.1 런처·namespace·서비스 초기화

| ID / 분류 | 파일·함수·라인 | 도입 이유 / 현재 필요성 | 제거 시 영향 | 일반화 판단 |
|---|---|---|---|---|
| L01 B | `src/prepare.rs:497–543`, `worker`; `src/guest_probe.rs:310–413`, `root_command` | Host mount 전파와 root/FD 노출을 막는 private namespace, chroot/pivot_root, old-root detach, FD 정리. 현재 핵심 경계다. | Host 경로가 보이거나 mount가 전파될 수 있고 userdata/서비스 격리 검증도 무의미해진다. | 공통 처리 유지. Zygote pivot 선택이 `SSAL_PHASE7FB_FORK`에 묶인 부분은 E와 분리 후보. |
| L02 A+B | `src/guest_launcher.rs:64–134`, `command` | Android root/data/APEX 환경, 명시적 UID/GID·보조 그룹 제거, exec SID 설정과 부모 사망 시 종료. init 없는 런처가 대신해야 한다. | 잘못된 파일/라이브러리/권한을 사용하거나 orphan Guest가 남는다. | 공통 실행 계약으로 유지. 모든 서비스가 UID=GID·보조 그룹 없음으로 동작한다는 일반화는 불가. |
| L03 B+C | 같은 파일 `:47–61,83–87,118–129`, `join_cgroups`; `src/memory_cgroup.rs:194–232,276–325` | 자식만 Guest 컨트롤러에 가입시키고 exec 전 membership 확인. 루트 전환 후 Guest view에서 가입한다. | Guest가 제한 밖에서 시작하거나 잘못된 namespace 경로로 가입 실패한다. | 공통 순서 유지; 실제 cgroup mount 경로는 플랫폼 예외. |
| L04 B+A | `src/guest_probe.rs:295–307`, `isolate_process_group` | 일반 자식은 setsid, Zygote는 setpgid. ZygoteInit의 추가 setpgid가 session leader에서 실패하는 문제를 피한다. | Zygote 초기화가 EPERM으로 중단될 수 있다. | Zygote 의미에 따른 예외 유지. 임의 서비스명 분기와 구분한다. |
| L05 B+D | `src/guest_launcher.rs:22–37,75–82`, `mapped_exec_domain` | 직접 exec에 대응하는 프로필 도메인 선택. property helper→init, app_process64→zygote, ServiceManager/linkerconfig/AIDL은 개별 매핑한다. | 현재 매핑을 없애면 shell/Host 도메인 실행 또는 transition 실패. | 공통화 후보지만 목록 불완전: installd/artd는 `_ => shell`이다. 아래 F1. |
| L06 D+B | 같은 파일 `:88–110,1661–1678`, `command`, `verify` | bootstrap linker, artd, derive_classpath, Zygote의 개별 `LD_LIBRARY_PATH`; ART namespace가 libart singleton을 소유하게 한다. | helper 로딩 실패 또는 ART 중복 로드 위험. | 서비스별 ELF/APEX 배치에서 도출 가능. 현재 경로 목록의 타 GSI 필요성은 UNKNOWN. |
| L07 A+B | 같은 파일 `:136–169`, `zygote_sockets`; `:1302–1320`, `verify` | init의 `ANDROID_SOCKET_*` 상속을 대신하고, child root 전환 후 `/dev/socket`에 bind. zygote GID 1000/mode 0660 및 abstract socket 충돌 방지용 net namespace. | socket이 Host/Guest에서 어긋나거나 Zygote client 연결·상속 FD가 실패한다. | 생성·상속은 공통; zygote/usap 이름·DAC는 서비스 명세로 유지. net namespace는 SSAL 공통 경계. |
| L08 B+E | 같은 파일 `:350–505,729–751`, `Service::start/stop`; `src/zygote_diagnostics.rs:11–67` | 부모가 pipe를 읽고 파일을 기록해 Guest의 system_file 쓰기 권한 없이 로그를 보존. 1 MiB 저장 한도 후에도 drain. 종료 시 unreaped leader의 process group을 종료한다. | 직접 파일 FD로 되돌리면 Guest 로그 write 거부가 재발하며 오류 원인을 잃는다. 무조건 종료 로직 제거 시 후손 잔존 가능. | pipe 수집은 공통 유지. 현재 SIGKILL 중심 종료는 disposable E이며 운영의 flush/TERM 계약과 다르다. |
| L09 A+B | `src/guest_launcher.rs:598–668,1545–1595`, readiness 함수; `tools/rsbinder/src/android.rs:187–246` | `servicemanager.ready=false`에서 실제 true를 기다리고 handle 0의 정상 응답, AIDL 왕복으로 readiness를 증명한다. transaction 오류를 서비스 부재로 취급하지 않는다. | false-ready로 다음 서비스를 시작하거나 DeadObject를 성공으로 오인한다. | 실제 readiness는 공통 유지. AIDL 시험 fixture의 이름/인터페이스는 E. |
| L10 B+E | `src/guest_launcher.rs:257–266,1194–1215,1506–1537` | getprop 직접 exec 대신 shell builtin 경로 사용. Guest shell의 getattr 제한으로 socket 존재를 잘못 판단한 검사를 Host-side Rust로 옮겼다. | 이전 직접 getprop spawn EACCES/거짓 missing 가능. | identity·socket type 검증은 공통; 정확히 socket 한 개만 허용하는 검사는 시작 단계 전용 E. 실제 getattr 거부의 모든 규칙 원인은 UNKNOWN. |
| L11 E+D | 같은 파일 `:1337–1367,1558–1566`; `module/sepolicy.rule:9–14` | phase3 AIDL helper의 실행 inode를 전용 exec type으로 라벨하고 mapped aidl_lazy_test_server로 실행. shell→service_manager:add 거부에 대응한다. | helper를 shell로 실행하면 등록 실패. 이 검사가 Zygote보다 앞에 있어 Zygote도 미도달한다. | AIDL fixture는 E. 올바른 exec type/서비스 domain 준비라는 패턴은 A+B로 일반화 가능. GSI에 이 시험 type이 없으면 현재는 실패한다. |
| L12 E | `src/guest_launcher.rs:1894–2007`, 6A/6B 분기 | installd/artd 생존 500 ms·descriptor 검사, 고정 test package/UID 10000의 create/delete. artd dexopt 미구현은 명시적 오류다. | 시험 증거가 줄어든다. 해당 루프는 서비스를 하나씩 종료하므로 운영 supervisor 역할을 대체하지 못한다. | 공통 서비스 기동과 시험 시나리오 분리 후보. 과거 6A PASS를 현재 mapped 서비스 SID PASS로 확대할 수 없다. |
| L13 E+B | `src/guest_mounts.rs:32–35`; `src/service_contract.rs:101–206`; `module/profiles/concurrent/services/initial.json:1–22` | 자동 launch 금지와 요구조건·복구 계약. 런처는 명시적 disposable worker로만 실행된다. | 단순 gate 삭제는 미검증 vold/HAL/FBE/복구까지 기동 허용한 것으로 바꾼다. | gate 유지. 계약 데이터가 현재 런처의 실행 spec 원본은 아니다. 아래 F2. |

### 3.2 SELinux 생성·추가 규칙·주입

| ID / 분류 | 파일·함수·라인 | 도입 이유 / 현재 필요성 | 제거 시 영향 | 일반화 판단 |
|---|---|---|---|---|
| S01 B+C | `src/guest_policy.rs:50–113,537–608,1148–1190`, ID/`generate/prepare` | `ssal_pNNNN_*` 타입·attribute와 영구 ID 예약, input hash/version 캐시. KernelSU에서 삭제 불가한 이전 Guest와 충돌을 피한다. | Host와 SID가 합쳐지거나 이전 프로필 권한을 재사용하고 stale plan을 쓸 수 있다. | 공통 유지. 프로필 제거 후 ID 재사용 금지 역시 필요. |
| S02 B | 같은 파일 `:474–535,651–813`, `shared_path/rewrite/generate` | Guest file/property/service/seapp contexts를 매핑하되 Host 공유 `/vendor,/odm,/dev,/proc,/sys` 라벨은 보존. private Binder/property/socket은 예외. source attribute는 private, target set은 공유 Host 라벨도 포함한다. | Guest 컨텍스트가 Host와 충돌하거나 Host inode relabel, 공유 device 접근 실패. | 두 매핑은 중복 SID가 아니라 process/file ownership와 공유 target의 구분이다. 경로 기반 shared 판정은 새 mount 종류마다 재검토. |
| S03 C+B | 같은 파일 `:1038–1049`, `generate` | Host constraints/MLS/genfscon/fsuse를 보존하고 GSI typepermissive를 적용하지 않는다. | GSI 정책으로 공유 커널 보안 제약을 덮어쓰는 위험. | Host 보존 원칙으로 유지. Guest CIL과 의미가 완전히 같다는 보장은 없다. |
| S04 B+C | `src/guest_policy.rs:1078–1093`, `generate` | init/shell이 Guest bootstrap linker를 직접 exec하므로 system_linker_exec entrypoint 추가. Android 통상 daemon 실행 방식과 다른 helper ABI 대응. | Property Service·phase3 client의 linker 실행 전환이 실패할 수 있다. | helper 실행 방식에 필요한 규칙으로 유지. 모든 domain으로 확대할 이유는 없다. |
| S05 C+B(+E) | 같은 파일 `:1094–1115`, `generate` | Guest init/shell/linkerconfig/ServiceManager/AIDL server가 ksu에서 연 ELF·stdio FD를 사용하도록 `ksu:fd use`, `ksu:fifo_file write` 추가. AIDL은 시험 전용 추가다. | inherited FD/pipe 접근이 막혀 시작·로깅·IPC 진단이 실패한다. | KernelSU 런처 공통 규칙이나 대상 domain은 서비스별 유지. Host ksu에 새 source 권한을 준 것과 혼동하지 않는다. |
| S06 B+A | 같은 파일 `:1116–1128`; `src/guest_properties/mod.rs:447–459` | init이 properties_device로 생성된 파일을 최종 property type으로 바꾸도록 `file relabelfrom` 추가. | 생성 직후 최종 라벨 변경이 필요한 파일에서 EACCES. | 현재 생성 순서의 보완. 모든 property type의 relabelfrom 허용으로 확대할 근거 없음. |
| S07 B+C | `src/guest_policy.rs:1130–1141`; `src/binder_probe.rs:89–112` | binderfs `context=`의 mapped binder_device가 filesystem에 associate하도록 같은 mapped type 대상 권한 추가. | binderfs mount EPERM 가능. 기존 Y702 실패 기록과 대응한다. | shared kernel의 private Binder 공통 처리. Host binder_device 자체의 권한 변경 불필요. |
| S08 A+B | `src/guest_policy.rs:175–201`; `src/guest_policy/runtime.rs:614–616`; `src/guest_mounts.rs:1186–1199` | Guest `/dev/socket`을 mapped socket_device로 라벨하고 init→property_socket 생성 transition 추가. 생성 단계부터 올바른 타입을 준다. | socket이 잘못된 타입으로 생기고 후속 relabel/connect가 거부될 수 있다. | 생성 라벨 보장은 공통. 캐시 후 보정 함수에 존재하는 구현 배치는 F3 정리 후보. |
| S09 B | `src/guest_policy.rs:144–161`; runtime `:615–616`; property policy `:113–160` | Guest init/ServiceManager의 AV 질의는 실제 커널의 `kernel:security compute_av`를 필요로 한다. 복제 Guest kernel type에 대한 allow로는 충족하지 못한다. | writer의 set allow가 있어도 property authorization이 EACCES, ServiceManager self-registration/readiness 실패. | 현재 공유 커널 구조의 공통 처리로 유지. 두 Guest source만 추가하며 Host source 권한은 늘리지 않는다. |
| S10 C+D | `src/guest_policy/runtime.rs:310–451`, `compatible_plan` | Host class/permission 없는 규칙을 누락·축소하고 미존재 공유 type은 permissionless placeholder로 선언. 기존 placeholder는 재시도에도 권한을 받지 않는다. | 다른 Android/커널 조합에서 전체 적용 실패 또는 placeholder를 실 device로 잘못 허용. | 호환 계층으로 유지. `compatibility.json`은 기능적 손실 기록이지 부팅 가능 판정이 아니다. |
| S11 C+E | `src/guest_policy.rs:203–219,849`; `usable/generate` | KernelSU 미지원 nlmsg xperm만 예외적으로 누락 허용. 나머지 unsupported는 중단한다. | 예외 제거 시 해당 CIL을 가진 GSI 준비 중단. 반대로 무제한 무시는 잘못된 정책을 통과시킨다. | 현재 한계가 명시된 shortcut. 어느 서비스에 실제 필요한지는 UNKNOWN. |
| S12 C | runtime `:51–74,157–308,458–590`; native `:5–7,172–267,300–365` | ksud 구문 정규화·xperm 분할, 선언→membership→rule 순서, 16 KiB native batch, UAPI 5 검증. 특수 filename transition은 native backend 선택. | 잘못된 policy 표현/순서/ABI로 적용 실패 또는 부분 적용. | KernelSU별 예외 유지. native 표현과 ledger text의 대응 검증을 삭제하지 않는다. |
| S13 C+B | runtime `:284–307,463–590`, `delta/apply_with_backend` | boot ID별 applied ledger, 프로필 lock, pending/부분 실패의 재부팅 요구, 기존 statement 비삭제. | 중복 선언·소유권 충돌·불명확한 부분 적용 위에 재시도할 수 있다. | 필수 공통 상태 관리. desired plan에서 규칙 삭제해도 같은 boot의 live rule은 제거되지 않는다. rule readback은 현재 미검증. |
| S14 C | runtime `:86–155`, `read_policy_with_recovery/recover_policy_export` | policy export EINVAL 때 이미 허용된 `ksu→ssal_image_file:file read`를 검증해 한 번 재적용. KernelSU serialization length 회복 목적. | 해당 Host에서 심볼 조회/prepare가 계속 실패한다. | 특정 KernelSU 동작의 예외로 유지. 원인 수정된 Host에서는 제거 후보이며 현재 버전별 적용 범위는 UNKNOWN. |
| S15 B+C | runtime `:635–695,756–843`, overlay/`bind_file/relabel_tree` | RO GSI·Host helper를 직접 relabel하지 않고 Guest ext4 upper에 copy-up. `metacopy=off`로 mprotect가 검사하는 backing inode도 Guest 라벨을 받는다. | exec/mprotect가 원본 Host label을 보고 거부하거나 Host 원본을 변조할 수 있다. | private 복제·라벨 공통 유지. directory patch 미지원은 명시적 한계다. |
| S16 B+D | runtime `:698–752`, `install`; `src/guest_mounts.rs:1176–1184,1362–1408` | mapped contexts 설치, stale file_contexts.bin 제거, linkerconfig 디렉터리 라벨, overlay backing 숨김, 실제 userdata restorecon probe. | stale context 우선 사용·잘못된 생성 라벨·restorecon이 system/APEX backing을 바꾸는 문제. | context 설치와 backing 보호는 공통. probe 생성/증거는 E이며 사용자 파일 전체 라벨 검증과 다르다. |
| S17 B+D | `native/binder-probe/context-map.c:9–65`; runtime `:722–736`; launcher `:426–439` | setcon/setexeccon/setfscreatecon의 원래 타입을 프로필 타입으로 변환하고 MLS suffix 보존. 이미 mapped 값은 그대로 전달, 미등록 값 실패. fork 전 map 로드. | Android runtime의 원래 SID literal이나 setter가 Host 타입을 선택하거나 전환 실패. | process/생성 context 변환 공통 유지. 8191 entries·256-byte 이름 한계와 동적 interposition 범위는 유지보수 대상. 모든 direct syscall/객체 setter를 포괄한다는 근거는 없음. |
| S18 D+B | `native/binder-probe/context-map.c:47–56`; launcher `:1382–1403`; mounts `:1283–1291` | RO selinuxfs를 libselinux가 미탐지하므로 실제 magic 검사·set_selinuxmnt 등록. prepare는 context query만 RW, launcher는 query 파일을 제외한 control을 RO bind. | is_selinux_enabled/context/AV 조회가 실패하고 property/service 접근 판정이 깨진다. | libselinux 버전별 탐지 예외와 query endpoint 공통 요구를 구분한다. load/enforce의 RO는 유지. |
| S19 E+C | `module/sepolicy.rule:15–36` | 과거 ssal_guest_probe/ssal_property permissive domain, 고정 property 타입·transition. Host global Enforcing과 별개인 실험 정책이다. | legacy probe/property fallback이 실패할 수 있다. mapped 전용 경로의 필요성은 별도다. | 유지 여부는 caller별 정리 후보. global Enforcing만으로 이 domain의 enforcing을 주장하지 않는다. Guest 실험 domain permissive를 Host 정책 전체 약화와 동일시하지도 않는다. |

### 3.3 Property Service와 저장소

| ID / 분류 | 파일·함수·라인 | 도입 이유 / 현재 필요성 | 제거 시 영향 | 일반화 판단 |
|---|---|---|---|---|
| P01 A+B | `src/guest_launcher.rs:1065–1223`; `src/guest_properties/mod.rs:100–152,436–532` | init 대신 private area/trie/serial 생성, Guest build props와 persistent 복구, 별도 socket 서비스. Host namespace/inode/FD 분리와 init SID 확인. | Host property 공유·Guest persist 유실·ServiceManager의 ready 갱신 불가. | 공통 핵심. mapped 타입과 legacy fallback의 두 경로는 중복 규칙 그 자체는 아니다. |
| P02 A+B | `src/guest_properties/policy.rs:11–160`; server `:30–115,125–171,231–278` | wire V1/V2·길이/타입 검증, peer credential/SELinux SID 조회, 실제 property:set allow 확인. socket 0666은 모든 UID의 접속 허용이며 쓰기는 property별 인증한다. | 비인가 property 쓰기, protocol 호환 실패. | 공통 유지. socket DAC를 좁혀서 authorization을 대체할 수 없다. |
| P03 B+E | policy `:69–105`, `validate`; launcher `:1531–1537` | ctl.*, sys.powerctl, selinux.restorecon_recursive를 거부하고 Host init으로 전달하지 않는다. 현재 service supervisor 기능의 제한이기도 하다. | Guest 요청이 Host 제어로 연결되면 격리 목표 위반. 단순 허용만으로 Guest service 시작을 구현하지 못한다. | Host 비전달은 B로 영구 유지; 향후 Guest 자체 제어 구현만 별도 후보. negative smoke는 E. |
| P04 A+B | `src/guest_properties/persistent.rs:35–175`, `Store`; mod `:69–93,444–446` | 디렉터리/lock/persistent 파일의 타입·소유권·라벨 검증, 단일 writer flock, protobuf 저장·staged 적용·임시 파일 fsync/rename. | 재기동 복구·동시 쓰기·중단 시 데이터 보존이 깨진다. | 공통 유지. 현 lock 오류를 넘기는 우회는 리팩터링 후보가 아니다. 오류 identity 출력은 E. |
| P05 B+C / 원인 UNKNOWN | mod `:154–284`, `label`; server `:174–229,286–332`, socket label helper | 실제 SID와 목표 SID가 정확히 같으면 재설정 생략, 다르면 setxattr 후 readback. 동일 SID fsetxattr EACCES 관측에 대응. | 불필요 relabel로 기존 초기화가 다시 막힐 수 있다. 오류/불일치를 무시하면 잘못된 label로 공개된다. | 멱등 라벨 보장은 일반화 가능. EACCES가 Samsung/커널/정책 어느 계층 때문인지는 UNKNOWN이며 universal Android 필수 우회로 확정하지 않음. |
| P06 D+E | launcher `:1073–1109,1411–1436,1506–1515`; mod `:404–433` | SDK 36 검사, REL/arm64-v8a/dex2oat64/GL preload disable override, system/build.prop만 명시 입력. import는 오류. | 현재 이미지 시험 조건이 달라지고 타 SDK·ABI 이미지는 정상이어도 실패 가능. | 이미지 metadata/boot property 우선순위에서 도출할 후보. GL disable은 미구현 그래픽 bring-up용 E, 보편 Android 요구 아님. 모든 override의 최초 고장 근거는 UNKNOWN. |
| P07 E | launcher `:1065–1086,1267,1418–1435`; `fork_probe.rs:315` | persist.ssal_probe=7, sys.ssal_probe, restore branch 등 private property 시험 fixture. | 시험의 저장/복구·fork readback 증거만 줄어든다. | 운영 seed와 분리 후보. mapped plan에서는 임시 contexts 입력을 전체 mapped property_contexts로 교체하므로 고정 persist mapping이 그대로 적용된다고 해석하지 않는다. |

### 3.4 GSI/APEX·플랫폼 및 진단 예외

| ID / 분류 | 파일·함수·라인 | 도입 이유 / 현재 필요성 | 제거 시 영향 | 일반화 판단 |
|---|---|---|---|---|
| X01 A+B+D | `src/guest_mounts.rs:469–620`, `apex/linkerconfig_binary/linkerconfig`; launcher `:1448–1471` | apexd/init 없이 APEX payload/alias와 linkerconfig를 구성. runtime APEX→system/bin 후보 순서 지원. 서비스 런처에서는 property와 private Binder 준비 이후 linkerconfig 실행. | linker namespace/공유 라이브러리 탐색이 깨진다. | APEX 준비와 의존 순서는 공통, 압축/partition/layout는 GSI별. 일반 prepare helper와 서비스 helper를 무조건 합치면 실행 문맥이 달라진다. |
| X02 A+D+E | launcher `:931–1062,1655–1677`, classpath 함수 | derive_classpath 결과 파싱·파일 검증은 Android 요구. `--override-device-sdk-version=36/REL`, controlled fork의 am.jar 추가는 이미지/시험 제약. | classpath 없으면 Zygote 실행 실패. override만 제거했을 때 현재 이미지 영향은 UNKNOWN. | 파싱·검증은 공통, SDK는 Guest에서 도출, am.jar slot은 E로 분리. |
| X03 B+C | `src/guest_mounts.rs:744–864,912–981`; `src/memory_cgroup.rs:194–232,484–564` | cpu/cpuset/blkio Guest subtree, v1 `/dev/memcg`와 v2 memory 지원. task profile의 비위임 memory action을 제거하되 제한은 별도 backend가 적용한다. | membership·메모리 제한·libprocessgroup 초기화 실패 또는 Host controller 침범. | backend별 예외 유지. v1 memory도 현재 task용 cgroup2 mount를 요구하며 모든 v1-only Host 지원은 아님. JSON schema/path 고정은 일반화 후보. |
| X04 B+C | `src/binder_probe.rs:72–222`, `provision_with_context`; launcher `:1448–1459` | fresh binderfs 기본 binder 재사용 또는 BINDER_CTL_ADD, alias inode/rdev/mount ID·protocol 8 검사, Guest node만 0666. | Host Binder 선택/다른 registry 사용 또는 UID 1000 접근 실패. | 공통 유지. default node 존재 여부·mount label은 커널 예외. 0666만으로 SELinux 허용을 대신하지 않는다. |
| X05 D / 필요성 UNKNOWN | `module/profiles/concurrent/mounts/initial.json:25–32`; mounts `:623–705`, `patches/permission_controller` | services/framework JAR·resource APK·audio library·extservices permissions·PermissionController의 선택적 교체. source 있을 때만 적용. | 실제 patch가 필요한 이미지에서 기능 실패 가능하나 현 파일만으로 각 patch 내용·필수성 판정 불가. | 장착 메커니즘은 B, payload는 D 또는 E UNKNOWN. 이름만 보고 Android 공통 필수로 승격하거나 전부 삭제하지 않는다. |
| X06 E+B / 목적 일부 UNKNOWN | mounts `:708–741`, `code_bridges`; `src/guest_lock_compat.rs:1–35`, mounts `:323–357` | Guest용 CLI/probe 복사, opt-in su bridge와 offline lockscreen/Weaver 호환 자료. Host /data/adb 전체 bind 대신 개별 파일 사용. | 선택적 probe/bridge가 사라진다. lock compat는 실행 승인 기능이 아니다. | 현재 핵심 성공 경로의 필수성 없음. su payload 내용/최종 권한 경계와 lockscreen 실기능은 UNKNOWN. |
| X07 B+D+E | `native/binder-probe/zygote-fd-reopen.c:15–122`; launcher `:395–398`; `src/guest_launcher/fork_probe.rs:48–75` | detached FD path를 Guest inode와 검증해 재open, offset/CLOEXEC/fdsan 유지. Java stdio clone만 /dev/null로 교체. Lineage resource·am.jar·BOOTCLASSPATH fallback 목록 포함. | stock Zygote FD allowlist가 Host/오래된 mount path 또는 stdio clone을 거부할 수 있다. | inode 동일성 검사·재open은 B, Lineage resource 목록은 D, probe trigger/stdio 시험 영향은 E. 안전 검사 없는 path 재작성으로 대체 금지. |
| X08 E | `native/binder-probe/zygote-diagnostics.c:26–65,186–210`; launcher `:375–417,1324–1335`; `src/zygote_diagnostics.rs:85–218` | preload로 property/socket/fatal/메모리 추적. Zygote 서비스명에 진단 파일과 라이브러리가 필수로 연결돼 있다. | 증거 수집과 일부 시험이 실패한다. 진단 없는 운영 기동은 현재 확인되지 않았다. | 진단 기능 분리 후보. 단순 로깅 제거가 preload와 FD 수명까지 바꾸지 않도록 한다. |
| X09 E | `zygote-diagnostics.c:56–62`; launcher `:1268–1280,1680–1682` | EINVAL일 때 UID10000·ssal_probe·정확한 이름/기존 SID 조건 아래 setcontext 실패를 성공으로 반환하는 retained-domain 우회. mapped plan과 동시 사용은 거부. | legacy Java probe 성공 경로가 다시 EINVAL로 중단될 수 있다. | 운영에 일반화 금지. 정상 app specialization의 증거로 사용하지 않는다. |
| X10 E+D | `native/binder-probe/zygote-selinux-noop.c:37–77`; launcher `:399–413,1368–1374`; `scripts/patch-app-selinux-same-context.py:1–38` | 이름이 noop인 wrapper는 현재 real setter 호출·결과를 보존하는 진단이다. 별도 same-context exact-binary patch는 재검증 분기를 바꾸며 setter는 유지한다. | 해당 비교 실험이 불가해진다. 정상 경로의 필수 요소는 아니다. | 이름만으로 “SELinux 모두 무시”로 분류하지 않는다. 후자는 hash/offset에 종속된 D+E이며 mapped 모드와 동시 사용 금지. |
| X11 E+D+C | `src/guest_launcher/system_server_runtime_sid.rs:5–97`; `scripts/patch-system-server-sid.py:7–30`; gate/boundary native 코드 | ssal_guest_ss/startup 고정 SID, exact hash/offset binary patch, one-shot gate/canary·SystemServer 진입 방지. 8B-5는 기기 전원 종료 후 `enabled`가 무조건 실패한다. | gate만 제거하면 검증되지 않은 시스템 실행을 다시 연다. dormant probe 삭제는 재현 도구 소실. | 과거 실험으로 격리 후보. 공유 kernel/FIVE 원인을 확정하거나 Samsung 공통 호환 해결책으로 간주할 수 없음. |
| X12 E | `src/guest_launcher/fork_probe.rs:7–15,57–75,335–342`; launcher `:1686–1711,1887–1892`; `scripts/run-guest-launcher.sh:3–44` | 고정 UID/package/seinfo/SID, am.jar 덮기, 특정 profile/image/staging, Zygote 진단 후 종료. 실제 Android 초기화 대신 제한된 probe다. | 과거 controlled-fork 재현이 깨진다. 이것을 제거한다고 boot supervisor가 생기지는 않는다. | 테스트 구성으로 분리 후보. 고정 domain과 mapped 경로 충돌은 F1, 단말 경로는 runtime 공통 config가 아니다. |

## 4. 중점 조사 결과와 기술 부채 우선순위

다음 8건은 수정 제안이며 이번 감사에서 수정하지 않았다. P1은 해당 기능을 일반화할 때 먼저 처리할 항목, P2는 첫 부팅 진전을 유지하며 단계적으로 처리할 항목이다. 현재 전체 부팅을 막는 새 보안 강화를 요구하는 목록이 아니다.

### Should fix

1. **F1 / P1 — 서비스 SID 선택과 고정 fork SID가 현재 매핑 계약을 벗어난다.** `mapped_exec_domain`은 installd/artd를 다루지 않아 6A의 `Service::start(..., GUEST_PROBE_CONTEXT)`가 mapped 모드에서는 shell로 실행된다(`guest_launcher.rs:22–37,1902–1907`). fork probe는 mapped seapp_contexts 위에 `domain=ssal_guest_probe` 한 줄을 bind하고 그 SID를 기대한다(`fork_probe.rs:65–75,335–342`). 따라서 6A 생존/descriptor 성공과 legacy fork PASS는 각각 실제 서비스 domain/app domain 성공을 증명하지 않는다. 최소 후보는 필요한 두 서비스의 실제 exec domain을 명시하고, mapped fork 시험은 plan 기반 seapp/domain을 쓰도록 시험과 기대값만 함께 맞추는 것이다. **회귀 위험 높음:** context-map, helper 라벨, 서비스 add 권한, 자식 SID assertion이 함께 영향을 받는다. 변경 없이 두면 정상 프로필 도메인에서의 서비스 검증이 계속 비어 있다.

2. **F2 / P1 — 서비스 명세가 계약 JSON, Rust 실행 목록, 정책 helper 목록에 나뉜다.** `initial.json`은 zygote가 artd/vold에 의존한다고 기록하지만, disposable 7A는 이들을 실행하지 않고 Zygote만 진단한다(`guest_launcher.rs:1597–1892`). JSON에는 고정 property SID가 있고 실제 mapped 실행은 init을 쓴다. 이는 지금의 시험 범위에서는 의도된 축소이며 곧바로 런처 버그로 판정하지 않는다. 최소 후보는 운영 계약과 진단 시나리오를 명확히 구분하고, 런처·정책에 공통으로 필요한 서비스 이름/실행 domain 목록만 맞추는 것이다. 일반 init rc parser나 새 supervisor framework 전체 도입은 불필요하다. 방치하면 E 단계 성공이 A 전체 계약 충족으로 오해된다.

3. **F3 / P1 — 생성 정책, 캐시 정책, 호환 적용 정책은 같지 않다.** `prepare`가 캐시/역사 plan을 먼저 저장한 뒤 `prepare_mounted`가 socket transition과 compute_av를 보정한다(`guest_policy.rs:1148–1190`, runtime `:614–616`). 이어 compatible_plan이 누락/축소하고 applied ledger는 과거 addition을 누적한다. 캐시 plan만 읽는 오프라인 소비자/감사는 실제 runtime 보정과 live 누적분을 놓칠 수 있다. 최소 후보는 보정 규칙의 생성 위치와 cache hit 처리를 하나의 최종 plan 계약으로 맞추고, desired/cached/compatible/applied의 차이를 증거에 명시하는 것이다. **같은 boot에서 불필요 allow를 제거했다고 주장해서는 안 된다.** 부작용 없는 오프라인 생성·native encoding 및 다음 boot의 delta를 각각 확인해야 한다.

4. **F4 / P1 — AIDL fixture가 GSI 기능 종속성을 런처 전체의 진입 조건으로 만든다.** 현재 `verify`는 optional plan이 없으면 `Guest SELinux plan missing for AIDL server`로 실패하고, `aidl_lazy_test_server_exec` type을 반드시 요구한다(`guest_launcher.rs:1353–1361`). 이 코드는 기존 미커밋 변경이며 최신 결과 문서의 attempt47은 아직 shell SID 등록 거부까지다. 따라서 전용 domain 변경 후 성공은 UNKNOWN이다. 최소 후보는 fixture에 필요한 domain/exec label을 명시하고, 실제 서비스 readiness와 AIDL 확장 시험의 PASS를 구분하는 것이다. fixture를 무조건 생략해 readiness를 통과시키는 방식은 회귀 검증을 없애므로 제안하지 않는다. 방치하면 시험 type이 없는 정상 GSI도 Zygote 이전에 중단된다.

5. **F5 / P2 — 반복되는 context 표현과 진짜 SID 중복을 구분해야 한다.** `Plan::context`, `Config::context`, native map, JSON의 `selinux_types`는 같은 변환을 다른 프로세스/ABI에서 소비한다. 이를 모두 중복 권한으로 세는 것은 잘못이다. 실제 부채는 JSON/legacy constants/fork probe/8B SID patch의 고정 타입 목록과 프로필 타입 경로가 병존하는 점이다. 최소 후보는 profile mapping의 유일한 타입 데이터는 유지하고, legacy 소비자는 명시적 시험 경로로 한정하는 것이다. 단일 formatter 통합만을 위해 Rust↔C 런타임을 새로 결합할 필요는 없다. 방치하면 한쪽의 SID 기대값만 바뀌어 성공 경로가 거짓 실패하거나 Host SID 선택을 놓친다.

6. **F6 / P2 — SDK/ABI/리소스·task profile 가정은 GSI와 Host 두 축으로 분리해야 한다.** SDK36/REL/arm64, GL disable, `org.lineageos.platform-res.apk`, 고정 cgroup JSON 스키마가 현재 구현에 들어 있다(L06, P06, X02, X03, X07). SDK가 다른 Guest는 property check에서, 다른 controller layout은 processgroup_config에서 중단된다. 최소 후보는 이미 있는 Guest property/classpath 산출값을 사용하고, Host cgroup backend 감지와 GSI resource 목록의 예외만 남기는 것이다. 정상 첫 부팅 근거 없이 모든 경로를 동적으로 탐색하는 재작성은 제안하지 않는다. 현재 이미지의 library-path 예외를 전부 지우면 Zygote/ART 재회귀 위험이 높다.

7. **F7 / P2 — 진단 preload와 즉시 kill이 운영 실행에 결합돼 있다.** 이름 `guest-zygote`만으로 diagnostics preload가 필수이며, Service stop은 SIGKILL이다(`guest_launcher.rs:375–417,729–751`). 운영 계약의 TERM→KILL·write quiesce를 만족했다고 볼 수 없다. 최소 후보는 disposable lifecycle은 유지하고 운영 경로를 열 때 진단 on/off와 정상 종료 검증을 먼저 분리하는 것이다. **회귀 위험 높음:** preload 순서가 context-map/setcontext/FD hook 해석을 바꾼다. 지금 전부 삭제하면 디버깅 능력과 fork 성공 조건을 함께 잃는다.

### Nice to have

8. **F8 / P2 — 관측용 로그와 실제 필요 권한을 같은 임시 코드로 취급하지 않아야 한다.** property label/lock의 PID·SID·fs type 출력과 SIGABRT 복사본은 E지만, exact-label 비교/readback/atomic persistence와 부모 pipe 수집은 현재 진행 경로를 지탱한다(P04/P05/L08). 최소 후보는 진단 verbosity와 진단 artifact 의존성만 줄이는 것이다. 새 allow로 log file 쓰기를 열거나 label 오류를 무시할 이유는 없다. 방치의 비용은 초기화 로그·증거 해석 부담이며, 보안 검증 삭제로 줄일 부채가 아니다.

확정적인 데이터 유실/Host 정책 제거 버그를 이번 정적 범위에서 새로 입증하지 못했으므로 Must fix를 억지로 채우지 않았다. 위 우선순위는 리팩터링 선후관계이며 전체 동작의 안전성 인증이 아니다. 삭제 가능 줄 수·의존성 절감 수치는 실행/사용 증거 없이 산정하지 않았다.

## 5. 성공 경로와 회귀 위험

기존 문서의 기기·정책·우회 조건을 보존한 평가다. “성공”은 아래 범위로 한정한다.

| 경로 | 저장소의 성공 근거 / 한계 | 보존해야 하는 처리 | 리팩터링 회귀 위험 / 후속 검증 후보 |
|---|---|---|---|
| Property Service | [property-socket-label-fix-20261115.md](property-socket-label-fix-20261115.md):53–61은 attempts41–44의 service/shell smoke 통과. :76–92,114–127은 compute_av 후 ready=true/Context Manager 도달을 기록한다. 초기 11/01 property area 성공은 [별도 고정 SID PoC](property-fd-area-success-20261101.md):26–28이며 전체 daemon과 다르다. | P01–P05, S06/S08/S09, L08/L09. mapped init SID·private inode·property allow·socket 생성 type·같은 label 생략·persist atomicity. | **높음.** 타입 매핑·socket transition·캐시 후 보정·stdio 변경이 함께 작용한다. 향후 offline type/wire/atomic store 검사 후 fresh Guest 데이터와 persist 재시작을 별도로 확인해야 한다. 원본 userdata로 시험하지 않는다. |
| ServiceManager | 위 문서 :88–107,114–132는 attempts46/47의 실제 true 및 Context Manager transaction 성공. 전체 AIDL readiness는 아직 실패. [이전 readiness review](servicemanager-readiness-review-20261115.md)의 실패 판정은 후속 코드/문서에서 갱신됐다. | live kernel compute_av, private Binder, service_contexts 매핑, property writer allow, 부모 pipe, 정상 null과 transaction error 구분. | **높음.** ready=true를 seed하거나 NameNotFound를 성공 처리하면 거짓 PASS. 후속에는 false→true·handle0·AIDL add/call을 각각 확인한다. |
| Private Binder | [private-binder-device-20261031.md](private-binder-device-20261031.md), [guest-services-phase6b-fix-results.md](guest-services-phase6b-fix-results.md):7–14는 과거 enforcing/registry/IPC 및 installd 시험 범위를 기록. 최신 attempt47도 Context Manager 응답까지다. 당시 SID/정책과 현재 mapped 경로는 동일하다고 가정하지 않는다. | S07/X04, Host와 다른 rdev/mount ID·alias inode 검사, Guest node DAC, Binder backend FD 검증, service_manager/binder 권한. | **높음.** “새 Binder node”만으로 registry 성공을 보증하지 못한다. 후속에는 실제 transaction/객체 callback 및 Host registry 비등록까지 구분한다. |
| Zygote / Java child | [zygote-phase7fc-results.md](zygote-phase7fc-results.md):3,25–30,47–58은 child main/property/Binder/userdata PASS이나 retained ssal_guest_probe 우회를 명시. mapped 모드는 이 우회를 금지한다. 최신 공통 런처는 AIDL 성공 뒤 Zygote에 도달한다. | socket FD 수명/DAC, net namespace, pivot/FD reopen, classpath/ART namespace, diagnostic stderr, 실제 app-domain transition. | **매우 높음.** 과거 Java 실행 PASS를 정상 mapped app specialization로 대체할 수 없다. F1 고정 seapp/SID부터 맞추고 readiness→fork→정상 SID→Java IPC 순으로 별도 확인한다. |
| system_server / 전체 부팅 / One UI 복구 | `system_server_runtime_sid::enabled`는 차단 중이며 [phase8b5-system-server-runtime-sid.md](phase8b5-system-server-runtime-sid.md):5는 FAIL/NO-GO. [guest-first-boot-20261115.md](guest-first-boot-20261115.md)는 첫 부팅 미도달과 후속 한계를 기록. | 기존 실패 gate와 Host 정책/실행 경계. | **성공 기준 자체 미확보.** 이 감사로 start-system-server 허용, Guest sys.boot_completed, FBE/HAL, 삼성 하드 재부팅 One UI 복구가 입증되지 않는다. |

최신 진행 기록은 Lenovo Y702/TB320FC다. 이를 Samsung One UI·순정 커널의 동일 성공으로 일반화할 수 없다. Samsung FIVE/KernelSU 패닉의 시간적 연관과 원인 확정을 구분한다([incident-summary.md](boot-incident-20261106/incident-summary.md):7–13). 원인조사 재실행이나 부팅 승인은 이번 범위가 아니다.

## 6. 공통화와 유지할 예외

공통화 우선 후보는 (1) 서비스별 executable/domain/UID/socket 명세의 일치, (2) 생성·cache hit·runtime 보정 후 최종 plan 계약, (3) private helper 복제·라벨·parent pipe 수집, (4) 정상 readiness와 시험 fixture PASS 구분이다. 이미 존재하는 `Plan`, `Service`, `Config`, cgroup backend를 사용해 작은 수정으로 정리할 수 있다. 새 범용 init 구현이나 plugin 구조는 요구되지 않는다.

플랫폼별로 남겨야 할 항목은 KernelSU UAPI/ksud 변환·export 복구·부분 적용 ledger, 실제 Host cgroup controller topology, binderfs 기본 node/mount 특성이다. GSI별로 남겨야 할 항목은 SDK/ABI·APEX/library/resource 위치와 optional binary/APK patch다. 후자는 원본 payload와 증거 없이는 일반 규칙으로 승격하지 않는다.

진단별로 유지/분리할 항목은 am.jar fixture, 고정 seinfo/UID/SID, same-context exact binary patch, 8B gate/canary, staging/profile 경로, property probe key와 fatal trace다. 향후 제거 작업은 AGENTS.md의 Luna 정리 규칙을 따르되 **이번 감사에서는 정리도 위임도 수행하지 않았다.**

## 7. UNKNOWN 및 검증 공백

| 항목 | 확인한 사실 | 확정하지 않은 것 / 필요한 근거 |
|---|---|---|
| 동일 SID relabel EACCES | 기존 문서 attempt29에서 fgetxattr 후 동일 SID fsetxattr EACCES. 현 코드는 정확히 같은 label만 생략한다. | 최종 거부가 SELinux AV인지 VFS/filesystem인지, Samsung 공통 문제인지 UNKNOWN. 원본 GSI AV table/정확한 kernel return 근거가 필요. |
| attempt44 ServiceManager exit 1 | 기존 문서가 waitid CLD_EXITED/status=1과 로그 부재를 기록. 이후 pipe에서 self-register/property 오류를 확보했다. | 과거 exit 1을 유발한 정확한 syscall/함수는 UNKNOWN. 후속 정상 동작이 과거 내부 원인 추적을 대신하지 않는다. |
| 현재 AIDL 전용 SID 변경 | 감사 작업 트리에 전용 executable 라벨·domain·stdio grant가 있다. attempt47은 변경 전 shell→service add DENY다. | 현재 변경 뒤 실제 AIDL 전체 PASS는 UNKNOWN. 현재 파일의 올바른 모양만으로 runtime 통과를 선언하지 않는다. |
| optional GSI patches/su | 파일이 있을 때만 bind하는 경로와 고정 대상 목록 확인. | 실제 patch payload 내용, 어떤 이미지 버그를 해결하는지, 현재 설치 여부/필수성 UNKNOWN. vendor나 원본 binary를 읽지 않았다. |
| context interposition의 완전성 | 세 setter와 mapped contexts, profile plan 전달 확인. | static/internal binding, direct `/proc/.../attr` 쓰기, setfilecon 등 모든 경로의 Host literal 제거를 보증하지 못함. 전체 GSI 호출 전수검사는 범위 밖. |
| 적용 정책과 원본 정책의 동등성 | Host constraints 보존, unsupported/nlmsg/compat 누락 기록, live ledger 누적 확인. | translated policy가 원본 GSI와 의미적으로 동등하거나 모든 실제 allow가 readback됐다는 주장은 불가. |
| 전반적인 Host 보존/복구 | Guest-only 주체 추가와 원본 파일 private 복제 의도를 정적으로 확인. 기존 문서는 일부 Host snapshot 동일성을 기록한다. | 모든 Host 간접 영향 부재, 원본 userdata 전체 hash, Samsung 재부팅 후 One UI 완전 복구는 미검증. |

테스트 소스는 확인했지만 실행하지 않았다. 확인한 회귀 장치에는 launcher의 `common_workers_share_live_property_readiness`, domain mapping/socket FD/early-exit stderr tests, policy의 Guest-only compute_av/idempotence·self expansion/native command·placeholder/compat/delta tests, property의 wire/type/atomic store/label exact-match tests, native context-map·FD reopen self-check가 있다. 이들은 실기기의 실제 SID 전환·커널 AV·부팅을 대신하지 않는다. 특히 source 문자열을 찾는 wiring 테스트는 branch가 존재함을 확인할 뿐 readiness 런타임 성공을 증명하지 못한다.

**최종 판정:** 정상 Android 초기화를 대신하는 A/B 처리를 지키면서, F1/F3/F4의 현재 매핑·정책·fixture 연결부터 작은 단위로 정리하는 것이 우선이다. 기존 성공 경로의 재검증 없이 고정값·preload·allow를 일괄 삭제하거나 첫 부팅 이전에 전면 리팩터링할 근거는 없다.
