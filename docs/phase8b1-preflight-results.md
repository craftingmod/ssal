# SSAL Phase 8B-1 — Preflight 결과

- 일자: 2026-11-05 KST
- 기기: SM-S937N, ADB serial `R5CY52JC03H`
- 판정: **PARTIAL**
- system_server fork 게이트: **BLOCKED — fork 및 `SystemServer.main()` 미실행**

Classpath 준비와 기존 Guest Java/Property/Private Binder 경로는 실기기에서 확인했다. Host SELinux Enforcing, 핵심 Host 프로세스, Guest 세션 cgroup 복구도 유지됐다. 다만 대상 GSI의 stock SELinux 전환은 Host와 같은 `u:r:system_server:s0`로 끝난다. Guest 전용 최종 도메인과 그 도메인으로만 이어지는 Zygote 전환이 입증되지 않았고, Host의 실효 정책 전체도 읽을 수 없어 실제 system_server fork를 안전하다고 판정할 근거가 없다.

## 1. 이미지 동일성

| 항목 | 값 |
|---|---|
| Phase 7I 등록 이미지 | `/data/local/ssal/images/1793366406758-25627/system.img` |
| Phase 8A 로컬 이미지 | `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img` |
| 크기 | 2,733,260,800 bytes |
| SHA-256 (양쪽) | `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff` |
| 이미지 메타데이터 | Android 16, SDK 36, build `BP4A.251205.006`; Lineage source commit은 unknown |

Phase 7I 로그 자체에는 SHA-256이 없었다. 이번 preflight에서 당시 등록 경로의 기기 파일과 Phase 8A 로컬 파일을 각각 해시해 동일함을 확인했다. 이미지 mismatch 시의 추가 회귀 조건은 발생하지 않았지만, 새 launcher 변경 검증으로 기존 Java/Property/Binder 회귀는 아래와 같이 다시 실행했다.

## 2. 변경 및 검증

`src/guest_launcher.rs`에서 `derive_classpath`의 Guest 출력에 `SYSTEMSERVERCLASSPATH`와 선택적 `STANDALONE_SYSTEMSERVER_JARS`를 포함했다. 경로를 `/apex`, `/product`, `/system`, `/system_ext` 하위로 제한하고, Guest root 안에서 모든 classpath 파일과 `/system/framework/services.jar`, `/system/lib64/libandroid_servers.so` 존재를 검사한다. Host 환경은 기존 `env_clear()`로 차단하며, 파생된 Guest 값만 Zygote에 전달한 뒤 `/proc/<Guest-Zygote>/environ`에서 다시 대조한다. Standalone 변수는 출력이 없거나 빈 경우 허용한다.

실기기 검증에서는 Guest SDK 36 / REL의 classpath가 파생됐다.

| 검증 | 결과 |
|---|---|
| Guest BOOTCLASSPATH / DEX2OATBOOTCLASSPATH | 46 / 14 entries |
| Guest SYSTEMSERVERCLASSPATH | 16 entries; 각 Guest 파일 검사 통과 |
| Guest STANDALONE_SYSTEMSERVER_JARS | 9 entries; 각 Guest 파일 검사 통과 |
| Guest Zygote 환경 전달 및 값 대조 | **PASS** |
| `services.jar`, `libandroid_servers.so` | Guest root에서 존재 확인 **PASS** |
| Host `SYSTEMSERVERCLASSPATH` 상속 | `env_clear()` 유지, Guest 환경 값만 전달 |
| `--start-system-server` / `SystemServer.main()` | 사용·실행 안 함 |

**실행한 빌드 및 회귀 검사**

- `cargo test --locked --bin ssald`: **50 passed, 0 failed, 4 ignored**. 무시된 항목은 privileged 환경의 `CAP_SYS_ADMIN`/chroot가 필요하다.
- Android arm64 release 빌드 (`cargo build --locked --release --target aarch64-linux-android --bin ssald`): **PASS**.
- 기기에서 기존 Phase 7I runner로 bounded 회귀 실행: **PASS**. Guest Property Service 및 persistent restore, Java child의 Private Binder 왕복과 Guest userdata read/write, Zygote fork/exit/reap가 성공했다. child PID `19182`, starttime `6437743`, pidfd open, exit 0; child는 UID/GID 10000, supplementary groups 없음, capabilities 0, `u:r:ssal_guest_probe:s0`였다. 이는 system_server의 UID나 권한을 대변하지 않는다.
- `cargo fmt --all -- --check`: **FAIL (기존 형식 차이)**. 기존 `fork_probe.rs`와 `guest_launcher.rs`의 변경 전 코드 구간에서 rustfmt 차이가 남아 있다. 이와 무관한 형식 변경은 하지 않았다.

기기 회귀의 `ctl.start` negative check는 존재하지 않는 표식 이름 `ssal_must_not_reach_host_init`에 대해 반환 1 및 `PROP_ERROR_HANDLE_CONTROL_MESSAGE`를 기록했다. 실제 Host init 서비스는 지정하거나 건드리지 않았다. 이는 system_server의 Host property/init 경계 검증을 대체하지 않는다.

## 3. GSI SELinux와 Host 경계

GSI에서 읽기 전용 추출한 `/system/etc/selinux/plat_seapp_contexts`는 `isSystemServer=true domain=system_server_startup`을 지정한다. 같은 GSI의 `plat_sepolicy.cil`은 `system_server_startup`에 self `process:setcurrent`, `system_server`에 `process:dyntransition`을 허용한다(추출 CIL 68829, 68834행). 이는 `system_server_startup`을 거쳐 `system_server`로 바뀌는 두 단계 경로와 일치한다. AOSP Android 16 정책도 같은 selector와 전환 규칙을 참조로 제공하지만, GSI의 Lineage source revision과 바이너리의 정확한 일치 근거는 없다. [AOSP seapp_contexts](https://android.googlesource.com/platform/system/sepolicy/+/android16-release/private/seapp_contexts), [AOSP system_server_startup 정책](https://android.googlesource.com/platform/system/sepolicy/+/android16-release/private/system_server_startup.te)

실행 시 Host에는 UID 1000, SID `u:r:system_server:s0`인 `system_server`가 존재했다. Guest와 Host가 공유하는 PID namespace에서 stock 전환을 그대로 쓰면 최종 Guest process가 Host `system_server`와 같은 SELinux domain에 놓인다. UID 1000도 Host system_server와 겹친다. 따라서 현재 증거만으로 이 SID 재사용을 Guest 격리로 간주할 수 없다.

Host global SELinux는 `getenforce=Enforcing`, `/sys/fs/selinux/enforce=1`이었다. 기기의 `/sys/fs/selinux/policy` 조회는 `EINVAL`로 실패한 기존 기록이 있으며, active policy hash와 전체 Host allow 차분은 **unknown**이다. `ksud`는 sepolicy patch/apply/check 명령을 제공하고 Phase 7I에서 Guest-only `ssal_guest_probe`, `ssal_property` 타입을 동적으로 사용한 기록이 있다. 이는 Guest 전용 타입 추가가 가능한 근거일 뿐, system_server 전환이나 Host 경계가 검증됐다는 뜻은 아니다. 이번 작업에서는 live policy를 변경하지 않았다.

**필요한 SELinux delta의 방향:** Host의 `system_server` SID를 재사용하지 않고, Guest 전용 startup/final type과 Guest Zygote에 한정된 선택·전환 경로를 설계해야 한다. stock `system_server_startup`에서 공통 allow만 추가하는 방식은 Host Zygote에도 열릴 수 있으므로 Guest origin이 정책과 실제 `selinux_android_setcontext()` 호출 양쪽에서 구별돼야 한다. 새 Guest 타입·속성·권한은 구현 과제로 계속 진행할 수 있지만, 공유 Host domain이나 broad allow를 추가하지 않는다. 실제 fork 전에는 최종 child SID와 Guest-only 전환을 증명해야 한다.

## 4. Process 및 capability 계약

아래는 다음 fork 시험에서 반드시 기록할 계약이다. system_server를 실행하지 않았기 때문에 미관측 값을 PASS로 추정하지 않는다.

| 항목 | 계약 및 현재 상태 |
|---|---|
| UID/GID | Android system_server 목표는 UID/GID 1000/1000. 이번 Java probe는 10000/10000이므로 증거로 대용할 수 없다. |
| Supplementary groups | 실제 GSI Zygote가 요청하는 목록을 확보하고 child `/proc/<pid>/status`의 `Groups`와 비교해야 한다. 현재 목록 unknown. |
| Parent/child capabilities | Guest Zygote의 `CapEff`/`CapBnd`와 child의 `CapEff`/`CapBnd`를 기록한다. GSI별 요청 mask와 실제 값은 unknown. launcher는 UID 변경 전에 명시적 `capset()` drop을 하지 않는다. |
| SELinux | 시작 SID, `system_server_startup` 단계, 최종 Guest 전용 SID를 각각 기록한다. 최종 SID가 Host `system_server`와 같거나 Guest 전용 여부를 확인할 수 없으면 차단한다. |
| Seccomp / NoNewPrivs | `/proc/<pid>/status`의 `Seccomp`, `NoNewPrivs`를 Zygote와 child에서 기록한다. SELinux specialization 순서를 확인하기 전에 NNP를 앞당기지 않는다. |
| rlimits | Zygote/child의 `/proc/<pid>/limits`를 저장하고 예상치 못한 무제한 항목을 평가한다. 이번 system_server 값은 unknown. |

허용 capability를 AOSP의 기본 system_server mask에서 그대로 복사하지 않는다. child effective/bounding set에 남을 경우 Host에 영향을 줄 수 있는 항목을 우선 제거하거나 별도 격리 효과를 증명해야 한다. `CAP_SYS_PTRACE`는 다른 process의 ptrace 및 `/proc` 민감 정보 접근, `CAP_KILL`은 임의 process signal, `CAP_SYS_BOOT`는 기기 재부팅, `CAP_SYS_MODULE`/`CAP_SYS_TIME`은 커널 전역 상태, `CAP_NET_ADMIN`/`CAP_NET_RAW`는 공유 kernel network에 영향을 줄 수 있다. 실제 권한 의미는 Linux capability 정의를 참조한다. [Linux capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)

Parent가 가진 capability의 일부를 child에 요청하는 경로가 있으므로, parent mask와 child 결과를 모두 확인해야 한다. 현재 GSI에서 어떤 capability가 요청되는지, child가 어떤 값을 갖는지는 **미관측**이다. 위 위험 capability가 유효한 상태로 남아 있는 경우, Host 영향이 차단된다는 별도 증거 없이는 fork 게이트를 통과시키지 않는다.

## 5. Host negative-test 설계

이번 Phase에서는 Host 핵심 프로세스에 접근·신호를 보내지 않았으며, 아래 계획도 실행하지 않았다. 다음 후보 Guest system_server에서 수행할 때에도 Host `init`, adbd, netd, zygote, system_server는 target에서 제외한다.

1. 전용 무해 Host sacrificial process 하나를 등록하고 PID, starttime, SID, executable, pidfd를 고정한다. Guest 후보가 `/proc/<pid>/root` 및 `/proc/<pid>/fd`를 열거·역참조할 수 없는지 확인한다.
2. 같은 pidfd에 signal 0 검사만 먼저 수행한다. 필요할 때만 no-op handler를 설치한 sacrificial process에 한해 harmless signal 또는 ptrace seize/detach를 시험한다. 매번 PID/starttime을 재확인하고 core process에는 signal을 보내지 않는다.
3. Host `/dev/binder`, property area, `/dev/socket`의 사전 identity를 저장하고 Guest 관점의 path 존재·device/inode 차이만 확인한다. Host binder transaction, property write, init/control socket 명령은 보내지 않는다. Host socket이 Guest에 보이면 접속하지 않고 즉시 차단한다.
4. Guest private Binder/Property endpoint의 identity가 Host와 다르고, Guest에서 Host property/control endpoint를 찾을 수 없음을 확인한다. Guest 전용 sentinel read/write가 필요한 경우에도 Host namespace로 전달되지 않는 독립 경로만 사용한다.

## 6. cgroup, 종료 및 복구

실기기 회귀는 `SSAL_MEMORY_MAX=2147483648` (2 GiB)로 실행했다. 기존 `GuestCgroups::prepare()`는 `memory.max`에 값을 쓴 뒤 정확한 문자열 readback을 검사하고, 불일치 시 실패한다. 이번 worker가 정상 완료되어 이 fail-closed readback guard를 통과했다. 로그는 실제 readback 값을 별도 줄로 출력하지 않으므로 이 수치는 command input과 코드 guard에 근거한다. worker는 `Guest cgroup cleanup: passed`를 기록했고 세션 후 `/sys/fs/cgroup/apps/ssal_guest`가 없으며 root/apps `cgroup.subtree_control`은 비어 있었다. 새 기기 staging은 `/dev` tmpfs에만 두고 mount/cgroup 복구를 확인한 뒤 제거했다.

이번 Java child는 Zygote가 PIDFD를 열고 exit 0을 확인해 reap했다. 기존 Phase 7D-Fix 절차는 PID/starttime 및 Guest cgroup membership을 다시 확인한 뒤 pidfd로 종료하고 reap하며, 예상 밖 자손이나 불명확한 membership이 있으면 cgroup을 보존한다. 이는 향후 system_server PID에 대한 pidfd 시험을 대신하지 않는다.

다음 실제 child 세션의 종료 계약은 fork 즉시 PID/starttime/pidfd를 session 기록에 고정하고, 같은 pidfd로 SIGTERM 후 제한 시간 대기, 필요 시 SIGKILL, wait/reap, cgroup의 모든 PID 부재 확인 순으로 진행한다. 이름 기반 kill이나 PID 재사용 후의 signal은 금지한다. starttime/cgroup 검증 또는 cleanup이 실패하면 cgroup과 필요한 mount를 보존하고 `RECOVERY_REQUIRED`로 기록한다. hard reboot는 마지막 Host 복구 수단이며 이번에는 시도하지 않았다.

## 7. Host 불변 조건

- SELinux: `Enforcing`; kernel enforce 값 `1`.
- boot ID: `03834516-215d-4fd6-8960-1b833882595e`.
- Host 핵심 process snapshot: zygote64 PID 1840 / `u:r:zygote:s0`, system_server PID 2911 / `u:r:system_server:s0`, adbd PID 8989 / `u:r:adbd:s0`, netd PID 1838 / `u:r:netd:s0`. 실행 후 같은 PID/context가 관찰됐고 worker는 `HOST_SAFETY_SNAPSHOT=UNCHANGED`를 기록했다.
- `module/profiles/concurrent/services/initial.json`: `launch_enabled=false` 유지.
- `src/ssald.rs`: `switch` 및 `return` 차단 유지.
- global permissive, broad Host allow, Host init rc 재사용, Host 핵심 프로세스 signal은 사용하지 않았다.

## 8. 차단 항목과 비침습 대안

| 차단 항목 | 정확한 이유 | 안전하게 진행할 다음 작업 |
|---|---|---|
| Guest 최종 SELinux domain | 추출된 GSI 전환은 `system_server_startup → system_server`; Host도 같은 `system_server` SID를 사용한다. Guest 전용 최종 type 및 Guest-only native specialization 경로는 아직 없음. | 정확한 GSI Zygote 동작을 고정하고 Guest-specific startup/final type 선택 경로를 최소 delta로 설계한다. 정책 전체를 permissive로 바꾸지 말고, live policy 변경 전 정적 type/role/transition 검토와 제한된 KSU check를 거친다. |
| Active Host policy 차분 | `/sys/fs/selinux/policy` read가 `EINVAL`; 전체 활성 정책과 Host target SID에 대한 effective allow/constraint를 추출하지 못한다. | read-only KSU policy query가 지원되는지 확인하고 개별 context/AV 조회를 수집한다. 성공하지 않아도 core Host access를 시험하지 말고 후보 Guest type의 안전성을 입증하기 전 fork하지 않는다. |
| UID 1000 process boundary 및 권한 | 실제 system_server child가 없으므로 groups, CapEff/CapBnd, seccomp, NNP, limits를 관측하지 못했다. `CAP_KILL`, `CAP_SYS_BOOT`, `CAP_SYS_PTRACE` 등 Host 영향 권한도 배제하지 못했다. | 실행 전 Zygote 요청을 정확히 고정하고 child mask를 최소화하는 구현을 준비한다. sacrificial Host process만 이용한 read-only/비파괴 negative test로 `/proc`, fd, signal 경계를 확인한다. |
| Host Binder/property/socket 경계 | 현재 Phase 7I에서 Private Binder/Property 경로는 통과했지만 system_server 자체가 Host endpoint를 열지 않는다는 증거는 없다. | Guest/Host endpoint identity 대조를 재사용하고 Guest namespace 안의 존재/접근 차단만 검사한다. Host service에 transaction이나 write를 보내지 않는다. |

## 9. 다음 단계 진입 조건

**실제 8B-1 fork 시험 전:** (1) Guest-only startup 및 final SELinux SID와 Guest Zygote 선택 경로가 증명될 것, (2) Host active policy의 미확인 범위를 가능한 read-only query로 좁히고 Host domain에 broad allow가 없을 것, (3) UID/GID/groups와 Parent/child CapEff/CapBnd 계약 및 제거할 Host-wide capability가 정리될 것, (4) sacrificial Host process negative test가 `/proc/root`, fd, signal 및 필요한 ptrace 경계를 통과할 것, (5) Host Binder/property/socket endpoint가 Guest에 비노출임을 확인할 것, (6) 유한 `memory.max` readback과 PID/starttime/pidfd cleanup이 실제 후보 child에서 확인될 것. 이 조건 전에는 `--start-system-server`를 추가하거나 활성화하지 않는다.

**8B-2 (`SystemServer.run()` 진입) 전:** 먼저 제한된 8B-1 fork가 `com.android.server.SystemServer` 진입 marker까지 도달하고, child의 Guest 전용 SID, UID/GID/groups, capabilities, seccomp/NNP/rlimits, cgroup, private Binder/Property 경계, 종료/reap 및 Host baseline 불변을 기록해야 한다. GSI는 `ro.debuggable=0`이고 정확한 Lineage source revision도 unknown이므로, `SystemServer.run()`에서 멈추는 관측 가능한 one-shot marker/pause 방식이 준비되지 않으면 첫 실행에서 Bootstrap으로 계속 진행할 수 있어 진입을 보류한다.

## 변경 파일 및 검증 목록

- 변경: `src/guest_launcher.rs` — Guest system-server classpath parsing, validation, Zygote env 전달/검증 및 관련 단위 검사.
- 추가: `docs/phase8b1-preflight-results.md` — 이번 결과와 blocker, 진입 조건.
- 실행: `cargo test --locked --bin ssald`, Android arm64 release build, Phase 7I 실기기 Java/Property/Binder 회귀.
- 미실행: system_server fork, `SystemServer.main()` / `SystemServer.run()`, Host PID/root/fd·signal·ptrace destructive test, Host binder/property/socket command, SELinux live policy 변경.

Phase 8A 문서의 기존 dirty/untracked 상태는 이번 변경과 별개이며 수정하지 않았다.
