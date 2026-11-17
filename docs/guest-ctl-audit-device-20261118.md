# Guest ctl 수명주기 감사와 Android 기기 검증 — 2026-11-18

검증 대상은 `guest-ctl-experimental-20261118.md`의 구현이다. 기존 start/stop/restart와 interface 제어를 유지하고 확인된 실행 경로 race, hybrid memory cgroup 선택, Guest spawn 권한만 수정했다. Host 서비스 제어, SELinux permissive 전환, 광범위한 allow 규칙 추가는 수행하지 않았다.

**결과:** 실제 Lenovo Android 기기에서 Mock의 모든 일반/interface 제어와 거절 사례를 검증했다. Host mount와 선정한 9개 Host 서비스의 PID/starttime/cgroup은 동일했다. Host Property는 4개가 달라 완전한 무변경을 주장하지 않는다. Property Service SIGKILL 이후 상태는 stale하고, Mock 종료는 세션 teardown의 pidfd 정리가 필요했다. 즉시 장애 회수나 SystemServer 복구까지 검증한 것은 아니다.

## 감사 결론

**실행 파일의 검사–exec 사이 symlink 교체 race를 수정했다.** 기존 코드는 `guest_input(path)`로 canonical 경로를 검사한 뒤 `Command::new(path)`가 같은 문자열을 다시 열었다. writable Guest runtime의 symlink가 그 사이 바뀌면 검사와 다른 inode를 실행할 수 있었다. 이제 파일을 먼저 열고 `/proc/self/fd/<fd>`의 실제 경로를 검사한 다음 같은 FD로 exec한다. 원래 argv[0]도 유지한다. FD는 spawn의 exec 완료/실패까지 보유하고 이후 닫으며 CLOEXEC로 서비스에 남기지 않는다.

이 방식은 **ELF 실행 파일**에 적용한다. 직접 shebang script는 CLOEXEC FD를 interpreter가 다시 열 수 없으므로 명시적으로 거절한다. 스크립트는 기존처럼 `/system/bin/sh`를 executable로 등록하고 args로 전달해야 한다. 이번 Android mock도 이 형태를 사용한다. 이는 파일 내용의 불변성까지 보장하지 않는다. Guest system partition은 RO여야 하고 `/run/ssal`의 실행 파일/설정은 신뢰된 세션 생성자가 소유해야 한다.

**v2 task + v1 memory의 Android hybrid 환경에서 memory cgroup을 누락하는 가정도 수정했다.** `/sys/fs/cgroup`이 v2라고 해서 memory controller까지 통합된 것은 아니다. 기존 mount 준비는 이 기기에서 v1 memory backend와 별도 Guest `/dev/memcg`를 사용한다. spawn은 실제 Guest `/dev/memcg/cgroup.procs`가 있으면 task fs 유형과 무관하게 반드시 진입하며, permission/기타 조회 오류를 단순 부재로 취급하지 않는다. v1 task인데 memory 경로가 없으면 계속 거절한다.

**Guest init이 Rust spawn의 exec-error pipe를 만들 수 없는 정책 누락도 확인했다.** 실제 kernel AV 조회에서 `fifo_file:create`의 mask는 `8`, allowed는 `1140657`로 create bit가 없었다. 기존 read/write/open은 있었지만 create가 없어 `Command::spawn`이 PermissionDenied로 실패할 수 있었다. Guest 정책 생성에 `allow ssal_<id>_init ssal_<id>_init fifo_file { create }` 한 권한을 추가했다. 이후 AV는 `114065f`이고 실제 Guest init의 `pipe2`도 성공했다.

**남은 exec EACCES는 nosuid SID 전환 검사였다.** 진단 fixture에서 child가 cgroup 진입, exec SID 설정, UID/GID 및 parent-death 설정까지 마친 기록을 확인했다. 파일 execute/entrypoint 및 process transition은 허용되어 있었지만 Guest init→shell의 `process2:nosuid_transition`은 mask `2`, allowed `0`이었다. Host policy capability `nnp_nosuid_transition=1`인 Android 커널은 이 경우 EACCES를 반환한다([Android kernel SELinux hook](https://android.googlesource.com/kernel/common/+/c5589c436d4646e0dc23f64264db8e04cf67c88f/security/selinux/hooks.c)). `allow ssal_<id>_init ssal_<id>_shell process2 { nosuid_transition }`만 추가하고 nosuid mount 옵션을 유지했다. 다른 서비스 domain은 별도의 실제 정책/exec 검증이 필요하다.

최종 정책 cache version은 29→31이다. Host init 규칙이나 null_device 권한은 추가하지 않았다(후자는 실제 Guest init의 read/write open에서 이미 허용). 기존 Guest ID/정책과 누적 적용 ledger를 유지하며 삭제·재생성하지 않는다. KernelSU 특성상 이 두 Guest 추가 권한은 같은 부팅에서 제거하지 않는다. 진단 중 시험한 execveat 우회와 child 단계 표식은 production 변경에 남기지 않았다.

## 수명주기와 race 조사

| 경계 | 확인 내용 | 한계/판정 |
|---|---|---|
| spawn 전 실패 | 경로/ELF/파일 검사 실패 시 fork 전에 반환 | registry에 PID를 추가하지 않음 |
| pre-exec cgroup 실패 | 순서대로 Guest cgroup에 진입·확인한 뒤 SID/UID/GID 설정. 중간 실패는 exec 전에 child 오류로 반환 | 실제 `Command::spawn` 실패가 부분 진입 자식을 회수함을 Linux 테스트로 확인. cgroup mount가 올바른 Guest bind인지 보장하는 책임은 기존 session mount 준비에 있음 |
| PID/PGID 소유권 | registry가 직접 생성한 Child만 저장. 신호 전에 `waitid(P_PID, WEXITED|WNOHANG|WNOWAIT)` 수행 | 현재 worker에는 같은 자식을 회수하는 별도 SIGCHLD handler/전체 wait 루프가 없음. 그 가정을 바꾸면 재감사 필요 |
| 재사용 방지 | leader를 회수하지 않고 기존 PID를 예약한 동안 `kill(-pid, SIGKILL)`, 그 뒤 wait | ECHILD이면 신호를 보내지 않음. 이 경우의 회귀 테스트 통과. 잘못된 PID를 proc 검색으로 채택하지 않음 |
| descendant 종료 | leader가 먼저 종료해도 같은 그룹 자식에 SIGKILL 후 leader 회수 | 그룹 이탈/daemonization은 기존 foreground 계약 밖. child.wait는 무기한 대기할 수 있으므로 이탈 서비스에 안전한 stop을 보장하지 않음 |
| descendant 회수 | registry는 직접 leader를 회수하고, 고아 자손은 session의 기존 subreaper가 teardown에서 pidfd로 확인·종료·회수 | active session 중의 고아 zombie를 registry가 즉시 회수하지는 않음. Guest cgroup 검증이 실패하면 기존 supervisor는 자원을 보존하고 오류 보고 |
| parent-death | UID/GID를 바꾼 **뒤** PDEATHSIG=SIGKILL을 설정하고 getppid 재확인 | 최종 부모 검사는 exec 전 부모 소실을 거절하지만 SELinux secureexec도 exec 시 PDEATHSIG를 지운다. 실제 Guest init→shell 전환 후 즉시 사망 회수는 보장되지 않음 |
| socket/상태 처리 | 기존 직렬 dispatcher가 상태와 child를 변경. 독립된 registry thread 없음 | 100ms polling은 요청 처리 중 2초 deadline만큼 지연 가능. start 응답은 readiness 확인이 아님 |

[Linux wait 문서](https://man7.org/linux/man-pages/man2/waitid.2.html)의 WNOWAIT/zombie 수명과 [PDEATHSIG 문서](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)의 credential 변경·fork·exec 예외를 확인했다. PID를 유지하는 것은 무관한 새 프로세스에 신호를 보내지 않기 위한 장치이며, 서비스가 스스로 그룹을 이탈하는 것을 막는 장치는 아니다.

## Property Service 장애가 Guest 전체에 미치는 영향

1. `serve()`가 Rust 오류로 반환하면 registry Drop이 소유 그룹을 정리한다. 생성/상태 기록 오류는 Host로 전달하지 않는다.
2. **SIGKILL/SIGTERM 기본 종료는 Drop을 실행하지 않는다.** 기존 supervisor의 정상 `Service::stop()`도 SIGKILL을 사용하므로 registry Drop을 거치는 graceful shutdown과 구분해야 한다.
3. PDEATHSIG는 best-effort이다. **일반 ELF여도 SELinux SID 전환의 secureexec가 이를 지울 수 있다.** 이번 Mock은 worker 사망 후에도 남아 있었으며 실제 subreaper가 teardown에서 종료·회수했다. 다단계 자손도 이 신호를 자동 상속하지 않는다.
4. 기존 shell/Android residence loop는 준비 이후 Property Service 사망을 지속적으로 감시하지 않는다. 따라서 Property Service 장애가 Guest 전체를 즉시 재시작/종료시키지는 않는다. 기존 mmap 읽기는 가능하지만 마지막 `init.svc.*`가 stale할 수 있고 새 property/control 쓰기는 실패할 수 있다.
5. Guest shell lease가 남아 있으면 environment와 area 수명이 계속된다. lease 종료 이후 admission을 보유한 기존 teardown이 Guest descendants → mount → cgroup/loop 자원을 정리한다. Host init이나 다른 Host 서비스에 종료 신호를 보내는 경로는 없다.

자동 worker 복구, watchdog, 즉시 zombie 수거, 새로운 shutdown protocol은 추가하지 않았다. 사망한 writer가 있는 area의 부분 갱신/serial 복구도 보장하지 않으므로 Property Service를 같은 area에 다시 띄우는 대신 전체 Guest 세션을 종료 후 새 area로 시작해야 한다. SystemServer가 이 장애를 어떻게 처리하는지는 이번 Mock 실험의 검증 범위 밖이다.

실제 정책에서 Guest init→shell의 `process:noatsecure`는 mask `80000`에 allowed `50084a`로 거절이었다. Android의 [SELinux secureexec 결정](https://android.googlesource.com/kernel/common/+/fb73974172ff/security/selinux/hooks.c)과 [exec의 pdeath_signal 초기화](https://android.googlesource.com/kernel/common/+/0ded6343cd442bf0c9de8e3ad85e7067f8e84ce4/fs/exec.c)를 대조하면 이 관찰과 일치한다. Mock 내부에서 PR_GET_PDEATHSIG를 직접 측정한 것은 아니므로 reset 원인은 이 코드/정책에 근거한 추론이다. 보안 sanitization을 끄는 noatsecure allow는 추가하지 않았으며, 보장된 즉시 회수에는 별도 owner-side 감시 설계가 필요하다.

## 기기와 실험 경계

- 연결 기기: Lenovo TB320FC, Android 15, ADB `HA1WAQ7P`, KSU root. 목표 삼성/One UI 기기는 아니다.
- Host init/service를 제어하지 않고 `/data/local/tmp/ssal-ctl-audit-20261118/bin`의 별도 바이너리를 사용했다. 설치된 모듈 바이너리는 교체하지 않았다.
- 기존 `y702`의 Guest system/userdata와 `p0001` 매핑을 사용했다. userdata를 포맷하거나 삭제하지 않았다.
- 검증용 fixture는 기존 `Config.services`에 **ssal-mock 한 개**만 추가하고 production `guest_properties::serve`를 실행한다. 별도 기능 플래그나 production 제어 명령을 추가하지 않았다.
- 기본 shell 환경은 cgroup을 생성하지 않으므로 Mock start도 fail-closed로 거절했다. 성공 검증용 `fixture-source`는 기존 ssald 소스를 복사해 `--shell-worker`에도 **기존** cgroup 준비와 subreaper 초기화를 적용한 별도 빌드다. production `src/guest/mount/mod.rs`는 변경하지 않았다. 다른 Android daemon을 띄우지 않고 Mock에 필요한 기존 Guest cgroup mount만 준비하기 위한 fixture 차이이며, 기본 shell 실행에서의 서비스 실행 성공으로 해석하지 않는다.
- Mock: `/system/bin/sh -c 'exec /system/bin/sleep 600'`, UID/GID 2000, domain `shell`. AIDL `aidl/dev.ssal.IMock/default`, HIDL `dev.ssal.mock@1.0::IMock/default`.
- 허용 요청은 fixture thread가 실제 Guest init SID에서 실제 Guest socket으로 전송한다. production SO_PEERCRED/SO_PEERSEC, Guest SID 필터, service-specific MAC 검사를 통과해야 한다. 상태는 같은 Guest area의 별도 rsproperties reader로 읽는다. 허용/거절 callback을 모의하지 않는다.
- Guest shell의 별도 setprop는 실제 권한 거절 사례로 구분한다. 성공 요청을 Guest shell 권한 성공으로 해석하지 않는다.

초기 fixture 시도는 (1) Guest init에서 fixture 파일 생성 거절, (2) 상태 확인용 getprop exec 거절, (3) shell-only 환경에 Guest cgroup이 없어 `Guest cgroup filesystem required`로 start 거절이었다. 모두 **ctl 수명주기 성공/장애 주입 성공으로 계산하지 않았다**. 첫 두 문제는 in-memory Config와 area reader로 해결했고, 세 번째는 위의 검증용 mount fixture로 해결한다. 각 시도 종료 후 기존 cgroup/mount/loop cleanup을 확인했다.

## 검증 결과

최종 성공 시도는 `shell-22036.log`와 `evidence-attempt9/`이다. 진단 전용 단계 표식이 들어간 복사본이 아닌 **최종 production Registry**를 링크한 fixture로 실행했다.

| 검사 | 결과와 근거 |
|---|---|
| 실제 peer/worker | PID 22814, `u:r:ssal_p0001_init:s0`, root. 로그 3007행과 lifecycle의 worker 기록 |
| 일반 명령 | start, 중복 start, stop, 정지 상태 restart, 실행 중 restart 모두 status=0, expected state 일치. 로그 3009–3018행 |
| interface 명령 | AIDL stop/start, HIDL restart/stop 모두 status=0. 로그 3019–3026행 |
| 미등록/잘못된 대상 | service `not-registered`, interface `aidl/not-registered`, `../ssal-mock` 모두 status=32. 로그 3027–3029행 |
| property 미저장 | 각 성공 명령 뒤 별도 Guest reader의 area.find로 해당 `ctl.*`가 없음을 assert. driver 전체 PASS 3030행 |
| Mock 신원 | SID `u:r:ssal_p0001_shell:s0`, 모든 UID/GID 슬롯 2000, 보조 그룹 없음, CapEff=0, NoNewPrivs=0. lifecycle 124행 이하 |
| Mock cgroup | v1 memory/cpuset/cpu/blkio 모두 `/ssal_guest`, v2 task `0::/ssal_guest`. hybrid memory 진입 수정 실기기 확인 |
| PID 변화 | start 22945 → restart-stopped 23011 → restart-running 23034 → interface-start 23078 → interface-restart 23105. 마지막 장애 실험용 start 23148. 중복 start는 기존 PID 유지 |
| Guest enforcing | global Enforcing 유지. init/shell kernel AV 응답의 permissive-domain flag 모두 0. nosuid_transition 응답은 변경 후 allowed=2 |
| 별도 권한 거절 | 이전 시도에서 Guest shell SID의 ctl 요청이 MAC 거절. 허용된 Guest init 요청과 혼동하지 않음 |

### Guest Property Service 장애 주입

모든 제어가 통과한 뒤 Mock을 다시 시작하고 fixture가 **자기 worker PID 22814에만 SIGKILL**을 보냈다(로그 3031–3033행). `owned_children=`의 빈 문자열은 proc 읽기 실패도 기본값으로 표시하는 fixture 부가 필드이므로 자식 부재 증거로 사용하지 않았다. 실제 PID/소유권은 별도 lifecycle 기록을 사용했다.

- Mock PID 23148은 worker 사망 후 PPID가 22814→22036으로 바뀌어 session subreaper에 채택됐다. lifecycle에 UTC 17:57:25–17:57:39(한국시간 11월 18일 02:57:25–02:57:39) 동안 계속 나타났다.
- 관찰 script는 process State를 기록하지 않았으므로 snapshot만으로 alive/zombie를 단정하지 않는다. 다만 로그 3035행의 `Guest owned descendant ... membership=/ssal_guest pidfd=verified`는 기존 cleanup 코드가 P_PIDFD/WEXITED/WNOHANG에서 아직 exit를 보지 못한 분기에서만 출력된다. 이어서 pidfd SIGKILL/회수한 3036행이 있으므로 적어도 그 cleanup 검사에서는 즉시 사망 완료가 관찰되지 않았다.
- Guest shell은 계속 실행됐고 `getprop init.svc.ssal-mock`는 마지막 `running`을 읽었다. 같은 socket의 새 setprop는 **Connection refused**였다(`guest.stdout` 4행, `guest.stderr` 마지막 3행).
- 세션 종료 뒤 Mock 회수, Guest cgroup cleanup, residual rootfs mount 부재, loop 자원 해제를 확인했다(로그 3035행 이후). 최종 Guest SID 프로세스, environment.json, Guest task cgroup, session mount가 남지 않았다.

### Host 전후 비교

`host-before.*`는 첫 실험 전, `host-after.*`는 실험/정리 뒤 snapshot이다. 선택한 daemon의 membership과 Guest subtree 존재 여부를 비교한 것이며, 모든 Host 프로세스/모든 cgroup controller 설정의 전체 동등성을 증명한 것은 아니다.

| 대상 | 결과 |
|---|---|
| Host property 수 | 1928 → 1928, 4개 값 차이 |
| Host PID 1 mountinfo | 파일 내용 동일 |
| boot ID | 동일, 재부팅 없음 |
| Host daemon PID/starttime/cgroup | 선정 9개 모두 동일. system_server 2280, surfaceflinger 1537, servicemanager 714, hwservicemanager 717, zygote64 1262, zygote 1263, vold 977, logd 696, netd 1261 |
| Host root membership/선정 Guest cgroup subtree 검사 | 전후 동일. 별도 최종 검사에서 실제 v1-backend task 경로 `/sys/fs/cgroup/ssal_guest`도 없음 |
| SELinux mode | 전후 Enforcing |
| Host Mock state | `init.svc.ssal-mock` 없음 |

Host Property 차이는 다음과 같다(`host-comparison.json`).

| property | before | after |
|---|---|---|
| `cache_key.get_packages_for_uid` | `-7659458767717428588` | `-7659458767717428560` |
| `cache_key.system_server.account_user_data` | `-7659458767717428563` | `-7659458767717428554` |
| `persist.debug.killcnt` | `800:3,900:336` | `800:3,900:337` |
| `sys.lmk.killcnt` | `800:3,900:336` | `800:3,900:337` |

Host property를 직접 설정한 명령은 없지만 **완전한 Host property 무변경 검증은 통과했다고 할 수 없다**. LMK 카운터는 1 증가했다. Luna의 좁힌 lmkd 로그 조회에 관련 kill 기록이 남아 있지 않아 대상/시각/Guest 실험과의 인과관계는 확인하지 못했다. Guest 준비 작업 자체의 Host 메모리 압력 가능성도 배제하지 않는다.

## Rust 회귀 검증

- 전체 `cargo test --locked -- --test-threads=1`: **178 passed, 0 failed, 7 ignored**.
- Guest Property 대상 테스트 26개를 포함하며 기존 wire/권한/상태/수명주기 테스트를 유지했다.
- 새 테스트: 검사 도중 symlink를 `/bin/true`에서 `/bin/false`로 교체해도 pin한 true inode 실행, 허용 경로 거절, 직접 script 거절.
- 새 테스트: 첫 cgroup에 진입한 뒤 두 번째 진입이 실패하는 pre-exec 경로에서 명령 본문이 실행되지 않고 `spawn`이 child를 회수했는지 ECHILD로 확인.
- 새 테스트: v2 task여도 존재하는 별도 v1 memory controller는 필수 진입 대상이며, v1 memory 경로 부재를 오류로 처리하는지 확인.
- 새 테스트: UID/GID를 root→2000으로 바꾼 자식에서도 pin한 ELF 실행 가능 여부를 Linux에서 검증. Guest init의 추가 FIFO create는 해당 Guest source/target에만 생성되고 native encoding도 일치하는지 확인.
- 변경 대상 clippy `-D warnings` 통과. Android release 링크 및 Android test cross-check 통과. WSLc 빌드는 저장소 지침대로 sandbox 밖에서 실행.
- privileged mount/saved policy fixture의 기존 ignored 테스트는 강제로 실행하지 않았다.

## 증거와 남은 위험

로컬 증거 디렉터리: `out/guest-ctl-audit-20261118/`. 검증 fixture 소스, 실행 script, 전후 Host snapshot, 기기 수명주기 기록을 보관한다. 전체 원본 logcat/dmesg는 본문에 포함하지 않았고 Luna가 필요한 log/AVC만 필터링했다.

Luna가 이전 진단 observer의 proc-attr 읽기에서 멈춘 `tr`와 그 부모 script만 cmdline/PPid/starttime으로 확인해 정리했다. 최종 observer는 timeout을 둔 cat을 사용한다. 모든 evidence를 로컬로 복사한 뒤 기기의 정확한 staging 디렉터리 `/data/local/tmp/ssal-ctl-audit-20261118`를 제거하고 부재를 확인했다. 모듈 바이너리, Guest userdata/profile, 기존 로그 및 추가된 Guest 정책은 유지했다. `.userdata-*.img`는 없었다.

남은 위험은 foreground/신뢰된 실행 파일 계약, process-group 이탈, writable inode 내용 변경, privilege exec 후 PDEATHSIG 해제, session teardown 전의 고아 zombie 및 stale property state이다. 별도 root 권한을 가진 공격자가 mount/정책/프로세스를 변경하는 상황까지 막는 보안 경계를 증명한 것은 아니다. 실제 삼성 순정 커널·잠긴 부트로더·One UI 복구 및 SystemServer 부팅은 미검증이다.
