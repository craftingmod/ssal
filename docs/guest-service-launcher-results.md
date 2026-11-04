# Phase 5B — Guest Service Launcher 진행 결과

- 날짜: 2026-11-04 (Asia/Seoul)
- Phase 5A: **PARTIAL 확정**. 정적 SELinux 호환성 조사는 수행하지 않았다.
- Phase 5B: **PASS, 종료**. cgroup PASS 확정 및 광범위한 추가 조사 중단. 공통 런처의 실제 shell/Private Binder AIDL/property/FD/Host 상태 비교 PASS. shared PID 공간을 유지한다.
- Phase 6A: **진입 및 초기 실행 PASS**. 공통 런처로 installd/artd 실행, Private Binder 등록·descriptor 응답 확인. 서비스별 자격과 실제 설치·컴파일 작업의 완전한 검증은 아직 아니다.

최신 결과는 [공통 런처 최종 기록](guest-service-launcher-common-results.md)에 있다. 아래 미완료·차단 표현은 이전 실행 당시의 기록이다.

## 기존 실행 경로

`guest_mounts::verify`는 별도 mount worker에서 rootfs, profile userdata, `/dev`, `/proc`와 APEX 등을 구성한다. `--guest-child-worker`는 private binderfs를 만든 뒤 `ssal-guest-domain-poc`에 root와 장치 identity를 전달하고, 해당 POC가 별도로 자격·FD·exec-stop 검사를 수행한다. 일반 `guest_probe::command`는 root 전환과 환경 정리를 담당하지만 현재 `require_guest_exec_admission`에 의해 차단된다. 두 경로는 아직 공통 서비스 런처가 아니다. 기존 진단 POC의 policy preflight는 Guest 전용 type이 없는 경우 실패할 수 있다. 이는 정책 완성도를 Phase 5B의 완료 조건으로 삼는다는 의미가 아니다.

[기존 bringup 결과](guest-bringup-results.md)의 Android 16 shell, 독립 profile userdata write/read, private Binder IPC는 각각 제한된 시험의 PASS로 유지한다. 해당 shell과 Binder helper를 새 공통 경로로 다시 실행한 결과는 아니다. 별도 filesystem이 아닌 profile userdata directory다.

## 이번 변경과 검사

기존 Guest command 두 경로와 Guest child POC 호출에 `close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)`를 추가했다. 스냅샷 이후 생긴 FD도 exec에서 닫히게 하며 syscall 실패 시 실행을 중단한다. 이 변경은 실제 exec 전후 FD 목록의 관측이나, stdio의 안전성, Host proc 경로 및 제어 소켓 격리 증거를 대체하지 않는다. Linux 전용 자식 프로세스 테스트를 추가했지만 이 환경에서는 실행하지 못했다.

| 검사 | 결과 |
|---|---|
| `cargo fmt --check` | PASS |
| Windows `cargo test --locked --features phase3-diagnostic` | PASS; Linux/Android 전용 FD 테스트는 실행되지 않음 |
| Android `cargo check --locked --tests --target aarch64-linux-android --features phase3-diagnostic` | PASS; 타입 검사만, 기기 실행 아님 |
| Host 상태 읽기 | Enforcing, boot ID `f7900911-c061-4570-8f65-900571a55c11`; init, zygote64, system_server, adbd, netd 실행 중. 읽기 전용 조회이며 전후 불변성 검증은 아님 |
| 변경 바이너리 실기기 실행 | 아래 재검증 참고. 이전 실행에서는 바이너리를 빌드하거나 실기기 실행하지 않았다. |

하드 재부팅, 정책 변경 및 기기 쓰기는 하지 않았다. Host 전체 Permissive 전환도 하지 않았다.

## WSL 접근 정정 및 재검증

기존의 `WSL 접근이 E_ACCESSDENIED로 실패`라는 표현을 철회한다. 당시 실패의 정확한 명령, 실행 도구, stderr 및 종료 코드는 이 보고서에 기록되지 않아 확인할 수 없다. 단일 sandbox 호출 실패로 WSL 전체 접근 장애를 결론낼 수 없다.

2026-11-04 재검증에서 Codex `exec_command`의 일반 sandbox에서 `wsl.exe --exec /bin/true`는 stderr에 `Wsl/E_ACCESSDENIED`, PowerShell `$LASTEXITCODE=-1`을 반환했다. 같은 도구의 sandbox 밖 실행에서는 동일 명령이 stderr 없이 종료 코드 0이었다. 앞서 일반 sandbox의 `wsl --status`와 `wsl --list --verbose`는 각각 `Wsl/E_ACCESSDENIED`, 종료 코드 1이었고, `wslc list`는 `액세스가 거부되었습니다.`, `오류 코드: E_ACCESSDENIED`, 종료 코드 1이었다. 이는 해당 실행 경로의 결과이며 사용자의 터미널 전체에 대한 판정이 아니다.

기존 `ssal-dev`에서 sandbox 밖 `wslc exec ssal-dev bash scripts/build-android.sh`는 종료 코드 0으로 Android AArch64 release 빌드에 성공했다. `wslc exec --workdir /src ssal-dev cargo test --locked --features phase3-diagnostic close_range_marks_fds_in_child_only -- --nocapture`도 종료 코드 0, 해당 테스트 1개 통과했다. 두 실행 모두 `guest_mounts.rs:768`의 미사용 변수 `major`, `minor` 경고가 있었다. 빌드 스크립트는 `out/bin` 산출물을 갱신했다.

연결된 SM-S937N에서 새 `ssal-guest-domain-poc` (SHA-256 `25f850eb0a9cb242ffd1461227c9805d2be303362a165e8fc273015ec0a6c3df`)를 임시 복사하고 해시를 확인했다. `--dry-run`은 종료 코드 0, `policy=unchanged; exec=not_run`이었다. 이어 root로 `ssal-guest-domain-poc --proc-only-preflight /data/local/tmp/ssal-proc-preflight-20261101/ssal-property-area-live-poc --sha256 bdab7c5f05f160c98041a092777632e354d70e184bb6c29a62dd27c9bf8a2415`를 실행한 결과 stderr `blocked or failed: Guest root is required for this mode`, 종료 코드 1이었다. 이 직접 호출에는 Guest root가 제공되지 않았으므로 Guest child 실행이나 FD 실측의 결과가 아니다. 임시 바이너리는 삭제했고 이후 Host는 Enforcing, boot ID는 이전과 같았다. 전체 Host 상태 불변성은 확인하지 않았다.

## 남은 작업

1. mount worker와 child 경로를 공통 런처로 통합하고 private Binder identity, Host Binder 대체 경로 부재, 독립 `/data`, Guest property 경로 및 Host control socket 부재를 실행 경계에서 확인한다.
2. 진단 child를 낮은 UID/GID 및 capability로 실행하고, 실제 서비스용 자격 프로필은 따로 지정한다. Guest 전용 SELinux domain이 가능하면 Guest에 한해 permissive 실험을 허용한다.
3. 공통 경로에서 exec 전후 실제 FD 목록과 Host proc/FD 및 제어 IPC 접근을 확인하고, Guest shell과 private Binder helper IPC를 재실행한다. Host Enforcing과 핵심 프로세스 및 관련 상태를 전후 비교한다.
4. 위 격리 확인 후에만 서비스별 실행 검증으로 진행한다. Guest property service 및 실제 Android 서비스의 성공 여부는 이번 Phase 완료 조건이 아니다.

## 2026-11-04 추가 실행

Phase 5B는 **미완료**, Phase 6A는 시작하지 않았다. mount worker의 `linkerconfig` 실행을 기존 `guest_probe::command`로 연결했고, private Binder alias가 아직 없을 때 경로 해석에서 ENOENT로 중단되는 오류와 진단 child의 UID/GID·보조 그룹 검증 불일치를 수정했다. Guest child POC와 일반 Guest command는 아직 하나의 서비스 런처가 아니다. 일반 Guest 실행 차단도 유지된다.

Android AArch64 release 빌드와 `cargo fmt --check`, WSL Linux `cargo test --locked --features phase3-diagnostic`는 통과했다. 특권 mount/chroot 관련 테스트 3개는 ignored이며 빌드에는 기존 미사용 변수 경고 2개가 있다.

SM-S937N에서 기존 Android 16 이미지와 `phase5a-bringup-20261104` profile userdata를 사용해 `--guest-child-worker`를 실행했다. 분리된 mount namespace와 userdata write/read를 확인했고, private Binder는 Guest `507:5`, Host `507:1`, protocol 8이었다. Guest 진단 child는 UID/GID 29999, Guest domain `u:r:ssal_guest_probe:s0`로 진입했고 exec-stop FD 검사는 PASS였다. Guest `/data`의 profile 일치 및 write/read/unlink, Host와 다른 property 디렉터리, property socket 부재, 표본 Host 프로세스의 `/proc/<pid>/root` 및 FD 디렉터리 열기 거부를 관측했다. 이는 해당 진단 child에 한정된다.

실행은 최종 검증에서 종료 코드 1로 중단됐다: `identity, process status, property-area result, or post-exec policy state mismatch`. 진단 child의 private Binder open은 `EACCES`(13)였고, 빈 Guest property area의 `properties_serial` open은 `ENOENT`(2)였다. 어느 조건이 최종 불일치를 일으켰는지는 아직 분리하지 못했으며, Binder EACCES의 DAC/SELinux 원인도 확정하지 않았다. 이 실행에서 Guest shell과 Binder IPC는 재검증되지 않았다. 전체 출력은 [기기 실행 로그](phase5b-device-run.log)에 있다.

각 worker는 rootfs 잔여 mount 부재와 55개 loop backing 해제를 보고했다. 실행 전후 Host Enforcing 및 boot ID `f7900911-c061-4570-8f65-900571a55c11`가 같았고, init 1/0, zygote64 27927/24968442, system_server 28271/24968569, adbd 23785/28445920, netd 27933/24968444의 PID/starttime도 같았다. Host 전체 데이터 불변성은 측정하지 않았다. 실행 중 정책을 변경하거나 재부팅하지 않았다.

다음에는 위 불일치의 각 조건과 Binder open EACCES를 분리해 수정하고, 공통 런처에서 shell·private Binder IPC 및 control socket 경계를 확인해야 한다. 그 전에는 installd/artd를 실행하지 않는다.

## Binder EACCES 집중 검증 및 UID 1000 전환

기존 실패를 재현했다. Guest mount namespace의 `/dev/binder`는 private binderfs 장치 `507:5`, inode 8, label `u:object_r:binder_device:s0`, root:root, mode `0600`이었다. Guest 진단 child는 UID/GID 29999, 보조 그룹 없음, 모든 capability 집합 0, `NoNewPrivs=1`, `u:r:ssal_guest_probe:s0`이고 해당 domain은 permissive였다. helper의 호출은 `open("/dev/binder", O_RDWR | O_CLOEXEC)` (flags `0x80002`), 결과 `EACCES`(13)였다. libc 아래의 실제 syscall 이름은 이번에 추적하지 않았으므로 `openat`으로 단정하지 않는다. 관련 child Binder AVC는 수집 버퍼에서 관측되지 않았고 overrun도 없었다. stat에서 private 장치 identity가 확인되어 잘못된 Host Binder 경로가 아니며, root:root `0600`과 위 자격이 DAC 거부를 설명한다. [재현 로그](phase5b-binder-denial-device-run.log).

생성 mount와 Host rdev를 검사하는 `private_device()` FD를 통해 진단 전용 Binder 노드의 owner/group을 child와 맞췄다. UID 29999 시험에서 Binder open `errno=0`, proc 보고 검증과 최종 검사 모두 true였다. 이어 사용자의 요청대로 진단 UID/GID, Guest 진단용 tmp 디렉터리, private Binder owner, property tmpfs owner를 **1000:1000**으로 변경했다. UID 1000 재시험에서도 private Binder open `errno=0`, Guest `507:5`, Host `507:1`, protocol 8로 확인됐다. Host Binder는 전후 `507:1`, root:root `0666`, 동일 label이었다. [UID 29999 수정 확인 로그](phase5b-binder-dac-device-run.log), [UID 1000 로그](phase5b-uid1000-device-run.log).

UID 1000에서는 Host proc 가시성과 신호 권한 가능성이 관측됐다. Guest domain permissive 상태에서 Host servicemanager PID 942의 `/proc/942/root`와 FD 디렉터리 열기가 성공했고 FD 목록 읽기도 성공했다. surfaceflinger PID 2108의 FD 디렉터리 열기와 목록 읽기도 성공했다. 이는 정보 조회이며 Host 데이터 손상의 증거가 아니다. FD 목록 읽기는 FD 대상 재개방과 다르고, 후자는 실행하지 않았다. `kill(pid, 0)`은 servicemanager 942, surfaceflinger 2108, system_server 28271에 대해 성공했다. 이는 신호 권한 가능성을 나타내지만 실제 신호 전송 성공의 증거는 아니며 실제 신호 전달은 수행하지 않았다. 최종 검증의 실제 값은 `status_valid=true`, `reporter_valid=false`, `host_proc_denied=false`, `guest_binder_opened=true`, `enforcing_after=true`, `state_matches=true`, `host_path_unchanged=true`, `host_processes_unchanged=true`이고, 각 보안 검사의 기대값은 true다. `reporter_valid=false`는 기존 proc 검증 조건 불일치다.

별도의 UID 29999 재시험에서 두 번째 property-area helper는 `root_credentials_required_for_tmpfs_area`로 실패했다. 실제 child UID는 29999인데 helper가 euid 0을 요구하므로 `status_valid=false`, `reporter_valid=false`였다. UID 1000 시험은 첫 번째 proc 검사에서 중단돼 두 번째 검사는 실행되지 않았다. Property-area 완성을 Binder open 성공의 증거로 사용하지 않는다.

Android AArch64 빌드, `cargo fmt --check`, Linux 테스트는 통과했다(특권 테스트 3개 ignored). 마지막 Binder owner/mode 확인 코드 추가 후 빌드는 통과했으나 Host 격리 실패 때문에 그 최종 바이너리는 기기에서 다시 실행하지 않았다. 실행 전후 Host SELinux Enforcing 및 boot ID `f7900911-c061-4570-8f65-900571a55c11` 유지, init 1/0, zygote64 27927/24968442, system_server 28271/24968569, adbd 23785/28445920, netd 27933/24968444, servicemanager 942/374의 PID/starttime 불변을 확인했다. worker는 rootfs 잔여 mount 부재와 loop 55개 해제를 보고했다.

당시 결론은 Phase 5B 미완료였다. UID 1000 진단 child에서 Host `/proc`/FD 일부를 읽고 `kill(pid, 0)`이 성공한 것은 가시성·권한 점검이며, 실제 종료 신호를 보낸 결과가 아니다. 공유 PID 조사 완료 판정에 따라 이 결과만으로 정상 Guest 프로세스 관리나 Phase 6A를 NO-GO 처리하지 않는다. 정상 Guest AMS/Zygote가 Host PID를 종료 대상으로 고르는지 확인하는 것과 Guest의 임의 Host 신호를 차단하는 것은 별도 항목이다.

## Host Binder 권한과 PID namespace 확인

Guest Binder의 소유권과 mode를 Host `/dev/binder`의 stat 값으로 설정하도록 수정했다. 변경 대상은 mount identity 및 Host와 다른 rdev를 검증한 private FD뿐이다. 실기기에서 Guest Binder `507:5`, inode 8, root:root `0666`, Host Binder `507:1`, root:root `0666`을 확인했고 UID/GID 1000 Guest child의 open은 `errno=0`이었다. Host Binder 자체는 변경하지 않았다. [실행 로그](phase5b-host-binder-mode-device-run.log). Android 빌드 및 Linux 테스트가 통과했으며 특권 테스트 3개는 ignored다.

실기기 `/proc/config.gz`는 `# CONFIG_PID_NS is not set`, `unshare -p /system/bin/true`는 `Invalid argument`를 반환했고 `/proc/self/ns/pid`도 없다. 따라서 현재 순정 커널에서는 Guest PID namespace와 그에 대응하는 별도 proc PID view를 만들 수 없다. mount namespace에 새 proc만 마운트해도 Host PID namespace를 숨기는 대책은 아니다.

당시에는 Guest에 상속되는 seccomp에서 signal syscall을 제한하거나 Guest enforcing domain으로 Host signal/ptrace를 거부하는 대안을 검토했으나 적용하지 않았다. 이는 적대적 Guest 차단을 보장하지 않으며 정상 AMS 표적 선택 분석을 대체하지 않는다. Host Enforcing과 표본 Host 프로세스 PID/starttime은 이전 시험에서 유지됐다.

## 2026-11-04 추가 판정 — 공유 PID 조사 완료

공유 PID Namespace 부재는 BLOCKER에서 제외했다. AOSP Android 16 Zygote의 자식 회수와 ActivityManager의 ProcessRecord 기반 종료는 공유 PID 조건에서도 정상 관리가 가능하며, Host PID 가시성 또는 `kill(pid, 0)`만으로 Host 종료 대상 선택을 뜻하지 않는다. 상세 근거는 [공유 PID 프로세스 관리 조사](shared-pid-process-management.md)에 있다.

실기기 cgroup 상태의 읽기 전용 확인과 Guest 경로 계약은 2026-11-04에 완료했다. v2 Guest root 후보는 `/sys/fs/cgroup/apps/ssal_guest`; v1 cpu/cpuset/blkio는 각 controller 아래 `/ssal_guest`이며, Guest mount namespace에서 이 child root만 Android의 기본 mountpoint로 bind한다. Guest 전용 subtree 및 mount는 아직 생성하지 않았다. 상세 controller와 task-profile 제약은 [공유 PID 프로세스 관리 조사](shared-pid-process-management.md)에 기록했다.

Phase 5B는 미완료다. 다음은 허용된 구성 단계에서 Guest-only cgroup child/mount/profile을 실제로 만들고 libprocessgroup 경로를 확인한 뒤 기존 private Binder/AIDL, property/control socket, 공통 launcher 검증을 마치는 것이다. Host cgroup 변경과 프로세스 신호는 이번 읽기 전용 작업에서 수행하지 않았다. Guest lmkd는 첫 부팅에서 제외하고, Host init으로 향하는 Guest `ctl.*`은 차단한다. 그 뒤 Phase 6A installd/artd로 진행한다.

## 2026-11-04 Phase 5B 제한 cgroup 실행 결과

SM-S937N에서 Host SELinux `Enforcing`과 동일 boot ID `f7900911-c061-4570-8f65-900571a55c11`을 확인했다. 네 전용 root `/sys/fs/cgroup/apps/ssal_guest`, `/dev/cpuctl/ssal_guest`, `/dev/cpuset/ssal_guest`, `/dev/blkio/ssal_guest`를 새로 만들고, cpuset의 CPU와 memory node를 부모 값으로 초기화했다. v2에 `uid_29999/pid_test`, 세 v1 root에 `foreground`를 만들었다. 새 shell child PID 22398이 자신의 PID만 네 그룹에 기록한 뒤 정상 종료했다. `/proc/22398/cgroup`은 v2 `/apps/ssal_guest/uid_29999/pid_test`, cpu/cpuset/blkio 각각 `/ssal_guest/foreground`를 보고했다. child 종료 후 생성한 그룹과 네 root를 모두 제거했고 잔여 경로가 없었다. v2 memory 위임이나 Host 기존 그룹의 이동·삭제, Host 프로세스에 신호 전송은 하지 않았다.

전후 표본에서 init PID 1/288, zygote64 27927, system_server 28271, lmkd 941의 PID와 각 cgroup membership이 같았고 Host는 Enforcing을 유지했다. 전체 Host membership의 불변성 및 PID starttime은 이번 시험에서 비교하지 않았다. 이는 직접 cgroup 파일에 쓴 제한 시험이며 Guest task profile이나 Guest libprocessgroup API 호출의 성공을 의미하지 않는다.

별도 mount namespace에서 bind 시험을 준비했으나 기기 Toybox `mount --make-rprivate`가 지원되지 않아 bind 전에 중단하고 생성한 경로를 정리했다. 기존 mount worker의 `MS_REC | MS_PRIVATE` 구현은 별도이며 이번 실험에서 실행하지 않았다. Guest mount worker 연결, Guest 설정의 memory profile 비활성화, 실제 Guest libprocessgroup의 create/set/kill/remove 및 task profile, Host 전체 구성 비교는 아직 수행하지 않았다. **cgroup Phase 5B는 미완료**이며 완료 판정 후에만 기존 Binder/property/공통 launcher 검증으로 복귀한다.

## 2026-11-04 Phase 5B cgroup mount worker 통합 — 제한 범위 PASS

`src/guest_mounts.rs`에 Guest 전용 subtree 생성, cpuset 초기화, non-recursive bind, backing inode 확인 및 종료/실패 시 정리를 구현했다. `--guest-child-worker`와 새 `--guest-cgroup-worker`에서만 활성화한다. 기존 `prepare::worker`의 `unshare(CLONE_NEWNS)`와 `MS_REC | MS_PRIVATE`를 재사용하며, cgroup 생성 전에 mountinfo의 private propagation도 확인한다. 기존 subtree가 있으면 세션 소유로 인수하지 않고 실패한다. Host controller 설정과 `cgroup.procs`/`tasks`에는 쓰지 않는다.

새 cgroup worker는 rootfs의 `/dev`, `/proc`, `/sys` 구성 후 기존 `ssal-guest-domain-poc`의 `--cgroup-mount-check GUEST_ROOT`를 실행한다. POC는 같은 private mount namespace의 Guest root로 chroot한 뒤 mountinfo, 네 `cgroup.procs`, cpuset 값, `/proc/self/cgroup`을 읽는다. 정확히 네 cgroup mount만 존재하고 각 backing root가 아래 계약과 일치하는지 검사한다. APEX 준비, Binder/property 검증과 Android 서비스 실행에는 진입하지 않는다.

| Host의 새 Guest 전용 subtree | Guest mountpoint | Guest 내부 mountinfo root | 결과 |
|---|---|---|---|
| `/sys/fs/cgroup/apps/ssal_guest` | `/sys/fs/cgroup` | `/apps/ssal_guest` (cgroup2) | PASS |
| `/dev/cpuctl/ssal_guest` | `/dev/cpuctl` | `/ssal_guest` (cgroup cpu) | PASS |
| `/dev/cpuset/ssal_guest` | `/dev/cpuset` | `/ssal_guest` (cgroup cpuset) | PASS |
| `/dev/blkio/ssal_guest` | `/dev/blkio` | `/ssal_guest` (cgroup blkio) | PASS |

SM-S937N의 최종 실행은 종료 코드 0이었다. Host namespace는 `mnt:[4026532950]`, Guest는 `mnt:[4026536483]`였다. Guest cpuset은 부모에서 복사한 `cpus=0-7`, `mems=0`을 보고했다. 첫 실행에서 prefix가 있는 cpuset 파일명을 사용해 ENOENT가 났으나 생성 자원은 모두 정리됐다. 기기의 확정된 `noprefix` 구성에 맞게 `cpus`/`mems`로 수정한 뒤 재실행했다.

진단 child의 membership은 읽기 전용으로 확인했으며 이동하지 않았다: v2 `/`, cpu `/general`, cpuset `/`, blkio `/normal` 등 실행 shell에서 상속한 값이 chroot 전후 같았다. 네 새 subtree의 `cgroup.procs`는 비어 있었다. 이는 이번 mount 검증의 의도된 결과이며, 앞서 PASS한 Guest child 배치 POC를 다시 실행하거나 libprocessgroup 동작을 검증한 것이 아니다. 이 진단은 trusted root POC로 실행했으며 Guest SELinux domain의 접근 제어를 입증하지 않는다.

종료 시 bind를 먼저 해제한 뒤 이번 세션에서 만든 네 root만 역순 `rmdir`했다. Guest cgroup root 잔여 경로, rootfs 잔여 mount가 없고 system loop 1개도 해제됐다. 기존/다른 세션 subtree나 예상 밖 하위 그룹은 재귀 삭제하지 않으며, 비어 있지 않으면 정리 실패를 보고한다. 부분 정리 실패 후 성공한 경로를 재시도하지 않는 동작도 단위 테스트로 확인했다.

Host 전후 비교는 `/sys/fs/cgroup`, `/dev/cpuctl`, `/dev/cpuset`, `/dev/blkio`의 전체 디렉터리 경로 목록, controller mountinfo, 네 hierarchy root의 inode/mode/UID/GID, v2 root/apps의 `cgroup.subtree_control`, cpuset 부모 `cpus`/`mems`를 포함했다. 비교 결과 byte-identical이었다(SHA-256 `0e14c9ad976530f792c489cb89316eee0aa9e106fc08a440725d07075c5e9972`). 원본 snapshot은 로컬 `out/phase5b-cgroup/before.txt`, `after.txt`에 보존했다. Host SELinux `Enforcing`과 boot ID `f7900911-c061-4570-8f65-900571a55c11`도 전후 동일했다. 전체 Host control 파일 값이나 전체 프로세스 membership을 비교한 것은 아니다.

검증: sandbox 밖 `wslc exec --workdir /src ssal-dev cargo test --locked`에서 79개 PASS, 특권 테스트 3개 ignored. 마지막 진단 보강 후 `cargo fmt --check`, cgroup 정리 단위 테스트 재실행, `bash scripts/build-android.sh` 및 최종 실기기 실행이 통과했다. 최종 Android AArch64 바이너리 SHA-256은 ssald `1ebd5b08b7889c353666dc79857b81bc91a932d78b7d216b22052fd08ce9090a`, POC `2f99b285493abc711cd79d174342687b7a118266afe76a780a8f41744c24d90b`다.

재현 명령(새 session 디렉터리에 `system`, `data` 디렉터리 사전 생성):

```sh
SSAL_GUEST_CHILD_POC=/data/local/tmp/ssal-phase5b-cgroup-poc \
  /data/local/tmp/ssal-phase5b-cgroup-ssald --guest-cgroup-worker \
  /data/local/ssal/images/1793366406758-25627/system.img \
  /data/local/ssal/guests/phase5a-bringup-20261104/userdata SESSION_DIR
```

실행 로그: [phase5b-cgroup-mount-device-run.log](phase5b-cgroup-mount-device-run.log). 기존 이미지/profile/module 파일은 교체하지 않았다. `killProcessGroup()`, 실제 Guest Zygote/system_server/lmkd, Host 프로세스 이동, 새 SELinux 정책 조사·변경 및 hard reboot는 수행하지 않았다. **이번 mount 통합 범위만 PASS이며 Phase 5B 전체는 미완료다.** task profile/libprocessgroup 및 공통 launcher 검증은 이번 범위에 포함하지 않았다.

## 2026-11-04 Phase 5B 실제 Guest libprocessgroup — PASS, cgroup 항목 완료

기존 `GuestCgroups::prepare/create/cleanup`과 mount worker의 private propagation 및 mount 정리를 재사용했다. 새 `--guest-processgroup-worker`가 실제 이미지의 JSON을 읽고 실행 환경에만 설정을 bind한다. `native/processgroup-probe/main.cpp`는 실제 GSI `libprocessgroup.so`에 동적 링크하며, Guest bootstrap linker와 Guest Bionic/libc++만 사용한다. Guest 이미지나 Host 라이브러리를 수정하거나 libprocessgroup을 재구현하지 않았다.

**확인한 설정 및 적용**

- 실제 LineageOS 23.2 이미지의 `/system/etc/cgroups.json`: v1 cpu/cpuset/blkio 경로는 기존 전용 mountpoint와 일치한다. v2 root는 `/sys/fs/cgroup`, freezer 및 optional memory descriptor가 있다.
- 이미지의 `/system/etc/task_profiles.json`에서 v1 `JoinCgroup` 경로와 중간 디렉터리를 추출해 새 Guest subtree 안에만 생성한다. cpuset 값은 Guest 부모에서 상속하고, 이번 시험에서는 CPU별 성능 정책을 튜닝하지 않았다.
- v2 memory controller descriptor와 memory attribute/action만 실행 시 비활성화한다. 기존 profile 이름과 aggregate는 유지하며 memory 전용 action은 빈 action으로 남긴다. Host memory controller의 위임·설정 변경은 하지 않는다.
- 설정 두 파일을 Guest `/run/ssal/processgroup` tmpfs에 만들고 Guest `/system/etc`의 원래 파일 위에 read-only bind한다. 원본 GSI 파일은 RO system mount에 그대로 남는다.
- vendor 설정은 요청대로 **Luna high 서브 에이전트**가 읽기 전용으로 확인했다. `/vendor/etc/cgroups.json`, `/vendor/etc/cgroups*.json`, `/vendor/etc/task_profiles/`와 ODM의 두 JSON은 없었다. `/vendor/etc/task_profiles.json`은 Samsung GPIS, midground, abnormal profile/aggregate만 추가한다(SHA-256 `158a5c44480afc3bc84c291a09ceb524f082b344dbd03a1bc4a5e0d255ab8ede`). 전체 Guest profile의 대체 파일로 쓰지 않는다. 이번 전용 worker는 Host `/vendor`와 property 영역을 bind하기 전에 실행하므로 이 vendor override와 Host API-level property를 로드하지 않는다.

새로 만든 Guest 디렉터리와 해당 `cgroup.procs`/`tasks`/`cgroup.threads`만 system UID/GID 1000에 허용했다. 새 helper 프로세스 자신의 PID만 Guest root 네 곳에 배치한 뒤 UID/GID 1000으로 낮춰 실행한다. mount worker와 Host 프로세스는 이동하지 않는다. helper는 이 자격으로 새 child를 fork하고 실제 라이브러리를 호출한다. SELinux context는 기존 `u:r:ksu:s0`였으며 별도 Guest domain 전환 또는 정책 변경은 하지 않았다. 따라서 이번 PASS는 이 자격의 cgroup 기능 검증이며 Guest SELinux confinement의 증거는 아니다.

**실기기 최종 실행 결과**

SM-S937N, Guest child PID `7152`, Host namespace `mnt:[4026532950]`, Guest namespace `mnt:[4026536282]`에서 다음을 확인했다.

| 실제 호출/검사 | 반환값·결과 |
|---|---|
| UID 1000의 Guest root 및 v1 대상 `cgroup.procs` 쓰기 접근 | `access(W_OK)=0`, errno 0 |
| `createProcessGroup(1000, 7152, false)` | **0**, errno 2 잔존. 생성 성공이며 성공 시 errno는 실패 판정에 쓰지 않음 |
| 생성한 v2 그룹 | Guest `/sys/fs/cgroup/system/uid_1000/pid_7152`, `cgroup.procs=7152` |
| `CPUSET_SP_BACKGROUND` 적용 | **true**, errno 2 잔존; cpu/cpuset/blkio 모두 `/ssal_guest/background` |
| `CPUSET_SP_TOP_APP` 적용 | **true**, errno 0; cpu/cpuset `/ssal_guest/top-app`, blkio `/ssal_guest` |
| `CPUSET_SP_FOREGROUND` 적용 | **true**, errno 0; cpu/cpuset `/ssal_guest/foreground`, blkio `/ssal_guest` |
| 각 profile 적용 후 v2 membership | `/apps/ssal_guest/system/uid_1000/pid_7152` 유지 |
| 정상 종료 및 정리 | pipe EOF 후 child exit 0, waitpid 성공; 생성한 PID/UID 그룹 rmdir 성공 |
| 기존 worker 정리 | Guest 전용 root/하위 그룹·rootfs mount 잔여 없음, system loop 1개 해제 |

`setProcessGroup`이라는 독립 export는 해당 라이브러리에 없다. Lineage Android `Process.setProcessGroup` JNI의 실제 native 경로는 `get_cpuset_policy_profile_name` → `SetProcessProfilesCached(uid,pid,profiles)`다. helper는 이 두 실제 export를 직접 호출했다. 정책 `0`, `5`, `-1`을 사용하고 `-1`은 JNI와 같이 foreground로 정규화했다. **JVM/JNI 자체를 실행한 것은 아니며**, native process-profile 경로를 검증했다. 참고 구현: [LineageOS android_util_Process.cpp](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/jni/android_util_Process.cpp), [libprocessgroup](https://github.com/LineageOS/android_system_core/blob/lineage-23.2/libprocessgroup/processgroup.cpp).

Host 전후 snapshot은 다음을 포함하며 byte-identical이었다: system/vendor JSON SHA-256, Host cgroup mountinfo, 네 hierarchy 전체 디렉터리 경로, hierarchy root inode/mode/UID/GID, 각 기존 그룹의 `cgroup.subtree_control`, `cpu.shares`, CPU CFS period/quota, cpuset `cpus/mems`, `blkio.weight`. 동적 사용량 counter는 비교하지 않았다. 표본 Host 프로세스 init `1/0`, init `288/270`, zygote64 `27927/24968442`, system_server `28271/24968569`, lmkd `941/374`의 PID/starttime 및 모든 cgroup membership도 동일했다. Host `Enforcing`과 boot ID `f7900911-c061-4570-8f65-900571a55c11`도 유지됐다. snapshot SHA-256은 양쪽 모두 `08a6881bc3444b79cd97948da84dda94b1c3413527f249facbb01a8e690cbda1`이며 로컬 `out/phase5b-processgroup/before.txt`, `after.txt`에 보존했다.

**실패 수정 및 재시험**

1. [r1 로그](phase5b-processgroup-device-run-r1.log): Guest bootstrap linker가 `--library-path`를 받지 않아 종료 1. 라이브러리 호출 전 실패이며 cgroup 함수 반환값은 없다. Guest-only `LD_LIBRARY_PATH`로 수정했다. 정리와 Host 비교는 PASS였다.
2. [r2 로그](phase5b-processgroup-device-run-r2.log): `createProcessGroup(1000,3257,false)=0`, errno 2, controller `/sys/fs/cgroup`. 이후 helper의 libc++ ABI 2 문자열 처리에서 SIGSEGV가 났고 profile 호출에는 도달하지 못했다. 해당 Guest libc++의 ABI 1/namespace `__1`로 수정했다. child의 자체 종료를 확인하고 빈 `/apps/ssal_guest/system/uid_1000/pid_3257` 및 세션 전용 부모만 rmdir했다. signal/reboot/Host cgroup 수정은 하지 않았다. 이 실패 시 worker는 남은 Guest 자원을 성공으로 숨기지 않고 정리 실패를 보고했다.
3. [r3 최종 로그](phase5b-processgroup-device-run-r3.log): 위 전체 호출·membership·정리·Host 전후 비교 PASS, worker exit 0. 새 helper 재빌드 후에도 SHA-256은 같은 값이다.

빌드/테스트: sandbox 밖 `wslc`에서 Android AArch64 release 빌드, `scripts/build-processgroup-probe.sh`, `cargo fmt --check`, `cargo test --locked` 통과(80 PASS, 특권 테스트 3 ignored). 새 단위 테스트는 memory action 제거 시 기존 profile/aggregate 보존과 Host 경로·traversal 거부를 검증한다. helper의 런타임 self-check는 반환값만 보지 않고 실제 child membership과 정상 종료·정리를 확인한다.

최종 SHA-256: ssald `7a8e43bcc544d86d046d257eec8783fbe1c236e5b49f012f0362c6e06d3a241e`, helper `edd927f42b18d24e39b5a35b521fcc0a2b90f093b7f245bebc6f5ca23eb0b402`, 원본 Guest libprocessgroup `f658b27758c992515c375cb406f718d62613567bb58ec36a15aad179292415ee`.

재현: `bash scripts/build-processgroup-probe.sh`로 기본 LineageOS 23.2 이미지에서 링크용 원본 라이브러리를 읽기 전용 추출하고 helper를 빌드한다. 기기에서는 새 session 디렉터리의 `system`, `data`를 준비한 뒤 다음과 같이 호출한다.

```sh
SSAL_PROCESSGROUP_PROBE=/data/local/tmp/ssal-phase5b-processgroup-probe \
  /data/local/tmp/ssal-phase5b-processgroup-ssald --guest-processgroup-worker \
  /data/local/ssal/images/1793366406758-25627/system.img \
  /data/local/ssal/guests/phase5a-bringup-20261104/userdata SESSION_DIR
```

**요청한 Phase 5B cgroup 항목은 완료했다. 다음 작업은 남은 Binder/property/공통 launcher 검증이다. Phase 5B 전체 완료 판정은 하지 않는다.** memory action은 위처럼 비활성화한 구성이며, freezer 동작·모든 task profile·별도 Guest domain 권한은 이번 PASS 범위가 아니다. `killProcessGroup`과 신호 전송, Guest Zygote/system_server/lmkd 실행, Host 프로세스 이동/종료, 전체 SELinux 정책 재검토 및 재부팅은 수행하지 않았다.
