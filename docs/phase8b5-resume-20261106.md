# Phase 8B-5 재개 — 2026-11-06

**결과: NO-GO.** 실기기 단발 실행은 재패닉 없이 정리됐지만, Guest Zygote가 종료 코드 98로 끝나 `forkSystemServer()`와 startup/final SID hook에는 도달하지 못했다. 재시도하지 않았다.

## Phase 7I 수정본 비교

이번 launcher는 최신 Phase 7I의 `make_guest_runtime_accessible()` 수정을 포함한다. launcher executable 및 UID 1000이 Guest에서 읽거나 실행하는 helper의 권한을 staging 전에 보완한다([구현](../src/guest_launcher.rs#L97), [적용](../src/guest_launcher.rs#L978)). 기존 8B-5 흐름은 Phase 7I Property Service, Private Binder, userdata와 Zygote fork 준비를 그대로 사용하고, 마지막에만 `--start-system-server`를 추가해 실제 SID 경로를 시험한다. 기존 시도의 `ssald`는 7I 권한 수정 전 산출물이어서 새 launcher와 진단 artifacts를 다시 빌드했다.

빌드는 WSLc `ssal-dev`에서 완료했다. `cargo test --locked --bin ssald`: **53 passed, 0 failed, 4 ignored**. Runtime hook/canary ARM64 빌드와 runner shell syntax 검사도 통과했다. 실행 artifact 및 hash 목록은 [`out/phase8b5-resume-20261106/sha256.txt`](../out/phase8b5-resume-20261106/sha256.txt)에 있다.

## 실기기 단발 결과

기기 SM-S937N, 실행 전후 SELinux Enforcing, boot ID `bfa2e92a-3dd0-42e5-8d1f-e03b55bc73da` 동일. 실행은 `/dev/ssal-phase8b5/runtime-1793961968`에서 수행했다.

| 단계 | 결과 |
|---|---|
| 최신 Phase 7I Property Service / persistent restore | **PASS**; Guest property area `[1048599,12]`, Host `[18,118]`; Guest `/data` `[1050416,2]`, Host `[65105,3]` |
| Private Binder/AIDL 회귀 | **PASS** |
| Guest Zygote 기동 및 8B-5 admission | admission **PASS**; private mount, pinned runtime, terminal gate 확인 |
| 실제 GSI `forkSystemServer()` | **미도달 확인**; Guest Zygote PID 21202 종료 코드 98 |
| startup/final SID, ART hook 반환, property 재초기화 | **미수집**; runtime evidence에는 `ADMISSION`만 있음 |
| disposable canary | 생성 및 parent 쪽 생존/proc-root 확인; final Guest SID에서 경계 검사는 실행되지 않음 |
| cleanup / Host 보존 | Guest cgroup 정리, rootfs 잔여 mount 없음, 56 loop allocation 해제; `HOST_SAFETY_SNAPSHOT=UNCHANGED` |

코드상 종료 98은 runtime hook constructor의 두 `check_domain()` 정책 조회 중 하나가 거부/오류일 때 발생한다([조회 구현](../native/binder-probe/system-server-runtime-sid.c#L78), [호출 순서](../native/binder-probe/system-server-runtime-sid.c#L196)). 현재 기록은 두 조회 각각의 진행 상태를 쓰지 않아 어느 SID에서 멈췄는지는 판별할 수 없다. `ADMISSION`만 존재하고 `startup`, `final`, `property_reinit` 기록이 없으므로 ART hook이나 final setter의 성공/실패를 추론하지 않는다.

실행 중 worker log는 호스트로 스트리밍했고, 기기의 worker/zygote 로그와 before/after snapshot을 로컬에 보존했다([콘솔](../out/phase8b5-resume-20261106/console.txt), [회수한 증거](../out/phase8b5-resume-20261106/device-stage/worker.log), [runtime report](../out/phase8b5-resume-20261106/device-stage/phase8b5/runtime.txt)). `dmesg` 필터 결과에는 해당 실행 시각의 DEFEX link-protection 메시지 3건만 있었고 FIVE panic, `task_integrity` BUG, AVC 거부는 없었다([필터 결과](../out/phase8b5-resume-20261106/dmesg-filtered.txt)). 이는 이번 실행에서 재패닉이 없었다는 증거이며 이전 사건 원인을 해소했다는 증거는 아니다.

## FIVE fork/exit 검토

기존 패닉의 직접 사실은 RCU task-free 경로에서 count 0인 FIVE 객체를 `five_task_free()`가 put하려 했다는 것이다. BYI3 `common` 소스에는 LSM `task_alloc` 오류 처리의 `security_task_free()`와 `copy_process()` cleanup이 같은 FIVE 참조를 정리할 수 있는 fork rollback 후보가 정적으로 있다([조사](five-task-free-followup.md)). 하지만 실행 기기는 BDZJ2이고 일치하는 kernel source/build config가 없어 이 후보를 패닉 원인으로 확정하거나 실행 커널에 수정할 수 없다. 이번 시도에서도 FIVE panic은 관측되지 않아 **kernel/FIVE 수정은 하지 않았다**.

실기기 runner와 launcher gate는 재개를 위해 열었고, runner는 worker log를 실행 중 로컬로 스트리밍한다. 첫 재개 시도는 policy type 누락으로 끝났으며 이후 아래처럼 Guest rule을 적용해 한 번 더 실행했다.

## Guest SELinux rule 적용 후 재실험 — 패닉 재현

첫 재개 실행에서 두 Guest context가 invalid였음을 확인했다. 기존 [Guest 전용 rule](../scripts/guest-domain-poc/phase8b-guest-system-server.rule)을 KernelSU `sepolicy check`로 확인한 뒤 `sepolicy apply`했다. Host rule이나 `module/sepolicy.rule`은 수정하지 않았다. 적용 후 두 Guest context가 valid였고 `getenforce=Enforcing`을 유지했다([적용 출력](../out/phase8b5-resume-20261106/policy-apply.txt), [적용 후 조회](../out/phase8b5-resume-20261106/policy-post-state.txt)).

같은 launcher와 runner로 단 한 번 재실행했다. 스트리밍 console에는 `SSAL_PHASE8B5 admission=PASS`와 Guest Zygote PID 24092가 남았고, 이어 사용자가 커널 패닉을 확인했다([console lines 235, 253–255](../out/phase8b5-resume-20261106/console-policy-run.txt)). console은 Phase 7B diagnostics 경로에서 끝나 `startup`, `final`, `property_reinit` 결과는 로컬로 회수되지 않았다. `/dev` stage는 재부팅으로 사라졌다.

ADB가 돌아온 뒤 boot ID는 `c9bf87b5-9d82-400f-be85-8e836ddd8d9f`, `ro.boot.bootreason=reboot`, `sys.boot_completed=1`, `getenforce=Enforcing`이었다. pstore 디렉터리는 비어 있었지만 `/proc/last_kmsg`를 회수했다. 전체 파일은 [`panic-last_kmsg.txt`](../out/phase8b5-resume-20261106/panic-last_kmsg.txt), 필터된 panic line은 [`panic-excerpt.txt`](../out/phase8b5-resume-20261106/panic-excerpt.txt)다. SHA-256: `8612b313d20032f49f9a9d5117b02e3be5a039c48c3799dac4beb48c69cb0adc`.

이번 dump는 이전과 같은 서명을 확인한다: uptime 29,792.755638초, `rcuop/4` PID 53에서 `include/linux/task_integrity.h:150` BUG; PC `five_task_free+0x40/0x70`, LR `security_task_free+0x5c/0x7c`; stack은 `five_task_free → __put_task_struct → delayed_put_task_struct → rcu_do_batch → rcu_nocb_cb_kthread`다. 이는 zero-count FIVE put이 RCU task-free 경로에서 다시 발생했다는 증거다. 실패한 `task_alloc`, 대상 task, clone flags는 dump에 식별되지 않는다. 따라서 fork hook double-put 정적 후보와 일치하지만, 그 경로가 실제 원인이었다고 확정하지 않는다([기존 조사](five-task-free-followup.md)).

**패닉 후 실험을 반복하지 않았다.** 지금 완료 기준은 NO-GO다. runtime SID, 실제 `forkSystemServer()` 도달, ART hook, property 재초기화는 미확인이다. 재부팅 후 Host는 Enforcing 상태로 부팅 완료했지만, 패닉 직후의 전체 Host snapshot은 확보되지 않았다. 재부팅 뒤 두 Guest context가 다시 invalid였고 module `sepolicy.rule` hash는 `f23c957c…11a6801d`였다([조회 결과](../out/phase8b5-resume-20261106/policy-after-reboot-state.txt)). 따라서 live KernelSU rule은 재부팅으로 초기화됐고 영구 module policy에는 저장되지 않았다. 반복 방지를 위해 8B-5 launcher admission과 runner를 다시 차단했다. BYI3/BDZJ2 소스 매칭 문제가 남아 있어 kernel/FIVE 코드 변경은 하지 않았다.

## 전역 Permissive 증상 확인 — 2026-11-06

사용자 요청에 따라 단발 실행에서 SELinux 전역 enforcement를 `0`으로 설정하고 Guest 전용 `ssal_property`, `ssal_guest_probe`, system-server 정책을 live 적용했다. 8B-5 admission과 두 target-domain 정책 질의는 통과했다. `startup` setter는 `u:r:ssal_guest_probe:s0`에서 `u:r:ssal_guest_ss_startup:s0`로, `final` setter는 `u:r:ssal_guest_ss_startup:s0`에서 `u:r:ssal_guest_ss:s0`로 성공했고, 두 `property_reinit`도 `result=0`이었다.

전역 Permissive에서는 boundary 검사가 실패했다. canary에 대한 `kill(pid, 0)`이 성공했고 `/proc/<canary>/{root,fd,fd/0}`를 열 수 있어 `boundary=0 checks=0`으로 종료했다. 이는 Guest system-server SID 전환은 작동했지만 전역 Permissive 상태에서 process/proc 경계가 보장되지 않았음을 관측한 결과다. 진단 hook은 Framework 진입 전에 종료했다(`framework=NOT_ENTERED`, worker exit 1). [실행 콘솔](../out/phase8b5-resume-20261106/permissive-console30.txt)과 [runtime evidence](../out/phase8b5-resume-20261106/permissive-runtime.txt)에 기록했다.

실행 wrapper는 정상 종료 시 Enforcing 복구를 요청했으며, 요청대로 사후 상태 검증은 하지 않았다. 적용한 KernelSU Guest 규칙은 재부팅 전까지 live policy에 남을 수 있다.

## Framework 지속 관찰 재실험 — 2026-11-06

사용자 지시에 따라 전역 SELinux Permissive 상태에서 재실행했다. 경계 확인과 enforcing 자동 복구를 실행 경로에서 비활성화했고, 사후 SELinux 상태 조회나 테스트는 하지 않았다. 8B-5 admission이 통과했고, startup/final SID 전환과 property 재초기화가 성공했다. ART hook은 `returned_without_pending_exception`을 기록했고, runtime marker는 `RUNTIME_SID acquired=1 boundary=DISABLED checks=1 framework=CONTINUING`이다. worker는 exit 0으로 정리됐다.

Framework 관찰 코드는 최대 90초 동안 Guest Zygote를 기다렸지만, 관찰 창 종료 시 `guest_zygote_alive=false`였고 worker 정리 과정에서 해당 PID에 SIGKILL을 보냈다. 이 기록만으로 zygote가 왜 종료됐는지는 판별하지 않는다. 캡처한 console/runtime 파일에서 `EINVAL`, `Invalid argument`, `os error 22`는 검색되지 않았다. 다만 console에는 `ctl.start`의 `ssal_must_not_reach_host_init` 설정 실패 메시지가 남아 있다.

[실행 콘솔](../out/phase8b5-resume-20261106/permissive-framework-console.txt), [runtime evidence](../out/phase8b5-resume-20261106/permissive-framework-runtime.txt). 실행 스크립트는 `setenforce 1` 복구 trap 없이 끝났으며, 실제 종료 후 전역 모드는 조회하지 않았다. SELinux 상태는 이 실험에서 확인되지 않았다.

## Guest Zygote 종료 원인 확보 — 2026-11-06

회수한 Guest Zygote stderr에서 직접 원인을 확인했다([원인 발췌](../out/phase8b5-resume-20261106/permissive-framework-zygote-cause.txt), [전체 stderr](../out/phase8b5-resume-20261106/permissive-framework-zygote-stderr.log)). 13:03:29 UTC에 SystemServer PID 19933가 `SystemServer.run(SystemServer.java:855)`의 `SystemProperties.set("sys.system_server.start_count", "1")`에서 `PROP_ERROR_HANDLE_CONTROL_MESSAGE (0x20)`를 받고, `RuntimeException`으로 `FATAL EXCEPTION IN SYSTEM PROCESS`를 냈다(stderr lines 1549–1571). 이어 PID 19933가 SIGKILL을 보내 종료했고, PID 19912 Zygote는 system_server FD 쓰기 실패를 기록한 뒤 system server 종료 때문에 자신도 나갔다(lines 1591–1594). 따라서 `guest_zygote_alive=false`는 관찰 코드가 먼저 종료한 결과가 아니라 system_server 실패 뒤의 결과다.

Property service 기록은 PID 19933, source `u:r:ssal_guest_ss:s0`, target `u:object_r:ssal_guest_property_area:s0`의 `property_service:set` 거부 두 건이다(console lines 358–359). service는 `policy::check_access()`에서 SELinux `allowed/decided` 비트에 명시 허용이 없으면 거부한다([정책 검사](../src/guest_properties/policy.rs#L108), [거부 분기](../src/guest_properties/policy.rs#L141), [요청 처리](../src/guest_properties/server.rs#L219)). 이 직접 접근 검사는 전역 permissive만으로 통과되지 않는다. 실행 당시 property context는 `persist.ssal_probe`만 별도 정의하고 나머지는 Guest property area 기본 context를 썼다([설정](../src/guest_launcher.rs#L799)). 적용된 property allow는 `ssal_guest_probe` 주체에만 있었고 final `ssal_guest_ss` 주체에는 없었다([적용 rule](../out/phase8b5-resume-20261106/guest-probe-property.rule)). 즉 최종 SID 전환 후 system_server의 property 쓰기 권한이 부족했던 것이 직접적인 종료 원인으로 확인된다.

추가로 system_server는 약 60초간 `zygote_secondary` socket에 연결하지 못한 뒤 `Log.wtf`를 기록했다(stderr lines 333–345, 1535–1545). 그러나 그 직후 실행이 계속되어 `SystemServer.run()`에 도달했고, 프로세스를 종료시킨 fatal exception은 위 property 쓰기 실패다. 8B-5를 다시 실행하지 않았다.

## Guest property 허용 후 Framework 재개 — 2026-11-06

요청대로 추가 허용은 Phase 8B-5 Guest Property Service 내부의 one-shot 경로에만 넣었다. `u:r:ssal_guest_ss:s0`에서 Guest property area로 쓰는 아래 5개 key만 `SSAL_PHASE8B5_ONCE=1`일 때 허용한다: `sys.system_server.start_count`, `sys.system_server.start_elapsed`, `sys.system_server.start_uptime`, `persist.sys.timezone`, `persist.sys.dalvik.vm.lib.2`. 기타 key, SID, target context에는 예외가 적용되지 않는다. Host Property Service나 Host SELinux policy는 수정하지 않았다. Guest Property Service의 denial log도 key와 SID를 함께 출력하도록 바꿨다. 대상/키 범위 단위 검사 1개 통과, Android AArch64 release build 성공.

실행 중 `start_count`, `start_elapsed`, `start_uptime`, `persist.sys.timezone`(값 `GMT`), `persist.sys.dalvik.vm.lib.2`(값 `libart.so`)의 추가 거부가 차례로 확인돼 각각 해당 key만 좁게 허용했다. 앞의 재실행 하나는 수정된 `ssald`만 staging하고 별도 `ssal-property-service`를 갱신하지 않아 구 바이너리로 동작했으며, 유효한 재실행 결과로 취급하지 않았다. 이후 두 바이너리 hash를 stage와 대조한 실행에서는 추가 property 거부가 없었고, crash handler가 fatal 보고 중 설정하려던 `sys.system_server.crash_java`만 거부됐다. 이 crash-report key는 startup 허용 목록에 추가하지 않았다.

최종 유효 실행에서 Guest SystemServer PID 24990은 `SystemServer.run()`에 진입해 `Entered the Android system server!` 및 `Reading configuration...`를 기록했다. 약 111ms 뒤 `ApplicationSharedMemory.nativeCreate()`가 `/dev/ashmem`을 찾지 못해 `RuntimeException: Failed to create ashmem: No such file or directory`로 fatal 종료됐다(stderr lines 1807–1826). 부모 Guest Zygote PID 24970은 system_server FD 쓰기 실패를 기록한 뒤 system server 종료로 따라 종료됐다(lines 1851–1854); runner 결과도 `guest_zygote_alive=false`다. Guest `/dev` 구성은 현재 null/zero/random/urandom만 노출한다([mount profile](../src/guest_mounts.rs#L123)); 따라서 다음 장애 지점은 Guest `/dev/ashmem` 제공이다. Framework 전체 기동까지는 도달하지 못했다.

[최종 실행 콘솔](../out/phase8b5-resume-20261106/permissive-framework7-console.txt), [runtime evidence](../out/phase8b5-resume-20261106/permissive-framework7-runtime.txt), [원인 발췌](../out/phase8b5-resume-20261106/permissive-framework7-cause.txt), [전체 Guest stderr](../out/phase8b5-resume-20261106/permissive-framework7-stderr.log). worker는 cleanup 후 exit 0이지만, 이는 Framework 성공을 뜻하지 않는다. runner는 전역 Permissive 복구를 하지 않으며 실험 종료 후 상태 조회도 하지 않았다.
