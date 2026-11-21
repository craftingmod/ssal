# Phase 7F-B — Controlled Zygote fork 결과

2026-11-05 KST. **PARTIAL: 실제 `forkAndSpecialize()` 요청과 새 자식 PID 생성은 확인했으나, SELinux specialization의 EINVAL로 Java entrypoint 실행 전에 자식이 SIGABRT했다.** 사용자 요청으로 추가 실기기 재시도를 중단하고 현재 상태를 남긴다. `PHASE7FB_FORK=PASS`는 출력되지 않았다. Guest system_server는 실행하지 않았다.

## 실측 범위와 최종 증거

기기 SM-S937N, boot ID `a9c9be4c-7c9c-4a84-bedf-e0547c9b3062`. Guest image는 기존 등록 이미지 `1793366406758-25627/system.img`이며, 읽기 전용 추출한 [build.prop](../out/phase7fb/source/build.prop:15)은 Android 16 / SDK 36 / SDK full 36.1 / REL, fingerprint `google/lineage_arm64_bvN4/generic_arm64:16/BP4A.251205.006/eng.andrew:userdebug/release-keys`다. 기존 LineageOS 23.2 이미지다.

| 실행 | Zygote PID / starttime | 반환된 child PID / starttime | 결과 |
|---|---|---|---|
| attempt15 | 7146 / 1650499 | 7175 / 1651255 | 실제 fork, setcontext EINVAL, SIGABRT |
| attempt16 | 13972 / 1662153 | 14002 / 1662887 | Guest `apps` cgroup 준비 후에도 setcontext EINVAL |
| attempt17 (최종) | 19978 / 1675922 | 20014 / 1676654 | 초기 Guest context 확인, context 질의 및 specialization EINVAL |

각 실행의 `out/phase7fb/attemptN/worker.log`, `worker/phase7fb/{client.txt,child-stat.txt,request.txt,zygote-fds.txt}`, `worker/phase7b/{stderr.log,stdout.log,metadata.jsonl}`에 증거가 있다. 자식은 응답 뒤 `pidfd_open`으로 고정하고 PID/starttime을 기록했다. PID만으로 자식에게 신호를 보내지 않았다.

최종 [worker.log](../out/phase7fb/attempt17/worker.log:248) 248·256·259행은 Zygote root/domain, 5초 상주 및 child pidfd/starttime을 기록한다. [stderr.log](../out/phase7fb/attempt17/worker/phase7b/stderr.log:374)의 logger 시각은 다음과 같다. Logger 시각을 KST로 간주하지 않는다.

- 374행, `11-04 19:20:18.959`: `Forked child process 20014`.
- 377행: child의 `getcon=0`, 초기 label `u:r:ssal_guest_probe:s0`.
- 378·380·381행, `19:20:18.965`: `selinux_android_setcontext(10000, 0, "ssal_probe", "ssal-fork-probe")`가 errno 22로 실패. 같은 자식에서 예상 context를 selinuxfs `context`에 질의한 write도 EINVAL이다.
- 436행: Zygote가 `Process 20014 exited due to signal 6 (Aborted)`를 기록했다. 성공적인 controlled exit 0은 아니다.

## 실제 프로토콜 및 소스 대조

실제 Guest `framework.jar` SHA-256은 `cc72f9cd2d55bf8b1f0afa50cb3c8a06baadac0bade9b7995cf41aa9dfb95590`, `libandroid_runtime.so`는 `d35220026ef94be6992d8b9b31cd446f937b8e782833813b2ac68140f41fc035`이다. 둘 다 기기 이미지에서 추출했다. `classes5.dex` disassembly에서 ZygoteConnection의 UID 1000 제한, `multipleOK` 분기, `forkAndSpecialize()` 호출을 확인했다. 참조 파일과 disassembly는 `out/phase7fb/source/`에 있다.

[LineageOS lineage-23.2 ZygoteConnection](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/java/com/android/internal/os/ZygoteConnection.java), 같은 tree의 `ZygoteArguments`, `Zygote`, `ZygoteInit`, `ZygoteServer`, `ZygoteCommandBuffer`, native Zygote·command-buffer·`fd_utils.cpp`와 [ART ZygoteHooks](https://github.com/LineageOS/android_art/blob/lineage-23.2/runtime/native/dalvik_system_ZygoteHooks.cc)를 필요한 부분만 대조했다. Java `ZygoteHooks` 및 `FileDescriptor`는 AOSP android16-release를 참조했다. **이 branch 전체가 실제 이미지의 정확한 빌드 commit이라는 증명은 없다.** 예를 들어 참조 native 소스와 실제 이미지의 processgroup 오류 처리는 동일하다고 단정할 수 없다.

요청은 ASCII 숫자 인자 수, LF로 구분한 인자, 마지막 LF다. 이번 최소 시험 요청은 정확히 다음 7개다.

```text
7
--runtime-args
--setuid=10000
--setgid=10000
--target-sdk-version=36
--nice-name=ssal-fork-probe
--seinfo=ssal_probe
dev.ssal.probe.ForkProbe
```

응답은 big-endian signed int32 PID와 1-byte `usingWrapper`다. PID > 1 및 wrapper=false를 검사한다. `--setgroups`는 생략했다. 부모 supplementary groups가 비어 있으므로 이를 상속하도록 하고, 성공 경로에서 자식 groups가 빈 값인지 검증하는 코드를 넣었다. 실제 최종 자식 groups 검증까지는 도달하지 못했다. `--instruction-set`, `--invoke-with`, capability, mount-external 및 앱 data-bind 인자는 사용하지 않았다. `--seinfo`는 SELinux context 문자열이 아니라 Guest seapp 매핑 선택자다.

별도 fork client는 UID/EUID/GID/EGID 1000, supplementary groups 제거, effective/permitted/inheritable/ambient capabilities 0, no_new_privs 상태에서 Guest socket 디렉터리를 사용한다. readiness와 별도 connection을 연다. Socket read/write timeout은 각각 10초, launcher의 client 대기는 15초다. Peer가 UID 1000일 때만 허용하는 실제 Guest 검사를 통과했다. 자식 UID/GID는 root 대신 10000을 지정했다.

USAP pool은 기본 disabled이고 enable 요청을 보내지 않았다. Guest ART에 `-XX:ForceJavaZygoteForkLoop=true`를 주어 `multipleOK=false`인 Java `forkAndSpecialize` 경로를 선택했다. 실제 로그의 `Resorting to Java fork code; multipleOK = false`와 자식 생성이 근거다. 각 fork 시험은 요청 1회, 자식 최대 1개다.

`ZygoteHooks.preFork()`의 daemon 정지와 ART pre-fork, native fork/specialization, post-fork hooks 및 `RuntimeInit` 경로를 조사했다. 이번 실행은 specialization에서 중단됐으므로 ART post-fork 완료와 entrypoint 호출은 실증되지 않았다. 자식 종료는 실제 Zygote SIGCHLD/waitpid 로그로 확인했다.

## 변경 파일 및 해결한 실행 장애

| 파일 | 변경 |
|---|---|
| `src/guest_launcher/fork_probe.rs` | 고정된 fork 요청, UID 1000 client, Guest seapp 매핑, pidfd/starttime, 성공 시 자식 snapshot·marker·exit 검사 |
| `src/guest_launcher.rs` | `SSAL_PHASE7FB_FORK`로 한정한 fork 실험, 기존 readiness·5초 상주·cleanup 재사용 |
| `src/guest_probe.rs` | 기존 pivot 경로에서 중첩 old-root mount 전부 detach하고 경로 제거 확인 |
| `src/guest_mounts.rs` | 자손 reap 이후 Guest 소유 cgroup 아래 빈 하위 디렉터리만 rmdir; 작은 회귀 테스트 |
| `src/ssald.rs` | 별도 `--zygote-fork-client` 진입점 |
| `native/fork-probe/dev/ssal/probe/ForkProbe.java` | 서비스 접근 없이 proc 진단, ready/completed marker, 최대 10초 대기 후 exit 0 |
| `native/binder-probe/zygote-fd-reopen.c` | Guest 전용 FD 재연결 및 stdio clone 처리, assert self-check |
| `native/binder-probe/zygote-diagnostics.c` | 실제 open/readlink 및 setcontext/getcon/context 질의 반환값 계측 |
| `scripts/build-rust/build-fork-probe.ps1`, `scripts/build-guest-launcher.sh` | javac/D8 및 Android native adapter 빌드 |

1. **FD 경로/allowlist:** 최초에는 `/dev/ssal-common-launcher/.../system/framework/telephony-common.jar`가 native allowlist에 거부됐다. Guest Zygote만 기존 `pivot_root` 경로로 옮겼다. Android root mount가 64층으로 겹쳐 있어 기존 단일 detach 후 rmdir가 EBUSY였고, private child namespace에서 mountinfo에 기록된 층을 모두 detach하도록 수정했다. `old_root_layers_detached=64 old_root_absent=true`를 기록한 뒤 실행한다.
2. **Preload 후 FD:** 직접 Guest 경로에서 연 FD는 정상이나 남아 있는 FD 일부는 `/framework/...`, `/javalib/...`, `/`로 관측됐다. Native adapter가 알려진 Guest JAR/resource/device와 **dev/inode, read-only 상태, device ID**를 비교한 뒤 같은 파일을 Guest 경로로 다시 연다. FD 번호·offset·descriptor flags를 유지한다. `readlink` 결과를 위조하거나 stock allowlist를 확장하지 않는다. 정확히 어느 upstream 코드가 해당 mount ancestry의 FD를 남기는지는 미해결이다.
3. **진단 pipe:** Libcore `FileDescriptor.cloneForFork()`가 복제한 stdout/stderr pipe FD 56/57은 stock 검사에서 FIFO로 거부됐다. 실제 standard pipe 1/2와 dev/inode가 일치하는 복제만 `/dev/null`로 바꾸고 native stdout/stderr pipe는 유지했다. 자식 RuntimeInit의 Java log stream 교체 완료는 아직 미검증이다.
4. **Probe classpath:** `/run/ssal/fork-probe.jar`는 stock FD allowlist에 없었다. 새 파일 주입 helper의 시도는 permission denied로 중단됐다. 최종 코드는 **사용하지 않는 Guest `/system/framework/am.jar` 슬롯에 probe JAR을 session bind**하고 CLASSPATH로 사용한다. 원본 이미지와 Host am.jar는 변경하지 않는다. 이는 이 최소 실험에 한정한 임시 배치이며 Framework 단계 전 전용 경로가 필요하다.
5. **Guest processgroup:** child가 요구한 `/sys/fs/cgroup/apps`가 없어 Guest subtree 안에 이를 준비했다. 이후 `+memory` activation 경고는 남는다. 최종 자식의 정상 cgroup specialization 완료는 미확인이다.

빌드 중 한 차례 잘못된 기존 `target/` 산출물을 복사해 daemon 진입이 `already running`으로 거부됐다(attempt3). 해당 실행은 fork 시험으로 세지 않는다. 이후 기존 `build-guest-launcher.sh`의 산출물 설치 경로를 사용했다. Stage가 남아 setup 검사만 실패한 호출도 성공 실행으로 세지 않았다.

## SELinux — 남은 차단 지점

부모와 초기 자식 context는 기존 `u:r:ssal_guest_probe:s0`다. Guest 내부 `plat_seapp_contexts`만 `user=_app seinfo=ssal_probe domain=ssal_guest_probe`로 session bind했다. 새 domain 생성, Host domain 권한 추가, global permissive 및 live 정책 로드는 이번에 수행하지 않았다. 기존 Phase 7D에서 설치된 Guest experimental permissive domain을 재사용했다. **Global Enforcing이 Guest domain 자체의 enforcing을 뜻하지 않는다.**

최종 자식은 `getcon`에 성공했지만, 같은 예상 context에 대한 raw selinuxfs 질의와 실제 `selinux_android_setcontext()`가 모두 EINVAL이다. 반면 [Host root query](../out/phase7fb/host-context-query.jsonl:2)는 그 label을 유효하다고 답했다. 이 차이의 원인은 아직 확인되지 않았다. 단순히 Guest type 부재나 AVC allow 부족으로 결론내리지 않는다. Export되지 않은 `security_check_context`를 dlsym하려던 attempt16 진단의 `-2`는 symbol 부재이며, 정책 판정이 아니다. attempt17은 기존 query helper와 같은 raw context write로 바꿨다.

Bulk 필터 로그 분석은 Luna에 위임했다. 확인한 필터 로그에는 최종 실패를 설명하는 AVC denial이 없고, 핵심 실패는 native setcontext EINVAL이다. 별도 전체 logcat/dmesg 수집·AVC 전수 분석은 하지 않았다.

## Cleanup, Host 보존 및 readiness 회귀

최종 attempt17의 [before](../out/phase7fb/attempt17/before.txt)와 [after](../out/phase7fb/attempt17/after.txt)는 byte-for-byte 일치한다. 비교에는 Enforcing, boot ID, Host mountinfo/property hash, `/data`·property area·property/zygote socket·Binder inode/DAC, init·zygote64·system_server·servicemanager·surfaceflinger·adbd·netd·lmkd·installd·artd의 PID/starttime·context·자격·root/exe/mount namespace가 포함된다. attempt1·2·4–17의 실제 worker 실행에서도 wrapper가 Host snapshot 일치를 기록했다.

수정 전 readiness 회귀는 UID 1000 `arm64-v8a`, Zygote 5초 상주, cgroup membership, Guest cleanup을 통과했다. 그 회귀의 전체 Host snapshot은 property hash만 달랐고 raw property 비교에서 `sys.siop.level`, `wlan.p2p.temp`가 -3에서 -2로 바뀌었다. 그 회귀를 전체 snapshot 일치로 보고하지 않는다. 이후 최종 fork 실행의 snapshot은 필터 없이 일치했다.

Guest Zygote는 기존 owned process-group SIGKILL/reap, 잔여 직접 자손은 기존 pidfd/subreaper 정리를 사용했다. Process-name `pkill`이나 Host 전체 process-group 신호를 쓰지 않았다. 최종 자식은 그 전에 Zygote가 SIGABRT 상태를 관측했다. 각 최종 실행에서 Guest cgroup 제거, rootfs 잔여 mount 부재, loop 55개 해제를 확인했다. 증거를 pull한 후 dedicated session tmpfs도 해제했다.

[final-postflight.log](../out/phase7fb/final-postflight.log)는 session stage, v1/v2 Guest cgroup 부재, memory subtree_control 원복, Enforcing 및 Host zygote64/system_server/adbd/netd 생존을 기록한다. [attempt17-cleanup.log](../out/phase7fb/attempt17-cleanup.log)는 별도 잔여 process/loop 검사와 tmpfs 제거의 `BUILD_VERSION_CLEANUP_PASS`를 기록한다. 재부팅은 수행하지 않았다.

## 빌드와 테스트

WSLc는 저장소 규칙대로 sandbox 밖에서 실행했다.

- `cargo test --locked`: **98 passed, 0 failed, 3 ignored**. ssald는 49 passed / 3 ignored. [최종 로그](../out/phase7fb/final-rust-tests.log).
- FD adapter의 `cc -Wall -Wextra -Werror -DSSAL_FD_TEST ...` assert self-check 통과: 다른 inode·writable FD 거부, read offset/FD_CLOEXEC 보존, stdio clone 분리 후 원래 pipe 유지.
- `python3 scripts/test-zygote-diagnostics.py`: SIGABRT/SIGSEGV marker 및 fatal semantics 회귀 통과. [최종 로그](../out/phase7fb/final-native-tests.log).
- `scripts/build-guest-launcher.sh`: Android AArch64 release 빌드 성공. 기존 memory-probe unused 경고 10개가 남는다. [최종 로그](../out/phase7fb/final-android-build.log).
- `scripts/build-rust/build-fork-probe.ps1`: javac `--release 8`, SDK D8 `--min-api 30`, `classes.dex` 포함 JAR 생성 성공. Java 8 target obsolete 경고가 있었다. JAR SHA-256 `6f2a34f4b5ac846fe78afeac0cf09e8aa2fd37481344cdc078f9a5c4f3c3ba77`.

Gate는 기존 `--guest-zygote-7a-worker`에 `SSAL_PHASE7FB_FORK=1`이다. 이 환경변수 없이 기존 readiness 경로를 유지한다. JAR 및 native adapter는 실행 바이너리 옆에 staging해야 한다. 실제 사용한 setup/run/extract 스크립트는 `out/phase7fb/`에 남겼다.

## 미완성 및 다음 작업

- **미완성:** SELinux specialization 해결, ART post-fork 완료, Java entrypoint 실제 실행, 정상 exit 0.
- **미검증:** 자식의 최종 UID/GID·supplementary groups/capabilities, 최종 SELinux domain, namespace/root/Binder 및 v1/v2 cgroup 검증. 초기 context, PID/starttime과 abort만 관측했다. 성공 경로의 검사 코드는 있으나 실행 증거가 없다.
- **수집 한계:** 성공 marker 전 조기 종료 시 자식의 status/attr/ns/cgroup 전체 snapshot은 저장되지 않는다. 현재 남은 것은 child stat, native/getcon 로그와 Zygote FD snapshot이다. 다음 재시험 전에 반환 직후의 자식 snapshot도 가능한 범위에서 먼저 저장해야 한다.
- **미검증:** 새 fork 경로에서 launcher interrupt/timeout lifecycle 회귀, 장시간 안정성, 재부팅 복구. 기존 SIGKILL/subreaper 안전망의 정상 실패 cleanup만 이번에 재확인했다.
- 다음 Phase로 넘기기 전에 Guest 내부와 Host root의 context query 차이를 UID, namespace 및 syscall 반환값으로 분리하고 최소 수정 후 자식 1개를 재시험한다. 실증 전 새 policy delta를 추측해 적용하지 않는다. 필요성이 입증되면 Guest domain에만 한정한다.
- 임시 `am.jar` classpath alias와 FD adapter는 최소 fork 검증용이다. 일반 앱/Framework 실행에 검증된 지원으로 취급하지 않는다.

**판정: PARTIAL. 새 Android runtime 자식이 실제 Zygote fork 경로에서 생성됨은 증명했지만, 그 자식이 Java main을 실행하고 정상 종료한다는 최종 목표는 아직 달성하지 못했다.**
