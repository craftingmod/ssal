# SSAL Phase 7A — Zygote Bring-up Readiness

2026-11-04, SM-S937N, Android 17 API 37 Host / Android 16 SDK 36 Guest.

## 판정

**Phase 7A: PARTIAL (실기기 초기 실행, socket 준비 실패).** WSLc의 기존 `ssal-dev`와 Android NDK r30으로 새 바이너리를 빌드·배포했다. Guest image mount, 54개 APEX 준비, private Binder, Guest property, SDK 36 classpath 생성은 통과했다. Guest `/system/bin/app_process64`는 PID 15920으로 실행됐지만 abstract socket 준비 전 `SIGABRT`했다. worker는 rootfs/cgroup/55개 loop 정리를 통과했고 core Host snapshot은 실행 전후 바이트 단위로 같았다. 같은 시간대 Host `lmkd`가 저수위 메모리 압박으로 캐시 앱 27개를 회수했다. 이는 시험과 시간상 강하게 연관되지만 정확한 메모리 소비 주체는 분리하지 못했다. Host 영향이 안전하다고 입증되지 않아 재실행하지 않는다.

| 항목 | 판정 | 근거 |
|---|---|---|
| Phase 6B `IInstalld` 생성·삭제 | **PASS** | 공통 launcher Phase 6B-Fix r3에서 같은 Private Binder session의 생성·삭제와 Guest backing 확인. [Phase 6B 판정](guest-services-phase6b-results.md) |
| `artd.dexopt` / OAT·VDEX | **BACKLOG** | 별도 backlog이며 Phase 7A와 Phase 6B installd PASS 판정의 gate가 아님. Phase 6B-Fix 반복은 중단 |
| Guest Zygote 의존성 및 Host 경계 분석 | **PASS** | Guest classpath/APEX/property/Binder/socket 경로를 정리하고 제한 worker에 검사 추가 |
| Linux worker 검사 | **PASS** | `cargo test --locked --bin ssald`: 37 passed, 0 failed, 3 ignored |
| Android-target type check | **PASS** | `ssald`와 Phase 2 `guest_probe`에 `cargo check --target aarch64-linux-android` 통과 |
| WSLc Android AArch64 빌드 및 stage hash | **PASS** | 기존 실행 중 `ssal-dev` 컨테이너, NDK r30 사용. `ssald` SHA-256 `35d0dad6a2763730a865bef6a0c70385b30cffcc3068410531e14b0f9db0fa5d`; helper도 stage 후 동일 hash 확인 |
| Guest mount/APEX/property/Binder/classpath preflight | **PASS** | 54 APEX, Guest SDK 36, ABI `arm64-v8a`, private Binder `507:5` (Host `507:1`), classpath 46/14 entries |
| Guest Zygote socket readiness | **FAIL** | `app_process64` PID 15920가 `SIGABRT`; `@ssal_guest_zygote_15655` 생성 전 종료 |
| Guest cleanup | **PASS** | private services 종료, cgroup/rootfs 정리, 55 loop backing 해제 확인 |
| Host core 보호 검증 | **PASS** | global Enforcing 및 core process/socket/property/mount snapshot이 실행 전후 동일; [before](zygote-phase7a-run-20261104/before.txt), [after](zygote-phase7a-run-20261104/after.txt) |
| Host app memory impact | **IMPACT / 재실행 중단** | 같은 5초 구간에 Host `lmkd`가 low/min watermark 이유로 cached app 27개를 회수. `system_server`, zygote, installd는 유지됐지만 부수 영향이 관측됨 |

## 실기기 preflight

- `adb.exe devices -l`에서 SM-S937N이 연결 상태였다. `adb shell`은 root `u:r:ksu:s0`; Host global SELinux는 `Enforcing`이었다.
- Guest system image `/data/local/ssal/images/1793366406758-25627/system.img`와 전용 userdata `/data/local/ssal/guests/phase5a-bringup-20261104/userdata`가 있었다.
- Host zygote는 PID 27927, `u:r:zygote:s0`, `/system/bin/app_process64`; Host `system_server`는 PID 28271, `u:r:system_server:s0`였다. Host `/dev/socket/zygote`는 존재했다.
- 실행 직전 worker snapshot에서 Host PID 1 mountinfo SHA-256은 `a5730bbd4b5f546eb60fc3c8b2c76c577f40bb2e84101081ac7addf7346277e1`, `getprop` 전체 출력 SHA-256은 `c7096d328f9343146490c18f5dd424f9394e40270246a34eed3aefc6eb1626ff`였다. 두 snapshot은 실행 후에도 byte-identical이었다. Device serial은 저장한 snapshot에서 지웠다.
- Host global SELinux는 `Enforcing`; boot ID는 `f7900911-c061-4570-8f65-900571a55c11`로 유지됐다. Host zygote PID/domain `27927/u:r:zygote:s0`, `system_server` `28271/u:r:system_server:s0`, installd PID `2607`, `/dev/socket/zygote` identity `18:2208`도 전후 snapshot에 같았다. `artd`는 계속 stopped였다.
- worker 종료 시 `HOST_ENFORCING_CORE_PROCESSES_ENDPOINTS=UNCHANGED`가 출력됐고, 이후 staging `/dev/ssal-common-launcher`를 제거했다. Host init/zygote/system_server/installd/artd를 중지·재시작하지 않았다. 다만 다음 절의 lmkd cache 회수는 core snapshot 바깥의 Host 부수 영향이다.

## 실제 수행 단계와 로그 범위

1. `adb.exe devices -l` 및 read-only preflight로 SM-S937N의 Enforcing, Host process/socket identity, Guest image/userdata 경로를 확인했다.
2. WSLc의 기존 `ssal-dev`가 `V:\workspace\Toy\ssal`을 `/src`로 사용하고 NDK r30을 `/opt/android-ndk`에 둔 것을 inspect로 확인했다. 컨테이너를 중지·재생성하지 않았다.
3. `wslc exec --workdir /src ssal-dev bash scripts/build-guest-launcher.sh`가 성공했다. `ssald`, `guest_probe`, `phase3-ipc`, `ssal-phase2-log.so`의 기기 stage hash가 WSLc 산출물 hash와 일치했다.
4. 이 파일들과 runner만 `/dev/ssal-common-launcher` tmpfs에 임시 stage한 뒤 `sh run-guest-launcher.sh --guest-zygote-7a-worker`를 1회 실행했다. Host init 및 기존 framework service를 제어하는 명령은 실행하지 않았다.
5. worker가 Zygote socket readiness 전에 종료됐고, cleanup과 Host core snapshot 검사는 통과했다. Host logcat에는 같은 시간대 `lmkd`의 low/min watermark cached app 회수 27건이 있었다. 시험과 시간상 연관된 위험으로 보고 추가 실행을 중단했다.
6. 실제 stderr는 [worker.log](zygote-phase7a-run-20261104/worker.log), Host 영향 요약은 [host-impact-summary.txt](zygote-phase7a-run-20261104/host-impact-summary.txt)에 보존했다. [pre/post snapshot](zygote-phase7a-run-20261104/before.txt)은 device serial을 redaction했다. `/dev/ssal-common-launcher` stage는 제거했다.

## Zygote 최소 조건과 준비한 경로

1. **실행 파일·ABI:** Guest `/system/bin/app_process64`를 절대경로로 실행한다. AOSP `app_main.cpp`는 Guest `ro.product.cpu.abilist64`를 읽어 ABI 목록을 넘긴다. Guest private property area에 SDK 36, codename `REL`, ABI `arm64-v8a`를 준비하고 실행 전 값을 검사한다. [AOSP Android 16 `app_main.cpp`](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r2/cmds/app_process/app_main.cpp)
2. **APEX·linker·classpath:** 기존 Guest mount/APEX/linkerconfig 준비를 재사용한다. Android runtime root, ART, i18n, tzdata 경로는 공통 launcher 환경에서 제공하고 `ANDROID_ASSETS`, `ANDROID_BOOTLOGO`, `EXTERNAL_STORAGE`도 추가한다. Guest `com.android.sdkext` APEX의 `derive_classpath`가 SDK 36/REL 기준 Guest `BOOTCLASSPATH`와 `DEX2OATBOOTCLASSPATH`를 만든다. classpath는 `/apex`, `/product`, `/system`, `/system_ext` 아래만 허용한다. Host 환경변수나 Host classpath는 상속하지 않는다. 이번 실행에서 Guest의 54 APEX를 준비했고 55 loop allocation을 종료 후 해제했다.
3. **Property·graphics:** Guest 전용 Bionic pre-split read-only property area만 사용한다. `ro.zygote.disable_gl_preload=1`을 넣어 초기 단계에서 graphics driver preload를 막는다. Guest `/dev/socket/property_service`는 만들지 않고 Host property area/socket도 bind하지 않는다. 따라서 property write는 Guest 안에서 실패할 수 있지만 Host init으로 전달될 endpoint는 없다. 전체 Guest property server와 지속 저장소는 후속 `system_server` bring-up 전까지 남은 항목이다. [AOSP Android 16 `ZygoteInit.java`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r3/core/java/com/android/internal/os/ZygoteInit.java), [AOSP Bionic property setter](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/bionic/system_property_set.cpp)
4. **Binder:** 기존 common launcher의 private binderfs와 Guest `servicemanager`를 사용한다. Phase 6B r3에서 확인한 Guest Binder는 `507:5`, Host `/dev/binder`는 `507:1`이었다. Guest 실행 child는 부모 FD를 닫고 chroot한 뒤 Guest domain으로 exec한다. Host Binder, hwbinder, vndbinder는 Guest root에 노출하지 않는다. Java framework의 전체 Binder 동작은 이 단계에서 검증하지 않는다.
5. **Zygote socket:** 직접 실행에는 Host init이 만든 `ANDROID_SOCKET_zygote` FD를 전달하지 않는다. `--socket-name=ssal_guest_zygote_<worker-pid>`를 쓰고 worker에서 `CLONE_NEWNET`으로 network namespace를 분리한다. Android의 기본 `LocalSocketAddress(String)`은 abstract namespace를 쓰며 Linux network namespace가 그 abstract socket namespace를 분리한다. 따라서 Host `/dev/socket/zygote`와 주소 공간을 공유하지 않는다. [Android `LocalSocketAddress`](https://developer.android.com/reference/android/net/LocalSocketAddress), [Linux `network_namespaces(7)`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
6. **system_server 및 Host init:** 실행 인자는 `-Xzygote /system/bin --zygote --socket-name=...`이며 `--start-system-server`는 넣지 않는다. Guest init rc를 읽거나 Host init에 `ctl.*`을 보내지 않는다. AOSP의 일반 `init.zygote64.rc`에는 zygote socket 생성과 on-restart power/media/network 동작이 있지만, 이 worker는 해당 rc를 Host init에 연결하지 않는다. 이 upstream rc는 Host One UI의 실제 vendor rc를 대체하는 근거가 아니다. [AOSP `init.zygote64.rc` template](https://android.googlesource.com/platform/system/core/+/b65b8835e509fc14407c8263da69abd3fb03e54f/rootdir/init.zygote64.rc)

실제 worker는 private ServiceManager와 Phase 5B AIDL smoke test를 통과했다. Guest Zygote는 custom network namespace에서 실행됐고 `start_system_server=false`였다. 실행 로그 핵심은 다음과 같다.

```text
Guest Zygote network namespace isolated: Host=net:[4026531840] Guest=net:[4026536773]
private Binder device: 507:5; host device=507:1
Guest classpath source=derive_classpath(Guest SDK 36, REL) boot_entries=46 dex2oat_entries=14
Guest Zygote launch socket=@ssal_guest_zygote_15655 start_system_server=false private_binder=507:5
Guest service=guest-zygote pid=15920 executable=/system/bin/app_process64
Guest owned service pid=15920 stopped=signal: 6 (SIGABRT)
libc: Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 15920 (app_process64), pid 15920 (app_process64)
Guest cgroup cleanup: passed
worker rootfs residual mount check: verified absent
session loop backing release: verified (55 allocations)
worker_exit=1
HOST_ENFORCING_CORE_PROCESSES_ENDPOINTS=UNCHANGED
```

Guest Zygote log에는 generic `Fatal signal 6` 외에 원인 stack이 없었다. crash buffer에 PID 15920 항목이 없고 실행 뒤 새 tombstone도 생기지 않았다. 실행 시간대 logcat/dmesg에서 Guest domain 관련 AVC denial도 발견되지 않았다. 따라서 **Zygote readiness는 FAIL**, 정확한 abort 원인은 미확정이다. `scripts/run-guest-launcher.sh`의 byte-identical core snapshot 검사는 통과했으나 lmkd cache 회수도 별도로 기록한다.

실행 로그의 non-blocking warnings는 다음과 같다. linkerconfig 생성 전 linker가 `/linkerconfig/ld.config.txt` 부재 경고를 냈지만 linkerconfig helper는 exit 0이었다. private `servicemanager`는 Guest property service 부재로 ready property 설정을 실패했으나 Phase 5B private AIDL smoke test는 통과했다. 이 두 warning은 Guest Zygote SIGABRT의 원인으로 입증되지 않았다.

## Host 보호 검증 범위

이번 worker의 before/after 파일은 global Enforcing, boot ID, PID 1 mountinfo, 전체 property hash, Host zygote socket/Binder identity, Host 주요 프로세스 PID/domain/root/namespace를 포함하며 바이트 단위로 같았다. init, zygote64, system_server, installd PID도 유지됐고 artd 상태는 stopped였다. 별도 logcat 검토에서 low/min watermark lmkd가 같은 실행 시간대 cached app 27개를 회수한 것은 확인됐다. 실행과의 인과를 완전히 분리할 수 없으므로 Host impact를 무시하거나 재실행하지 않는다.

## 남은 항목과 범위 경계

- **Zygote bring-up blocker:** Guest `app_process64`가 socket-ready 전에 SIGABRT했으나 stack/tombstone이 없어 직접 원인은 아직 미확정이다. Guest property service, `/data/property`, framework 전체 Private Binder routing, 앱 spawn 및 task-profile 수명주기도 후속 boot 단계 전에 필요하다. 이번 실행에서는 Guest AVC denial이 관측되지 않았다.
- **안전 재실행 blocker:** 실행 시간에 Host `lmkd` low/min watermark 회수가 27건 발생했다. 현재 Guest cgroup 경로는 메모리 상한을 설정하지 않는다. 이 영향이 안전하게 통제되기 전에는 같은 실기기 초기화를 반복하지 않는다. cgroup/SELinux/Binder 구조 변경은 이번 범위에서 하지 않았다.
- Guest `system_server`, UI, HAL/VINTF, 전체 Guest boot는 7A 범위 밖이다. 이들을 Phase 7A의 미완료 사유로 계산하지 않는다. `artd.dexopt` 또한 별도 backlog다.

## 참고

- [공통 launcher 및 6B PASS 결과](guest-services-phase6b-results.md)
- [system_server 정적 분석](system-server-static-analysis.md)
- [서비스 실행 계약](service-execution-contract.md)
