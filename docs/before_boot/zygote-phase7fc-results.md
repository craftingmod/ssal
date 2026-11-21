# Phase 7F-C — Guest Zygote SELinux specialization 및 Java child 결과

2026-11-05 KST. **Java child 검증 PASS, SELinux app-domain specialization PARTIAL.** 실제 Guest Zygote child가 Java entrypoint를 실행했고 property/Binder/data 검사 후 exit 0으로 정상 종료했다. `selinux_android_setcontext()` 자체는 `EINVAL`을 반환해 PoC 전용 retained-Guest-domain fallback을 사용했다. Host SELinux Enforcing과 Host 서비스는 유지됐다. Guest `system_server`는 실행하지 않았다.

## 실행 경로와 `seapp_contexts`

기존 Phase 7F Zygote 경로와 일반 `forkAndSpecialize()` 요청을 사용했다. Guest root의 `/system/etc/selinux/plat_seapp_contexts`에 아래 실험 항목을 bind했다.

```text
user=_app seinfo=ssal_probe domain=ssal_guest_probe
```

요청은 UID/GID 10000, `server=0`, `seinfo=ssal_probe`, nice name `ssal-fork-probe`, Java entrypoint `dev.ssal.probe.ForkProbe`였다. Bionic libselinux는 `selinux_android_setcontext()`에서 `seapp_context_lookup()` 결과를 만든 뒤 `security_check_context()`를 확인하고, 원래 context와 다를 때 `setcon()`을 호출한다. [AOSP libselinux 구현](https://android.googlesource.com/platform/external/selinux/+/refs/heads/master/libselinux/src/android/android_device.c), [AOSP seapp 경로 및 조회 구현](https://android.googlesource.com/platform/external/selinux/+/refs/heads/master/libselinux/src/android/android_seapp.c).

Guest Zygote가 사용한 plat seapp 파일과 요청은 실행 증거 `/dev/ssal-phase7i/run-1793879654/worker/phase7fc/`에 남았다. 이 규칙은 `ssal_guest_probe` domain을 요청하지만 실제 app-specific domain 전환을 만들지는 않는다. 실행 로그에서 내부 lookup이 반환한 전체 context 문자열이나 실패한 내부 함수는 별도로 노출되지 않았다.

## SELinux 관찰과 fallback

최종 run의 핵심 로그:

```text
SSAL_GUEST_CONTEXT_PRECHECK pid=31806 uid=0 gid=0 context=u:r:ssal_guest_probe:s0 fd=3 result=23 errno=0
SSAL_ORIGINAL_CONTEXT pid=31836 getcon=0 label=u:r:ssal_guest_probe:s0
SSAL_SETCONTEXT pid=31836 uid=10000 server=0 process_uid=10000 process_gid=10000 seinfo=ssal_probe name=ssal-fork-probe expected_context_check=23 check_errno=0 result=-1 errno=22
SSAL_SETCONTEXT_BYPASS pid=31836 uid=10000 mode=retained_guest_domain context=u:r:ssal_guest_probe:s0
```

Zygote의 UID 0 상태에서 SELinuxFS `context` endpoint가 retained Guest SID를 받아들였고, specialization 시에는 실제 child UID/GID가 이미 10000이었다. 이 시점의 `selinux_android_setcontext()` 호출은 `-1/EINVAL`을 반환했으며 `getcon()`은 계속 `u:r:ssal_guest_probe:s0`였다. 현재 증거로는 `seapp_context_lookup`, `security_check_context`, `setcon` 중 어느 내부 호출이 최초 실패했는지 구분할 수 없다. `seapp_contexts` line과 SELinuxFS query는 확인했지만 앱 대상의 최종 context 문자열을 libselinux 내부에서 직접 덤프하지는 않았다.

우회는 다음 조건을 모두 만족한 Guest child에서만 적용된다: 원래 결과 `EINVAL`, Zygote 시작 때 검증한 retained Guest context, 원래 SID `u:r:ssal_guest_probe:s0`, UID 10000, `server=0`, `seinfo=ssal_probe`, 이름 `ssal-fork-probe`, `SSAL_PHASE7FC_BYPASS_SETCONTEXT=1`. 반환 성공은 새 context를 가장하지 않고 기존 Guest SID를 유지한다. 따라서 이 PASS는 app-specific domain 전환이나 production SELinux 정책 PASS가 아니다.

`out/phase7i/guest-only.rule`의 제한된 정책 delta는 KSU 진단 경로로 동적 적용했다. `ssal_guest_probe`와 `ssal_property`만 Guest 실험용 permissive domain이고 Host domain에는 새 allow를 주지 않았다. Host global SELinux는 **Enforcing**이었다. 이 KSU SID/Guest permissive 경로는 PoC에 한정하며, 미검증 인가는 위와 같이 문서화했다.

## Java child와 실행 결과

첫 Java 시도에서는 JAR이 `/system/framework/am.jar`에 bind되어도 일반 `CLASSPATH`만으로는 Zygote child classloader가 클래스를 찾지 못했다. controlled fork에서만 이 파일을 Guest `BOOTCLASSPATH`에 추가했다. probe가 실행하는 하위 Bionic `getprop` 및 AIDL client에서는 진단용 `LD_PRELOAD`를 제거해 진단 출력이 결과 문자열에 섞이지 않게 했다.

최종 child는 아래 검사를 통과했다.

- UID/GID 10000, supplementary groups 없음, capabilities 0, retained Guest SID
- Guest root, Guest mount/net namespace, Guest cgroup
- Guest Property Area에서 SDK 36과 `persist.ssal_probe=7` 읽기
- Guest Private Binder AIDL 왕복 호출
- 8 GiB ext4 Guest userdata marker 읽기와 child 파일 쓰기
- ready/completed marker, exit 0 및 Zygote PIDFD reap

최종 로그에는 `Guest Java child property=PASS private_binder=PASS userdata_read_write=PASS`, `Guest fork entrypoint=executed ...`, `PHASE7FB_FORK=PASS child_pid=31836 ... exit=0`가 기록됐다.

| 검증 항목 | 상태 | 결과 |
|---|---|---|
| Property Service ready 및 Bionic property | **PASS** | Phase 7I integration report 참조 |
| Persistent property 재실행 복구 | **PASS** | Guest userdata의 값 7 복구, volatile 키 없음 |
| Private Binder 회귀 | **PASS** | Java child AIDL 왕복 성공 |
| Zygote fork | **PASS** | child 31836 생성·검증·정상 reap |
| SELinux specialization | **PARTIAL** | 원래 setcontext `EINVAL`; 제한된 retained Guest SID fallback 통과 |
| Java child entrypoint | **PASS** | `ForkProbe.main()` 실행 및 세 검증 모두 통과 |
| Host 주요 서비스 및 격리 | **PASS** | Host safety snapshot 동일, Host Enforcing 유지 |
| Guest 종료·mount/loop/socket/cgroup 정리 | **PASS** | cgroup 제거, rootfs 잔여 mount 없음, 56 loop allocation 해제, cleanup OK |

실행은 `/dev/ssal-phase7i/run-1793879654`에서 이뤄졌다. `system_server`를 시작하거나 Host `init`, `adbd`, `netd`, Host Zygote, Host `system_server`, Host Binder/Property 또는 Host `/data`를 대상으로 제어 명령을 보내지 않았다. Host boot ID도 변경되지 않았다.

## 재현 및 빌드 산출물

승인된 실기기 경로는 staged `ssald`로 `/dev/ssal-phase7i/run.sh`를 실행한다. test flags는 Guest Property Service, persistent restore, controlled fork, gated context fallback만 켰다. 실행 전후 Host snapshot 비교는 `HOST_SAFETY_SNAPSHOT=UNCHANGED`였다.

- `scripts/build-guest-launcher.sh`: Android arm64 build **PASS**.
- `cargo test --locked --bin ssald`: **50 passed, 0 failed, 4 ignored**.
- `scripts/test-zygote-diagnostics.py`: fallback gate 및 fatal diagnostics self-check **PASS**.
- `scripts/build-rust/build-fork-probe.ps1`: Java 8 + D8 **PASS**, JAR SHA-256 `02718a2f1b2724a4c0c211435e11d33a084dcfe07abae73606163246a977877a`.
- `bun scripts/package-module.ts`: module ZIP **PASS**, SHA-256 `c70d588638ede4352d0fda64d62ba89ebe11c823f1ce665f5d62e2be21072592`.

**판정:** Phase 7I의 PoC 완료 기준(Java child entrypoint, Property/Binder/data 통합 및 Host 경계 유지)은 충족했다. Guest app-specific SELinux domain 전환과 Guest 전용 production authorization은 보류한다. `system_server`는 이 Phase에서 실행하지 않았다.
