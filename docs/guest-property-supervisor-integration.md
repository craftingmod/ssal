# Phase 7I — Property Service와 Guest Supervisor 통합

2026-11-05 KST. **Phase 완료 기준 PASS (PoC 범위).** 기존 Guest Supervisor 경로에서 Property Service, Private Binder/AIDL, Zygote fork, Java child 실행과 정리를 실기기에서 확인했다. Guest child는 PoC용 permissive `ssal_guest_probe` SID에 남으므로 production SELinux specialization은 완료되지 않았다. Host SELinux는 Enforcing이었고 Host 안전 스냅샷은 실행 전후 동일했다. Guest `system_server`는 시작하지 않았다.

## 재사용한 실행 경로

기존 `--guest-zygote-7a-worker`를 사용했다. 별도 Supervisor나 부팅 프레임워크는 추가하지 않았다. Property Service 계약은 [Guest Property Service 문서](guest-property-service.md)를 따른다.

1. `prepare::worker`가 기존 8 GiB ext4 Guest userdata와 read-only system image를 기존 private mount namespace에서 준비한다. Guest mount propagation은 private로 만든다.
2. 기존 Guest root 및 `/dev` 구성을 사용한다. Guest `/dev/__properties__`, `/dev/socket`, Guest `/data/property`는 Host 대응 객체와 다른 identity를 갖는다.
3. `SSAL_PHASE7I_PROPERTIES=1`일 때만 Guest `guest_build.prop`, `property_contexts`, service config를 준비하고 `ssal-property-service`를 `u:r:ssal_property:s0`로 새로 exec한다. Host property area·socket·persistent directory로 요청을 전달하지 않는다.
4. `guest_property_service_ready` JSON, service SID, Guest/Host 경로 identity를 확인한 다음 새 Bionic client를 실행한다. 다른 phase의 임시 property 초기화 경로는 그대로 유지된다.
5. 기존 Private Binder, Guest ServiceManager/AIDL server와 linkerconfig 순서를 재사용하고 마지막에 기존 Phase 7F Zygote를 실행한다. 시험 JAR은 이번 controlled fork에서만 Guest `BOOTCLASSPATH`에 더한다.

## 실기기 결과

최종 성공 실행은 `/dev/ssal-phase7i/run-1793879654`였다. 같은 8 GiB Guest userdata에 앞서 쓴 persistent 값을 재실행에서 복구했다.

| 검증 항목 | 상태 | 기기 결과 |
|---|---|---|
| Property Service ready | **PASS** | `u:r:ssal_property:s0`; Guest property area `[158,12]`, Host area `[18,118]`; Guest `/data` device `1050416`, Host `/data` device `65105` |
| Bionic `getprop`/`setprop` | **PASS** | 첫 통합 실행에서 SDK/ABI 읽기, volatile 및 persistent set/get 후 `SSAL_PROPERTY_BIONIC=PASS` |
| Persistent property 재실행 복구 | **PASS** | 후속 실행에서 `persist.ssal_probe=7` 복구, volatile `sys.ssal_probe` 부재; `SSAL_PROPERTY_RESTORE=PASS` |
| Private Binder 회귀 | **PASS** | `PHASE5B=PASS`, Java child의 AIDL 왕복과 `private_binder=PASS` |
| Guest Zygote fork | **PASS** | Child PID `31836`, Zygote가 PIDFD로 exit 0 확인 및 reap |
| SELinux specialization | **PARTIAL (PoC 우회 적용)** | 원래 `selinux_android_setcontext()`는 `EINVAL`; 정확히 제한된 Guest fallback 후 child가 Guest probe SID를 유지 |
| Java child entrypoint | **PASS** | `ForkProbe.main()` 실행; Guest property, Private Binder, Guest userdata 검사 모두 통과 |
| Child UID/GID/capabilities | **PASS** | UID/GID 10000, supplementary groups 없음, capabilities 0; Guest root/mount/net namespace/cgroup 확인 |
| Host 서비스 및 격리 | **PASS** | Host Enforcing 유지, init/adbd/netd/zygote/system_server 등 전체 안전 스냅샷 동일, Host control socket Guest에서 보이지 않음 |
| Guest 종료·정리 | **PASS** | Guest userdata 임시 marker 제거, cgroup 정리, rootfs 잔여 mount 없음, 56 loop allocation 해제, socket 제거 |

실행 시 `HOST_SAFETY_SNAPSHOT=UNCHANGED`, `worker_exit=0`, `mount cleanup and session loop backing release checks: OK`가 기록됐다. 기기 boot ID는 `03834516-215d-4fd6-8960-1b833882595e`로 유지됐다. Host `/data`에는 staging하지 않았으며 시험 파일은 `/dev/ssal-phase7i`에만 두었다. 최종 실행에서 Guest property child 증거는 `sdk=36`, `persist.ssal_probe=7`, `property=PASS private_binder=PASS userdata_read_write=PASS`다.

## SELinux 범위와 남은 제한

`out/phase7i/guest-only.rule`의 최소 Guest rule만 KSU 진단 경로로 동적 적용했다. `ssal_guest_probe`와 `ssal_property` 두 Guest domain만 permissive였고 Host global Enforcing 및 기존 Host domain policy는 변경하지 않았다. 이 정책은 Guest 전용 production policy가 아니며 property/file 인가를 완성하지 않는다.

Zygote 시작 시 UID 0의 `u:r:ssal_guest_probe:s0` context query가 23 bytes write와 errno 0으로 통과했다. Child 요청은 UID/GID 10000, `server=0`, `seinfo=ssal_probe`, 이름 `ssal-fork-probe`였고 실제 process UID/GID도 10000이었다. 실제 `selinux_android_setcontext()`는 `-1/EINVAL`을 반환하고 기존 Guest SID를 유지했다. 제한된 fallback은 Zygote에서 검증한 동일 Guest SID를 그대로 사용하며, Guest fork flag·현재 SID·UID·server·seinfo·이름이 모두 맞을 때만 child에 적용된다. 내부 libselinux의 정확한 실패 지점(seapp lookup, `security_check_context`, `setcon`)은 이 빌드의 로그만으로 분리되지 않았다.

초기 Java 실행은 probe JAR이 `CLASSPATH`만으로는 Zygote child classloader에 잡히지 않아 `ClassNotFoundException`을 냈다. controlled fork에만 JAR을 Guest `BOOTCLASSPATH`에 더해 해결했다. Java probe 하위 `getprop`/AIDL 명령은 진단 `LD_PRELOAD`를 제거해 로그가 client stdout에 섞이지 않게 한다.

## 빌드와 패키징

- `scripts/build-guest-launcher.sh`: Android arm64 release build **PASS**.
- `cargo test --locked --bin ssald`: **50 passed, 0 failed, 4 ignored**.
- `scripts/test-zygote-diagnostics.py`: Guest 전용 EINVAL fallback gate 및 fatal diagnostics self-check **PASS**.
- `scripts/build-fork-probe.ps1`: Java 8 + D8 JAR **PASS**, SHA-256 `02718a2f1b2724a4c0c211435e11d33a084dcfe07abae73606163246a977877a`.
- `bun scripts/package-module.ts`: module ZIP **PASS**, SHA-256 `c70d588638ede4352d0fda64d62ba89ebe11c823f1ce665f5d62e2be21072592`.

모듈 ZIP은 로컬 산출물이다. 실기기 실행에는 동일 launcher/probe 산출물을 `/dev/ssal-phase7i`에 임시 staging했으며 모듈을 설치하거나 Host `/data`를 수정하지 않았다. `system_server`는 이번에도 시작하지 않았다.
