# Phase 8A — 분석 결과

- 조사일: 2026-11-05 KST
- 판정: **PARTIAL**
- 범위: 정적 분석 및 읽기 전용 GSI 확인
- Host 상태: 이번 Phase에서 device/Host init, daemon, property, Binder, SELinux policy, mount, userdata를 변경하지 않았다. system_server는 시작하지 않았다.

## 결과 요약

| 완료 기준 | 상태 | 근거 |
|---|---|---|
| 실제 GSI 식별 | **PASS** | 이미지 SHA-256·크기 및 Android 16/API 36 build properties를 `debugfs`로 읽어 기록했다. |
| 기존 Guest 실행경로 | **PASS** | Phase 7I Property Service, Private Binder/AIDL, Guest Zygote fork, Java `ForkProbe.main()`과 userdata read/write 결과를 교차 확인했다. |
| `SystemServer.main()` → Bootstrap 의존성 | **PARTIAL** | Android 16 AOSP reference branch와 실제 GSI의 binary/init 파일을 연결해 분석했다. GSI 정확한 source manifest/commit은 없어 완전한 source↔binary 동일성은 UNKNOWN이다. |
| Host resource 경계 | **PARTIAL** | Guest Binder/property/socket/data와 Host HAL 차단 경로는 확인됐으나 shared PID namespace에서 `/proc/<pid>/root/fd`, signal 및 Guest system_server capability는 실제 시험 전이다. |
| SELinux fallback 적용 범위 | **PASS (범위 판정)** | Phase 7F-C fallback은 probe 전용이다. system_server UID/domain fork에 적용되지 않으며 재사용·완화해서는 안 된다. Guest 전용 target type은 구현 항목이다. |
| 8B 실행·cleanup 계획 | **PASS** | [8B 계획](system-server-phase8b-plan.md)에 단계별 준비, timeout, 로그 및 cleanup을 정의했다. |

## 확인된 현재 상태

1. 실제 GSI는 `out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img`, 2,733,260,800 bytes, SHA-256 `7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff`다. 이미지 안 fingerprint는 `Android 16 / SDK 36 / BP4A.251205.006 / security patch 2026-05-01 / 2026-05-24 build`를 나타낸다. 공식 build number 문서는 `BP4A.251205.006`을 `android-16.0.0_r4`에 매핑하지만, GSI의 Lineage source revision을 특정하지 않는다.
2. GSI에는 `app_process64`, `services.jar`, `libandroid_servers.so`, `servicemanager`, `installd`, `keystore2`, Android 16 init/property/SELinux 파일과 runtime APEX가 있다. 파일 존재는 해당 서비스를 Guest에서 실행했거나 Host와 안전하게 호환된다는 증거가 아니다.
3. Phase 7I에서 Guest property area/service, Guest Private Binder/AIDL, Zygote fork, Java `ForkProbe.main()`, Guest `/data` write/read 및 session cleanup을 확인했다. 실행 당시 Host SELinux는 Enforcing, Host safety snapshot은 동일했다. system_server는 시작하지 않았다.
4. 현재 launcher는 Guest `app_process64` Zygote만 시작하며 `--start-system-server`가 없다. system-server classpath 파서는 Guest `BOOTCLASSPATH`/`DEX2OATBOOTCLASSPATH`만 반환한다. `SYSTEMSERVERCLASSPATH`는 GSI에서 계산해 별도로 넣어야 한다. 따라서 현재 소스 상태는 system_server Java 진입을 제공하지 않는다.
5. 서비스 계약은 `launch_enabled=false`이며 `switch`/`return`은 차단된다. 이 차단은 유지된다. Phase 7I PoC worker가 별도로 통과한 사실을 production 전환 경로로 오인하지 않는다.
6. SELinux fallback은 UID/GID 10000, `server=0`, `seinfo=ssal_probe`, `ssal-fork-probe`로 고정돼 있다. system_server의 UID 1000/server fork에 대한 `selinux_android_setcontext()` 결과는 없다. Guest system_server type과 transition을 따로 구현해야 한다.

## 선행 문서와의 차이

2026-11-04 [기존 정적 분석](system-server-static-analysis.md)은 Phase 7I 통합 전 스냅샷이다. 그 문서가 말한 Property Service와 Private Binder의 부재는 현재 상태 설명으로는 낡았다. 이번 Phase 8A는 최신 Phase 7I의 PoC 증거를 반영했지만, 이를 Java framework/system_server 전체 검증으로 확대하지 않았다.

## UNKNOWN과 후속 확인

- 실제 GSI와 일치하는 Lineage `.repo/manifest.xml`/source commit 및 `services.jar`의 정확한 framework source revision
- 해당 GSI binary가 실제 사용하는 supplementary groups, final capability bitset, per-process rlimits
- Java `SystemServer`의 Guest private Binder/servicemanager registration과 full property contexts
- Guest system_server SELinux context, `/proc` Host root/FD, ptrace/signal 접근 음성 결과
- Bootstrap 시점의 display, installd/artd, health/power/security HAL 첫 호출과 실패가 caught/fatal인지 여부
- system_server 전용 memory 상한을 적용한 실기기 수치 및 전체 descendant cleanup

이 항목들은 이번 Phase의 정적 경고 또는 구현 일감이다. 그 자체만으로 Host 영향이 발생했다고 보지는 않는다. 8B는 Host PID/FD/Binder/Property 제어가 가능한 직접 경계를 확인하기 전까지 bounded PoC 범위로만 실행한다.

## 산출물

- [의존성 분석](system-server-phase8a-dependencies.md)
- [Host 경계](system-server-phase8a-host-boundaries.md)
- [8B 실행 계획](system-server-phase8b-plan.md)

