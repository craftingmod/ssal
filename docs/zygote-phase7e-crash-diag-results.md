# Phase 7E-Crash-Diag — Guest Zygote SIGSEGV

2026-11-05 KST. **판정: PASS (기존 SIGSEGV 진단·수정 범위).** 정확한 PC, 레지스터, native stack과 충돌 명령어를 확보했다. Launcher의 Guest Zygote `LD_LIBRARY_PATH`에서 ART 디렉터리 하나를 제거한 뒤 같은 실행 경로에서 기존 SIGSEGV가 사라지고 class preload까지 진행했다. **Zygote 부팅은 아직 미완료:** 별개의 `Build.VERSION` Java 초기화 예외로 socket readiness 전에 종료한다.

날짜는 클라이언트 KST 기준이다. Guest logger의 `11-04 17:38`/`17:41`, device shell 시각과 metadata epoch가 같은 시간대라고 가정하지 않는다.

## 기존 증거 조사

- 우선 [Phase 7E-Retry 보고서](zygote-phase7e-retry-results.md)와 run5 stderr를 조사했다. PID 21160, 기기 로그 `11-04 17:25:00.917`, SIGSEGV/SEGV_MAPERR, fault address `0x278`은 확인되지만 PC/register/stack은 없었다. Luna에 로컬 필터 로그 분석을 위임했다. metadata의 `host_debuggerd_tombstoned=unchanged; not connected`는 연결 상태 기록이며 debuggerd 실패 원인의 증명은 아니다.
- 새 재현 전에 Host crash buffer와 debuggerd 관련 현재 logcat을 읽었다. crash buffer는 비어 있었고 보존된 logcat에는 해당 crash dump가 없었다. Host tombstone 00~31의 header를 읽어 PID·시각·실행 파일을 비교했으며 대상은 없었다. Guest userdata 아래 tombstone 경로도 발견되지 않았다. 전체 Host tombstone 본문을 가져오거나 수정·삭제하지 않았다. 현재 PID 21160에 attach하거나 신호를 보내지 않았다.
- 증거: [tombstone header index](../out/phase7e-crash-diag/tombstone-index.txt), [debugger 관련 필터](../out/phase7e-crash-diag/host-debugger-filter.log), [기존 run5 필터](../out/phase7e-crash-diag/existing-filter.log). 현재 버퍼에 없다는 사실이 과거 dump 생성 자체가 없었다는 뜻은 아니다.

## Guest 전용 수집

기존 Guest Zygote 전용 preload `native/binder-probe/zygote-diagnostics.c`에 SIGSEGV `SA_SIGINFO | SA_ONSTACK` handler를 추가했다. Host debuggerd/tombstoned 설정은 바꾸지 않았다. ptrace는 필요하지 않았다.

- kernel signal context에서 PID/TID, signal/si_code/si_addr, AArch64 x0~x30, PC/LR/SP/FP를 기록한다.
- `/proc/self/mem`의 `pread`로 PC 주변 96 bytes, SP부터 최대 1 KiB, 최대 32개 FP record를 읽는다. 실패하면 errno를 기록한다. FP는 SP 이상 8 MiB 이내, 정렬·증가 조건을 검사하며 raw LR도 보존한다. PAC 제거 후 PC는 offline 분석용이며 CFI unwind를 대체하지 않는다.
- `/proc/self/maps`를 최대 128 KiB 기록한다. launcher의 기존 stderr pipe/1 MiB cap/timeout/cleanup을 사용한다. signal handler에서 allocator, dladdr 및 unwind 라이브러리를 호출하지 않는다. 기존 abort capture는 유지한다.
- 이전 SIGSEGV handler를 호출한 뒤 기본 fatal 처리를 복원한다. stop/attach/wait를 사용하지 않으며 기존 subreaper/pidfd/reap 경로를 바꾸지 않는다. launcher 부모 소멸 시 기존 PDEATHSIG가 적용된다. 실기기에서는 ART sigchain이 collector를 호출했고 최종 wait status도 SIGSEGV였다.
- handler의 SIG_DFL 복원에 ART sigchain이 native/Java stack을 추가 출력했다. 이 stack은 collector가 끼어 있는 unwind이며 원래 fault PC는 반드시 ucontext 값을 쓴다. sigchain이 보인 `0x55a8`은 return-PC 보정값으로, 실제 fault instruction은 `0x55ac`다.
- 수집기의 maps 상한 초과·FP 생략 프레임·다른 라이브러리의 handler 재설치·stderr 손실 가능성은 남는다. 이번 실행은 `SSAL_CRASH_END`와 필요한 전체 maps를 확보했다. 일반 Android crash service 구현으로 간주하지 않는다.

## 첫 재현: 충돌 위치 확정

Guest PID/TID **24705**, 기기 로그 `11-04 17:38:16` 부근. SIGSEGV=11, si_code=1, si_addr=`0x278`.

| 항목 | 값 |
|---|---|
| PC | `0x0000007ca094c5ac` |
| LR | `0x0000007ca094c590` |
| SP | `0x0000007fcaa3a880` |
| FP | `0x0000007fcaa3a8c0` |
| x8 | `0x0` |
| mapping | `7ca094b000-7ca094e000 r-xp 00004000 07:158 105 /apex/com.android.art/lib64/libopenjdkjvm.so` |
| ELF relative PC | `PC - 0x7ca094b000 + 0x4000 = 0x55ac` |
| 함수 | `JVM_NativeLoad + 0x70` (함수 시작 `0x553c`) |
| 명령어 | `f9413d18: ldr x24, [x8, #0x278]` |

따라서 **NULL + 0x278 접근**이 명령어와 레지스터로 확인됐다. `memfd.cc:68` 로그를 원인으로 사용하지 않았다.

직전 명령어는 `adrp x8, 0x8000; ldr x8, [x8,#0x240]; ldr x8,[x8]`이다. ELF relocation `0x8240`은 `_ZN3art7Runtime9instance_E` (`art::Runtime::instance_`)다. 이 singleton의 값이 NULL인 상태에서 JavaVM 필드를 읽다가 충돌했다. [AOSP JVM_NativeLoad](https://android.googlesource.com/platform/art/+/refs/heads/main/openjdkjvm/OpenjdkJvm.cc)의 `Runtime::Current()->GetJavaVM()` 경로와 부합한다. 사용한 함수/offset 판정은 이 소스의 버전 동일성을 가정하지 않고 실제 ELF·disassembly에 근거한다.

native/Java 호출 경로는 다음과 같다. 전체 수집 stack은 별도 파일에 있다.

```text
JVM_NativeLoad + 0x70                    libopenjdkjvm.so (fault)
art_quick_generic_jni_trampoline        libart.so
java.lang.Runtime.loadLibrary0
java.lang.System.loadLibrary
android.util.StatsLog.loadNativeLibrary
android.util.StatsLog.<clinit>
com.android.internal.util.FrameworkStatsLog.write
com.android.internal.os.ZygoteInit.main
android::AndroidRuntime::start
app_process64 main
```

## ELF 식별 및 원인

동일 Guest system image를 별도 private mount namespace에서 RO로 열어 `com.android.art.capex`의 `original_apex`와 payload를 추출했다. payload mount는 I/O error로 실패하여 재실행 없이 payload를 로컬에 복사하고 `debugfs`로 ELF를 읽었다. Host 동명 ELF는 사용하지 않았다. LLVM readelf/objdump/addr2line과 `.gnu_debugdata`를 사용했다. line debug 정보는 없지만 함수 심볼은 확보했다.

| Guest ELF | Build ID | SHA-256 |
|---|---|---|
| libopenjdkjvm.so | `eff8107d634b0e1544c0a93deaa52fa9` | `0b9c2014255e472b7a3642909857db8bd7ace3b0aefdc33ea2e05bd69478597b` |
| libart.so | `448a8ce89fb4fdbeea9d1dc3756d6f96` | `bdbb62005b32fd575e92d58afac9ac85e8551ff26e643474bcae02bd9061a465` |

sigchain의 Build ID가 추출 ELF와 일치한다. 수집한 PC 주변 **96 bytes 전체가 ELF와 일치**하며 해당 LOAD의 file offset과 virtual address 모두 `0x4000`이다.

충돌 당시 동일 inode의 Guest libart.so가 서로 다른 base에 두 벌 있었다.

```text
7c9ee00000-7c9f5e3000 r-xp 00200000 07:158 85 .../libart.so
7caf000000-7caf7e3000 r-xp 00200000 07:158 85 .../libart.so
```

원인 분류는 **Launcher 실행 환경의 라이브러리 검색 경로에 의한 Guest ART 중복 로드/namespace 혼용**이다. 강제 `LD_LIBRARY_PATH`의 `/apex/com.android.art/lib64`가 default namespace에서 ART를 직접 찾도록 만든 반면 생성된 `com_android_art` namespace도 ART를 소유한다. 실행 중 ART와 JNI가 참조한 singleton이 분리된 것으로 해석된다. 두 singleton의 주소/값을 각각 직접 읽은 것은 아니지만, NULL 역참조·두 벌 매핑·단일 경로 제거 후 한 벌 매핑과 crash 해소가 이 결론을 뒷받침한다. Host/Guest ELF 혼용의 증거는 없다.

## 최소 수정과 두 번째 실행

`src/guest_launcher.rs`의 **Zygote 전용** library path에서 `/apex/com.android.art/lib64` 한 항목만 제거했다. artd 경로·ART binary·boot image·SELinux·Binder·cgroup 구조는 바꾸지 않았다. 진단용으로 생성된 `ld.config.txt`도 phase7b에 보존한다.

두 번째 Zygote PID **25638**. 마지막 maps snapshot의 libart executable mapping은 **1개**다. `libstats_jni.so` 로드 성공(`stderr.log:131`), `begin preload`(`:132`), class preload(`:140`)를 확인했고 SIGSEGV/collector marker는 없었다. worker는 socket readiness 이전 종료를 실패로 처리하며 성공으로 오판하지 않았다.

**새 장애:** `Build.VERSION.<clinit>(Build.java:522)`에서 `ArrayIndexOutOfBoundsException: length=0; index=0` (`stderr.log:141` 이후), 이어 `SystemServiceRegistry` class preload가 실패했다. Java fatal exception 후 AndroidRuntime이 VM을 종료했으며 native exit code는 0이다. 이것은 기존 SIGSEGV와 다른 실패다. 이번 crash 진단 범위에서 새 property/Framework 수정을 추가하지 않았다.

총 Zygote 재현은 **2회**다. 그 전에 setup script의 마지막 CR 때문에 worker 인자가 잘못 전달된 실행은 daemon lock에서 거부됐다(`run1-console.log`); Guest를 생성하지 않았으며 기존 daemon을 중지하거나 lock을 우회하지 않았다.

## 검증과 Host 상태

- Rust `ssald`: **46 passed, 3 privileged ignored**. 최종 `cargo fmt --check`, Android AArch64 release build PASS. 기존 `ssal-memory-probe` dead-code warnings는 남아 있다.
- native 자가검증: abort marker/backtrace/SIGABRT 유지 및 SIGSEGV context/maps/stack/FP cap/fatal signal 유지 PASS. PC mapping·96-byte code/ELF 비교·NULL+offset·ART mapping 수 2→1·preload 진입의 assert 검증 PASS (`analyze.py`).
- 첫 crash 실행: Host Enforcing/boot ID/PID 1 mountinfo/core PID-starttime/endpoint identity는 일치했다. 전체 property 해시만 변경됐다. 이 실행의 property 원문은 보존하지 않아 변경 key·원인 귀속은 미확정이다. Host 전체 불변 PASS로 보고하지 않는다.
- 수정 후 실행: 기존 Host snapshot 전후 **완전 일치**, 별도 raw `getprop` 전후도 일치했다. 두 실행 모두 `start_system_server=false`, 공유 PID/procfs, private Binder(Guest `507:5`), Guest userdata, Guest domain 기존 프로파일을 사용했다.
- 수정된 launcher의 기존 helper **SIGTERM 및 timeout** 회귀 모두 `LIFECYCLE_PASS`. pidfd 자손 reap, rootfs residual mount 부재, 매 실행 **55 loop allocations 해제**, memory controller 원복과 Host snapshot 일치를 확인했다. Zygote 자신의 SIGTERM/timeout 시험은 아니며 이번 Zygote는 각각 SIGSEGV와 Java 실패로 종료했다.
- Host init 서비스 조작·Host 핵심 프로세스 attach/kill·Host global permissive·추가 live policy·hard reboot는 수행하지 않았다. 최종 cleanup은 별도 로그에 남긴다. 장시간 Host 영향과 hard reboot 후 복구는 시험하지 않았다.
- 최종 audit에서 ELF 추출용 mount 실패가 남긴 loop39를 발견했다. backing file이 이번 `/data/local/tmp/ssal-crash-diag/art.img`임을 확인하고 holders와 살아 있는 프로세스의 mountinfo에 사용이 없는지 검사한 뒤 해제했다. 최종 Guest cgroup/v1 그룹 부재·controller 원복·세션 프로세스/loop 부재 검사 후 전용 tmpfs를 unmount/rmdir했다. `EXTRACTION_LOOP_RELEASED`, `CRASH_DIAG_CLEANUP_PASS`를 확보했다. 영구 userdata와 증거 디렉터리는 보존했다.
- 검증한 수정 binary SHA는 `cleanup-final.log`에 기록했다. 이후 최종 rebuild는 `native_capture` 설명 문자열만 갱신했으며 최종 SHA는 `analysis.json`에 있다. 그 최종 문자열 변경 뒤 기기 Zygote를 추가 실행하지 않았다.

## 산출물

- [PC/LR/SP·전체 레지스터](../out/phase7e-crash-diag/registers.txt), [충돌 시 maps](../out/phase7e-crash-diag/crash-maps.txt), [native/Java backtrace](../out/phase7e-crash-diag/native-backtrace.txt), [code/stack/FP raw](../out/phase7e-crash-diag/code-stack-fp.txt)
- [ELF headers·Build ID](../out/phase7e-crash-diag/elf-info.txt), [disassembly](../out/phase7e-crash-diag/disassembly.txt), [relocations](../out/phase7e-crash-diag/jvm-relocations.txt), [자동 대조 결과·SHA](../out/phase7e-crash-diag/analysis.json)
- [첫 재현](../out/phase7e-crash-diag/device-run1/worker/phase7b/stderr.log), [수정 후](../out/phase7e-crash-diag/device-fixed/worker/phase7b/stderr.log), [Guest linker config](../out/phase7e-crash-diag/device-fixed/worker/phase7b/ld.config.txt)
- Host [수정 전 before](../out/phase7e-crash-diag/device-run1/before.txt) / [after](../out/phase7e-crash-diag/device-run1/after.txt), [수정 후 before](../out/phase7e-crash-diag/device-fixed/before.txt) / [after](../out/phase7e-crash-diag/device-fixed/after.txt)
- [회귀 결과](../out/phase7e-crash-diag/lifecycle-regression.log), [최종 cleanup](../out/phase7e-crash-diag/cleanup-final.log), [Rust 검사](../out/phase7e-crash-diag/rust-tests-final.log), [native 검사](../out/phase7e-crash-diag/native-tests.log), [Android build](../out/phase7e-crash-diag/android-build-final.log)

공유 PID/procfs의 알려진 신뢰 Guest 한계는 그대로다. 이번 PASS는 기존 native crash 해결에 대한 판정이며 Android/LineageOS 첫 부팅 완료나 전체 Host 무영향 인증은 아니다.
