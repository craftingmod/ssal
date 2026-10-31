# Guest SELinux exec SIGSEGV 추적

## 상태

Ptrace 진단 모드와 사용법을 런처에 추가했다. Windows Native 셸에서 `cargo`를 찾지 않고, 실제 Cargo가 실행되는 WSLC `ssal-dev`에서 Android AArch64 release 빌드를 완료했다. 결과 ELF는 `out/bin/ssal-guest-domain-poc-ptrace`이며 SHA-256은 `153834e8c053692630383e07be829ba06d923ccea376f536765366bc9135685e`, 크기는 676056 bytes다.

2026-11-01 실기기 Ptrace 대조군과 Guest 전환을 실행했다. 대상 `R5CY52JC03H`의 boot ID는 `bd037ba2-9b84-438e-ae43-5717af227c53`, 전역 SELinux는 Enforcing, 런처 context는 `u:r:ksu:s0`였다. 기존 정책은 그대로 두고 전용 Bare ELF 파일에 기존 실행 type label만 적용했다. 실행 후 임시 파일을 정리했으며, 재부팅 및 Guest Framework/HAL 실행은 하지 않았다.

## 직전 Bare ELF 결과

기존 [분석 기록](guest-selinux-sigsegv-analysis.md) 및 [원본 출력](../out/guest-domain-sigsegv-run-20261031/entry-exit-control-run.json), [전환 출력](../out/guest-domain-sigsegv-run-20261031/entry-exit-transition-run.json)에 기록된 값이다.

| 실행 | child PID | wait status | 관측 |
|---|---:|---:|---|
| KSU 대조 | 25496 | `0x2a00` | Bare ELF가 `exit_group(42)`로 종료. ELF 진입 확인 |
| Guest 전환 | 25499 | `0x000b` | SIGSEGV. `setexec` open/write는 errno 0, `execveat_entered`는 기록, syscall 반환 표식과 exit-42 결과는 없음 |

이전 무계측 대조군과 전환군은 비교용으로 유지한다. 이 기록의 다음 절에 동일한 Bare ELF를 사용한 신규 Ptrace 측정값을 추가했다.

## 실기기 Ptrace 결과

원본 런처 출력: [KSU control](../out/guest-selinux-exec-trace-20261101/ptrace-control.txt), [Guest transition](../out/guest-selinux-exec-trace-20261101/ptrace-transition.txt).

| 실행 | child PID | PTRACE_EVENT_EXEC / PC | 시그널 / PC | wait status | 결과 |
|---|---:|---|---|---:|---|
| KSU 대조 | 12723 | 확인, `0x2000e8` | 없음 | `0x2a00` | Bare ELF 진입 후 exit 42 |
| Guest 전환 | 12788 | 미관측 | SIGSEGV, `si_code=128 (SI_KERNEL)`, `si_addr=0x0`, 정지 시 PC `0x7d610cf924` | `0x000b` | Bare ELF 진입/Reporter 실행 전에 종료 |

두 모드 모두 `PTRACE_TRACEME`, `execveat_entered` 단계까지 진행했다. Guest 전환에서도 `setexec` open/write는 errno 0이었다. Ptrace가 exec를 막았다는 증거는 없다. 같은 전환 SIGSEGV가 앞선 무계측 실행에서도 관측됐다. `PTRACE_GETSIGINFO`와 AArch64 `PTRACE_GETREGSET`는 모두 정보를 반환했다. 따라서 이번에는 정보 부족/Ptrace 차단에 대비한 tracefs 추적 조건이 발생하지 않았고 PID 한정 커널 추적은 켜지 않았다.

## 실행 단계 판정

`si_code=128`은 Linux `SI_KERNEL` 값이다. Android common 6.6의 `exec.c`는 `begin_new_exec()`에서 `point_of_no_return`을 설정하고, 그 뒤 exec가 실패하면 `force_fatal_sig(SIGSEGV)`를 보낸다. 같은 코드에서 `PTRACE_EVENT_EXEC`와 `sched_process_exec`는 binfmt 처리 성공 뒤 기록된다. Android common의 signal 구현은 `force_fatal_sig()`가 `si_code`를 `SI_KERNEL`로 설정함을 보인다. 이 조합은 **Guest 전환에서 PONR 이후, successful exec event 및 Bare ELF entry 이전에 exec가 실패해 커널이 SIGSEGV를 강제한 경우**와 일치한다. [Android common `exec.c`](https://android.googlesource.com/kernel/common/%2B/refs/heads/android15-6.6/fs/exec.c), [Android common `signal.c` (`force_fatal_sig`/`SI_KERNEL`)](https://android.googlesource.com/kernel/common/%2B/5215557f73ed7ea65f73e9119d8c11a37d7a8740/kernel/signal.c)

이는 삼성 기기 커널에서 직접 PONR tracepoint를 관측한 결과가 아니라, 같은 계열 Android common 6.6 exec/signal 동작에 실제 `SI_KERNEL`, exec event 부재, Bare ELF 진입 부재를 대조한 강한 판정이다. 기기 tracefs에는 `sched_prepare_exec`가 없어 PONR 자체를 직접 기록하지 못했다. `PTRACE_GETREGSET`에서 얻은 PC `0x7d610cf924`는 SIGSEGV stop 시의 AArch64 사용자 레지스터 값이다. 성공 대조군의 Bare ELF entry `0x2000e8`와 다르므로 Bare ELF에서 실행 중 난 fault를 뜻하지 않지만, 이 값만으로 실패한 커널 함수나 이전 사용자 mapping의 심볼을 특정할 수는 없다. 이 때문에 정확한 하위 실패 함수는 아직 미확정이다.

전환 중 출력된 `process:getattr allowed=false`는 런처의 정책 조회 결과이며 실제 AVC denial 로그는 확인되지 않았다. 이 출력만으로 SIGSEGV 원인이라고 볼 수 없다. 기존 네 개 정책 문장은 유지했고 새 allow 또는 Permissive 전환은 하지 않았다.

## 런처 변경

기존 `src/bin/ssal-guest-domain-poc.rs`에 다음 두 명시 모드를 추가했다. 기존 정책 검사, 고정 Guest context, helper 해시 검사와 `bare-exit.S`는 그대로 재사용한다.

```text
--bare-ptrace-control /path/to/ssal-sigsegv-bare-exit --sha256 HASH
--bare-ptrace-transition /path/to/ssal-sigsegv-bare-exit --sha256 HASH
```

Ptrace 모드에서만 child가 exec 직전에 `PTRACE_TRACEME` 후 `SIGSTOP`으로 대기한다. 부모가 `PTRACE_O_TRACEEXEC`를 설정하고 재개한다. `PTRACE_EVENT_EXEC`에서 AArch64 `NT_PRSTATUS` (`PTRACE_GETREGSET`)의 PC를 출력하고, SIGSEGV stop에서 `PTRACE_GETSIGINFO`의 `si_code`와 `si_addr`, `PTRACE_GETREGSET`의 PC를 출력한다. 조회가 실패해도 오류를 기록하고 child를 계속해 실제 wait status를 회수한다. 기존 비-Ptrace 모드의 wait 경로는 바꾸지 않았다.

Ptrace는 완전히 수동적인 계측이 아니다. Linux exec 경로는 ptraced task에 `LSM_UNSAFE_PTRACE`를 표시하고, SELinux의 exec credential 경로는 도메인 전환 시 tracer가 새 SID를 ptrace할 수 있는지 검사할 수 있다. 따라서 Ptrace 실행 결과가 무계측 결과와 다르면 그 자체로 원인을 확정하지 않는다. 추가 정책으로 Ptrace를 우회하지 않는다. Android common 6.6 `exec.c`의 unsafe exec 처리와 SELinux hook을 참고하되, 실제 삼성 커널은 별도 확인이 필요하다. [Android common exec 경로](https://android.googlesource.com/kernel/common/%2B/refs/heads/android15-6.6/fs/exec.c), [SELinux exec hook](https://android.googlesource.com/kernel/common/%2B/refs/heads/android15-6.6/security/selinux/hooks.c)

## PID 한정 커널 추적 가능성

읽기 전용으로 확인한 기기 커널은 `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k`다. `/sys/kernel/tracing` tracefs와 `instances`, `set_event_pid`, `options/event-fork`가 있다. 사용 가능한 이벤트에는 `sched:sched_process_exec`, `signal:signal_generate`, `signal:signal_deliver`가 있다. `sched_prepare_exec`, `sys_enter/exit_execveat`는 없었다. `available_tracers`는 `nop`만 출력했고 `available_filter_functions` 파일은 없었다. `kprobe_events` 파일은 있으나 probe 등록은 하지 않았다.

Ptrace를 못 쓰거나 결과가 계측으로 달라지면, 별도 tracefs instance에서 launcher PID를 `set_event_pid`에 넣고 `event-fork`를 켠 뒤 위 세 이벤트만 수집하는 방식은 가능성이 있다. `sched_process_exec`는 새 이미지 전환 완료를, signal 이벤트는 발생/전달된 SIGSEGV의 signal number와 code를 보여줄 수 있다. 현재 이벤트 형식에는 fault address나 PC가 없다. 또한 이 기기에서 `sched_prepare_exec`를 제공하지 않아, PID 한정 tracepoint 결과만으로는 PONR 진입 여부를 가를 수 없다. `kprobe_events`로 exec 함수 경계를 더 볼 수 있을지는 심볼·권한을 확인하지 않아 unknown이다. tracefs는 쓸 수 있더라도 instance 안에서만 변경하고 종료 후 instance를 제거해야 한다. 전역 trace 설정이나 SELinux 정책은 바꾸지 않는다.

상류 Android common 6.6 커널은 `sched_prepare_exec`를 PONR 지점, `sched_process_exec`를 새 exec 전환 성공 뒤의 tracepoint로 설명한다. 하지만 이 기기의 `available_events`에는 전자가 없고 후자만 있어 그 구분을 현재 tracefs만으로 복원할 수 없다. [Android common exec tracepoint 설명](https://android.googlesource.com/kernel/common/%2B/refs/heads/android15-6.6/include/trace/events/sched.h), [tracefs PID 필터 문서](https://docs.kernel.org/next/trace/events.html), [ptrace UAPI 이벤트 정의](https://github.com/torvalds/linux/blob/master/include/uapi/linux/ptrace.h)

## 원인 및 최소 수정 대상

- 실효 AV 조회에서 `ssal_guest_probe → ssal_guest_probe_exec`, class `file`의 `entrypoint`만 허용되고 `map`, `read`, `execute`, `open`은 모두 거부됐다. 기존 네 개 정책 문장은 변경하지 않았다.
- 아래 승인된 1회 tracefs 추적에서 child PID 18687의 `begin_new_exec()` 반환은 `0`, 이어진 `selinux_mmap_file()` 반환은 `-13` (`-EACCES`)이었다. 같은 PID에서 `SIGSEGV`, `code=128 (SI_KERNEL)`가 생성됐고 child의 성공 `sched_process_exec` 이벤트는 없었다. 따라서 실제 실패 지점은 ELF 파일 mapping의 SELinux 검사다.
- Android common 6.6 SELinux hook은 `selinux_mmap_file()`에서 먼저 `file:map`을 검사하고 거부 시 바로 반환한다. live AV도 `file:map` 거부이므로 이 trace의 `-EACCES`를 유발한 구체 권한은 `file:map`으로 특정된다. Android ELF 경로는 `begin_new_exec()` 뒤 `elf_map()`을 호출하며, 이 mapping 실패 errno가 exec 실패 경로로 전달된다. [Android common `fs/exec.c`](https://android.googlesource.com/kernel/common/%2B/refs/heads/android15-6.6/fs/exec.c), [Android common `fs/binfmt_elf.c`](https://android.googlesource.com/kernel/common/%2B/refs/heads/android15-6.6/fs/binfmt_elf.c), [Android common SELinux `hooks.c`](https://android.googlesource.com/kernel/common/%2B/refs/tags/android15-6.6-2024-10_r2/security/selinux/hooks.c)
- 최소 수정 후보는 추후 별도 승인 후 `allow ssal_guest_probe ssal_guest_probe_exec file map` 한 문장을 추가하는 것이다. 이번 조사에서는 적용하지 않았다. `read`, `execute`, `open`은 현재 거부 상태이며, map 검사를 통과한 뒤 추가로 필요한지 재측정해야 한다.

## 2026-11-01 별도 tracefs 추적 결과

기기 커널 심볼에서 `begin_new_exec`, `selinux_mmap_file`, `elf_map`, `load_elf_binary`를 확인했다. 전용 tracefs instance와 launcher PID 18686 및 fork된 child PID만 대상으로 실행했다. 두 kretprobe는 등록됐고, `elf_map` 및 `load_elf_binary` 반환 probe 등록은 커널이 거부해 사용하지 않았다. instance event로 `sched_process_exec`와 `signal_generate`도 수집했다.

| 대상 | 실효 허용 | 실효 거부 |
|---|---|---|
| `ssal_guest_probe → ssal_guest_probe_exec`, `file` | `entrypoint` | `map`, `read`, `execute`, `open` |

| child PID 18687 추적 | 관측값 |
|---|---|
| `begin_new_exec()` 반환 | `0` |
| `selinux_mmap_file()` 반환 | `-13` (`-EACCES`) |
| 생성된 signal | `SIGSEGV`, `code=128 (SI_KERNEL)` |
| child `sched_process_exec` | 없음 |
| launcher 출력 | `setexec_open/write` errno 0, `execveat_entered`, wait status `0x000b`, `bare_entry=not_seen` |

원본 trace: [kretprobe-trace.txt](../out/guest-selinux-exec-trace-20261101/kretprobe-trace.txt). 재사용한 기존 런처와 Bare ELF의 SHA-256은 각각 `7d7bc8e755bff31b9975249a087a8a82db4881f798151d2f2e0ed8b15d84e61a`, `e64760a5270c15b462e159f896ef7ead685916f5a8d289440aa5434b33bfa2e4`다. 이 기기의 kernel release는 `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k`다. Samsung의 정확한 downstream 소스는 이번 작업공간에서 확인할 수 없어, 순서는 Android common 6.6 소스로 교차 확인하고 실패 함수/errno는 실기기 kretprobe 결과로 확정했다.

추적 후 전용 instance, 두 kprobe 정의, 기기 임시 실행 파일을 제거했다. 재확인 시 kprobe 정의와 전용 instance가 없고 임시 디렉터리도 없었다. boot ID는 추적 전후 `bd037ba2-9b84-438e-ae43-5717af227c53`, SELinux는 계속 Enforcing이었다. 정책 변경, 재부팅, Guest Framework 또는 인증 HAL 실행은 하지 않았다.

## 확인

- `cargo test --locked --bin ssal-guest-domain-poc`: 7 passed.
- `cargo check --locked --target aarch64-linux-android --bin ssal-guest-domain-poc`: passed.
- Windows PowerShell에서 직접 실행한 `cargo build`는 host/linker 설정 불일치로 실패했다; `wslc exec --workdir /src ssal-dev cargo build --locked --release --target aarch64-linux-android --bin ssal-guest-domain-poc`는 성공했다.
- `out/bin/ssal-guest-domain-poc-ptrace`: AArch64 PIE, `/system/bin/linker64`, 676056 bytes, SHA-256 `153834e8c053692630383e07be829ba06d923ccea376f536765366bc9135685e`.
- 실기기 Ptrace control/transition: control은 `PTRACE_EVENT_EXEC` 및 exit 42 확인, Guest 전환은 `SI_KERNEL` SIGSEGV 확인. tracefs 수집은 조건이 발생하지 않아 실행하지 않았다.
- 실기기 상태 정리 후 root/KSU 실행 context, Enforcing 상태와 boot ID는 유지됨을 read-only 확인했다. 정책 변경이나 재부팅은 하지 않았다.

## 2026-11-01 승인된 `file:map` 추가 후 Bare ELF 결과

사용자 승인 후 기기 `R5CY52JC03H`에서 동적 정책 규칙 `allow ssal_guest_probe ssal_guest_probe_exec file map`만 `ksud sepolicy patch`로 추가했다. 앞선 네 정책 문장은 수정·재적용하지 않았고, 다른 allow나 permissive 전환도 하지 않았다.

| 시점 | `ssal_guest_probe → ssal_guest_probe_exec file:map` | 대상 `process:getattr` flags | 전역 |
|---|---|---|---|
| 적용 전 | mask `0x400`, 거부, sequence `1` | `0` (Enforcing) | Enforcing |
| 적용 후 | mask `0x400`, 허용, sequence `1` | `0` (Enforcing) | Enforcing |

적용 후 같은 source/target에서 `file:entrypoint`는 허용, `file:read`, `file:execute`, `file:open`은 거부였다. target `process:getattr` 자체는 `allowed=false`였지만 permissive flag는 적용 전후 모두 `0`이었다.

기존 Bare ELF `out/bin/ssal-sigsegv-bare-exit` (SHA-256 `e64760a5270c15b462e159f896ef7ead685916f5a8d289440aa5434b33bfa2e4`)와 Ptrace 런처를 재사용했다. 런처가 `PTRACE_EVENT_EXEC`에서 실제 child SID를 출력하도록 [최소 변경](../src/bin/ssal-guest-domain-poc.rs)을 했고 Android AArch64 release 빌드를 성공했다. 산출물은 [launcher-ptrace-context](../out/guest-selinux-exec-trace-20261101/launcher-ptrace-context), SHA-256 `b5801d522834cd4eb3d3bfbaaba80eaf94f9bfd3be3756d234edfbf16a4b1c6a`다. ELF를 전용 `/data/local/tmp/ssal-guest-map-run-20261101`에 복사해 해시를 재확인하고 Bare ELF에만 `u:object_r:ssal_guest_probe_exec:s0` 라벨을 부여했다.

Ptrace 실행 child PID `20788`은 `execveat_entered` 뒤 `PTRACE_EVENT_EXEC` 전에 `SIGSEGV`로 종료됐다. `si_code=128 (SI_KERNEL)`, `si_addr=0`, wait status `0x000b`, PC `0x71f7153924`였고 `execveat` 반환 errno는 관측되지 않았다. 따라서 이 실행에서 실제 child SID와 exit code 42는 확인되지 않았다.

원인을 확인하려고 같은 Ptrace 시도를 한 차례 더 PID/fork 한정 tracefs instance에서 계측했다. launcher PID `23698`, child PID `23826`에서 `begin_new_exec()`는 `0`, `selinux_mmap_file()`은 `-13` (`-EACCES`)을 반환했다. child `sched_process_exec`는 없었고 `SIGSEGV`, `code=128 (SI_KERNEL)`가 생성됐다. [원본 kretprobe trace](../out/guest-selinux-exec-trace-20261101/post-map-kretprobe-trace.txt)와 [런처 출력](../out/guest-selinux-exec-trace-20261101/post-map-ptrace.txt)을 보존했다. 추가 정책 변경이나 실행은 하지 않았다.

실기기 AV에서는 `file:map`이 허용인데도 `selinux_mmap_file()`이 `-EACCES`를 반환했다. `read`와 `execute`도 target에서 거부 상태다. Android common 6.6의 [SELinux hook](https://android.googlesource.com/kernel/common/%2B/refs/tags/android15-6.6-2024-10_r2/security/selinux/hooks.c)은 `file:map` 검사 뒤 실행 매핑에 `file:read`와 `file:execute` 검사를 추가한다. 이 기기의 kretprobe는 함수 반환값만 기록하므로 두 거부 중 어느 AV가 실제 반환을 유발했는지는 구분되지 않았다. 삼성 downstream 코드와 그 하위 권한은 이 결과만으로 특정하지 않는다.

마지막 확인에서 boot ID `bd037ba2-9b84-438e-ae43-5717af227c53`, 전역 Enforcing 및 핵심 Host 프로세스 PID/start time/context/exe가 기준과 같았다. 두 child PID는 종료됐고 임시 디렉터리, tracefs instance, 두 kprobe 정의가 제거됐으며 global `tracing_on=0`이다. 동적으로 추가한 map 규칙은 현재 부팅에 남아 있을 수 있다. 재부팅은 하지 않았다.

**완료 기준 미달:** Guest enforcing domain의 Bare ELF exit 42와 실제 child SID를 확인하지 못했다. Property Area 단계 조건은 이 실패에 따라 보류한다.

## 2026-11-01 승인된 `file:read`·`file:execute` 추가 후 Bare ELF 성공

같은 부팅 ID `bd037ba2-9b84-438e-ae43-5717af227c53`에서 사용자 요청에 명시된 규칙 하나만 `ksud sepolicy patch`로 추가했다: `allow ssal_guest_probe ssal_guest_probe_exec file { read execute }`. 명령은 `NormalPerm(...)`, exit 0을 반환했다. 직전 승인 적용분인 `file:map`은 이미 허용 상태였고 재적용하지 않았다.

| 권한 | 적용 전 | 적용 후 및 실행 정리 후 |
|---|---|---|
| `file:read` (mask `0x2`) | 거부; allowed mask `0x04000400` | 허용; allowed mask `0x04004402` |
| `file:execute` (mask `0x4000`) | 거부; allowed mask `0x04000400` | 허용; allowed mask `0x04004402` |
| `file:map` (mask `0x400`) | 허용; allowed mask `0x04000400` | 허용; allowed mask `0x04004402` |
| `file:entrypoint` (mask `0x04000000`) | 허용; allowed mask `0x04000400` | 허용; allowed mask `0x04004402` |

각 질의의 policy sequence는 `1`, flags는 `0`이었다. Guest 대상 `process:getattr`는 allowed=false지만 flags=`0`이라 permissive가 아니며, 전역 `enforce=1`도 유지됐다. 런처의 관리 source인 `u:r:ksu:s0`는 기존 flags=`1`이며 Guest 대상의 enforcing 확인과 구분한다. 적용 전후 원본 selinuxfs 응답은 [read-exec-av.txt](../out/guest-selinux-exec-trace-20261101/read-exec-av.txt)에 있다.

기존 Ptrace 런처와 `exit_group(42)` Bare ELF를 재사용했다. device에 복사한 ELF SHA-256은 `e64760a5270c15b462e159f896ef7ead685916f5a8d289440aa5434b33bfa2e4`, 런처는 `b5801d522834cd4eb3d3bfbaaba80eaf94f9bfd3be3756d234edfbf16a4b1c6a`로 로컬 파일과 일치했다. Child PID `27071`에서 `PTRACE_EVENT_EXEC`, PC `0x2000e8`, 실제 SID `u:r:ssal_guest_probe:s0`를 확인했고 wait status `0x2a00`과 `bare_entry=seen; proof=exit_42`를 받았다. 원본 런처 출력은 [read-exec-ptrace.txt](../out/guest-selinux-exec-trace-20261101/read-exec-ptrace.txt)에 보존했다.

종료 후 child와 전용 임시 디렉터리는 없고, 이 시험의 tracefs instance 및 kprobe 정의는 없으며 `tracing_on=0`이었다. 확인한 `init`, `vendor_init`, `servicemanager`, `zygote64`, `system_server`, `surfaceflinger`의 PID/start time/context/exe는 실행 전후 같았다. boot ID와 전역 Enforcing도 유지됐다. 재부팅, Guest Framework, 인증 HAL은 실행하지 않았다. `file:read`·`file:execute` 및 기존 `file:map` 동적 규칙은 현재 부팅의 실효 정책에 남아 있을 수 있다.

**완료 기준 통과:** Guest enforcing domain에서 Bare ELF가 `PTRACE_EVENT_EXEC` 후 실제 SID를 유지하고 exit code 42로 종료했다. 다음 Property Area 시험은 별도 단계다. 실제 Guest writer/client SID, property·serial·socket 파일 context와 DAC, Guest 전용 mount의 per-inode 라벨 지원 및 superblock SID를 먼저 고정하고, 생성·relabel·associate·open/read/write/map·socket/`property_service:set` 권한과 Host 경로·FD·socket 차단을 실기기에서 확인해야 한다. 이 작업에서는 Property Area 생성과 Framework/HAL 실행을 하지 않았다.
