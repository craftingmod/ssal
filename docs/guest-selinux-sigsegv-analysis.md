# Guest SELinux Identity Reporter SIGSEGV 분석

**결론:** SIGSEGV는 Reporter `main` 이후가 아니라, 성공한 `setexec` 준비 다음 `execveat`/ELF 진입 경로에서 발생한다. libc와 동적 링커가 없는 AArch64 probe도 전환 실행에서 SIGSEGV를 재현했다. 다만 crash buffer와 tombstone에 fault PC가 없어 커널 ELF 로딩과 첫 user instruction 경계 중 어느 주소에서 fault했는지, 정확한 원인은 아직 식별하지 못했다.

## 실행 결과

승인된 SM-S937N (`R5CY52JC03H`)에서 2026-11-01 00:00–00:07 KST에 실행했다. fingerprint는 `samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`, boot ID는 `bd037ba2-9b84-438e-ae43-5717af227c53`, 전역 SELinux는 Enforcing, 런처 source context는 `u:r:ksu:s0`였다. 실행 전 기록은 [baseline](../out/guest-domain-sigsegv-run-20261031/baseline.json)에 있다.

| Helper | 전환 없는 동일 런처 대조 | `setexec` 후 전환 실행 |
|---|---|---|
| Rust Identity Reporter | PID 5551, status `0x0000`, `reporter_main=seen`, context `u:r:ksu:s0` ([기록](../out/guest-domain-sigsegv-run-20261031/control-run.json)) | PID 11452, status `0x000b` (SIGSEGV), `setexec_open/write errno=0`, `reporter_main=not_seen` ([기록](../out/guest-domain-sigsegv-run-20261031/transition-run.json)) |
| 정적 C Reporter, `PT_INTERP` 없음 | PID 14816, status `0x0000`, `reporter_main=seen`, context `u:r:ksu:s0` ([기록](../out/guest-domain-sigsegv-run-20261031/static-control-run.json)) | PID 14872, status `0x000b`, `setexec` 두 단계 성공, `reporter_main=not_seen` ([기록](../out/guest-domain-sigsegv-run-20261031/static-transition-run.json)) |
| libc/CRT 없는 bare `_start` Reporter | PID 20446, status `0x0000`, `BARE_ENTRY`와 KSU context 출력 ([기록](../out/guest-domain-sigsegv-run-20261031/bare-control-run.json)) | PID 22002, status `0x000b`, `BARE_ENTRY` 미출력 ([기록](../out/guest-domain-sigsegv-run-20261031/bare-transition-run.json)) |
| 세 명령어 ELF: `exit_group(42)` | PID 25496, status `0x2a00`, 같은 런처가 `bare_entry=seen; proof=exit_42`로 판정 ([기록](../out/guest-domain-sigsegv-run-20261031/entry-exit-control-run.json)) | PID 25499, status `0x000b`, `setexec_open/write errno=0`, `execveat` 반환 표식 없음, exit-42 표식 없음 ([기록](../out/guest-domain-sigsegv-run-20261031/entry-exit-transition-run.json)) |

마지막 helper는 NDK로 만든 AArch64 `ET_EXEC`이며 `PT_INTERP`가 없고 entry는 `0x2000e8`이다. `_start`의 첫 세 명령은 메모리 접근 없는 `mov x0, #42`, `mov x8, #94`, `svc #0`이다. 대조군에서는 그 결과가 기대한 exit code 42로 관측됐다. 전환 실행에서는 SIGSEGV가 동일하게 발생했다. 따라서 **고정된 SELinux target으로 실행 전환을 시도할 때 ELF의 첫 user-space 동작 이전 또는 그 handoff 경계에서 실패한다**고 분류한다. Rust Reporter, C runtime 초기화, 동적 링커만의 문제는 이 재현 결과와 맞지 않는다.

런처의 `execveat_entered`는 syscall 직전 trace write이고, `execveat_returned`는 syscall이 오류로 반환했을 때만 기록된다. 따라서 `execveat_entered`만으로 커널 진입을 단정하지 않는다. 현재 증거는 실패 위치를 fork/setexec 이후, exec/ELF handoff, bare ELF 진입 전으로 좁히지만 정확한 fault PC, fault address, 커널 내 syscall 위치는 결정하지 못한다.

## 충돌 자료

가장 마지막 전환 실행 직후 수집한 자료:

- [`logcat -b crash`](../out/guest-domain-sigsegv-run-20261031/entry-exit-crash-logcat.txt): crash 항목 없음.
- [tombstone 목록](../out/guest-domain-sigsegv-run-20261031/entry-exit-tombstones.txt): 실행 시각 전후 새 파일 없음. 최신은 이전에 생성된 `tombstone_25` (기기 시각 2026-10-31 14:02)였다.
- [dmesg](../out/guest-domain-sigsegv-run-20261031/entry-exit-dmesg.txt) 및 [전체 logcat](../out/guest-domain-sigsegv-run-20261031/entry-exit-full-logcat.txt): SIGSEGV 상세, PC, backtrace, 새 AVC denial이 없다. 전체 logcat의 관련 내용은 adbd가 시험 명령을 요청한 기록뿐이다.

기존 [enforcing 검증 기록](guest-selinux-enforcing-fixed-validation-20261031.md)에도 child PID, PC, fault address, backtrace가 없었다. 이번에도 wait status는 SIGSEGV를 보이지만 tombstone이 생성되지 않아 fault 주소를 얻지 못했다.

## 정책 및 기기 상태

명시 승인된 기존 네 문장만 `ksud sepolicy patch`로 현재 실행 중인 정책에 적용했다. 각 문장의 파서 검사와 적용 명령은 [1](../out/guest-domain-sigsegv-run-20261031/policy-apply-1.json), [2](../out/guest-domain-sigsegv-run-20261031/policy-apply-2.json), [3](../out/guest-domain-sigsegv-run-20261031/policy-apply-3.json), [4](../out/guest-domain-sigsegv-run-20261031/policy-apply-4.json)에 기록돼 있다.

```te
type ssal_guest_probe domain
type ssal_guest_probe_exec file_type
allow ksu ssal_guest_probe process transition
allow ssal_guest_probe ssal_guest_probe_exec file entrypoint
```

전환 실행 직전 필수 AV 조회는 허용됐고 target permissive flag는 false였다. 전역 Enforcing도 유지됐다.

추가 `allow`, `permissive`, 정책 후보 파일 변경은 없었다. Reporter 파일에만 전용 exec label을 설정했고 시험 후 임시 파일은 삭제했다. 정책 patch는 현재 boot의 live policy에 남아 있다. 안전한 무재부팅 rollback 경로가 확인되지 않아 임의 제거를 시도하지 않았다. 기기 재부팅 명령은 실행하지 않았고 사용자에게 재부팅을 요청하지 않는다. Guest Framework와 인증 HAL도 실행하지 않았다.

시험 후 전역 Enforcing, KSU source context, boot ID와 다섯 개 임시 파일의 부재를 확인했다([최종 기기 상태](../out/guest-domain-sigsegv-run-20261031/final-device-state.json)).

## fork 이후 안전성

Rust `Command::pre_exec`와 `std::io::Error::last_os_error()` 경로를 제거했다. fork child는 고정 trace record와 `open`, `dup2`, `fcntl`, `close`, `write`, `execveat` syscall, `_exit`만 수행한다. child 안에서 Rust 표준 입출력, 동적 할당, 잠금, 포맷팅, unwind를 호출하지 않는다. 코드 검토상 기존 `pre_exec` 경로의 async-signal-safe 위반 가능성은 있었지만 이번 충돌의 원인이라는 증거는 없으며, 전환 crash가 no-lib bare ELF에서도 재현돼 Reporter의 Rust 후처리가 원인일 가능성은 배제된다.

## 재현 코드와 검증

- 런처의 `--control`은 같은 런처와 Reporter를 전환 없이 실행한다.
- `--bare-control` / `--bare-transition`은 libc 없는 ELF의 출력 또는 `exit_group(42)` status로 ELF 진입을 검증한다. status `0x2a00`은 exit code 42다.
- 단계 trace에는 fork child 준비, `setexec` open/write syscall errno, `execveat` 직전 표식, Reporter `main` 표식이 포함된다.
- 정적 C 및 두 bare ELF 빌드: [`build-static-reporter.sh`](../scripts/guest-domain-poc/build-static-reporter.sh). 세 ELF 모두 `PT_INTERP`가 없음을 검사한다.
- fork child의 trace/status 검증 및 bare 출력/exit-42 판정 테스트: `cargo test --locked --bin ssal-guest-domain-poc` — 6개 통과.
- Android AArch64 검사 및 런처 빌드: `cargo check --locked --target aarch64-linux-android --bin ssal-guest-domain-poc`, release build 통과.

시험에 쓴 최종 바이너리 SHA-256:

| 파일 | SHA-256 |
|---|---|
| Android launcher | `7d7bc8e755bff31b9975249a087a8a82db4881f798151d2f2e0ed8b15d84e61a` |
| Rust Identity Reporter | `1295abba10df884551a27b6dd7b1dc0df2d568c6bcbb35d66a2a2d2168492fe90` |
| 정적 C Reporter | `946f0338a1856fa2966bd367f04a64cbe168fc7be3a3faf95584a544479282b1` |
| libc 없는 context Reporter | `5181715c36e4db47ecf49e28edc545af81cce9cd348b727dd82f25e9c5e05d5c` |
| `exit_group(42)` ELF | `e64760a5270c15b462e159f896ef7ead685916f5a8d289440aa5434b33bfa2e4` |

## 다음 수정

현 증거로 Reporter나 SELinux 정책을 수정하지 않는다. 확인된 결함 구간은 `setexec`가 아니라 exec/ELF handoff 단계다. 실제 원인 수정을 정하려면 다음 재현에서 fault PC/backtrace를 확보해야 한다. 이번에는 crash buffer와 tombstone이 비었으므로, fault 주소를 제공하는 기기 측 exec/crash 추적을 추가한 뒤 그 주소를 기준으로 수정한다. 그 전에는 정책 권한을 더하거나 Reporter를 임의 변경하지 않는다.
