# SSAL Phase 7B — Zygote Diagnostics Infrastructure

2026-11-05 KST. 대상은 기존 Samsung 순정 Host / Android 16 Guest이다. Zygote 부팅 성공은 이번 판정 조건이 아니다.

## 판정

**진단 인프라 구현·오프라인 검증 PASS. 실기기 Zygote 진단은 미실행.** Guest memory controller가 전달되지 않아 메모리 보호는 아직 검증되지 않았다. Guest 서비스 실행, 배포, Host cgroup·SELinux·debuggerd·tombstoned 설정 변경은 하지 않았다.

| 항목 | 결과 | 근거 |
|---|---|---|
| Zygote stdout/stderr 전용 pipe | PASS, Linux 모의 검증 | 별도 nonblocking pipe를 readiness loop와 종료 시 drain. 각 스트림 1 MiB 저장 상한 이후에도 drain 유지 |
| 종료 signal/status·시각 | PASS, Linux 모의 검증 | epoch ms, monotonic 경과 시간, PID, raw wait status, exit code, signal, core flag, drain/save byte 수를 JSONL 기록 |
| ART fatal/native abort/backtrace 경로 | 구현·모의 검증 PASS; Android runtime UNKNOWN | 기존 Guest liblog→stderr 로거 재사용, Zygote 전용 abort interposer에서 최대 64 native PC/object/offset 프레임 수집. Linux에서 SIGABRT 보존 검증, Android 빌드 통과 |
| Guest cgroup memory/pressure 진단 | 구현 PASS; 실제 Guest 계측 미실행 | memory.current/peak/max/high/events/events.local/stat/pressure, membership, Host PSI·meminfo 및 프로세스 status/maps 읽기. 파일 부재는 `unavailable`로 기록 |
| memory controller 경로 분석 | PASS, 읽기 전용 | root가 memory를 광고하지만 subtree_control이 비어 있고 apps에도 전달되지 않음. 현재 apps/ssal_guest 부재 |
| Phase 5B/6A/6B 회귀 | 오프라인 검사 PASS; 기존 실기기 PASS 유지 | ssald 40 passed / 0 failed / 3 ignored, lib 15 passed / 0 failed. 기존 서비스 파일 로깅과 cleanup 유지. 이번에 실기기 회귀를 새로 실행한 것은 아님 |
| Host 핵심 상태 | 읽기 전용 관측 PASS | 00:01:28–00:02:05 KST 표본에서 Enforcing·boot ID, 6개 핵심 프로세스 PID/starttime/context 및 관측 service 상태 유지 |
| 전체 raw log의 메인 컨텍스트 전달 | 없음 | Luna가 로컬 필터링과 읽기 전용 조사를 수행하고 요약·경로·행 번호만 전달 |

기존 실기기 Phase 5B/6A 및 Phase 6B IInstalld 생성·삭제 PASS는 [Phase 6B 결과](guest-services-phase6b-results.md)의 범위 그대로다. artd dexopt/OAT/VDEX backlog를 이번 PASS에 포함하지 않는다. 새 바이너리의 실기기 회귀 PASS를 주장하지 않는다.

## 구현과 저장 위치

- [guest_launcher.rs](../src/guest_launcher.rs): `guest-zygote`에만 pipe·진단 객체·추가 preload를 연결한다. 그 외 servicemanager/AIDL/installd/artd의 기존 stdout/stderr 정규 파일 경로를 유지한다. 기존 `Service::stop`/Drop의 소유 프로세스 종료 및 wait 뒤에 진단을 마무리한다. readiness 전 조기 종료와 Drop에서도 signal·stderr 보존을 시험했다.
- [zygote_diagnostics.rs](../src/zygote_diagnostics.rs): rootfs와 별도인 worker 세션의 `phase7b/`를 mode 0700으로 생성한다. `stdout.log`, `stderr.log`, `metadata.jsonl`, `memory.jsonl`, 마지막 관측 `process-maps.txt`를 저장한다. `/run/ssal`의 Guest 코드 영역과 Host 로그 서비스에 진단을 쓰지 않는다.
- stdout/stderr는 각각 처음 1 MiB를 보존하고 초과분을 버리면서 drain한다. 매 drain 호출은 스트림당 최대 256 KiB이며, writer 후손이 pipe를 계속 열고 있어도 EOF를 기다리지 않는다. 종료 metadata의 byte 수와 `tail_may_be_incomplete`로 한계를 표시한다.
- memory sample은 시작·약 250 ms 간격·종료 시점에 수집한다. `memory.jsonl`은 8 MiB 도달 이후 추가 sample을 중지하며 마지막 한 레코드만큼 상한을 넘을 수 있다. maps는 최대 1 MiB의 최근 비어 있지 않은 관측본이다. reap 이후에는 재사용될 수 있는 PID의 `/proc` 정보를 읽지 않는다. 종료 시 cgroup 값은 정리되기 전 읽는다.
- [zygote-diagnostics.c](../native/binder-probe/zygote-diagnostics.c): Zygote만 preload하는 `ssal-zygote-diag.so`를 추가했다. `abort()` 경로에서 timestamp/PID와 native unwind 프레임을 stderr로 쓰고 libc abort로 넘긴다. 기존 `ssal-phase2-log.so`가 liblog fatal 메시지를 같은 stderr pipe로 보낸다. Host crash socket을 연결하거나 crash daemon을 띄우지 않는다.
- [build-guest-launcher.sh](../scripts/build-guest-launcher.sh)가 NDK로 새 `.so`를 빌드한다. 향후 승인된 실기기 stage에는 기존 네 파일에 `ssal-zygote-diag.so`를 함께 넣어야 한다. 별도 Phase 7B 실행 모드 없이 기존 Zygote launcher 경로를 재사용한다.
- [run-guest-launcher.sh](../scripts/run-guest-launcher.sh)는 진단 디렉터리가 있으면 경로를 출력한다. 예: `/dev/ssal-common-launcher/run-<epoch>/worker/phase7b`. rootfs unmount 뒤에도 이 세션 디렉터리는 남는다. **향후 실행에서 세션 tmpfs를 지우거나 재부팅하기 전에 해당 디렉터리를 로컬로 pull해야 한다.** 이번에는 stage/실행/pull을 하지 않았다.

## 실기기 읽기 전용 결과와 메모리 경계

상세 결과는 [로그 분석](../out/phase7b/log-analysis.md), [cgroup 분석](../out/phase7b/cgroup-analysis.md), [보존한 읽기 전용 증거](../out/phase7b/cgroup-readonly.txt)에 있다.

2026-11-05 00:01:17 KST 관측에서 `/sys/fs/cgroup/cgroup.controllers`는 `memory`, root `cgroup.subtree_control`은 비어 있다. `/sys/fs/cgroup/apps`의 controllers/subtree_control도 비어 있고 memory.current/max/high/events가 없다. 실제 launcher의 v2 대상 `/sys/fs/cgroup/apps/ssal_guest`는 정리되어 존재하지 않는다. [증거 18행](../out/phase7b/cgroup-readonly.txt#L18), [23행](../out/phase7b/cgroup-readonly.txt#L23), [28행](../out/phase7b/cgroup-readonly.txt#L28).

현재 경로에서 Guest leaf의 memory.max/high만 쓰는 것으로 해결되지 않는다. 우선 Host 공통 ancestor에서 memory controller를 전달해야 하며 이는 Guest 전용 limit 설정과 구분되는 Host 계층 변경이다. 이번에는 어떤 cgroup 파일에도 쓰지 않았다. 안전한 전용 부모 위치, Host 프로세스 배제, 전체 Guest membership, 적절한 예산과 OOM 동작은 UNKNOWN이다.

새 계측은 서비스 child가 Guest cgroup에 가입한 뒤의 관측 경로다. worker/APEX 준비와 공유 file cache의 비용 전체가 그 cgroup에 charge된다는 보장은 없다. 새 진단 코드가 메모리 보호를 제공하거나 7A의 LMK 영향을 해소하지 않는다. **메모리 보호가 별도로 검증될 때까지 Guest Zygote 재실행을 보류한다.**

읽기 전용 전후 표본의 Host zygote, zygote_next, system_server, installd, lmkd, tombstoned는 PID/starttime/context가 같았고 global Enforcing과 boot ID도 같았다. debuggerd 프로세스는 표본에 없고 on-demand 동작은 검증하지 않았다. 전체 Host 상태 또는 장기간의 무영향을 증명하는 결과는 아니다. [전후 증거](../out/phase7b/cgroup-readonly.txt#L31).

## crash 분석 결과와 수집 한계

기존 PID/TID 15920의 23:21:35 SIGABRT/SI_QUEUE만 직접 확인된다. 원인 fatal 메시지·backtrace·tombstone이 없어 원인은 **UNKNOWN**이다. 이전 실행과 같은 시간대의 Host lmkd cached app 회수 27건은 시간상 연관일 뿐 Guest의 기여량이나 abort 원인을 확정하지 못한다. linkerconfig 및 property warning도 원인으로 분류하지 않았다. [분석의 원본 경로·행 번호](../out/phase7b/log-analysis.md).

새 interposer는 동적 심볼을 통해 호출되는 `abort()`의 수집 가능 경로다. 직접 전달된 SIGABRT, libc 내부에서 interposition을 우회하는 호출, unwinder/loader lock 문제, Java managed stack, Android 실제 ART fatal 전달은 검증되지 않았다. PC 프레임은 해당 Guest 빌드의 심볼로 offline symbolization이 필요하다. tombstone 생성을 보장하지 않으며 Host debuggerd/tombstoned를 대체하지 않는다. 스트림 상한을 넘는 fatal 및 마지막 미수집 tail은 유실될 수 있다.

## 검증 기록

기존 WSLc `ssal-dev`에서 sandbox 밖으로 실행했으며 기기 배포는 하지 않았다.

| 검사 | 결과·보존 파일 |
|---|---|
| `cargo test --locked --bin ssald` | 40 passed, 0 failed, 3 ignored — [ssald-tests.txt](../out/phase7b/ssald-tests.txt) |
| `cargo test --locked --lib` | 15 passed, 0 failed — [lib-tests.txt](../out/phase7b/lib-tests.txt) |
| `python3 scripts/test-zygote-diagnostics.py` | native stderr marker, ≤64 frames, SIGABRT 보존 PASS — [native-tests.txt](../out/phase7b/native-tests.txt) |
| `bash scripts/build-guest-launcher.sh` | Android AArch64 ssald/helper 및 새 진단 `.so` 빌드 PASS — [android-build.txt](../out/phase7b/android-build.txt) |
| 수정 Rust 파일 rustfmt / 대상 파일 diff whitespace | PASS |

새 Rust 시험은 pipe 용량을 넘는 1,200,000-byte 출력의 drain과 저장 상한, stderr 분리, 없는 memory controller의 unavailable 처리, exit code와 SIGABRT, 열린 후손 writer의 bounded 최종 drain, 실제 Service readiness 실패→Drop 진단 보존을 포함한다. ignored 3건은 기존 환경 의존 시험이며 이번에 실행했다고 계산하지 않는다.

최종 Android 산출물 SHA-256:

```text
ssald               c9c6ace5cdeb94759af8de9aa4761b12a879a376debbd215e57e233346ab9455
ssal-zygote-diag.so  92d7023d4325e62e19731b2e951e88cd565ac569fcd578283d0b0d60ba79d1b8
```

## 별도 backlog

1. Host 공통 ancestor 변경 없이 가능한 memory controller 전달 경로를 확정하거나, 필요한 Host 변경의 별도 범위를 결정한다. APEX/worker/shared-cache 비용, membership/Host 배제, limit readback·OOM·PSI·cleanup을 검증한다.
2. 메모리 보호 검증 후에만 새 진단 바이너리의 실기기 회귀 및 Zygote 진단을 수행한다. Android ART/liblog/abort interposition과 PC symbolization을 확인한다.
3. 실제 출력이 상한에 도달하면 tail 보존을 보완한다. 유효한 fatal/backtrace가 확보된 뒤 원인 수정을 판단한다.
4. artd dexopt/OAT/VDEX는 기존 별도 backlog를 유지한다.

자동 Fix 체인이나 후속 실행 작업을 생성하지 않았다. vendor 대규모 소스 조사와 추측 기반의 abort 수정도 수행하지 않았다.
