# Phase 8B-5 — Guest System Server Runtime SID

2026-11-06 KST. **FAIL / NO-GO — 첫 단발 실행 직후 사용자가 기기 전원 종료를 보고했고 ADB 연결도 소실됐다.** 실제 fork 또는 최종 SID 획득을 입증할 출력을 회수하지 못했다. Host 상태 보존과 안전 조건 충족을 주장할 수 없다. 재실행, 자동 재부팅 및 추가 기기 조작을 중단했다.

## 관측 결과

| 시점 / 증거 | 관측 | 판정 범위 |
|---|---|---|
| 실행 전 `adb devices -l` | `R5CY52JC03H`, SM-S937N, device | 연결 확인 |
| 실행 전 read-only shell | `getenforce=Enforcing`, boot ID `03834516-215d-4fd6-8960-1b833882595e` | 실행 전의 일부 상태만 확인 |
| staging 명령 | `/dev/ssal-phase8b5/` 생성, 기존 7I helper 재사용, 새 산출물 5개와 runner 전송 성공 | 전송 확인; runtime 적용/실행 성공과 다름 |
| 약 04:36:50 KST | `adb shell su -c 'sh /dev/ssal-phase8b5/run.sh'` 한 번 실행 | 단발 시도 |
| `out/phase8b5/run1-console.txt` | 길이 **0 byte** | worker 시작, namespace admission, fork, setter 결과 모두 알 수 없음 |
| 후속 read-only 조회 | `adb: no devices/emulators found`, 이어서 `adb devices -l` 목록 비어 있음 | 연결 소실 |
| 사용자 보고 | “폰이 꺼졌네요” | 전원 종료 보고; 커널 panic/reboot/OOM 원인 확정 아님 |

runner는 worker 실행이 끝난 뒤 필터된 결과를 출력하고, 그 전에 기기 `/dev`에 snapshot과 worker 로그를 저장하도록 작성됐다. 따라서 로컬 콘솔이 비었다는 사실만으로 **worker 미실행 또는 fork 미실행을 결론내릴 수 없다.** 기기의 runtime stage 경로도 회수하지 못했다. 프로세스 종료 코드나 로컬 shell 반환을 기기 진단 성공 근거로 사용하지 않는다.

이번 실행과 전원 종료의 시간적 연관성은 있지만, 어느 syscall/단계에서 발생했는지는 확인되지 않았다. pstore, last-kmsg, boot reason, 커널 로그 및 실행 중 snapshot은 미확보다. 원인 규명 없이 SELinux, KSU, cgroup 또는 GSI 코드 중 하나를 원인으로 지목하지 않는다.

## 준비한 진단 경로 — 실기기 성공 근거가 아님

기존 [KSU native SID 검증](phase8b-guest-system-server-sid-ksu.md)과 `out/phase8b-sid/patched/`의 runtime/seapp 산출물을 재사용했다. 원본 GSI 이미지, 기존 SID 패치 산출물 및 Host module policy 파일은 수정하지 않았다. `vendor/` 소스는 읽지 않았다. 이번 단계에서 `ksud sepolicy apply/check/patch` 또는 type 추가/삭제를 실행하지 않았다.

- [`patch-system-server-runtime-gate.py`](../scripts/patch-system-server-runtime-gate.py)는 기존 SID runtime SHA-256을 확인하고 **별도** 진단 runtime을 만든다. 파일 offset/VA `0x260dd4`의 `cbz w0, 0x260e80`를 `b 0x29bf70 <_exit@plt>`로 바꾼다. 최종 `selinux_android_setcon` 호출은 보존하며 반환하면 성공/실패 모두 종료한다. 이 제어 흐름은 objdump로 확인했다. 실제 로드 및 gate 실행은 확인하지 못했다.
- [`system_server_runtime_sid.rs`](../src/guest_launcher/system_server_runtime_sid.rs)는 opt-in flag `SSAL_PHASE8B5_ONCE=1`, 기존 7I private Binder/property/userdata와 fork 준비 경로를 사용하도록 추가했다. 다른 SELinux 진단/bypass flag와 혼용을 거부하고, 별도 mount namespace/private propagation 및 pinned runtime/seapp hash 확인 뒤 Guest에만 read-only overlay하도록 작성했다. 기존 app-only seapp overlay 위에 이번 patched seapp 파일을 적용한다.
- [`system-server-runtime-sid.c`](../native/binder-probe/system-server-runtime-sid.c)는 GSI의 원래 startup/final setter를 호출하고 mmap에 SID/반환값/errno와 property 재초기화를 기록한다. constructor에서 Guest mount namespace, global Enforcing, 기존 두 Guest context 유효성과 access vector의 permissive flag 부재를 검사하도록 작성했다. 해당 검사가 실기기에서 통과했는지는 알 수 없다.
- startup 성공은 원래 호출자에게 반환하고, final setter 후에는 Java로 돌아가지 않고 `_exit`한다. final callsite 도달은 앞선 ART system-server hook이 pending exception 없이 반환했다는 제어 흐름 근거로만 사용하도록 설계했다. ART 내부 작업 전체 성공을 별도로 측정한 것은 아니다.
- disposable canary는 worker가 직접 소유하는 별도 executable로, Guest chroot 밖에서 UID/GID 1000, groups 없음, stock `system_server` SID로 대기하도록 작성했다. final Guest SID에서 `kill(canary,0)`과 proc root/fd/fd0 open만 수행하고 파일 내용을 읽거나 ptrace/실제 signal을 보내지 않는다. 소유 parent의 canary 생존 및 proc 접근 대조가 있어야 차단으로 판정한다. **이번에 canary 생성·검사·회수가 실행됐다는 증거는 없다.**
- 기존 `Service`의 소유 process-group 종료와 reap, worker의 mount/loop/cgroup/property/Binder 정리 경로를 재사용했다. Host 서비스 PID를 signal 대상으로 지정하는 코드는 추가하지 않았다. 정상 정리 경로의 존재가 이번 실행의 정리 완료를 뜻하지 않는다.

Host `/proc` mount/remount, hidepid=4, global permissive, stock SID fallback, Host 서비스 stop 또는 reboot 명령은 실행하지 않았다. 기존 memory lifecycle은 Host 공용 cgroup ancestor controller를 일시 변경하는 [8B-4B-1의 제한](phase8b4b1-system-server-preflight.md)을 그대로 가진다. 이번 실행에서 그 단계가 수행됐는지 또는 전원 종료와 관련됐는지는 미확인이다.

## 로컬 검증 및 산출물

- WSLc는 저장소 지침대로 sandbox 밖에서 실행했다.
- `cargo test --locked --bin ssald`: **52 passed, 0 failed, 4 ignored**. 추가된 테스트는 gate 없는/손상된 runtime의 거부를 검사했다. ignore 4개는 권한이 필요한 기존 테스트다.
- Android arm64 진단 library/canary `-Wall -Wextra -Werror` 빌드, Android launcher release 빌드 및 runner shell syntax 검사 통과. launcher 빌드에는 기존 memory probe dead-code 경고가 있었다.
- 이는 빌드·정적 검증이며, 실제 GSI gate 실패 주입이나 이 hook의 runtime 정상 동작 검증은 완료하지 못했다.

| 전송 산출물 | SHA-256 |
|---|---|
| 진단 runtime | `89ed7a21342583b3c3c598c55db75bdc759ff56567da0bc2479a2f1adc3d26fc` |
| 재사용 patched seapp | `5dedabe4fc84cb3344f55bb9e054e92b008fedee847deae7f6f4ad7c7b639d0b` |
| runtime SID library | `88d5173f5414bf77deb6f092060550d1df7d53765a999bd704fbd1a37fedc3c5` |
| canary | `0b89c0f7391fc1ef0d4fa7b79ff21bf534e1210eee22c8beebec45c384cae448` |
| 실행한 ssald | `bfc54f41f7bb8b039ae3939e2b61f7cf6079686fdf77786f720eec513bbd6e51` |

실행 당시 runner/source 및 manifest는 `out/phase8b5/launched-runner.sh`, `launched-system_server_runtime_sid.rs`, `launched-sha256.txt`에 보존했다. 전원 종료 보고 후 저장소 runner에는 즉시 NO-GO 종료를, launcher admission에는 명시적인 오류를 추가했다. **기기에 이미 전송했던 binary/runner를 수정하거나 회수한 것은 아니다.** 로컬 산출물과 원격 상태를 혼동하지 않는다.

## 미검증 항목 및 완료 판정

| 완료 기준 | 이번 관측 |
|---|---|
| Guest 전용 mount namespace / 실행 경계 확보 | 결과 미회수 |
| 실제 GSI `forkSystemServer()` 도달 | 미확인 |
| startup → `u:r:ssal_guest_ss:s0` | 미확인 |
| UID/GID, supplementary groups, capabilities, seccomp | 미확인 |
| 원래 `selinux_android_setcon()` 반환값 | 미확인 |
| property 재초기화 및 ART hook | 미확인 |
| final Guest SID에서 global/domain Enforcing | 미확인 |
| Host canary signal/proc 차단 | 미확인 |
| Framework 진입 전 gate의 실제 종료 | 미확인 |
| Guest child/canary reap 및 mount/cgroup/loop 정리 | 미확인 |
| Host 핵심 서비스, SELinux, mount namespace, cgroup, Binder, property 전후 보존 | **확인 불가** |

**FAIL / NO-GO.** 최종 SID 획득 증거가 없으므로 PARTIAL도 아니다. 기기 복구 후 재시도에 앞서 보존된 crash/boot 증거와 현재 Host 상태부터 확인해야 한다. 이 문서를 작성하는 동안 자동 재부팅·재연결 반복·실험 재실행은 하지 않았다.
