# SSAL Phase 5A-Diag-Fix — 결과

- 검증일: 2026-11-04 (Asia/Seoul)
- 기기: Samsung SM-S937N, Android 17 Host
- 최종 판정: **BLOCKED / NO-GO**
- 범위: active SELinux policy 원인 확인, read-only 상태 점검, Phase 2–4 코드 회귀 검사. 소스와 SELinux 정책은 변경하지 않았고 진단 child는 생성하지 않았다.

## 1. SELinux context 실패 원인

현재 loaded policy를 기기에서 읽어 로컬에서 해시와 SETools 결과를 확인했다. policy SHA-256은 `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723`이다. 현재 policy에서 `seinfo -t ssal_guest_probe`와 `seinfo -t ssal_guest_probe_exec`는 각각 `Types: 0`을 반환했다. 알려진 유효 type `ksu`는 `domain` attribute로 정상 조회됐다.

따라서 `u:r:ssal_guest_probe:s0`의 SELinuxFS context→SID 변환 `EINVAL (22)` 원인은 **active policy에 process type `ssal_guest_probe`가 없음**이다. 별도 `ssal_guest_probe_exec` 파일 type도 active policy에 없다. 임시 helper inode에 저장된 `u:object_r:ssal_guest_probe_exec:s0` 문자열은 파일 라벨이 설정됐다는 뜻일 뿐, 현재 policy가 그 type을 정의한다는 뜻은 아니다. `_exec` 파일 type과 `u:r:` process domain은 서로 다른 type이다.

MLS/MCS 및 role을 별도로 확인했다. active policy에는 sensitivity `s0`가 있고, user `u`는 role `r` 및 range `s0 - s0:c0.c1023`를 가진다. 이 범위에서 `s0` 자체는 유효하다. 다만 target type이 없으므로 target의 `domain` attribute와 `role r` 연결은 현재 policy에 존재할 수 없다. 이 결과는 role 또는 MLS range 오류보다 **type 부재**를 직접 가리킨다.

2026-11-01에 저장한 과거 policy dump(SHA-256 `591b6588474b2a36e03d66179a5ce0cbd2ee902c0104f5478b159d7d9dc788bb`)에는 두 type이 있었고, `ssal_guest_probe`는 `domain` 및 role `r`, `ssal_guest_probe_exec`는 `file_type` 및 role `r`에 연결돼 있었다. 해당 dump의 규칙에는 `allow ksu ssal_guest_probe process transition`과 target→helper의 `file { read map execute entrypoint }`가 있었다. target에 대한 별도 `type_transition` 규칙은 해당 dump에서 확인되지 않았다. 런처는 자동 type transition 대신 `/proc/thread-self/attr/exec`에 고정 context를 지정하는 명시적 `setexec` 경로를 사용한다. 이 과거 dump는 현재 loaded policy의 증거로 사용하지 않았다.

현재 target type가 없어 `process:transition`, helper `file:entrypoint/execute`, target `process:getattr` 또는 Host 핵심 process의 `process:signal/ptrace`를 유효한 target SID로 조회할 수 없다. 이전 Phase 5A 기기 read-only preflight도 target context 검증과 SELinuxFS AV query에서 `EINVAL`로 중단했다. Host에 signal을 보내거나 ptrace attach하지 않았다.

## 2. 정책 변경, 원복 및 KernelSU 한계

| 관측 | 실행 전 | 실행 후 | 판정 |
|---|---|---|---|
| Global SELinux | Enforcing (`/sys/fs/selinux/enforce=1`) | Enforcing | PASS |
| Loaded policy SHA-256 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` | 동일 | PASS, 변경 없음 |
| 설치된 `sepolicy.rule` SHA-256 | `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389` | 동일 | PASS, 변경 없음 |
| 임시 KSU policy patch | 적용 안 함 | 적용 안 함 | PASS, 변경 없음 |
| 원복 | 적용하지 않아 원복 작업 없음 | 해당 없음 | 적용 전 상태 보존 |

기기의 `ksud`는 `samsung-v2.2 (uapi:5)`이며 `sepolicy --help`에는 `patch`, `apply`, `check`가 있고 live patch 제거/rollback 명령은 없다. 기존 기기 기록과 KernelSU 정책 코드 검토에서도 live patch의 원자적 되돌리기 또는 no-reboot 복구가 확인되지 않았다. `enforce ssal_guest_probe`는 permissive 상태만 바꾸며 type과 allow 규칙을 제거하지 않는다. 정책 patch를 적용한 뒤 이를 복구할 수 없을 위험이 있어, **test-only patch도 실제 적용하지 않았다**. 전역 Permissive, 광범위 allow, Host 도메인 권한 변경은 없었다.

정책 적용 전/후 hash와 상태를 대조한 결과는 동일하다. 이는 정책 변경 후 원복 시험을 뜻하지 않는다. 변경 자체를 하지 않았으므로 정책 복구 절차는 검증할 대상이 없었다. 다음 시도에 필요한 최소 전제는 `ssal_guest_probe`를 `domain`으로, `ssal_guest_probe_exec`를 `file_type`으로 active policy에 포함하고 role 연결 및 명시적 전환/entrypoint/실행 AV를 구성하는 것이다. 정확한 규칙을 AV query로 확인하고, 안전한 rollback을 먼저 검증하기 전에는 runtime patch를 적용하지 않는다.

## 3. Guest namespace, `/proc`, `/dev`

같은 날 실행된 disposable Guest worker 기록을 재사용했다([Phase 5A validation](rsbinder-phase5a-validation.md)). worker는 Host `mnt:[4026532950]`와 다른 `mnt:[4026536262]`에서 실행했고, mount propagation을 private로 설정했다. 새 Guest rootfs에 `/proc`를 type `proc`, `nosuid,nodev,noexec`로 mount하는 기존 worker 경로를 사용했으며, Guest `/dev`는 tmpfs였다.

실기기 worker에서 확인한 Guest `/dev` allowlist는 `binderfs`, `block`, `null`, `random`, `socket`, `urandom`, `zero`였다. tmpfs는 4 MiB, mode `0755`, `rw,nosuid,noexec`였고 `/dev/null`, `zero`, `random`, `urandom`만 확인된 rdev로 bind됐다. Host Binder node, Binder control, property area/socket 및 HAL node는 Guest `/dev`에서 보이지 않았다. 이 결과는 disposable mount composition의 증거이며, 새 child 내부에서 경로 접근이 거부됨을 뜻하지 않는다.

해당 worker는 기존 Guest executable gate에서 중단돼 Guest linkerconfig나 Android service를 실행하지 않았다. 이번 Diag-Fix에서도 child가 없으므로 `/proc` mountinfo와 child의 실제 visibility, chroot root identity, Host `/proc` 경로 차단은 측정하지 않았다. 기존 worker는 mount namespace만 분리한다. **PID 및 IPC namespace 분리는 확인되지 않았고, 이 결과에서 격리됐다고 판정하지 않는다.**

## 4. Child 자격·context·FD 실측

진단 child는 생성되지 않았다. 따라서 exec-stop에서 UID/GID `1000:1000`, supplementary groups `[3009]`, capability bounding/effective/permitted/inheritable/ambient set 0, `no_new_privs=1`, `u:r:ssal_guest_probe:s0`, helper hash, stdio/trace FD만 남았는지 실측한 결과는 모두 **UNKNOWN**이다. SELinux context SID 변환 실패가 child 생성 전 차단점이었다.

현재 source에는 ProcOnly용 credential drop 및 exec-stop credential/FD 확인 코드가 있으나, 그 코드가 기기 child에서 검증된 것은 아니다. 추가로 현재 ProcOnly 경로는 Host mount namespace를 기준으로 하고 Guest worker의 rootfs로 chroot하는 연결이 없다. child 환경에도 `SSAL_PROC_ONLY=1` 이외에 `SSAL_STAGE_FD`, `SSAL_HOST_CORE_PIDS`가 전달된다. 따라서 이번 요구의 “실제 Guest root/proc와 정확히 하나의 환경 변수” 조건을 아직 충족하지 않는다. policy 선행 조건이 안전하게 해결된 뒤, 기존 worker namespace에서 launcher를 호출하고 rootfs 안에서 child를 시작하도록 연결하며 trace FD와 Host PID 목록은 FD/argv로 전달해야 한다.

## 5. Host 경계 판정

| 경계 | 상태 | 근거 |
|---|---|---|
| Host `/proc/<pid>/root` 접근 | UNKNOWN | child 없음; 실제 접근 시도 없음 |
| Host `/proc/<pid>/fd` 접근 | UNKNOWN | child 없음; 실제 접근 시도 없음 |
| Host root 및 민감 Host FD 접근 | UNKNOWN | child 없음; 실제 FD 접근 시도 없음 |
| Host 핵심 process `signal` / `ptrace` AV | UNKNOWN | target SID 변환 실패로 AV query 불가; 실제 signal/ptrace 없음 |
| Private Binder 및 Host property endpoint의 Guest `/dev` 노출 | PASS (mount composition 범위) | disposable worker에서 해당 node/socket 부재 확인 |
| Child에서 Private Binder/Host property 경로 접근 | UNKNOWN | child 없음; Host Binder/property service에 연결하지 않음 |
| Guest `/dev` allowlist | PASS (disposable worker 범위) | 기존 same-day worker의 정확한 allowlist 확인 |
| Guest `/proc` mount 및 visibility | PARTIAL | worker 구성에서 fresh proc mount; child 가시성/Host PID 접근은 미측정 |
| PID/IPC namespace separation | UNKNOWN / 제한 유지 | MNT만 분리. PID/IPC 분리 주장은 하지 않음 |

SELinuxFS AV query와 실제 접근 시험은 구분했다. AV query 자체가 target SID 부재로 실패했으며, 접근 시험은 child 미생성으로 실행하지 않았다.

## 6. Binder/SELinux 회귀

요청한 코드 회귀 검사를 기존 `ssal-dev` 컨테이너에서 실행했다.

| 검사 | 결과 |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| Root workspace (`phase3-diagnostic`) | PASS: 77 passed, 3 ignored (privilege/mount 의존) |
| Phase 2 crate | PASS: 1 passed |
| Phase 3 crate | PASS: 명시적 test 없음 |
| Android AArch64 `cargo check` | PASS |
| Android AArch64 `cargo check --tests` | PASS |
| Phase 2–4 device Binder/SELinux runner 재실행 | 이번 실행에서 하지 않음 |

`ssal-enforcing-binder` 및 Guest namespace/Binder 관련 unit test는 root workspace 결과에 포함된다. Phase 4의 Private Binder/AIDL device 성공 및 runtime rule 원복은 [Phase 4 결과](rsbinder-phase4-results.md)의 기존 기록을 재사용했다. 이 보고서의 새 기기 child 시험으로 간주하지 않는다.

## 7. Host 상태 및 cleanup

이 Diag-Fix 확인 구간에서는 정책 적용, Guest worker 실행, child 실행, property write, Binder 연결, Host service 조작을 하지 않았다. read-only snapshot의 시작과 종료에서 주요 Host process PID/starttime/context/executable이 같았다. 조사에 사용한 로컬 policy binary 복사본은 SHA-256과 SETools 조회를 기록한 뒤 삭제했다.

| Host 상태 | 시작 / 종료 | 판정 |
|---|---|---|
| SELinux policy | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` / 동일 | PASS |
| 설치된 `sepolicy.rule` | `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389` / 동일 | PASS |
| Host mount namespace | `mnt:[4026532950]` / 동일 | PASS |
| `/proc/1/mountinfo` SHA-256 | `a305108be07a09622a4a10e64a89c5642f0934fbe1fa7439551c21716419c83d` / 동일 | PASS |
| init | PID 1, starttime 0 / 동일 | PASS |
| servicemanager | PID 942, starttime 374 / 동일 | PASS |
| zygote64 | PID 1854, starttime 609 / 동일 | PASS |
| system_server | PID 3059, starttime 774 / 동일 | PASS |
| surfaceflinger | PID 2108, starttime 656 / 동일 | PASS |
| installd | PID 2607, starttime 712 / 동일 | PASS |
| netd | PID 1852, starttime 608 / 동일 | PASS |
| adbd | PID 30624, starttime 19688121 / 동일 | PASS |
| artd | PID 29657, starttime 24121174, `running` / 동일 | PASS for this read-only window; earlier report's state change remains unexplained |
| Host property digest | `f7ade46ae744437ad2e91de80cffc8ec07406979bc7589679b402b809f3c42a2` / 동일 | PASS for this window; earlier cross-run digest changes remain unattributed |
| `losetup -a` sorted digest | `d2e1a08a6c6b5d62398260cb701f2acf9ccd93208e1495f9bfdfc2b55233a42e` / 동일 | PASS, no loop delta in this window |

Earlier same-day disposable worker cleanup passed: Guest rootfs mounts were absent after cleanup, all 55 loop-backed system/APEX resources were released, and its unique test directory was removed. No existing profile/userdata or `/data/adb/modules/ssal/bin` file was changed here. The previously existing `/data/local/tmp/ssal-proc-preflight-20261101` staging directory was left untouched. The current loop digest differs from an earlier snapshot (`5e35394f219683694eaea06eaf1c7bf6f2c422335e6491eab4444800b98f11da`); that cross-window change is not attributable to this read-only Diag-Fix check.

## 8. 다음 단계 진입 여부

**Phase 5A 제한 진단 child: NO-GO. Phase 5B 및 Guest service 실행: NO-GO.** 현재 active policy가 요구된 process/file type을 정의하지 않아 SID 생성 및 AV query가 불가능하다. 또한 KSU live policy patch의 안전한 no-reboot rollback을 확인하지 못했으므로 이번 단계에서 policy를 적용하지 않았다.

다음 실행에 필요한 최소 작업은 다음과 같다.

1. `ssal_guest_probe` domain type와 `ssal_guest_probe_exec` file type을 active policy에 안전하게 포함하고 `role r`, entrypoint, 실행 및 명시적 전환에 필요한 최소 규칙을 검증한다. 적용 전 rollback을 실제로 검증하고, 불가능하면 재부팅 없이 live patch하지 않는다.
2. 유효한 SID에서 모든 required AV query를 실행한다. Host 핵심 process의 `signal`/`ptrace`는 전부 Enforcing deny여야 한다.
3. ProcOnly를 기존 disposable worker의 MNT namespace/rootfs에 연결하고 child를 Guest root 안에서 실행한다. stdio/trace 이외 FD, exact `SSAL_PROC_ONLY=1` env, 실제 credential/context/FD를 exec-stop에서 확인한다.
4. 그 조건이 모두 통과한 뒤에만 child를 재개해 Host `/proc`, FD, Binder/property endpoint, `/dev` 경계를 실제로 측정한다.

현재 결과는 정책 precondition을 또 추가한 것이 아니라 active policy에서 그 precondition이 실제로 충족되지 않음을 parser로 확인한 중단 결과다. 복구 불가능할 수 있는 runtime policy 변경 없이 child를 실행하는 방법은 확인되지 않았다.
