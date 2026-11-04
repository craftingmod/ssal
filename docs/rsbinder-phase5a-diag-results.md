# SSAL Phase 5A-Diag — 결과

- 검증일: 2026-11-04 (Asia/Seoul)
- 기기: Samsung SM-S937N, Android 17 Host
- 판정: **PARTIAL**. 진단 child 실행은 active SELinux policy에서 target context를 SID로 변환할 수 없어 중단했다.
- 범위: `ssal-property-area-live-poc`의 `SSAL_PROC_ONLY=1` 진단 경로. Guest Android 서비스, linkerconfig, zygote, system_server는 시작하지 않았다.
- 전역 Guest executable gate, SELinux Enforcing, 기존 policy 및 `sepolicy.rule`은 유지했다.

## 1. SELinux AV query `EINVAL`

기존 `--proc-only-preflight` 재현에서 global SELinux는 Enforcing이었다. 알려진 유효 context인 `u:r:ksu:s0 → u:r:ksu:s0`의 `process:getattr` query는 응답했지만, `u:r:ssal_guest_probe:s0` 또는 그 context를 대상으로 한 query는 `EINVAL (22)`, 빈 응답, `allowed_mask=unknown`으로 끝났다. Enforcing은 정책 모드이며, 그 자체로 특정 접근의 허용을 뜻하지 않는다.

SELinuxFS `/access` 요청은 source context, target context, class index를 전달하고 context를 SID로 변환한 뒤 access vector를 조회한다. [Linux SELinuxFS 구현](https://github.com/torvalds/linux/blob/master/security/selinux/selinuxfs.c)을 기준으로 요청 형식, class index 폭(`u16`), permission 번호를 1부터 시작하는 bit 위치로 변환하는 부분을 점검했다. `permission_mask`와 응답 mask 파싱에 단위 회귀 검사를 추가했다.

수정한 Android launcher와 reporter로 기기 preflight를 다시 실행했다. launcher/helper SHA-256, ELF 형식, helper SELinux label을 통과하고 `global_enforcing=true`, `cap_last_cap=40`을 관측했다. `/sys/fs/selinux/context` 검증에서 `u:r:ksu:s0`는 유효했지만, target `u:r:ssal_guest_probe:s0`는 `EINVAL (22)`로 거부됐다. 따라서 이번 실패는 class/permission mask 해석 전에 발생하며, active policy가 target context를 SID로 변환하지 못하는 것이 직접 원인이다. 거부된 구성 요소가 type, role, range 중 무엇인지는 이 검증만으로 구분하지 않았다.

코드는 AV query 전에 source, target, helper context의 변환을 확인하고 오류를 명시하도록 했다. invalid context 또는 query 오류는 계속 fail-closed이며 허용으로 취급하지 않는다. 현재 기기 run은 target 검증에서 중단되어 helper context 변환 및 후속 `signal`/`ptrace` AV 결정을 실행하지 않았다. 기존 policy와 `sepolicy.rule`은 변경하지 않았다.

## 2. 진단 child 자격 증명 및 artifact

수정한 launcher는 다음 값을 child에서 설정하고, syscall 결과와 exec-stop 시 `/proc/<pid>/status`를 검사하도록 구성했다. 이번 기기 실행은 child 생성 전 중단됐으므로 **실제 child 값은 관측되지 않았다**.

| 조건 | child 경로의 강제·검증 | 기기 관측 |
|---|---|---|
| UID/GID | real/effective/saved UID와 GID를 각각 `1000`으로 설정·확인 | 미관측: child 없음 |
| Supplementary groups | 정확히 `[3009]` 설정·확인 | 미관측: child 없음 |
| Permitted/Effective/Inheritable capabilities | `capset`으로 전부 0, `capget`으로 확인 | 미관측: child 없음 |
| Ambient capabilities | clear-all 후 각 capability가 0인지 확인 | 미관측: child 없음 |
| Bounding capabilities | 기기 `cap_last_cap=40`; `0..=40` 제거 후 전 항목 확인 | 준비 단계만 관측, child 미생성 |
| `no_new_privs` | `PR_SET_NO_NEW_PRIVS=1` 후 조회 | 미관측: child 없음 |
| SELinux context | exec 대상 `u:r:ssal_guest_probe:s0` | **설정 전 차단**: active policy SID 변환 실패 |
| FD allowlist | stdin `/dev/null`, stdout/stderr 수집 pipe, 명시적 trace pipe만 유지. exec-stop에서 child FD 목록 확인 | 미관측: child 없음 |

기기에서 확인한 artifact:

| Artifact | SHA-256 | 기기 label / 결과 |
|---|---|---|
| 새 AArch64 `ssal-guest-domain-poc` launcher | `ad88086386070cc4a6ef3be598fb7a4834ab20207b733d3daa8f20732ac2acbe` | `shell_data_file`, mode `0755`; `/system/bin/linker64`, `libc.so`, `libdl.so` 사용 |
| 수정한 native proc reporter | `d223460dc36a4ee491a4c68e16cf41a6377003340a2aa5b247247538deda404e` | `ssal_guest_probe_exec`, mode `0755`; static ELF64 AArch64, `PT_INTERP`/`NEEDED` 없음 |

reporter는 `O_PATH`로 Host `/proc/<pid>/root` 경로 접근을 확인하고 `/proc/<pid>/fd` 목록만 열거하도록 구성했다. Host FD target을 열지 않고, Host 프로세스에 signal을 보내거나 ptrace attach를 하지 않는다. 이 reporter probe는 child가 실행되지 않아 **기기에서 실행되지 않았다**.

## 3. Host 경계 및 Guest `/dev`

| 경계 | 결과 |
|---|---|
| Guest mount namespace | 같은 날 disposable worker 검증에서 Guest `mnt:[4026536262]`, Host `mnt:[4026532950]`로 분리됨. 현재 `ProcOnly` child 경로는 mount-free이며 Host mount namespace와 같아야 하는 기존 검사다. 이 진단 child가 실제 Guest namespace에 들어가는지는 **UNKNOWN**이며, Guest 실행 경로로는 아직 승인할 수 없다. |
| Guest `/proc` 및 Host `/proc/<pid>/root` 접근 | child의 제한 probe는 코드에 추가됐지만 실행되지 않아 runtime 결과 **UNKNOWN**. |
| Host `/proc/<pid>/fd` 및 민감한 Host FD 접근 | FD target 미개방 방식은 코드로 구성했으나 child 미실행. 실제 차단 여부 **UNKNOWN**. |
| Host 핵심 프로세스 `process:signal` / `process:ptrace` | target SID 변환 실패로 AV query 미실행. Host에 signal을 전달하거나 ptrace attach하지 않음. 접근 여부 **UNKNOWN**. |
| Guest `/dev` allowlist | 같은 날 disposable worker에서 `binderfs`, `block`, `null`, `random`, `socket`, `urandom`, `zero`만 확인. Host Binder, property, binder-control, HAL endpoint가 그 Guest `/dev`에 없었음. 이번 preflight에서는 child가 없어 재실행하지 않음. |

이번 snapshot에서 Host에는 `/dev/binderfs/binder` (`507:1`), binder-control (`507:0`), Host property area와 `property_service` socket, GPU (`kgsl-3d0`, `462:0`), dma-heap 및 video 노드가 존재했다. Binder/property/HAL Host node는 before/after metadata가 같았다. 이는 Host 측 존재 확인이며 Guest에 노출됐다는 뜻은 아니다. Guest 측 부재는 위 같은 날 disposable worker 결과를 재사용했다. 자세한 Guest `/dev` 검증은 [Phase 5A validation](rsbinder-phase5a-validation.md)을 참조한다.

## 4. 회귀 결과

| 검사 | 결과 |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| Linux root workspace tests | PASS: 77 passed, 3 ignored |
| Phase 2 crate | PASS: 1 passed |
| Phase 3 crate | PASS: `cargo test` 성공, 정의된 test 없음 |
| Android AArch64 launcher build | PASS |
| Android AArch64 `cargo check --tests` (diagnostic bin) | PASS |
| native reporter build | PASS: static AArch64 ELF, 동적 interpreter/dependency 없음 |
| Phase 4 Binder/AIDL 기기 회귀 | 같은 날의 [Phase 4 결과](rsbinder-phase4-results.md) 재사용. 이번 진단에서는 반복하지 않음. 해당 Phase 4 runtime policy 원복 기록은 그 결과 문서를 참조한다. |

새 Rust 검사에는 credential allowlist, SELinux permission bit 변환, Enforcing 상태별 fail-closed 처리, Host `/proc` report 필드 검증이 포함된다. 단위 테스트 통과는 실기기 child credential이나 Host 접근 차단을 증명하지 않는다.

## 5. Host 상태 및 cleanup

| 항목 | 실행 전 | 실행 후 | 판정 |
|---|---|---|---|
| Global SELinux | Enforcing (`/sys/fs/selinux/enforce=1`) | 동일 | PASS |
| loaded policy SHA-256 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` | 동일 | PASS |
| installed `sepolicy.rule` SHA-256 | `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389` | 동일 | PASS |
| Host mount namespace | `mnt:[4026532950]` | 동일 | PASS |
| `/proc/1/mountinfo` SHA-256 | `a305108be07a09622a4a10e64a89c5642f0934fbe1fa7439551c21716419c83d` | 동일 | PASS |
| 주요 Host PID | init `1, 288`; zygote64 `1854`; system_server `3059`; installd `2607`; netd `1852`; adbd `30624`; servicemanager `942`; surfaceflinger `2108` | 동일 | PASS |
| `artd` | PID 없음, `init.svc.artd=stopped` | PID `29657`, `init.svc.artd=running` | 변화 관측, 원인 미확인 |
| `getprop` digest | `e1d0294717a1870e7e67a0d8caed892db831fb66e48cbdef98989a9d1f3e145f` | `11a07fd1d00be5310e43cf31ef7a474691ccbb7ffb1d2def841ed1d703223409` | 변화 관측, 원인 미확인 |
| 선택 property | `ro.build.fingerprint=samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`; `sys.boot_completed=1`; `init.svc.installd=running`; `init.svc.artd=stopped` | fingerprint, boot-completed, installd 동일; `init.svc.artd=running` | `artd` 상태만 변화 |

이 작업은 `artd`를 시작·정지·신호하지 않았고 property write/`setprop`, Host Binder IPC 또는 property service socket 연결을 하지 않았다. `artd`와 digest 변화는 별도 Host 관측으로 기록하며 SSAL 원인으로 귀속하지 않는다. 이전 [Phase 5A validation](rsbinder-phase5a-validation.md)에는 `artd` PID `22327 → stopped`, property digest `0e47ca5bceb72174fb34318b2ef624d1b833a5797671d1307fa83096859a99d1 → e1d0294717a1870e7e67a0d8caed892db831fb66e48cbdef98989a9d1f3e145f`의 앞선 변화도 기록돼 있고, 원인은 확인되지 않았다.

임시 launcher와 reporter는 `/data/local/tmp`에만 복사했다. reporter는 기존 `ssal_guest_probe_exec` type으로 임시 label을 적용해 확인했고 두 임시 파일을 모두 삭제했다. 후속 검사에서 두 파일은 없고 `/proc/1/mountinfo`에는 task 경로가 없었다. child가 생성되지 않았으므로 이 진단은 mount나 loop를 할당하지 않았다. 종료 후 Host `losetup -a`에는 38개 loop device가 보였다. 실행 전 loop inventory snapshot은 없어 이 목록의 delta는 **UNKNOWN**이다. child와 launcher 프로세스가 종료되어 해당 프로세스 FD는 커널이 닫았다.

설치된 SSAL 바이너리, profile, userdata, Host init/zygote/system_server/installd/netd/adbd/servicemanager는 변경하지 않았다. Guest 서비스도 시작하지 않았다.

## 6. 경계별 판정 및 다음 단계

| 항목 | 상태 |
|---|---|
| EINVAL 원인 분리 | **PASS**: AV wire/mask 처리 전에 target context SID 변환이 `EINVAL`임을 재현·특정 |
| SELinux AV allow/deny 및 Host signal/ptrace | **UNKNOWN**: 유효한 target SID가 없어 query 불가. fail-closed 유지 |
| child credential/context/FD 실제 관측 | **UNKNOWN**: child 미생성 |
| Host root/proc/FD 실제 접근 경계 | **UNKNOWN**: reporter 미실행 |
| Guest worker mount namespace 및 `/dev` 구성 | **PASS** for same-day disposable worker evidence; 이번 child namespace는 **UNKNOWN** |
| Phase 2–4 Binder/SELinux regressions | **PASS** for rerun unit/build checks; Phase 4 device result reused from same-day report |
| Host policy/mount namespace/mountinfo | **PASS**: before/after 동일 |
| Host process/property state | **PARTIAL**: core PID는 동일하나 `artd`와 property digest가 변했고 원인 미확인 |
| cleanup | **PASS** for task-specific files/mounts; loop inventory delta **UNKNOWN** |
| Phase 5B 또는 서비스 부팅 진입 | **NO-GO** |

다음 실행 전제는 active policy에서 `u:r:ssal_guest_probe:s0` context가 정상 SID로 변환되는 것이다. 그 뒤에도 Enforcing 상태의 Host 핵심 프로세스 전체에 대해 `signal`과 `ptrace`가 명시적으로 deny되는지 확인해야 한다. 또한 child를 실제로 검증된 Guest mount namespace와 Guest `/proc` 경계 안에서 시작하도록 경로를 연결해야 한다. 현재 `ProcOnly` 경로는 Host mount namespace를 기대하므로 이 연결을 확인하기 전에는 Guest child로 실행하지 않는다. 모든 조건을 만족한 뒤 exec-stop에서 UID/GID/groups/capabilities/ambient/bounding/`no_new_privs`/context/FD를 실제 검증한다. 현재 제한에서는 policy나 `sepolicy.rule`을 바꾸지 않았고 선행 조건이 충족되지 않았으므로 제한 child 실행은 중단 상태로 남긴다.
