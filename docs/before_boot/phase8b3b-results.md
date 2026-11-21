# Phase 8B-3B — Guest Zygote No-op SELinux Interposer PoC

2026-11-06 KST. **두 API의 no-op 후킹과 실기기 관측 완료. Java child no-op 경로는 EINVAL로 실패하며, 기존 정상 경로 복원은 PASS.** 격리된 native 진단에서는 선행 `system_server_startup` 전환과 final `system_server` 전환이 모두 성공했다. 따라서 선행 전이가 반드시 실패한다는 가설은 이 기기의 현재 실행 조건에서 재현되지 않았다. 실제 Zygote `forkSystemServer()` specialization 및 `SystemServer.main()`은 실행하지 않았다.

## 구현과 범위

- [`zygote-selinux-noop.c`](../native/binder-probe/zygote-selinux-noop.c): `selinux_android_setcontext(uid_t, bool, const char *, const char *)`, `selinux_android_setcon(const char *)`를 export한다. `RTLD_NEXT`로 원본 경로를 한 번 호출하며 인자 포인터, 반환값, 원본 호출 직전/직후 `errno`를 보존한다. 로그에는 PID, UID/GID, realtime timestamp, 인자, 반환값, errno 및 `/proc/thread-self/attr/current`의 전후 context 문자열을 남긴다. 심볼이 없으면 성공을 위조하지 않고 `-1/ENOSYS`로 실패한다.
- [`guest_launcher.rs`](../src/guest_launcher.rs): `SSAL_PHASE8B3B_NOOP=1`일 때만 Guest Zygote preload 목록 맨 앞에 추가한다. 기존 logger/crash capture/FD reopen을 유지한다. 기존 진단 라이브러리의 setcontext hook은 이 모드에서 즉시 원본으로 전달하고 `SSAL_PHASE7FC_BYPASS_SETCONTEXT`는 child 환경에서 제거한다. 플래그가 없으면 기존 경로다.
- constructor는 실제 exec 환경의 `LD_PRELOAD`를 제거한다. 현재 프로세스와 fork child의 매핑은 유지되지만 이후 exec에는 preload가 전파되지 않는다. `/proc/PID/environ`에는 초기 환경 문자열이 남을 수 있어 그것만으로 실제 exec 상속을 판단하지 않는다.
- [`selinux-startup-probe.c`](../native/binder-probe/selinux-startup-probe.c): Guest root/net namespace/cgroup, UID/GID 1000, 시작 context `ssal_guest_probe`인 별도 native 프로세스다. 기존 app용 `seapp_contexts` overlay 설치 **이전**에 원래 GSI 규칙으로 실행한다. API만 순서대로 호출하고 종료하며 ART, Binder service 등록, Java entrypoint는 실행하지 않는다. startup 실패 시 final setter를 호출하지 않는다.
- 빌드와 module package 목록에 두 산출물을 추가했다. 모듈 ZIP은 생성만 했고 설치하지 않았다. 이미지나 Host/GSI 정책을 변경하지 않았고, 신규 allow, SID 인자 치환, global permissive는 적용하지 않았다. 이전 Phase의 Guest 실험 실행 조건은 그대로 사용했다.

## 실기기와 재현

ADB `R5CY52JC03H`, SM-S937N. system image는 `/data/local/ssal/images/1793366406758-25627/system.img`, userdata는 `/data/local/ssal/guests/phase5a-bringup-20261104/userdata.img`다. 기존 `phase7i` 도구를 별도 `/dev/ssal-phase8b3b`에 복사하고 이번 빌드의 ssald/diagnostic SO/helper만 교체했다. 기존 `/dev/ssal-phase7i` 실행 파일은 덮어쓰지 않았다.

[`run-phase8b3b.sh`](../scripts/run-phase8b3b.sh)는 `baseline` 또는 `noop`을 받는다. 두 모드 모두 기존 Phase 7I Property/persistent-restore/Java-fork 경로를 사용하며, `noop`만 새 모드를 켠다. baseline의 기존 제한적 EINVAL fallback은 비교 기준이며 **no-op 성공 증거로 취급하지 않는다.**

```sh
# 빌드 컨테이너에서
bash scripts/build-guest-launcher.sh
python3 scripts/test-zygote-selinux-noop.py
python3 scripts/test-zygote-diagnostics.py
cargo test --locked --bin ssald

# 도구를 별도 디렉터리에 staging한 기기에서
sh /dev/ssal-phase8b3b/run.sh baseline
sh /dev/ssal-phase8b3b/run.sh noop
```

아래 evidence는 저장소 `out/phase8b3b/`에 pull했다. 최종 정리 때 기기의 새 interposer/helper와 `/data/local/tmp/ssal8b3b-*` 전송 파일은 제거했으므로 재실행하려면 다시 staging한다. run별 텍스트 증거는 기기와 로컬에 보존했다.

| 실행 | 결과 | evidence 디렉터리 |
|---|---|---|
| 최초 baseline | Java Property/Binder/userdata, exit 0, reap PASS | `baseline-1793897922` |
| 첫 helper 시도 | helper exit 2, Java 미시도; 아래 구현 수정 참고 | `noop-1793897962` |
| 첫 no-op 전체 실행 | native API 전환 성공, Java EINVAL/SIGABRT, worker exit 1 | `noop-1793898035` |
| baseline 복원 | Java 검증·exit 0·reap 다시 PASS | `baseline-1793898149` |
| 정리 검사 포함 최종 no-op | 같은 native 성공/Java 실패, worker exit 1 | `noop-1793898233` |

첫 helper는 GSI libselinux가 public export하지 않는 `security_check_context`를 찾다가 exit 2로 종료했다. SELinux transition 실패가 아니다. 기존 진단과 같은 SELinuxFS `/sys/fs/selinux/context` write 검증으로 수정했고, 이후 두 실행에서 성공했다. 정책 적용은 없었다.

## 실제 호출 흐름

최종 native 진단 PID **27894**, 2026-11-06 **02:04:01 KST**:

```text
context check u:r:system_server_startup:s0 -> write=28 errno=0
setcontext(1000, true, NULL, NULL)
  -> original result=0 errno=2
  -> u:r:ssal_guest_probe:s0 → u:r:system_server_startup:s0
setcon("u:r:system_server:s0")
  -> original result=0 errno=0
  -> u:r:system_server_startup:s0 → u:r:system_server:s0
native process exit=0; SystemServer.main=never
```

증거: [`worker.log:235`](../out/phase8b3b/noop-1793898233/worker.log#L235), 인자/전후 context는 같은 파일 237–243행. **성공 반환 시 errno=2는 실패가 아니다.** wrapper가 성공 후 남아 있던 원본 errno까지 보존한 결과다.

실제 Guest Zygote PID **27910**에서 preload 로드 후 일반 app child PID **27960**, **02:04:08 KST**:

```text
libandroid_runtime / nativeForkAndSpecialize
  -> no-op setcontext(10000, false, "ssal_probe", "ssal-fork-probe")
  -> 기존 diag의 no-op 전달 분기
  -> 원본 libselinux
  -> result=-1 errno=22(EINVAL)
  -> before=after=u:r:ssal_guest_probe:s0
  -> Zygote JNI FatalError → ART abort → SIGABRT
```

증거: [`stderr.log:1`](../out/phase8b3b/noop-1793898233/worker/phase7b/stderr.log#L1)의 parent 로드, 같은 파일 294–298행의 인자/결과/fatal, 353행의 child SIGABRT. 이 경로에서는 final `selinux_android_setcon`을 호출하지 않는다.

실기기에서 Zygote의 `setcontext` import가 interpose됨을 확인했다. `setcon` wrapper와 원본 호출은 별도 native 진단에서 확인했다. **Zygote의 versioned final-setcon PLT 호출 자체는 실행되지 않았으므로 그 binding까지 runtime 검증했다고 주장하지 않는다.**

## 선행 전이와 실패 원인 판정

1. **system_server 선행 API 전이는 실패하지 않았다.** 현재 로드된 정책과 원래 Guest seapp 규칙에서 startup SID가 유효했고, UID 1000 native 진단이 startup과 final SID를 실제로 획득했다. 앞선 정적 문서의 “선행 전이가 실패하면 final에 도달하지 못한다”는 조건은 유지되지만, 이 기기의 native 진단에서는 그 실패 조건이 성립하지 않았다.
2. 이 결과는 Guest 전용 system_server 격리 PASS가 아니다. 원본 호출은 **Host와 같은 `system_server_startup`/`system_server` type**을 선택했다. namespace/cgroup이 별도여도 SELinux type 분리가 생기지 않는다. 이 상태로 `SystemServer.main()`을 실행하는 것을 다음 단계로 권고하지 않는다.
3. Java 회귀에서 처음 확정되는 실패는 app `setcontext`의 **원본 `-1/EINVAL`**이다. no-op이 그 실패를 보존해 ART가 정상 fatal 처리했다. 실패 후 SID는 바뀌지 않았다. 해당 함수 내부의 context 계산·검증·setter 중 최초 EINVAL 발생 지점은 이 계측만으로 확정하지 않았다.
4. 기존 baseline은 동일 EINVAL을 기존의 좁은 retained-Guest-domain fallback으로 통과했다. 복원 실행 child PID 26099는 `stderr.log` 395행에서 원본 EINVAL, 397행에서 기존 bypass를 기록하고 `worker.log` 271–281행에서 Java 통합 검사와 exit 0/reap을 통과했다. **no-op Java regression은 FAIL**, **기존 정상 경로의 보존·복원은 PASS**로 별도 판정한다.

## Host 안전과 종료 정리

각 실행 전후 safety snapshot은 byte-for-byte 동일했다. 검산은 [`host-snapshot-verification.json`](../out/phase8b3b/host-snapshot-verification.json)에 저장했다. 최종 no-op `before.txt`/`after.txt`에서 다음을 확인했다.

| Host 항목 | 결과 |
|---|---|
| Global SELinux | Enforcing 유지 |
| boot ID | `03834516-215d-4fd6-8960-1b833882595e`, 동일 |
| Zygote | PID 1840, starttime 783, 동일 |
| system_server | PID 2911, starttime 934, 동일 |
| adbd | PID 8989, starttime 4249683, 기존 `u:r:ksu:s0` 포함 동일 |
| netd | PID 1838, starttime 782, 동일 |
| Host mount/net namespace, PID 1 mountinfo | 동일 |
| Property 전체 출력, property/zygote/Binder endpoint metadata | 동일 |
| Host core process SID/credentials/capabilities/namespaces | 동일 |
| Host core process의 새 hook 매핑 | 없음 |
| module `sepolicy.rule` SHA-256 | `f23c957c0eb653b8fdcba5f0d6151c1687aeb4545ef0d7ad1b87963511a6801d`, 동일 |

최종 worker는 failure를 유지해 exit 1로 종료했다. Guest Zygote 및 owned services를 종료했고, Guest userdata probe 파일 정리, Guest cgroup 제거, rootfs unmount, **56 loop allocations 해제**를 확인했다(`worker.log` 281–301행). harness는 `/proc/*/maps` 전체에서 새 interposer 잔여 매핑도 검사했다. 추가 종료 후 검사는 [`final-cleanup.txt`](../out/phase8b3b/final-cleanup.txt)에 있으며 Guest cgroup, Host mountinfo의 session mount, hook 매핑이 없고 staging hook/helper도 제거됐다.

**정책 측정 한계:** 이 기기에서는 `/sys/fs/selinux/policy` read가 `EINVAL`이므로 활성 binary policy hash를 얻지 못했다. 최종 snapshot은 `ACTIVE_POLICY_HASH=UNAVAILABLE`로 명시한다. 최초 baseline에서 빈 stdin hash가 찍힌 것은 활성 정책 hash 증거로 사용하지 않는다. 이번 명령·코드에 policy load/write는 없으며 module rule 파일 동일성은 확인했지만, 활성 정책의 byte 단위 동일성을 검증했다고 주장하지 않는다. 스냅샷은 실행 전후 관측이며 모든 순간의 연속 감시 증거는 아니다.

## 빌드·검증

- Android arm64 launcher/SO/helper 빌드 PASS (`out/phase8b3b-build.txt`). 기존 memory-probe dead-code 경고는 남아 있다.
- `scripts/test-zygote-selinux-noop.py` PASS: 8 조합의 인자 포인터·NULL·server flag·정확히 한 번 호출·성공/실패 반환·errno 보존, legacy bypass 비활성화, exec 환경 제거. 원본 두 심볼 누락 시 `-1/ENOSYS` 검사도 PASS.
- 기존 `scripts/test-zygote-diagnostics.py` PASS: 기존 gated fallback 및 abort/segfault fatal semantics.
- `cargo test --locked --bin ssald`: **50 passed, 0 failed, 4 ignored** (`out/phase8b3b-tests.txt`).
- `shellcheck scripts/run-phase8b3b.sh` PASS.
- `bun scripts/package-module.ts` PASS. ZIP 생성만 했으며 기기 module 교체·설치는 하지 않았다.

| 산출물 | SHA-256 |
|---|---|
| `out/bin/ssald` | `0a6816f6629022fe8c9fae74bce162cd2b7b7a89d642f69a7451ccc1b298b53c` |
| `out/bin/ssal-zygote-diag.so` | `2895bcac169272048f14e8eb0fc18e3f1d525b47c13f500cc78946689ffe1e83` |
| `out/bin/ssal-zygote-selinux-noop.so` | `a2c0912f4606a37d06c99915691176cbb29054d641973835d0e0966aaf1b4281` |
| `out/bin/ssal-selinux-startup-probe` | `f2a71f8179e3256ea41e6b9339471b5db29b7e2496ef726b0464a1770411938b` |
| `out/ssal-module.zip` | `16530798e3f5352ee7bc3e355003951a0aded0a177e98198ab5bc4f13ae0863f` |

로그는 로컬에서 PID/AVC 기준으로 prefilter한 후 Luna에게 분석을 위임했다. 최초 no-op Java child의 EINVAL → JNI fatal → SIGABRT 순서가 확인됐고, 필터된 dmesg/logcat에서 그보다 앞선 원인을 확정할 증거는 없었다. raw logcat/dmesg 전체를 주 에이전트 문맥으로 읽지 않았다.

## 다음 단계 권고

1. 이 no-op은 기본 비활성 진단 도구로 유지한다. 기존 정상 경로 복원은 플래그를 끄는 것으로 충분하며, 기기 기본 실행 파일은 보존했다.
2. app Java를 strict no-op 상태에서도 실행하려면 먼저 libselinux 내부의 최종 context 계산/검증/setcon 중 EINVAL 지점을 더 좁힌다. 반환값을 성공으로 바꾸는 방법은 이번 결과의 해결책으로 간주하지 않는다.
3. system_server는 startup API 자체의 선행 실패보다 **Guest 전용 type 선택·격리**가 다음 과제다. 별도 Phase에서 허용된 범위를 정한 후 실제 Zygote `forkSystemServer`와 final PLT binding을 `SystemServer.main()` 이전 정지 지점으로 검증한다. 이번 Phase에서는 새 정책/SID 치환을 구현하지 않았다.

미검증: 실제 system_server specialization/post-fork hook, 32-bit/다른 GSI, 전체 LineageOS 부팅. 현재 native 진단이 Host와 같은 system_server type으로 전환된다는 점은 후속 실행의 격리 위험이다.
