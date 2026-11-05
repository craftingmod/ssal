# Phase 8B-4B-2 — Safe procfs Namespace Probe

2026-11-06 03:59:05 KST, SM-S937N (`R5CY52JC03H`). **환경 구축 PASS / hidepid=4 격리 FAIL / Host 상태 불변 PASS.** 진단은 한 번 실행했다. 실제 SystemServer 실행을 허가하는 결과가 아니다.

## 구현

- `native/binder-probe/procfs-namespace.c`: 독립적인 Host supervisor가 disposable canary와 단일 스레드 진단 child를 직접 fork한다. 대상 PID는 supervisor가 생성한 canary로 고정되며 외부 PID 입력을 받지 않는다. child는 추가 프로세스를 생성하지 않는다.
- 진단 child의 `unshare(CLONE_NEWNS)` 후 namespace device/inode를 supervisor 및 Host init의 사전 값과 비교한다. 분리 확인 뒤에만 `mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)`를 호출한다. 그 이전에도 mountinfo를 읽어 상태를 기록한다.
- 모든 mountinfo 레코드의 optional field에서 `shared:`, `master:`, `propagate_from:` 부재를 확인한 후에만 `/dev/ssal-procfs-XXXXXX`에 새 procfs를 `hidepid=4,nosuid,nodev,noexec`로 mount한다. mount 뒤에도 propagation과 대상 procfs 옵션을 확인한다. `/proc`에 대한 mount/bind/remount/umount는 없다. namespace 또는 private 전환 실패는 즉시 BLOCKED 종료이며 재시도하지 않는다.
- mount 준비는 privileged child에서 수행하고 **접근 검사는** UID/GID 1000, supplementary groups 없음, `u:r:system_server:s0`, effective capabilities 0으로 수행한다. canary도 같은 credentials이며 dumpable, FD 0은 `/dev/null`이다. `gid=3009` 예외 부재를 명시적으로 확인한다. 보고는 기존 boundary helper와 같은 원리의 fork 전 공유 mmap을 사용한다.
- supervisor는 child 안의 procfs와 별개로 `/proc/1/mountinfo`, 자신의 mountinfo, SELinux enforce 값 전체를 전후 비교한다. 기존 `/proc`의 `hidepid=invisible,gid=3009`도 확인한다. 실행 shell은 별도의 전후 snapshot을 비교한다.
- timeout 및 부모 종료 시 소유 child만 회수한다. 아직 reap하지 않은 직접 child PID만 SIGKILL 대상으로 사용하며 실제 Host 서비스 PID는 받지 않는다. 진단 child 종료로 private mount namespace가 소멸하고 supervisor는 빈 임시 디렉터리만 rmdir한다. mount/umount cleanup 명령은 없다.
- 기존 shell mount 실험을 재사용하지 않는다. 새 경로는 `scripts/build-procfs-namespace.sh`, `scripts/run-procfs-namespace.sh`이며 launcher/기존 preflight에 자동 연결하지 않았다. vendor 코드는 읽지 않았다.

## 실기기 결과

로컬 증거 `out/phase8b4b2/probe.txt`의 줄 번호 기준. 기기 원본은 `/dev/ssal-phase8b4b2/run-1793905145/`이다.

| 구분 | 관측 | 판정 |
|---|---|---|
| Namespace 독립성 | Host/supervisor inode `4026532950`, child `4026536329`, task count 1 (`:8`) | PASS |
| Propagation 차단 | 기존 193개 mount 모두 private 확인 후 mount, 이후 194개 모두 private (`:9–14`) | PASS |
| Guest 전용 procfs | `/dev/ssal-procfs-SHReUJ`, 별도 device `0:392`, `hidepid=ptraceable`, gid=3009 없음 (`:13`) | 환경 구축 PASS |
| 검사 credentials | UID/GID 각 1000/1000/1000, stock system_server SID, CapEff=0, groups=0, gid3009_exception=0 (`:16`) | PASS |
| Canary 열거 | canary PID 22177, `readdir seen=1 errno=0` (`:17`) | 격리 FAIL |
| Canary stat | PID 디렉터리, root, fd, fd/0 모두 성공 (`:18–23`) | 격리 FAIL |
| Canary open | root, fd, fd/0 모두 성공 (`:20–24`), 즉시 close, 내용은 읽지 않음 | 격리 FAIL |
| Host 상태 | init/supervisor mountinfo 전체 동일, Enforcing 유지 (`:27`), 독립 shell snapshot 동일 | PASS |
| 정리 | child 22178와 canary 22177 reap (`:26`), PID/임시 디렉터리 부재와 Host mountinfo 잔여 없음은 `cleanup.txt` | PASS |

`hidepid=4` 요청이 mountinfo에서 `hidepid=ptraceable`로 표시됐다. 이 옵션의 수용이나 namespace 준비 성공만으로 격리가 성공했다고 판단하지 않았다. 이번 helper는 ptrace를 호출하지 않으며 과거 PTRACE_ATTACH 거부를 성공 근거로 사용하지 않았다. 동일 UID/SID의 dumpable canary에 대해 위 접근이 성공한 **관측 결과**로 FAIL을 판정한다. 정확한 커널 내부 원인은 이번 실험에서 규명하지 않았다.

## 검증 및 재현

NDK Android arm64와 Linux native 빌드에 `-Wall -Wextra -Werror`를 적용했다. `--self-test`는 mount 없이 option token 경계, malformed mountinfo 및 각 propagation 필드 거부를 assert로 검사한다. runner shell 구문 검사도 통과했다. helper SHA-256은 `4e6fe97f1ea864ba8816e1bd75c5f5fae1cc63ebb0d37bc3b4324525e45da9a3`이다.

```text
wslc exec ssal-dev bash scripts/build-procfs-namespace.sh
# out/phase8b4b2/bin/ssal-procfs-namespace 및 runner를 /dev/ssal-phase8b4b2에 staging
adb shell su -c 'sh /dev/ssal-phase8b4b2/run.sh'
```

WSLc는 저장소 지시에 따라 sandbox 밖에서 실행했다. runner는 이번 실행에서 exit 1(격리 FAIL)을 반환했다. 사전 조건 실패는 3(BLOCKED), Host snapshot 차이는 4로 구분한다. `before.txt`와 `after.txt`의 로컬 SHA-256은 모두 `37f9b14c43b0134c4037ba12e00e85e91bb9735e4251269f51f0055941a5c8b4`이다.

실제 Host init/zygote/system_server/adbd/netd를 중지하거나 신호 대상으로 사용하지 않았다. SELinux 모드/정책 변경 및 Host `/proc` 조작은 하지 않았다. raw logcat/dmesg/AVC 수집 없이 전용 진단 출력만 읽었다. 이번 검사에서 정책 해시나 모든 Host 서비스의 상태까지 검증한 것은 아니다. 기존 작업의 `docs/TODO.md` trailing whitespace 때문에 전체 `git diff --check`는 실패했으며 이 작업에서 해당 파일을 변경하지 않았다.

**남은 제한:** 실제 GSI Zygote/SystemServer와 전체 credentials/seccomp 모델, LineageOS 첫 부팅은 검사하지 않았다. 현재 stock SID/동일 UID canary 모델에서는 hidepid=4만으로 Host proc 접근을 막지 못하므로 다음 단계의 격리 성공 조건으로 사용할 수 없다.
