# 독립 Guest Shell 구현 및 실기기 검증

2026-11-17 KST, Lenovo TB320FC (`HA1WAQ7P`), 프로필 `y702`, Guest LineageOS Android 16에서 검증했다. 삼성 기기 검증이나 Android 전체 부팅 완료를 뜻하지 않는다.

## 사용

root에서 실행한다. 프로필이 하나면 이름을 생략한다.

```sh
/data/adb/modules/ssal/bin/ssal shell y702
/data/adb/modules/ssal/bin/ssal exec -- /system/bin/id
printf 'id\ngetprop ro.build.version.sdk\n' | /data/adb/modules/ssal/bin/ssal exec -- /system/bin/sh
```

`shell`은 TTY를 요구하며 Guest 전용 devpts와 `/dev/tty`를 사용한다. `exec`는 argv를 보존하고 입출력을 별도 파이프로 중계한다. 문자열 평가가 필요하면 명시적으로 `/system/bin/sh -c SCRIPT`를 사용한다. 명령 종료 코드를 그대로 반환한다.

## 구현 경계

- `src/guest/mount/mod.rs`: 기존 system/userdata, SELinux overlay, APEX 준비를 재사용한다. Shell은 이 준비 후 분기하며 Binder·Android 서비스를 시작하지 않는다.
- `src/guest/environment.rs`: Property 서비스 준비를 Android launcher에서 추출했다. 프로필별 admission lock, 환경 등록, shared lease로 준비·진입·종료를 조정한다. boot ID, PID start time, pidfd, namespace와 root inode를 확인한다.
- `src/guest/shell.rs`: 기존 환경에 진입하거나 독립 환경을 만든다. `/system/bin/sh`를 mapped `shell` SID, UID/GID 2000, 빈 supplementary groups와 모든 capability 집합 0으로 실행한다. HOME/TMPDIR은 Guest userdata의 `/data/local/ssal-shell`이다.
- `src/shell_client.rs`: PTY와 exec 스트림 중계, 창 크기 전달, 터미널 복원, 부모 종료 감시를 담당한다. Host 파일 FD는 Guest 표준 입출력으로 직접 상속하지 않는다.
- Android launcher는 서비스 실패 후에도 Shell lease가 끝날 때까지 Property와 mount를 유지한다. Shell 자식 회수는 Android cgroup 검증과 분리했고, Android의 기존 cgroup 검증은 유지했다.

등록 파일은 마지막 lease 종료 시 제거한다. 안정된 flock inode가 필요하므로 `environment.lock`, `environment.leases` 파일은 남긴다. 준비 상세 로그는 `/data/local/ssal/logs/shell-PID.log`에 남긴다.

Guest Shell에만 KSU 소유 상속 FIFO의 `read/getattr/ioctl`을 추가했다. `mksh`는 조회 권한이 없으면 stdin 스크립트의 첫 줄만 실행했으며, 해당 권한 추가 후 여러 줄 입력을 통과했다. 기존 Host 정책을 제거하거나 permissive로 변경하지 않았다. 실행 전 kernel AV 응답으로 Guest Shell 도메인 Enforcing도 확인한다.

## 검증 결과

로컬 Cargo 회귀 124개 통과, 환경 의존 테스트 6개 제외. 기존 fork 테스트가 다른 테스트의 flock FD를 잠깐 상속하는 병렬 경합이 한 번 발생해 최종 전체 실행은 `--test-threads=1`로 확인했다. 실제 chroot FD 회귀도 별도로 통과했다. `tests/shell_transport.py`로 argv·stdout/stderr·여러 줄 stdin·개행 없는 프롬프트·PTY·resize·Ctrl-C·터미널 복원을 확인했다. Android AArch64 release 빌드와 새 검증 스크립트 shellcheck를 통과했다. Clippy는 기존 `src/guest/cgroup/memory.rs`의 `double_ended_iterator_last` 경고 한 건을 제외하고 통과했다.

실기기에서는 다음을 확인했다.

| 상태/경계 | 결과 |
| --- | --- |
| Guest 미부팅 | 독립 mount/APEX/Property 준비 후 Shell/exec 성공 |
| Android 부팅 중 | 부팅 worker의 준비 완료 후 기존 환경에 Shell 진입 |
| 실행 중 환경 | 기존 namespace·Property 재사용, UID/GID 2000과 mapped Shell SID 확인 |
| Android 서비스 실패 | Guest servicemanager 실패 주입 후 Shell 유지 |
| SystemServer 실패 | Guest SystemServer PID 29767, SID `u:r:ssal_p0001_system_server:s0`만 종료한 뒤 Shell 유지·Property 읽기 성공 |
| 실행/입출력 | 종료 코드 37, 다중 줄 stdin, 개행 없는 프롬프트, PTY job control·`stty`·Ctrl-C 통과 |
| 격리 | capability 전부 0, Host Binder/init socket·boot property·`/proc/1/root` 차단, Host 파일 FD 없음 |
| 정리 | 백그라운드 자식 회수, 환경 등록 제거, 잔여 rootfs mount 없음, loop 46개 해제 |
| 데몬 독립성 | Shell 실행 중 SSAL 데몬 재시작 후 Shell 정상 완료 |

`out/shell-cli-20261117/final-systemserver-lifecycle/android.log:340`은 Guest SystemServer ready를 기록한다. 같은 파일 3190–3192행은 잔여 mount 부재와 loop 46개 해제를 기록한다. `shell.stdout`의 `SHELL_SURVIVED_ANDROID_FAILURE`가 실패 후 Shell 유지 근거다. 전체 Android `sys.boot_completed=1`은 검증하지 않았다.

Host 전후 boot ID는 `187ab5ca-c953-4032-b5fb-38875175d198`, SystemServer PID는 2280, PID 1 mountinfo SHA-256은 `a8ce4473229b32f35b98196666d803da179739f4f893b6a665117f7ee1288142`로 동일했다. Enforcing=1을 유지했다. 최종 설치 경로 검증의 근거는 `out/shell-cli-20261117/final-installed/`에 있다.

## 반영 및 한계

기기 모듈 바이너리와 공용 helper를 검증한 버전으로 반영하고 SSAL 데몬을 재시작했다. 기존 파일 백업은 기기의 `/data/local/tmp/ssal-shell-20261117/backup/`에 있다. 바이너리 백업 복원은 동적으로 추가된 Guest 정책을 제거하지 않는다.

이 기기는 `CONFIG_PID_NS`가 없다. 이 경우 PID 번호는 공유하며 전용 SELinux SID, UID/GID, proc DAC, FD 및 network/mount 격리를 사용한다. PID namespace 지원 커널의 해당 분기, 삼성 순정 커널, 완전한 Android 부팅 및 하드 재부팅 복구는 미검증이다. 강제 SIGKILL·전원 차단 후 scratch 회수는 정상 종료 정리와 별개다.

Luna가 완료된 시험 scratch의 mount/loop 참조 부재를 확인한 뒤 제거했다. `.userdata-*.img` 임시 파일은 없었다. vendor 소스는 읽지 않았다.
