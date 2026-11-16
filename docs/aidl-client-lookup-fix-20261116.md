# Guest AIDL client 조회 수정: attempt51–52

2026-11-16 KST, TB320FC (`HA1WAQ7P`), Host Enforcing.
vendor 소스는 읽지 않았고 운영 daemon은 교체하지 않았다.

## 조사 결과

- attempt50은 등록 뒤 client의 `check_interface`에서 `NameNotFound`로 실패했다.
- 커널 `/sys/fs/selinux/access` 조회에서 Guest shell → Guest
  `aidl_lazy_test_service:service_manager find`는 이미 ALLOW였다.
  Host shell → Guest 서비스는 DENY였으며 이를 변경하지 않았다.
  증거: `out/property-readiness-20261115/attempt51/query-find-before.txt:1–4`.
- 반면 Guest shell → Guest AIDL 서버의 `binder call`과 서버 → shell의
  `binder transfer`는 DENY였다.
  증거: `attempt51/query-binder-before.txt:1,3`.
- rsbinder 0.12.0의 `check_interface`는 `check_service`가 transaction 오류를
  None으로 바꾼 경우에도 NameNotFound를 반환한다. client를 오류를 보존하는
  `try_get_service`와 명시적인 interface 변환으로 바꿨다. attempt51은 실제 오류
  `ServiceManager service lookup: FailedTransaction`을 기록했다
  (`attempt51/device-stage/worker.log:226`).
- Luna가 분석한 필터링된 로그에는 이 실패를 직접 설명하는 enforcing Binder AVC가
  없었다. 아래 두 규칙의 개별 permission 중 어느 것이 조회 실패를 일으켰는지까지는
  분리하지 않았다.

## 변경과 검증

`src/guest_policy.rs`는 기존 시험 client의 add/echo와 양방향 callback을 위해
아래 Guest 타입 간 규칙만 추가한다. 정책 캐시 버전을 12에서 13으로 올려 기존
계획도 재생성한다. Host domain이나 서비스에 대한 권한은 추가하지 않는다.

```text
allow ssal_p0001_shell ssal_p0001_aidl_lazy_test_server binder { call transfer }
allow ssal_p0001_aidl_lazy_test_server ssal_p0001_shell binder { call transfer }
```

attempt52의 applied-before/after 비교는 위 두 statement 추가뿐이었다.
커널 조회에서도 기존 DENY였던 call/transfer가 ALLOW로 바뀌었다
(`attempt52/query-binder-after.txt:1,3`). `service_manager:find` 추가는 없다.
이 조합이 실제 실패를 해결했으며, syscall 수준의 단일 원인 규명은 아니다.

샌드박스 밖 WSLc `ssal-dev`, `/src`에서 다음 검사가 통과했다.

```sh
cargo fmt --all -- --check
cargo test --locked -- --test-threads=1
cargo test --locked --manifest-path experiments/rsbinder-phase3/Cargo.toml
cargo build --locked --release --manifest-path experiments/rsbinder-phase3/Cargo.toml --target aarch64-linux-android
bash scripts/build-android.sh
```

새 회귀 테스트 `launcher_aidl_calls_only_extend_guest_peers`는 Guest 전용 source와
각 규칙의 두 native permission command 인코딩을 확인한다. 기존 ignored 테스트는
실행하지 않았다. 변경 파일 `git diff --check`도 통과했다.

## attempt52 실기기 결과

시험용 별도 bin과 원본에서 분리된 userdata 사본을 사용했다. attempt51은 attempt50
사본을, attempt52는 attempt51 사본을 복제했다. 원본 userdata를 Guest에 연결하지 않았다.
memory high/max는 1 GiB / 1.5 GiB이며 SELinux 우회는 사용하지 않았다.

`out/property-readiness-20261115/attempt52/device-stage/worker.log`:

- `:219–221`: `servicemanager.ready=true`, private Binder Context Manager 조회 성공.
- `:226`: 서비스 조회, descriptor 검사, add(17,25)=42, echo와 같은 callback 객체의
  두 번 호출 성공 (`ipc_passed`). client SID는 `ssal_p0001_shell`이다.
- `:228–229`: `GUEST_SERVICEMANAGER_READINESS=PASS`, `PHASE5B=PASS`.
- `:231`: 서버 SID `ssal_p0001_aidl_lazy_test_server`, AIDL 서비스 등록 확인.
- `:3076–3079`: Guest cgroup 정리, rootfs 잔여 mount 부재, loop 46개 해제 성공.
- `device-stage/worker.rc`: 0. `remote-run.log`의 전체 실행 결과도 성공이다.

ssald SHA-256: `5ce31529637319d4bea106a73c135ecbc0c7e9770c4525e2e513e9663560b196`.
property-service SHA-256: `653ff02daa4dd316a902f89d85cc2f6e6eedb4169abbd9435e3b8a4325506d69`.

Host Enforcing, boot ID, sys.boot_completed, system_server PID, PID 1 mountinfo,
Host cgroup 설정과 원본 userdata의 크기/mtime/inode가 실행 전후 동일했다.
active policy는 위 Guest 규칙 추가로 hash가 바뀌었다. 원본 userdata의 전체 hash 검사나
Host 전체 policy 의미 비교를 수행한 것은 아니다.

## 범위와 남은 검증

로컬 증거는 `out/property-readiness-20261115/attempt51`, `attempt52`에 보존한다.
Luna가 attempt48–52의 시험 userdata 사본, 별도 bin과 remote stage, 이번 조회용
임시 스크립트 3개를 제거하고 부재를 확인했다. 정리 전후 원본 userdata와 system 이미지
메타데이터, 운영 바이너리 hash, active policy hash와 PID 1 mountinfo hash가 동일했고
Guest 프로세스·cgroup·mount·loop 참조도 없었다. 증거는
`out/property-readiness-20261115/cleanup-attempt48-52.txt`의 `CLEANUP=PASS`다.
이번 부팅에 추가된 Guest SELinux 정책은 제거하지 않았다.

이번 PASS는 공통 `--guest-service-worker` readiness까지다. 전체 LineageOS 부팅,
Guest sys.boot_completed, 다른 worker의 개별 실기기 실행과 하드 재부팅 후 복구는
이번 작업에서 검증하지 않았다.
