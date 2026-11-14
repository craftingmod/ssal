# Property service 종료 진단 및 공통 readiness 계약 수정

2026-11-15 KST, Lenovo TB320FC / Y702 (`HA1WAQ7P`), Host Enforcing.
기존 작업 트리 변경은 보존했다. vendor 소스는 읽지 않았다.

## 종료 오류와 로그 쓰기 거부

attempt20의 `logcat-targeted.txt:4–5`에는 08:30:04.806에 Guest init의
`/run/ssal/guest-property-service.log` 쓰기를 거부한 AVC가 있다.
이는 stderr 유실의 증거다. 그 로그만으로 service의 startup 오류를 알 수는 없다.

Guest property service만 stdout/stderr를 pipe로 전달하고, 부모 launcher가 기존 bounded
`zygote_diagnostics::Stream`으로 파일을 기록하도록 바꿨다. 종료를 관측한 뒤 pipe를
drain하고 오류를 보고하므로 빠른 exit에서도 마지막 stderr를 보존한다. Guest init의
system_file 쓰기 권한이나 Host 정책을 추가·완화하지 않았다.

- attempt21: attempt20과 같은 property-service 바이너리에서 `Permission denied (os error 13)`를 회수했다 (`out/property-readiness-20261115/attempt21/worker.log:177`). 로그 파일 쓰기 AVC와 별개인 startup 오류다.
- attempt22: 단계 진단을 추가해 `property area initialization`에서 EACCES가 반환됨을 확인했다 (`attempt22/worker.log:177`). 격리 검사, property context·seed 읽기, persistent store 열기는 통과했다.
- attempt23: `/dev/__properties__/u:object_r:ssal_p0001_net_radio_prop:s0`를 같은 context로 라벨 처리하는 helper에서 EACCES가 반환됐다 (`attempt23/worker.log:177`). 이 helper는 파일 open, fsetxattr, label readback을 포함한다. 정확한 실패 syscall이나 SELinux 규칙까지 확정한 것은 아니다.

attempt23 PID 7094의 08:48:27.226–27.246 AVC (`attempt23/logcat-targeted.txt:134–138`)는
permissive transition/inherited-process 관련 기록이며, 해당 파일 작업을 거부한 enforcing AVC는 없다.

따라서 재현된 실제 exit 1 경로는 **property area 파일 라벨 처리 오류 → serve/main의 Err → exit(1)**이다.
attempt20에도 같은 오류가 있었을 가능성을 뒷받침하지만, 당시 유실된 메시지를 복원한 것은 아니다.
Enforcing AVC가 없는 EACCES를 근거로 새 allow 규칙을 추측해 넣지 않았다.

## 두 P1 수정

1. `experiments/rsbinder-phase3/src/android.rs`의 Context Manager probe 및 미등록 서비스 검사에서
   `check_interface`의 `NameNotFound` 성공 판정을 제거했다. `try_get_service`의 `Ok(None)`만
   정상 부재로 인정한다. `Ok(Some(_))`와 모든 transaction 오류는 실패다. 서비스 사망 후
   부재 검사도 transaction 오류를 전파한다. 실제 서비스의 `check_interface` 오류는 여전히 실패로 처리한다.
2. 공통 launcher의 `--guest-child-worker`, `--guest-service-worker`, `--guest-services-6a-worker`,
   `--guest-services-6b-worker`, `--guest-zygote-7a-worker` 모두 같은 Guest property-service 실행 경로를 쓴다.
   이전의 service 없는 private-area 초기화 경로를 제거했다. 모든 worker에서 binary 배치,
   service 시작, socket/초기 property 검사가 일치한다.

`servicemanager.ready`는 계속 **false**로 seed한다. ServiceManager를 시작한 뒤 실제 true
전환을 기다리고, Context Manager의 정상 응답을 확인한 다음 AIDL 등록·실제 호출을 검사한다.
사전 true 주입은 없다. 기존 Zygote 전용 진단 기능의 phase7a 제한은 유지했다.

## 회귀 및 기존 테스트

- `only_successful_null_reply_proves_absence`: 정상 null만 성공하며 NameNotFound, DeadObject,
  FailedTransaction, PermissionDenied 등 오류와 실제 객체 응답은 실패한다.
- `common_workers_share_live_property_readiness`: 공통 setup의 service 배치·시작, 이전 초기화 경로 부재,
  false seed, Property → Context Manager → AIDL 순서를 검사하는 wiring 회귀다.
- `property_failure_stderr_survives_child_exit`: exit 1 fixture의 stderr가 readiness 오류와 종료 후 로그에 남는다.

샌드박스 밖 WSLc `ssal-dev`, `/src`에서 실행했다.

```sh
cargo fmt --all -- --check
cargo fmt --manifest-path experiments/rsbinder-phase3/Cargo.toml -- --check
cargo test --locked -- --test-threads=1
cargo test --locked --manifest-path experiments/rsbinder-phase3/Cargo.toml
bash scripts/build-guest-launcher.sh
```

최종 전체 Rust 테스트 135개와 독립 phase3 회귀 1개가 통과했다. 기존 ignored 테스트 6개는
실행하지 않았다. 병렬 재실행 중 기존 persistent store 재개방 테스트가 한 번 EWOULDBLOCK으로
실패했다. fork 테스트의 열린 FD 상속 간섭 가능성이 있어 최종 전체 suite는 직렬 실행했다.
이 원인은 확정하지 않았고 해당 기존 테스트나 제품의 locking 동작은 바꾸지 않았다.
Android release build 및 변경 파일의 `git diff --check`도 통과했다.

## 실기기 순차 검증

운영 daemon은 교체하지 않았다. 별도 시험 bin과 원본 userdata의 8 GiB 사본을 사용해
수정한 공통 경로의 `--guest-service-worker`를 실행했다. 메모리 soft/hard limit은 1 GiB / 1.5 GiB다.
SELinux bypass나 고정 SID 진단은 선택하지 않았다.

attempt23에서 실행한 ssald SHA-256은 `754a60169a94490cd264b53d6641cb65b603ccdac6946e82bf4d12e869b6ac10`,
property-service는 `d4c25e8056d9fde3f45c3d13debebbbec6d7046017255b33d2d79974c4a68545`,
phase3-ipc는 `9bb34ec1498127c74e8057220114129329e14e41e258e2ec12078f175c119bbc`다.
ssald는 attempt22와 동일한 launcher 빌드이며 attempt23에서는 단독 property-service의 파일별 진단만 갱신했다.

| 순서 | 결과 |
|---|---|
| Property | **FAIL** — net_radio_prop area 파일 라벨 처리 중 EACCES, service exit 1 |
| ServiceManager | 미도달 |
| Context Manager | 미도달 |
| AIDL | 미도달 |

각 실행에서 Host Enforcing, boot ID, Host sys.boot_completed, system_server PID, PID 1 mountinfo,
active policy hash, Host cgroup 상태와 원본 userdata 크기/mtime/inode가 전후 동일했다.
worker가 Guest cgroup, rootfs mount, loop 46개를 정리했다. 원본 userdata 전체 hash는 검사하지 않았다.
Luna는 프로세스·Host mountinfo·loop backing 참조 부재를 확인한 뒤 정확한 시험 userdata
`/data/local/ssal/guests/y702/.userdata-property-readiness-test21.img`와 시험 bin 디렉터리
`/data/adb/modules/ssal/bin/.ssal-property-readiness-test`만 제거하고 부재를 재확인했다.
운영 바이너리, 원본 userdata, device stage/cache와 로컬 증거는 보존했다.
필터링한 로그와 정리 증거는 `out/property-readiness-20261115/cleanup-summary.md` 및 각 attempt 디렉터리에 있다.

남은 실패는 property area 라벨 처리의 권한 오류다. readiness의 런타임 PASS, 다른 worker의
개별 실기기 PASS, 전체 Guest 부팅과 하드 재부팅 후 복구를 검증한 결과가 아니다.
