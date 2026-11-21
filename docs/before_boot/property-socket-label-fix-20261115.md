# Property socket 동일 라벨 재설정 생략

attempt29에서 확인한 동일 SID `fsetxattr` EACCES를 바탕으로,
파일 helper의 기존 동일 SID 생략을 유지하고 socket에도 같은 원칙을 적용했다.
socket에서도 동일 SID였다는 증거는 없으므로, 이 변경만으로 attempt28의
socket 거부가 해결됐다고 판단하지 않는다.

`src/guest_properties/server.rs`의 socket 라벨 처리:

- 최초 `lgetxattr` 결과와 목표 SID가 정확히 같으면 `lsetxattr`를 생략한다.
- 다르면 기존처럼 설정하고 다시 읽어 목표 SID와 비교한다.
- 읽기·쓰기 오류와 readback 불일치는 계속 startup 실패로 처리한다.
- 읽은 실제 SID와 목표 SID를 기록하고 syscall 오류에는 경로·목표 SID를 포함한다.

socket 존재 검사, mode 0666 공개 시점, SO_PEERSEC 기반 property 권한 검사와
종료 시 socket 정리는 유지했다. Guest/Host SELinux 정책은 변경하지 않았다.
원본 GSI binary policy 대조와 enforcing AVC로 EACCES 원인을 확정하는 작업은 하지 않았다.

## 검증

저장소 지침대로 sandbox 밖 기존 WSLc `ssal-dev`에서 실행했다.

```sh
cargo test --locked --lib guest_properties -- --test-threads=1
cargo fmt --all -- --check
cargo build --locked --release --target aarch64-linux-android --bin ssal-property-service
```

property 테스트 10개, 포맷 검사, Android release build와 변경 파일의
`git diff --check`가 통과했다. 새 회귀는 동일 SID의 NUL 유무, 재설정 후 readback,
최초 읽기·쓰기·후속 읽기 거부, 부분 일치 SID 거부를 확인한다.
전체 suite와 Android 전용 ignored 테스트는 실행하지 않았다.

## attempt30 실기기 제한

`HA1WAQ7P` / TB320FC, Enforcing에서 원본 userdata의 별도 8 GiB 사본과
시험 바이너리 경로로 `--guest-service-worker`를 실행했다. 운영 바이너리는 교체하지 않았다.
시험 property-service SHA-256:
`8f37800e12982c29eeaa7dd1232d5efed520cf63947a68b74b94c5c4b29a58c2`.

`out/property-readiness-20261115/attempt30/worker.log:177`에서
`property persistent store: Permission denied (os error 13)`로 종료했다.
이번 사본은 새로 생성했으며 이전 시험 사본의 내부 상태까지 재현한 것은 아니다.
실패한 persistent store 내부 syscall과 원인은 확정하지 않았다.
socket 라벨 처리, property readiness, ServiceManager와 전체 부팅에는 도달하지 못했다.

Enforcing, boot ID, sys.boot_completed, system_server PID, PID 1 mountinfo hash,
active policy hash, Host cgroup 상태와 원본 userdata 크기/mtime/inode가 전후 같았다.
원본 userdata 전체 hash는 검사하지 않았다. worker의 cgroup·rootfs mount·loop
해제 결과와 전후 snapshot은 attempt30 디렉터리에 보존했다.
시험 파일 정리 결과는 같은 디렉터리의 `cleanup-summary.md`에 기록한다.

## attempt35–44 핵심 실기기 진행

- attempt35에서 persistent store/property area 초기화는 통과했고 property socket bind에서 EACCES가 났다. attempt36에 Guest 전용 socket type transition을 적용했지만 Guest `/dev/socket` 라벨 문제가 남았다. 이후 Guest socket 디렉터리 라벨과 `property_service` endpoint를 확인해 attempts41–44에서는 property service 및 shell smoke가 통과했다.
- attempts37–40에서는 Guest shell의 `test -S`와 `test -e`가 SELinux getattr 제한 때문에 socket을 잘못 missing으로 판단했다. attempt40의 Host-side Rust socket type 검사로 endpoint 존재와 directory isolation을 확인했다.
- attempt42의 `phase3-ipc` shell 접근 검사는 설치 파일 mode `0700` 때문에 실패했다. attempt43 시험 설치기는 패키지와 같은 mode `0755`를 적용했고, Guest UID 1000의 read/execute 검사가 통과했다. attempt42 결과의 `GUEST_PHASE3_IPC=VERIFIED`는 명령문 로그 안의 marker를 잡은 거짓 양성이었고, attempt43에서 실제 출력 줄과 정확히 비교하도록 고쳤다.
- attempts41, 43, 44에서 ServiceManager는 예상 Guest SID로 실행됐지만 `servicemanager.ready=true` 전에 exit status 1로 끝났다. attempt43의 직접 `getprop` 실행은 spawn EACCES를 냈다. attempt44에서는 기존 Guest shell 경로로 readback해 명령은 성공했고 값은 두 번 모두 `false`였다. Binder node는 mode `0666`; Context Manager probe는 `DeadObject`; ServiceManager stdout/stderr 로그는 비어 있었다.
- attempt44의 종료 관측은 `wait_guest_servicemanager_property`에서 ServiceManager PID 26819의 `CLD_EXITED/status=1`을 받은 시점이다 (`out/property-readiness-20261115/attempt44/device-stage/attempt44/evidence/worker.log:213–225,3067`). 관련 enforcing AVC나 dmesg 오류는 없다. runtime logcat의 ServiceManager 실행 관련 AVC는 `permissive=1`이므로 원인으로 보지 않는다. 기존 증거로는 프로세스가 readiness 전에 종료했다는 지점까지만 확정하며, 내부 syscall/함수 원인은 미확정이다.

attempt41–44에서는 Host Enforcing/boot ID/system_server, active policy hash, 적용된 Guest policy, 원본 userdata 크기·mtime·inode가 각 실행 전후 유지됐다. attempt36에 추가한 Guest-only type transition은 계속 적용되어 있다. attempt41–44 시험 stage, bin, userdata clone은 정리했고 로컬 evidence는 `out/property-readiness-20261115/attemptN/device-stage/attemptN/evidence/` 아래 보존했다. 기기를 재부팅하지 않았다.

## 2026-11-16: ServiceManager 로그와 live kernel AV 조회

`Service::start`의 일반 서비스는 Guest `/run/ssal/*.log` 파일 FD를 stdout/stderr로
상속했다. property service에 이미 사용하던 부모 pipe 수집을 ServiceManager에
적용한 attempt45에서는 status 1 종료가 재현되지 않았고, 프로세스가 이벤트 루프에서
살아 있는 상태로 readiness timeout이 났다. 보존된 로그는 self registration 실패와
`Failed to set servicemanager ready property`를 보여준다
(`out/property-readiness-20261115/attempt45/device-stage/worker.log:395–403`).
property service는 실제 Guest ServiceManager SID에 대한 authorization EACCES를
기록했다 (`worker.log:3245`).
attempt45의 Context Manager 진단은 운영 경로에서 복사한 구버전 `phase3-ipc`가
`context-manager` 명령을 지원하지 않아 무효였다. attempt46/47에는 현재 빌드 helper를 설치했다.

Host에서 실제 selinuxfs access decision을 조회한 결과:

- Guest ServiceManager → Guest servicemanager_prop `property_service:set`: ALLOW.
- Guest init → 복제 Guest kernel `security:compute_av`: ALLOW.
- Guest init → 실제 kernel `security:compute_av`: DENY.

즉, property writer 권한은 있었으나 property service가 실제 커널에서 AV 결정을
계산할 권한이 없었다. `Plan::ensure_kernel_av_access`는 Guest init과 Guest
ServiceManager에 실제 `kernel:security compute_av` 두 규칙만 추가한다.
기존 plan cache를 읽은 경우에도 `prepare_mounted`에서 적용하며 기존 정책은 보존한다.
Guest ServiceManager의 libselinux 자체 서비스 접근 검사에도 같은 live kernel 조회가 필요하다.

attempt46에서 `servicemanager.ready=true`, private Binder Context Manager 도달을
확인했다 (`out/property-readiness-20261115/attempt46/device-stage/worker.log:218–220`).
이후 AIDL 서버가 빈 로그로 종료했으므로 같은 FD 문제를 공통 경로에서 수정했다.
일반 서비스는 부모가 pipe를 읽어 로그를 저장하며, Zygote/memory probe의 기존
diagnostic 수집 경로는 유지한다. readiness 대기와 실패 진단에서 출력을 drain한다.
Guest에 system_file 쓰기 권한을 추가하지 않았다.

attempt47 실행 중 조회에서도 Guest ServiceManager와 shell의 Guest system_file
`file:write`는 DENY였고, init과 ServiceManager의 실제 kernel `compute_av`는 ALLOW였다
(`out/property-readiness-20261115/attempt47/query-av.txt:1–4`). 이것은 직접 로그 파일 FD의
권한 문제를 뒷받침하지만, attempt44에서 status 1을 발생시킨 정확한 내부 함수나
syscall은 별도로 추적하지 않았다.

attempt46의 적용 기록 차이는 위 Guest 주체 두 규칙의 추가뿐이고, 기존 statement
삭제와 symbol 변경은 없었다 (`out/property-readiness-20261115/attempt46/policy-delta.json`).
이때 active policy hash 변경은 의도한 additive 변경이다. Host Enforcing, boot ID,
system_server PID, PID 1 mountinfo, 원본 userdata 크기/mtime/inode와 Host cgroup 상태는
전후 같았다. attempt45/46 시험 파일과 userdata 사본은 Luna가 정리했으며 로컬 evidence는 보존했다.
attempt46 harness는 기존 hash 동일성 검사 때문에 전체 exit 1을 유지했고, worker 자체의
실패 원인은 AIDL 서버 종료였다. ServiceManager readiness 통과와 구분한다.

검증: WSLc `ssal-dev`에서 Guest policy 테스트 21개 PASS/fixture 2개 ignored,
launcher 테스트 10개 PASS, `cargo fmt --all -- --check`, Android release build PASS.
새 security 회귀 테스트는 Guest 주체 두 개의 compute_av 규칙만 추가되는지,
중복 호출 시 규칙/native command가 늘지 않는지를 검사한다.

### attempt47 최종 결과와 다음 중단점

공통 부모 pipe 로깅 적용 후에도 ServiceManager는 계속 살아 있었고,
`GUEST_SERVICEMANAGER_PROPERTY=PASS value=true`와 Context Manager Binder transaction
성공을 재확인했다 (`out/property-readiness-20261115/attempt47/device-stage/worker.log:213–220`).
다음 AIDL 서버의 status 1은 이제 자체 로그에
`Security / Ok: SELinux denied for service.`로 보존된다 (`worker.log:232–233,3077`).
같은 로그 파일 FD 문제가 다른 일반 서비스에서도 진단을 가렸음을 확인했다.

별도 access decision 조회로 원인을 분리했다
(`out/property-readiness-20261115/attempt47/query-aidl-av.txt:1–2`):

- 현재 AIDL helper의 Guest shell SID → Guest aidl_lazy_test_service `service_manager:add`: DENY.
- Guest aidl_lazy_test_server SID → 같은 target의 `service_manager:add`: ALLOW.

따라서 다음 작업은 AIDL helper의 전용 Guest server domain 실행/entrypoint 준비다.
이번 수정에서 shell의 서비스 등록 권한을 확대하지 않았다. 전체
`GUEST_SERVICEMANAGER_READINESS=PASS`, `PHASE5B=PASS`, Zygote/system_server 첫 부팅은
아직 통과하지 않았으며 worker exit는 1이다. attempt44의 status 1 내부 호출 추적과도
구별한다. 실행 관련 permissive AVC를 원인으로 단정하지 않는다.

attempt47의 Host core snapshot, active policy hash, Guest applied policy, 원본 userdata
크기/mtime/inode, Host cgroup snapshot은 전후 byte 단위로 일치했다. 원본 userdata 전체
hash는 검사하지 않았다. worker의 cgroup/rootfs mount/46개 loop 정리는 통과했다.
운영 바이너리를 교체하거나 기기를 재부팅하지 않았다. 시험용 ssald SHA-256:
`873cc0beb1abc388b07135fba828fb279d0a640b206af62b1f8a2165e036ba73`.

Luna가 attempt47 시험 stage/bin/userdata 사본도 정리했다
(`out/property-readiness-20261115/attempt47/device-stage/cleanup-summary.md`).
00:52:40 KST의 ServiceManager SIGABRT PID 32060/32061/32066은 조사 중 main agent의
adb/su 셸 인용 오류로 필터 문자열 일부가 별도 명령으로 실행된 진단 오염이다.
`servicemanager I`, `servicemanager E`, `servicemanager readiness`라는 cmdline이 남아
있으며 Guest PID 31676/4274/5275의 종료 증거로 해석하지 않는다
(`logcat-runtime-filtered.txt:29–40`). 이후 원래 Host ServiceManager PID 714,
system_server PID 2280, Enforcing과 boot ID가 유지됨을 재확인했다.
