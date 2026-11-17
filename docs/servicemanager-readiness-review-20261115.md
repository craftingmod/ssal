# servicemanager readiness 패치 검토 및 attempt20

2026-11-15 KST, Lenovo TB320FC / Y702 (`HA1WAQ7P`), Host Enforcing.
검토 범위는 servicemanager readiness 변경과 직접 연결된 공통 launcher, property service, phase3 IPC 및 호출 worker다. vendor 소스는 읽지 않았다. 제품 코드는 변경하지 않았다.

## 검토 판정: 수정 필요

1. **[P1] Context Manager probe가 조회 오류를 성공으로 처리한다.**
   `tools/rsbinder/src/android.rs:245`는 존재하지 않는 이름에 대한 `check_interface`의 `NameNotFound`를 성공으로 인정한다. 설치된 rsbinder 0.12.0의 `src/hub/mod.rs:944`는 `check_service`가 반환한 None을 NameNotFound로 바꾼다. Android16 `src/hub/servicemanager_16.rs:147–152`는 checkService2 transaction 오류도 None으로 바꾼다. 따라서 서비스가 없는 정상 응답과 transaction 오류를 구분하지 못한다.
   최소 수정은 오류를 보존하는 `try_get_service`의 `Ok(None)`만 정상 응답으로 인정하는 것이다. 최종 AIDL 실제 호출 검사는 별도이므로 이 문제만으로 최종 readiness 전체가 거짓 PASS한다고 단정하지 않는다.

2. **[P1] 이전 worker가 property readiness를 충족할 수 없다.**
   `src/guest_launcher.rs:1219`는 phase7a에서만 Guest property service를 선택하지만, `:1533`은 모든 공통 launcher worker에 `servicemanager.ready=true`를 요구한다. phase7a가 아닌 `--guest-service-worker`, `--guest-services-6a-worker`, `--guest-services-6b-worker`는 false로 초기화한 area와 property socket 부재 경로를 사용하므로 true로 갱신할 수 없어 실패한다.
   최소 수정은 이 worker들에도 Guest property service를 제공하고 socket/초기 property 검사도 일치시키거나, 해당 worker 계약에 맞게 property readiness 검사를 phase7a로 제한하고 PASS 문구를 구분하는 것이다. 시작 전 true 주입으로 되돌리면 안 된다.

## 실제 실행

`out/guest-first-boot-20261115/attempt20/run-attempt20.sh`로 원본 userdata 사본을 사용했다. 운영 daemon은 교체하지 않았으며, 시험 바이너리는 별도 디렉터리에 배치했다. Guest memory soft/hard limit은 1 GiB / 1.5 GiB다. SELinux bypass, 고정 SID, 8B-5 hook은 선택하지 않았다.

- ssald SHA-256: `a3d75d19d3e650c58d21157accee6d7b6e09d73e24c0f231a483d089ed04864b`
- phase3-ipc SHA-256: `aa3e7d67b4074dd9d883bf704999003300fe27745df13b60c0385b6da7a89245`
- `worker.log:173–175`: Guest property service PID 1647가 /ssal_guest membership 확인 후 exit status 1로 종료했다. readiness 로그는 비어 있었다.
- `worker.log:177–180`: cgroup 정리, rootfs 잔여 mount 부재, loop 46개 해제 후 worker exit 1.
- servicemanager, Context Manager probe, AIDL 시험 서비스, Zygote 시작에 도달하지 못했다. readiness 런타임 PASS는 없다.
- `logcat-targeted.txt:4–5`: 08:30:04.806에 `ssal_p0001_init`의 `/run/ssal/guest-property-service.log` 쓰기가 Enforcing 정책에 거부됐다. 실패 메시지 기록이 차단된 증거이며, 이 거부만으로 startup exit 1의 직접 원인은 확정할 수 없다. servicemanager의 property 쓰기 권한은 아직 미검증이다.
- before/after core, active policy hash, Host cgroup snapshot 및 원본 userdata 크기/mtime/inode는 동일했다. 원본 userdata 전체 hash 검증은 아니다.

## 빌드 및 검사

WSLc를 샌드박스 밖에서 실행했다. `cargo fmt --all -- --check`, Android release build 및 phase3-ipc release build가 통과했다. 기존 guest_launcher 테스트 8개와 guest_probe 테스트 7개가 통과했다. 권한이 필요한 기존 테스트 2개는 ignored였다. 위 두 판정 오류를 직접 검증하는 회귀 테스트는 현재 없다.

대량 runtime 로그 분석과 시험 파일 정리는 Luna가 수행했다. 시험 userdata 사본과 별도 bin 디렉터리를 제거했고 Guest 프로세스·cgroup·Host mount·loop 잔여 참조가 없음을 확인했다. 로그와 stage/cache는 보존했다. 별도 `attempt20/runtime-analysis.md`를 참고한다. 전체 Guest 부팅, Guest sys.boot_completed, 하드 재부팅 후 복구는 검증하지 않았다.
