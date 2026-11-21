# Guest cgroup 사전 배치와 조기 종료 구분

2026-11-15. 공통 Guest launcher의 부모 측 `spawn()` 후 cgroup 재등록을 제거했다. `command()`를 사용하는 서비스, 일회성 명령, libprocessgroup probe 모두 자식의 `pre_exec`에서 준비된 Guest cgroup에 등록한다. v1 memory와 v2 unified를 포함한 각 bind mount의 `cgroup.procs`를 읽어 현재 PID가 있는지 확인하고, UID/GID 변경 뒤 memory membership 경로를 한 번 더 확인한다. 등록·검증 실패 시 `exec`하지 않는다. cgroup 생성·제한·mount 준비는 기존 ssald 경로를 유지한다.

`spawn()` 성공 뒤 부모는 membership을 관찰만 한다. 서비스가 이미 종료됐으면 `waitid(WNOWAIT)`의 `si_code`와 `si_status`를 별도로 보고한다. membership 검사 실패 시에도 종료 상태를 다시 기록한다. `si_code`의 CLD_EXITED는 exit code, CLD_KILLED/CLD_DUMPED는 종료 signal을 뜻한다. leader는 기존 `Service::stop()`의 `Child::wait()`까지 회수하지 않아 process group 종료와 진단 수집을 유지한다.

Y702에서 읽기 전용으로 조회한 `/data/local/tmp/ssal-first-boot-20261115/attempt15/worker.log:211–217`은 servicemanager PID 17805의 v1 memory 경로가 `/`였음을 보여준다. 이 기록에는 그 시점의 종료 상태가 없으므로 task profile 재배치, exec 전후 이동 또는 프로세스 종료 중 어느 것이 원인인지 확정하지 않는다. 이번 수정은 exec 후 재등록으로 이 차이를 덮지 않는다.

검증: sandbox 밖 기존 WSLc `ssal-dev`에서 `cargo test --locked --bin ssald guest_launcher::tests` 8개 PASS, `cargo fmt --check` PASS, Android AArch64 `ssald` release 빌드 PASS. 새 테스트는 임시 파일로 독립 계층의 사전 등록 순서와 readback 실패·등록 실패 시 exec 차단을 검사한다. 기존 SIGABRT 테스트는 waitid 반복 관찰이 종료 상태를 회수하지 않고 이후 진단 수집이 유지됨을 검사한다.

수정 바이너리의 실기기 실행과 실제 cgroup controller 동작은 이번 변경에서 재검증하지 않았다. servicemanager 종료 원인과 첫 부팅 성공은 여전히 미확정이다. Host SELinux 정책과 cgroup controller 설정 변경은 추가하지 않았다.
