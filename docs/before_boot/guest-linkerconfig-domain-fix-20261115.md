# Guest linkerconfig 실행 문맥 수정

`guest_launcher::command`의 mapped Guest 실행에서 runtime APEX와 `/system/bin`의 linkerconfig를 Guest `linkerconfig` 도메인으로 실행한다. 기존 기본값인 Guest `shell` 대신 실행 파일에 대응하는 서비스 도메인을 선택한다. private property 초기화의 Guest `init` 문맥과 일반 probe의 Guest `shell` 문맥은 유지한다.

직접 실행하는 Guest linkerconfig에도 기존 init/shell helper와 같은 런처 stdio 권한(`ksu:fd use`, `ksu:fifo_file write`)을 추가한다. 정책 생성 버전은 9로 올려 기존 프로필 캐시가 갱신되도록 했다. Guest 규칙을 추가하며 Host 규칙과 enforcing 상태는 변경하지 않는다.

## 검증

- WSLc 컨테이너에서 `cargo test --locked --lib --bin ssald guest_`: 64 passed, 5 ignored. 도메인 선택, 정책 native encoding, 캐시 갱신 회귀를 포함한다. ignored는 외부 fixture/특권 환경이 필요한 기존 시험이다.
- Android AArch64 release `ssald` 빌드, 수정 파일 rustfmt check 및 diff whitespace check 통과.
- 시험 바이너리 SHA-256: `f896ec99a3523cf01bf8b98d1622308aa3f8c9a5c6bd9ce431a4d89aefc1d101`.

## 실기기 시험 환경

Lenovo TB320FC (`HA1WAQ7P`), Y702, Host enforcing. 기존 `.userdata-first-boot-test.img` 사본을 사용하고 운영 바이너리는 교체하지 않았다. 증거는 `out/linkerconfig-domain-fix-20261115/`에 보존한다.

첫 worker는 시험 디렉터리에 context-map 라이브러리를 빠뜨려 초기 준비에서 중단됐다. 두 번째 worker는 기존 시험 디렉터리의 오래된 guest_probe 때문에 private property 초기화에서 중단됐다. 세 번째 worker에는 로컬 `out/bin/guest_probe`의 수정된 helper를 배치했다.

첫 실행에서 추가된 정책은 `ssal_p0001_linkerconfig`의 위 stdio 규칙 2개다. KernelSU 동적 정책은 재부팅 전까지 남는다.

## 세 번째 worker 결과

2026-11-15 03:50:51 KST에 시작했다. `worker3.log:175`에서 private property 초기화 exit 0, `:193`에서 readback 완료를 확인했다. `:195`에서는 linkerconfig가 실제 실행된 뒤 SIGABRT로 종료했다. 기존 `spawn/root setup: EACCES`는 이 실행에서 재현되지 않았다. 다만 이전 EACCES의 정확한 syscall을 새로 확정한 것은 아니다.

linkerconfig stderr에는 생성 전 `ld.config.txt` 경고와 PID 23769의 fatal signal만 남았다(`:196–198`). 필터링 logcat은 Luna 에이전트가 분석했지만 해당 PID의 abort message/stack 또는 직접적인 AVC가 없었다. dmesg에서도 해당 PID/domain으로 일치하는 항목이 없었으며 새 Host tombstone도 생성되지 않았다. 따라서 **linkerconfig 생성 성공과 Guest 부팅 성공은 미검증**이며, 내부 SIGABRT 원인은 후속 조사 대상이다. 근거 없는 추가 allow는 적용하지 않았다.

`worker3.rc`는 전체 worker의 `1`이다. cgroup 정리, 잔여 rootfs mount 부재, loop 46개 해제는 `worker3.log:200–202`에서 확인했다. `before-worker3.txt`와 `after-worker3.txt`는 동일하다: Host enforcing, boot ID, Host 부팅 완료, system_server PID, PID 1 mountinfo hash 및 원본 userdata 크기/mtime/inode가 일치한다. 원본 userdata 전체 hash 검증은 하지 않았다. 세 번째 실행 전후 활성 정책 SHA-256도 동일하다(`cb29f489d64aadc440b1a855de17e5288700c9c1c574738638af1e4d51ec0f68`).

전체 첫 부팅, 삼성 순정 커널에서의 검증, 하드 재부팅 후 One UI 복구는 이번 시험 범위에 포함하지 않았다. 재부팅은 하지 않았다.

## 정리 인계

2026-11-15 KST에 Lenovo TB320FC (`HA1WAQ7P`)에서 아래 일곱 시험 산출물을 수동 삭제했고, 사후 확인에서 모두 부재했다.

- `/data/local/tmp/ssal-linkerconfig-domain-fix-20261115`
- `/data/adb/modules/ssal/bin/.ssal-linkerconfig-domain-test`
- `/data/local/tmp/ssal-linkerconfig-domain-ssald`
- `/data/local/tmp/ssal-linkerconfig-domain-guest-probe`
- `/data/local/tmp/ssal-linkerconfig-domain-run.sh`
- `/data/local/tmp/ssal-linkerconfig-domain-run2.sh`
- `/data/local/tmp/ssal-linkerconfig-domain-run3.sh`

실행 중인 일치 프로세스는 발견되지 않았다(adb 검색 셸 자체는 제외). Host enforcing 상태, boot ID, system_server PID, PID 1 mountinfo SHA-256은 `before-worker3.txt`와 일치했다. `/proc/*/fd` 전체 검사는 제한 시간 안에 끝나지 않아 열린 파일 참조 부재까지는 확인하지 못했다.

재부팅, 동적 정책 변경, 운영 바이너리 교체는 하지 않았다. 동적 Guest 정책은 재부팅 전까지 남는다. 로컬 증거, 원본 userdata와 기존 시험 userdata 사본도 보존했다.
