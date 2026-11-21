# Guest private property 초기화 검증

2026-11-15 KST, Lenovo TB320FC (`HA1WAQ7P`), enforcing mode. 이 기록은 `out/property-init-fix-20261115/`의 worker5 증거를 정리한다.

## 패치와 결과

이 변경은 기본 private property 초기화에서 bootstrap linker 실행을 `run()`에서 `run_as(..., PROPERTY_SERVICE_CONTEXT)`로 바꿔 Guest init 문맥으로 실행한다. `SSAL_PHASE7I_PROPERTIES=1` 경로는 이번 시험에서 선택하지 않았다.

`out/property-init-fix-20261115/worker5.log:175–176`에서 property 초기화 프로세스가 exit 0으로 끝났고, private area readback에서 SDK `36`, full SDK `36.1`, codenames `REL`을 확인했다. 이어진 `linkerconfig` 실행은 `worker5.log:198`에서 EACCES로 막혔고 전체 worker 종료 코드는 `worker5.rc`의 `1`이다. 따라서 이 결과는 property 초기화 성공이며 Guest 부팅 성공이 아니다.

`before1.txt`와 `after.txt`의 Host 상태 스냅샷은 동일하다: enforcing 상태, boot ID, `sys.boot_completed`, system_server PID, PID 1 mountinfo hash, 원본 userdata의 크기/mtime/inode가 일치한다. 이는 원본 userdata의 메타데이터 확인이며 **userdata 전체 hash 검증은 하지 않았다**. 정책 자체는 `policy-before.txt`와 `policy-after.txt`의 hash가 다르다. `policy-additions.rule`의 Guest 규칙 5개가 적용된 상태를 기록한 것이다. KernelSU 동적 정책은 재부팅 전까지 남으며 여기서 제거하거나 되돌리지 않았다.

## 임시 자원과 검증 범위

단말 `HA1WAQ7P` (`TB320FC`)에서 두 대상 경로 모두 존재를 확인한 뒤, matching process, mount, loop backing 참조가 없는 것을 확인하고 `/data/local/tmp/ssal-property-init-fix-20261115`와 `/data/adb/modules/ssal/bin/.ssal-property-init-fix-test`만 삭제했다. 삭제 후 경로 부재와 참조 부재를 재확인했다. 이번 진단 tracefs instance는 이미 없었고, 활성 tracefs의 `kprobe_events`에서도 `ssal_property_diag` 항목이 없었다. 다른 추적 설정은 변경하지 않았다.

원본 userdata, 기존 `.userdata-first-boot-test.img`, `.ssal-y702-first-boot-test`, 운영 바이너리와 로컬 `out/property-init-fix-20261115/` 증거는 보존했다.

전체 부팅, 하드 재부팅 후 One UI 복구, optional property service는 검증하지 않았다. 재부팅은 하지 않았다.
