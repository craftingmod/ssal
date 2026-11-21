# SSAL Phase 6B-Fix — installd PASS, artd backlog

2026-11-04, SM-S937N, Android 17 Host / Android 16 Guest.

**Phase 6B-Fix 결과: PASS (installd create/delete).** artd dexopt와 Guest OAT/VDEX는 별도 backlog다. 이 작업을 위해 Phase 6B-Fix를 반복하지 않는다.

| 검사 | 결과 | 근거 |
|---|---|---|
| Phase 5B | PASS | Guest property/FD 및 control socket 경계, Private Binder 507:5 AIDL 호출 |
| Phase 6A | PASS | 같은 session의 installd 및 artd descriptor |
| `createAppData` | PASS | RPC 성공, CE/DE 디렉터리 UID 10000 및 Guest userdata inode 확인 |
| `destroyAppData` | PASS | RPC 성공, CE/DE 디렉터리 부재 확인 |
| `dexopt(verify)` / OAT·VDEX | BACKLOG | 공통 launcher에 Phase 2 compiler proc shim, broker, classpath와 fixture를 아직 연결하지 않음. 6B-Fix 완료 조건에서 제외 |
| Host 핵심 상태 및 cleanup | PASS (아래 범위) | 실행 전후 snapshot 동일, Host Enforcing 유지, Guest 서비스 종료, cgroup·mount·55개 loop 정리 |

세 번째 실행의 자세한 로그는 [기기 로그](guest-services-phase6b-fix-device-r3.log)에 있다. `ssal_guest_probe`에서 실제 Phase 2 Binder client를 실행했으며 Host `installd`/`artd` domain이나 global SELinux mode를 바꾸지 않았다. 사전에 테스트 패키지와 profile 경로가 없음을 검사하고, create 실패 시에도 destroy를 시도한다. 생성한 테스트 profile은 정리했다.

첫 실행은 이미 read-only bind된 Binder helper를 다시 생성하려 해 RPC 전에 실패했고, 이를 수정했다. [두 번째 실행](guest-services-phase6b-fix-device-r2.log)은 Guest `misc/profiles/cur/0` 부재로 create가 실패했고 destroy는 성공했다. 세 번째 실행에서 누락된 디렉터리를 준비해 생성·삭제를 확인했다. 각 실행에서 Host snapshot은 동일했고 cgroup, mount, loop 정리는 통과했다. 마지막 실행의 Guest PID와 테스트 경로도 부재를 확인했으며 `/dev/ssal-common-launcher` 임시 staging과 이 시험에서 만든 빈 profile 상위 디렉터리를 제거했다.

Host snapshot은 boot ID, PID 1 mountinfo, `/data` 및 Binder/property endpoint의 identity, 표본 property, 핵심 프로세스 및 registry 검사로 한정되며 Host `/data` 전체 내용의 digest는 아니다. PID namespace는 기존 구조를 유지했다. Zygote/system_server는 실행하지 않았다.

Phase 6B-Fix는 여기서 닫는다. 남은 dexopt/classpath/compiler-proc fixture 작업은 별도 backlog에서 다루며, 이를 위해 installd 검증을 다시 실행하지 않는다.
