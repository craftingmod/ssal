# SSAL rsbinder Phase 4 결과

- 상태: **PARTIAL**
- 시험일: 2026-11-04 (Asia/Seoul)
- 계획: [rsbinder-phase4-plan.md](rsbinder-phase4-plan.md)
- 호환성 조사: [rsbinder-phase4-compatibility.md](rsbinder-phase4-compatibility.md)

## 판정

Android 16 Guest SDK 36에서 Private Binder 기반 `IServiceManager` 조회와 Phase 3 Rust AIDL 회귀가 통과했다. Host registry 격리와 SELinux Enforcing도 유지했고, 시험용 runtime rule은 원복했다. 다만 실제 Guest `installd` 또는 `artd`의 AIDL 메서드, FD 인수, Java system_server client 및 Android 16 Host 단말은 검증하지 않았다. 계획상 Phase 4에서 실제 서비스를 실행하지 않으며, 별도 userdata/mount/property 경계 증거도 실제 서비스에 충분하지 않아 `PARTIAL`로 남긴다.

확인된 Binder 호환성 결함은 없다. 따라서 source, AIDL, SELinux 영구 정책 또는 Cargo 의존성 변경은 하지 않았다.

## 실행한 검증

| 항목 | 결과 |
|---|---|
| Root Cargo unit tests | 통과: 25개 |
| Phase 2 crate unit tests | 통과: 1개 |
| Phase 3 crate unit tests | `cargo test` 성공, 정의된 unit test 없음 |
| Rust format | `cargo fmt --all -- --check` 통과 |
| Android AArch64 빌드 | `ssald` (`phase3-diagnostic`), Phase 2 `guest_probe`, Phase 3 `phase3-ipc`, Phase 3 helper 통과 |
| Phase 2C Guest Private Binder | 통과: protocol 8, Guest SDK 36, `BBinder` descriptor, `IServiceManager.checkService2` 조회 |
| Phase 3 Rust AIDL | 통과: 등록/조회, descriptor, `add(17,25)=42`, `echo`, callback Binder 전달 및 2회 호출, death notification, 재시작·재연결 |
| SELinux | Enforcing 유지. 시험 중 runtime allow 1개 적용 후 원복, policy hash 기준값과 일치 |
| 실제 Guest `installd` / `artd` | 실행하지 않음 |

Root 및 Phase 2/3 host unit tests의 전체 상세는 기존 [Phase 3 결과](rsbinder-phase3-results.md)를 참고한다. 이번 Android runner 결과는 아래 기기 범위에 한정된다.

## 기기 및 Guest 결과

- 기기: SM-S937N, Android 17 / API 37 Host; Android 16 / SDK 36 Guest image `lineage`의 `profile1`.
- Global SELinux는 시험 전후 `Enforcing`이었다.
- Guest Private Binder와 Host Binder는 다른 Binder device identity였다. Guest probe에서 protocol 8을 협상하고 Android 16 ServiceManager variant로 `aidl_lazy_test_1`의 `BBinder` descriptor를 조회했다.
- Phase 3 `IPhase3Service` descriptor는 `org.ssal.phase3.IPhase3Service`였다. 동기 메서드와 callback 두 번, 서버 사망 감지, 서비스 제거, 서버 재시작 뒤 재조회가 통과했다.
- Host registry의 `package`는 계속 found였고 `aidl_lazy_test_1`은 Host에서 계속 absent였다. runner의 5개 Host snapshot 지점에서 변경이 없었다.
- `installd`는 시험 전후 같은 PID `2607`이었다. Host `artd`는 시험 전후 프로세스 목록에 없었다. Phase 4는 둘 중 어느 것도 stop/start 하지 않았다.

## SELinux runtime rule 기록

Baseline에서 callback transaction이 `TransactionFailed`로 끝났다. 기존 [Phase 3 결과](rsbinder-phase3-results.md)는 동일 경로의 거부를 `aidl_lazy_test_server → shell : binder call`로 특정했고, runtime 최소 규칙으로 재시험했을 때 통과했다. 이번 runner도 해당 AIDL callback을 포함하므로 아래 한 규칙만 runtime으로 적용했다.

```selinux
allow aidl_lazy_test_server shell binder call
```

| 시점 | `/sys/fs/selinux/policy` SHA-256 |
|---|---|
| 적용 전 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` |
| 단일 allow 적용 중 | `589ecad0b5eada1d940e678250c3dfd977ee194e315bb4b98e84cc61984f7663` |
| 동일 권한 deny로 원복 후 | `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723` |

설치된 영구 `/data/adb/modules/ssal/sepolicy.rule` SHA-256은 전후 모두 `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389`였다. 전체 Permissive 전환이나 영구 정책 변경은 없었다. 최종 확인에서 SELinux는 Enforcing이고 runtime policy hash는 baseline과 같았다.

## 실행 및 정리 기록

첫 두 runner 호출은 임시 runner 옆에 필요한 helper/manifest가 빠졌거나 기존 helper가 Phase 3 역할을 모르는 빌드여서 AIDL 회귀에 도달하지 못했다. 현재 source의 Phase 3 helper와 설치본의 일치하는 Binder helper manifest를 임시 위치에 두고 재실행했다. 이 준비 오류들은 Binder 호환성 실패로 계산하지 않았다.

최종 실행은 Phase 3 callback 검증을 포함해 통과했고, runner가 Test B server, Rust server/client, Guest mount와 loop allocation을 정리했다. 후속 확인에서 `/data/local/ssal/mnt`는 비어 있었고, Host의 `package`는 found, Guest 전용 service 이름은 Host에서 absent였다. 모든 임시 바이너리, manifest, SELinux rule 파일도 지정한 `/data/local/tmp` 경로에서 삭제하고 부재를 확인했다.

## 남은 검증 및 다음 단계

1. Android 16 Host 실기기에서 동일한 Android 16 Guest 시험을 재현한다.
2. `IInstalld`와 `IArtd`의 실제 Android 16 AIDL method, Java client, FD 전달과 소유권을 각각 격리한 mock/service 시험으로 확인한다. 대상 서비스를 직접 실행하는 검증은 Phase 5로 남긴다.
3. oneway, 큰 transaction, 동시 thread pool, `getService`/`listServices`/lazy registration, Binder caller identity를 호출 계약상 필요한 범위만 시험한다.
4. Guest 전용 `/data`, `/config`, `/mnt/expand`, ART APEX data, property service 및 private ServiceManager가 Host 경로·서비스와 분리되어 있음을 입증한 뒤 Phase 5 진입 여부를 판정한다.

