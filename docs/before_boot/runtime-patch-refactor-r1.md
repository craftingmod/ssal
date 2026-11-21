# SSAL Runtime Patch Refactor — Phase R1

2026-11-16 KST. 대상: `runtime-patch-classification-audit.md`의 F3. F1/F4, vendor 소스, 실기기 정책 주입 및 서비스 실행은 범위 밖이다.

## 변경 파일과 계약

| 파일 | 변경 |
|---|---|
| `src/guest_policy.rs` | socket transition·live kernel compute_av 보정을 `generate`의 마지막 단계로 이동. 생성 버전 11→12로 이전 캐시를 재생성. 생성·cache miss/hit·history의 동일성, 중복·누락·encoding 회귀 테스트 추가. 저장 GSI의 고정 기대값 갱신. |
| `src/guest_policy/runtime.rs` | `prepare_mounted`의 메모리 전용 보정 호출 제거. 기존 필수 타입 검사는 유지. 호환 plan 저장과 두 plan의 SHA-256 기록, ledger의 readback 미검증 필드 추가. 구형 ledger 역직렬화 및 desired 불변성 테스트 보강. |
| `docs/runtime-patch-refactor-r1.md` | 결과·예외·검증 한계 기록. |

동일 profile ID·입력·생성 버전에서는 `generate`, `prepare`의 cache miss/hit, `selinux/plan.json`, `selinux/plans/v12-<input_hash>.json`이 같은 최종 **desired** plan을 사용한다. `generate-encode`도 같은 생성 함수를 사용한다. 구버전 history는 삭제하지 않는다. 캐시 적중 시 parser 재실행이나 artifact 재기록은 하지 않는다.

제거한 중복 처리는 생성·저장 이후 mounted 경로에서만 다시 보정하던 별도 단계다. 보정 규칙 자체나 CIL에서 동일 규칙이 도출되는 처리는 제거하지 않았다. 기존 `BTreeSet` 및 native `record`의 중복 제거를 재사용한다. 새 규칙·권한을 설계한 것이 아니라 기존 mounted 성공 경로의 규칙을 생성 artifact에 포함했다.

## desired / compatible / applied 증거

| 상태 | 파일 / 의미 |
|---|---|
| desired | `selinux/plan.json`과 버전별 history. GSI 변환 및 SSAL 공통 보정 완료. Host class/symbol 호환 변환 전이다. |
| compatible | 새 `selinux/compatible-plan.json`. 현재 Host 심볼·class/permission 및 기존 placeholder ledger를 반영한 적용 후보다. `compatibility.json`의 기존 omission·backend·unsupported 정보와 desired/compatible plan SHA-256으로 구분한다. hash 대상은 pretty JSON 직렬화 bytes다. |
| applied | 기존 `selinux/applied.json`. 해당 boot에서 backend가 성공 응답한 statement 누적 원장과 pending/부분 실패 증거다. 새 `rule_readback_verified`는 false이며 구형 파일의 필드 누락도 false로 읽는다. 성공 문자열도 backend acknowledgement와 rule readback 미검증을 구분한다. |

`compatibility.json`과 `compatible-plan.json`은 마지막 호환 변환 시도의 증거다. 이후 delta 검증, 충돌 검사, driver 또는 주입 단계가 실패할 수도 있으므로 적용 완료 증거가 아니다. 두 파일은 각각 atomic 저장되지만 한 transaction은 아니다. 불일치 여부는 hash로 확인해야 한다.

applied 원장은 desired/compatible과 집합이 같을 필요가 없다. 같은 boot에서 desired에서 지운 규칙도 kernel과 누적 ledger에 남는다. 다음 boot에서는 기존 boot ID 초기화 경로를 그대로 사용한다. 기존 context 질의는 process context 존재를 확인할 뿐 모든 rule의 kernel readback이나 GSI 원본 정책과의 의미적 동등성을 입증하지 않는다.

## 보존한 예외와 경계

- profile ID 형식·영구 예약·중복 검사, 기존 `Plan` schema와 실행 API를 유지했다. 새 ledger 필드는 serde default로 이전 파일과 호환된다.
- KernelSU의 boot별 ledger, 소유권 충돌, pending/부분 실패 후 reboot 요구, 비삭제 누적, lock 순서와 적용 순서를 유지했다.
- ksud 정규화·xperm 분할, native UAPI 5·16 KiB batch·특수 filename transition backend 선택·structured command 검증을 유지했다.
- Host constraints·filesystem label 보존, Guest source 제한, Enforcing 검사, nlmsg 예외, permissionless placeholder와 재시도 보호, Host permission 축소·누락 기록, export EINVAL 복구를 유지했다.
- 최소 타입만 있는 오프라인 fixture의 생성은 계속 허용한다. 필요한 타입이 모두 있을 때 해당 보정을 생성한다. mounted 경로는 기존 init/servicemanager/socket_device/property_socket 필수 검사를 유지한다.
- 명시적 `encode/check/apply`로 주어진 과거 JSON을 몰래 보정하거나 재작성하지 않는다. 캐시 업그레이드는 `prepare`에서 버전으로 수행하며, mounted 경로와 신규 offline 생성은 v12 계약을 사용한다.

## 오프라인 검증

WSLc 명령은 저장소 지침에 따라 sandbox 밖에서 실행했다. adb·정책 주입·실기기 prepare는 실행하지 않았다.

1. 변경 전 `cargo test --locked --lib guest_policy`: **21 passed, 2 ignored**.
2. 변경 후 synthetic 정책 테스트: **22 passed, 2 ignored**. cache miss/hit·v11 누락 보정 재생성·history bytes 동일성, 기존 mounted 보정과 rules/native commands 동일성, 중복 transition의 plan 및 encoding 불변성, 누락 native command 거부를 확인했다. 기존 pending/부분 실패·다음 boot 빈 ledger delta·placeholder·Host capability 누락/축소·xperm·특수 이름 encoding 테스트도 통과했다.
3. 저장 fixture 포함 전체 library: **49 passed, 0 failed, 0 ignored**.

   ```text
   wslc exec --workdir /src ssal-dev env SSAL_POLICY_FIXTURE=/src/.cache/selinux-check-20261031/guest SSAL_HOST_POLICY_FIXTURE=/src/out/property-host-policy-20261101.bin cargo test --locked --lib -- --include-ignored
   ```

4. `wslc exec --workdir /src ssal-dev cargo test --locked --bins`: **91 passed, 0 failed, 4 ignored**. mount/chroot/pivot/ext4의 권한 필요 테스트는 미실행.
5. 저장 GSI의 `generate-encode` 성공: **26 inputs, 2,040 types, 49,817 rules, 347 transitions, 133,809 native commands, 11,259,969 bytes, 702 batches**. 주입 없음. `out/runtime-patch-r1/`에 desired JSON·encoding manifest·batch가 있다.

저장 GSI 테스트의 기존 golden(49,802 rules / 133,794 commands)은 첫 fixture 실행에서 불일치했다. 이번 보정 세 규칙을 뺀 v11 생성 plan 재구성도 **49,814 rules / 133,806 commands / 11,259,718 bytes**로 기존 golden과 달랐다. 이는 과거 소스 checkout 재실행 결과가 아니라, 이번 diff가 추가한 세 보정 규칙을 v12 plan에서 제외한 오프라인 재구성이다. 이번 생성 위치 이동의 차이는 **+3 rules / +3 commands / +251 bytes**다. 새 golden은 현재 저장 fixture 전체 encoding 결과로 갱신했다. 이 수치를 실기기 적용 결과로 해석하지 않는다.

## 남은 UNKNOWN

- 현재 kernel의 최종 rule readback, 실제 새 SID 전환·AV 허용, AIDL 전체 PASS·첫 부팅·삼성 One UI 복구는 검증하지 않았다.
- compatible artifact 저장의 실기기 I/O 및 기존 KernelSU ledger와의 실제 재시도는 실행하지 않았다. synthetic 변환·delta·구형 ledger 읽기 검증에 한정된다.
- cache key는 기존처럼 입력 hash·ID·버전이다. 현재 버전 캐시를 외부에서 변조하거나 규칙을 지운 경우의 무결성 검증은 추가하지 않았다. native 검증은 존재하는 rule과 command의 대응을 검사하며 원본 입력에서 모든 규칙을 재도출하는 검사는 아니다.
- 기존 nlmsg 23건 누락의 서비스별 영향, Host 호환 변환으로 축소된 정책과 GSI 원본의 의미적 동등성은 UNKNOWN이다.
- F1의 실행 도메인·고정 SID와 F4의 AIDL fixture gate는 수정하지 않았다. 이번 검증은 그 문제를 해결하거나 실행 승인을 제공하지 않는다.
