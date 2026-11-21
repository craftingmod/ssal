# Guest Enforcing 도메인 Live PoC 준비

> 후속 요청으로 `ksu`에서 전용 도메인으로의 최소 전환 규칙은 제한적으로 검토할 수 있다. 전체 정책 export는 필수 조건이 아니다. 최신 계획은 [Live PoC 계획](guest-selinux-live-poc-plan.md)을 따른다.

**판정: 실행 준비 차단.** 오프라인에서 고정 도메인 전환에 필요한 조건과 검토용 후보를 구체화했지만, 현재 커널 정책의 전체 export와 신규 타입에 대한 실효 AV가 없어 **완전하고 최소인 적용 정책은 결정할 수 없다.** 기존 Host 도메인 변경을 허용하지 않는 조건에서 `ksu`의 기존 권한이 부족하면 중단한다. 이번 작업은 저장된 자료와 로컬 dry-run만 사용했다. 기기 정책 적용, 라벨 변경, 프로세스 전환, permissive 설정은 수행하지 않았다.

## 정책 및 실행 계약

[정책 후보](../scripts/guest-domain-poc/policy-candidate.txt)의 정확한 세 문장은 `type ssal_guest_probe domain`, `type ssal_guest_probe_exec file_type`, `allow ssal_guest_probe ssal_guest_probe_exec file entrypoint`다. 이들은 대상과 entrypoint를 만들기 위한 **조건부 delta**이며 실행에 충분하다는 증거가 아니다. 중복 타입, role/MLS, 라벨 유효성, attribute, policy constraint, neverallow, 실제 파일시스템을 해결하지 못했다. 대상 permissive 문장은 포함하지 않는다. 전체 정책의 `-N` 재구성은 기존 기록에서만 성공했고 neverallow 검사를 통과하지 못했다.

| 단계 | 필요한 정확한 검사 | 현 상태 |
|---|---|---|
| 명시적 exec 지정 | `ksu → ksu process:setexec`, `ksu → ssal_guest_probe process:transition`; 필요시 실제 mount의 `process2:nosuid_transition`, NNP 및 자격 변화 조건 | 새 target은 현재 유효하지 않아 AV unknown. 기존 `ksu`의 동작은 permissive 관리 도메인의 관측이다. 기존 Host 도메인에 allow를 추가하지 않는다. |
| helper 접근 | `ksu → ssal_guest_probe_exec file:open/read/getattr/execute/map`, 상위 dir search, DAC, exec 가능한 mount; `ssal_guest_probe → ssal_guest_probe_exec file:entrypoint` | target 파일 라벨 및 모든 AV unknown. 헬퍼는 검토·승인한 바이너리와 SHA-256으로 고정해야 한다. |
| helper 실제 실행 | 대상 도메인의 dynamic linker와 각 라이브러리 접근, 자기 `/proc`·namespace·status 및 stdout pipe/FD 접근, 실행 파일 조회, 필요한 DAC | reporter와 실제 파일·프로세스 라벨에 따라 달라진다. 관련 AV와 libc 실행을 오프라인에서 확정할 수 없다. 거부될 때 무작위 allow를 추가하지 않는다. |
| 전용 파일 라벨 | 임시 파일의 기존 SID→새 SID `relabelfrom`/`relabelto`, 새 SID→실제 filesystem SID `filesystem:associate`, 해당 파일시스템의 per-inode SELinux 라벨 지원, DAC/capability | 초기 SID, filesystem SID, mount 옵션과 권한 unknown. `context=` mount, `nosuid`/`noexec`, 보안 mount 및 추가 constraint도 확인한다. 라벨 변경은 별도 승인 대상이다. |

AV 조회 허용은 실제 `execve` 성공을 보증하지 않는다. source/target, class, requested/allowed mask, permissive flag, sequence와 실제 FD 라벨을 기록한다. source로 사용하는 `ksu`는 과거 관측에서 permissive이므로 이것으로 Host source의 enforcing 집행을 증명하지 않는다. 런처의 `getattr` AV 조회는 대상 permissive flag 확인용이며, 그 권한의 허용을 실행 성공 조건으로 삼지 않는다. launcher가 모든 dynamic linker, NNP, mount, pipe, proc 조건을 사전 검증하지 않으므로 해당 부분은 별도 사전 점검이며 실패 가능성이 있다.

## Host 영향과 KernelSU 실패

저장된 삼성 platform CIL `out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/system/etc/selinux/plat_sepolicy.cil`, SHA-256 `425aba8b73da746a6338a3d42f6dfd20b5bfdd02163928f1aee0b7b333ab03c9`, 22173–22199행에는 `crash_dump → domain`의 `fd:use`, `process:getattr`, file read 계열 규칙이 있다. 24155행 등에는 `domain → self process`와 proc 접근 규칙도 있다. `domain`/`file_type`을 공용 attribute로 지정하면 신규 대상과 Host 사이의 권한 및 제약에 영향을 줄 수 있다. 이 정적 CIL은 당시 수집된 입력이지 현재 실효 정책이 아니며, 이미 컴파일된 AV가 KernelSU의 동적 attribute 추가 후 신규 타입에 어떻게 반영되는지는 별도 확인이 필요하다. 이 예는 영향 후보이지 실효 권한 증가의 증명이 아니다. attribute 참조 외 macro, 역방향 접근, constraint, wildcard와 type 생성 시 role 확장도 조사해야 한다.

기존 [기기 구문 검사와 포크 코드 분석](guest-selinux-domain-poc.md)은 타입·permissive 문법과 구현 경로만 확인한다. `check`는 정책 반영 검사가 아니다. [이전 분석](private-binder-enforcing-research.md)은 포크의 부분 적용 실패가 warning으로만 드러날 수 있음을 기록한다. 명령 종료 코드만으로 성공·원자성·복구를 판정하지 않는다. live patch는 커널 전역이고 타입 생성 후 실패하면 부분 반영을 가정해 즉시 중단한다. 이 PoC는 정책 적용 또는 자동 재적용 파일을 만들지 않는다. `enforce ssal_guest_probe`는 추가된 타입이나 allow를 삭제하지 않는다. 재부팅은 후보 복구 방법일 뿐이며, 자동 재적용 확인과 One UI 복귀 결과가 나오기 전까지 복구가 보장된다고 볼 수 없다.

## 승인 후 순서와 중단 조건

1. 적용 전 boot ID, fingerprint, 전역 enforce, 정책 hash 또는 실패 사유, AV sequence, 기존 모듈 및 자동 정책 로드 설정, 주요 Host 프로세스의 PID/start time/context/exe, 고정된 Host↔Host AV 집합을 읽기 전용으로 저장한다. 전용 process 및 파일 context가 이미 유효하거나 이름 충돌이 의심되면 중단한다. `EINVAL`만으로 타입이 없다고 단정하지 않는다.
2. 검토된 파일시스템·초기 라벨·launcher/helper SHA-256 및 정확한 정책 문장, 영향, rollback 및 대상 기기를 제시해 별도 승인을 받는다. 부족한 권한을 추측해 후보를 확장하지 않는다. 전체 정책 hash/AV 차분이 불가능한 한계를 승인 범위에 명시한다.
3. 승인된 별도 절차로만 정책을 단계별 적용한다. 각 단계 뒤 context 유효성, 라벨 및 기대 AV/flags/sequence를 다시 조회한다. 오류, 부분 성공 의심, Host 상태 변화, 전역 non-Enforcing, 대상 permissive, 허용되지 않은 권한 변화, 예상 밖 context가 발생하면 즉시 중단하고 추가 patch나 permissive 우회를 하지 않는다. 새 target의 접근이 불충분할 때는 필요한 정확한 주체·객체·권한을 기록하고 다시 검토한다.
4. 승인된 전용 파일에만 라벨을 부여한 뒤 inode, label, mode, mount 및 해시를 검증하고 기존 런처를 실행한다. 런처는 해시를 실행 전후 다시 확인하고 조건 불일치 시 실패한다. 해시 검사 사이에 같은 inode가 수정되는 경합은 남으므로 다른 주체가 쓸 수 없는 보관 조건을 별도 확보해야 한다. 대상 permissive는 사용하지 않는다.
5. 결과에서 actual child SID·PID·exe inode·정상 종료, 대상 flag 0, 전역 Enforcing, probe 전후 동일 sequence를 확인한다. 전후 주요 Host 프로세스 및 같은 Host AV 집합을 비교한다. 접근 음성 시험과 Host 완전 불변성은 별도다. 실패하면 child 회수와 전용 임시 파일 정리를 확인하고 정책 상태는 부분 적용 가능으로 남긴다.
6. 커널 정책을 원상 복구하는 자동 기능은 없다. 계획된 하드 재부팅 뒤 boot ID, 전역 Enforcing, 전용 context 부재, 자동 재적용 설정, 주요 Host 서비스 및 One UI를 다시 확인한다. 재부팅 후에도 규칙이 남거나 기기가 비정상이면 복구 실패로 기록한다.

## 오프라인 비교기

[비교기](../scripts/guest-domain-poc/compare-snapshots.js)는 기기에 접근하지 않는다. 별도 승인된 관측 절차가 수집한 두 JSON을 비교한다. `apply` 단계는 새 정책으로 인한 sequence 변경을 기록만 하고, `probe` 단계는 sequence 변경을 실패로 본다. 수집 누락, Enforcing 미확인, Host 프로세스 신원이나 제공한 Host AV 변경은 실패다. 전체 정책 hash가 없으면 `unknown`이며 전체 Host 불변성을 증명하지 않는다. `cleanup`은 같은 부팅 중 프로세스·AV 비교용이고, 재부팅 후 boot ID 변화는 별도 복구 체크로 평가한다.

```sh
bun scripts/guest-domain-poc/compare-snapshots.js apply before.json after-apply.json
bun scripts/guest-domain-poc/compare-snapshots.js probe before-probe.json after-probe.json
bun test scripts/guest-domain-poc/compare-snapshots.test.js
```

JSON은 `captured_at`, `boot_id`, `fingerprint`, 숫자 `enforce`(1), 숫자 `av_sequence`, 선택적 `policy_sha256`, 동일한 질의 키와 boolean 값을 가진 `host_av`, `processes`를 포함한다. `processes`에는 `init`, `servicemanager`, `zygote64`, `system_server`, `surfaceflinger` 각각의 `pid`(정수), `start_time`(문자열), `context`, `executable`이 필요하다. AV는 쌍마다 source/target/class/permission과 raw flags·sequence를 별도 원본 기록에 남겨야 하며, 비교기의 boolean은 그 요약일 뿐이다. 동일한 재현 가능한 질의 집합을 사용하고 최소 한 개 이상을 제공해야 한다.

## 로컬 검증

기본 dry-run, 인자/진단 옵션 단위 시험 및 Android 타깃 `cargo check`와 비교기 테스트를 수행한다. 실제 Android 링크·기기 helper hash·신규 도메인의 AV·실행/복구는 `not_run`이다. 상세 도메인과 Property Area 계약은 [기존 PoC](guest-selinux-domain-poc.md)를 참조한다.
