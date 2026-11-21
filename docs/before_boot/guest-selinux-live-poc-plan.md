# Guest SELinux Live PoC 실행 계획

**검토할 일회성 정책 후보와 절차는 확정했지만, 실제 실행 가능성은 아직 입증되지 않았다.** 성공 목표는 `ssal-selinux-identity` 한 프로세스가 `u:r:ssal_guest_probe:s0`에서 정상 종료하고 해당 도메인이 Enforcing임을 확인하는 것이다. 정책 적용·파일 라벨 변경·전환은 별도 명시적 승인 이후에만 수행한다. 전체 실효 정책 export는 필수 성공 조건이 아니다. 다만 export가 없으면 전체 정책 차분 및 Host 전체 영향은 unknown으로 기록한다.

## 정확한 검토 후보

[후보 파일](../scripts/guest-domain-poc/policy-candidate.txt)의 네 문장이 전부다. 괄호, wildcard, permissive 및 자동 재적용 규칙은 없다.

```text
type ssal_guest_probe domain
type ssal_guest_probe_exec file_type
allow ksu ssal_guest_probe process transition
allow ssal_guest_probe ssal_guest_probe_exec file entrypoint
```

`ksu`에 대한 예외는 **새 전용 도메인으로의 `process:transition` 하나**다. `setexec`, 새 파일의 open/read/getattr/execute/map, 상위 디렉터리 접근이나 relabel 권한은 추가하지 않는다. 기존 실효 AV와 DAC가 부족하면 중단한다. 네 문장은 정확한 검토 대상이지 충분성이나 최소성이 증명된 최종 정책이 아니다. 실제 policydb의 타입·attribute와 role/MLS, constraint, 파일시스템과 기존 권한에 따라 실패할 수 있다. 더 많은 권한이 필요하다는 관측이 나와도 별도 검토·승인 없이 추가하지 않는다.

## 오프라인에서 확인한 것

- 기존 기기 조사에서 네 문장 각각 `ksud sepolicy check` exit 0, 잘못된 문장 exit 1이었다. 파서 검사이며 신규 타입 생성이나 AV 허용을 입증하지 않는다. 이번 작업에서 기기 실행·정책 검사는 하지 않았다.
- 저장된 삼성 platform CIL의 `domain` 관련 Host 참조와 self 규칙을 확인했다. 새로운 `domain`/`file_type` attribute의 전역 영향과 동적 확장은 현재 실효 정책에서 미확인이다. 저장된 Host 재구성 정책은 `-N` 컴파일만 성공했고 strict neverallow 컴파일은 실패했다. 이번 후보를 포함한 전체 정책 호환성 또는 neverallow 통과는 입증되지 않았다. 이 환경에서 WSL/기존 Linux 정책 컴파일러 실행은 `E_ACCESSDENIED`로 불가했다.
- 후보 구성 테스트와 런처 dry-run, Android 타깃 `cargo check`를 통과했다. 현재 환경에서 Android 실행 파일 링크는 하지 못했다. 로컬에 이미 있던 identity ELF는 AArch64, `/system/bin/linker64`, `libc.so`, `libdl.so` 의존이며 SHA-256 `155709304ee012e9d803b4dfe02da4cfd5d9a0bba2cd5588f36a5a66604dba9c`다. 해당 기존 파일과 현재 소스의 빌드 동일성은 미확인이다. 적용 승인 전 launcher/helper를 신뢰 가능한 Android 빌드 환경에서 만들고 각각 해시·출처를 고정해야 한다.
- 런처에서 Guest permissive 진단 옵션을 제거했다. 대상 permissive flag가 1이거나 global Enforcing이 아니면 실행을 거부한다. 원래 관리 도메인 `ksu`의 permissive 관측은 Guest의 enforcing 입증에 사용하지 않는다.

## 승인 후 일회성 순서

1. 대상 기기·boot ID·fingerprint를 고정하고 전역 Enforcing, 필수 Host 프로세스 PID/start time/context/exe, 이전 자동 적용 정책과 재부팅 복구 경로, 선택한 Host↔Host AV 집합 및 policy sequence를 수집한다. 정책 export 실패는 오류와 함께 unknown으로 기록하되 그 자체로 중단하지 않는다. 전용 두 context의 유효성, 이름 충돌 및 기존 타입 존재 여부를 가능한 범위에서 확인한다. 이미 존재하거나 기존 소유자를 배제할 수 없으면 중단한다.
2. 실행할 네 문장과 정확한 helper/launcher SHA-256, 임시 경로와 대상 기기, 파일 라벨 변경 및 아래 복구 계획을 승인받는다. 이후에만 각 후보 문장을 설치된 `ksud sepolicy patch '<문장>'`으로 순서대로 일회성 적용한다. 자동 재적용 파일은 만들지 않는다. 각 단계의 stdout/stderr/종료 상태와 적용 후 두 context, 관련 AV/sequence를 저장한다. CLI 성공은 정책 반영 성공의 증거가 아니다. 단계 실패나 부분 반영이 의심되면 중단하며 다음 문장을 적용하지 않는다.
3. 정책이 적용된 후 `ksu→ksu process:setexec`, `ksu→ssal_guest_probe process:transition`, `ssal_guest_probe→ssal_guest_probe_exec file:entrypoint`, `ksu→ssal_guest_probe_exec file:open/read/getattr/execute/map`의 실효 AV를 질의한다. 각 질의에 source·target·class·permission·mask·flags·sequence를 보존한다. 대상 `process:getattr` 질의의 **flags**로 대상 permissive 여부를 확인한다. launcher가 요구하는 권한이 거부되거나 sequence가 불안정하면 중단한다. 필요한 경우 NNP, `nosuid`/`noexec`, DAC, 상위 디렉터리와 SELinux constraint도 확인한다.
4. 전용 임시 파일에서만 초기 inode/라벨, 파일시스템 SID·mount, `relabelfrom`/`relabelto`/`filesystem:associate`와 DAC/capability를 확인한다. 별도 승인된 파일 한 개의 라벨을 `u:object_r:ssal_guest_probe_exec:s0`로 지정하고 실제 라벨·inode·mode·해시를 기록한다. `context=` mount의 제한 여부 및 파일 변경 경합을 확인한다. 불확실하면 중단한다. 실행 파일은 외부 주체가 쓸 수 없는 전용 파일이어야 한다.
5. dynamic linker·`libc.so`·`libdl.so`, reporter의 `/proc/self/attr/current`, `/proc/self/exe`, namespace·status와 stdout pipe/FD의 실제 라벨 및 접근 조건을 확인한다. 필요한 정확한 AV가 거부되거나 확인할 수 없으면 중단하고 추가 규칙 후보를 별도 검토한다. 이 검사는 런처가 모두 자동으로 수행하지 않는다.
6. 승인된 런처를 한 번만 실행한다: `ssal-guest-domain-poc --run-after-approval /절대경로/ssal-selinux-identity --sha256 <승인된_64자리_해시>`. helper FD의 해시와 라벨, 전환 및 entrypoint AV, global Enforcing 및 대상 flag를 검사하고 child를 전환한다. PID·실제 SID·exe device/inode·정상 종료 및 child 회수, probe 전후 Enforcing·대상 flags 0·동일 sequence를 확인한다. 이는 identity 실행만을 입증하며 Guest/Host 자원 격리나 인증 경로 차단의 증거가 아니다.
7. 전용 child와 임시 파일 제거 후 동일 Host 프로세스 및 AV 집합을 다시 수집한다. 기존 [오프라인 비교기](../scripts/guest-domain-poc/compare-snapshots.js)는 지정된 관측의 차이와 누락을 검출한다. 전체 Host 상태의 불변성은 증명하지 않는다. 누락·예상 밖 Host 변화는 실패로 남긴다.
8. 동적 정책 변경은 일회성으로 적용해도 공유 커널에 남으며 이 런처는 역패치를 지원하지 않는다. 실패·부분 반영 시 추가 변경을 중단하고 운영자가 계획한 하드 재부팅으로 복구한다. 재부팅 후 boot ID 변경, 전역 Enforcing, 전용 context의 재조회, 자동 재적용 부재, Host 서비스 및 One UI를 확인한다. `enforce` 명령은 추가 타입이나 allow를 제거하지 않는다. 재부팅 후 복구 및 One UI 동작은 미검증이며 다른 구성 요소의 자동 정책 주입도 배제되지 않았다.

## 실행을 막는 구체적 미확인 사항

신뢰 가능한 Android launcher 빌드·승인 해시, 두 타입의 충돌 여부 및 동적 생성 성공, 새 target/file에 대한 실제 AV와 대상 enforcing flag, 임시 파일의 relabel/associate 및 mount 조건, 동적 링커·reporter 의존 파일과 pipe/proc의 접근 가능성, 적용 후 Host 관측 및 재부팅 복구가 남아 있다. 이 확인 중 정책 적용이나 라벨 변경이 필요한 항목은 별도 승인 후에만 확인할 수 있다. `ksu`가 전용 파일을 실행할 기존 권한이 없을 가능성도 남으며, 그때 일반적인 Host 권한 확장으로 우회하지 않는다.
