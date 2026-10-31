# Guest 전용 SELinux 도메인 PoC — 2026-10-31

> 2026-11-01 승인된 계측 시험을 실기기에서 수행했다. SIGSEGV의 확인된 단계와 증거는 [SIGSEGV 분석](guest-selinux-sigsegv-analysis.md)을 따른다. 아래의 설계·정책 검토 기록에는 시험 전 상태가 남아 있다.

`ssal_guest_probe`에 대한 정책 후보와 고정 도메인 전환 런처를 유지한다. 기본 실행은 dry-run이다. 승인된 시험에서는 후보의 기존 네 문장만 현재 boot의 live policy에 적용하고 전용 Reporter 파일에 라벨을 설정했다. enforcing exec는 SIGSEGV로 실패했으며 자세한 단계 분석은 [별도 보고서](guest-selinux-sigsegv-analysis.md)에 있다. 정책 조각이 완전하거나 Guest 환경의 격리를 입증한다고 보지 않는다.

## 파일과 실행

- [정책 후보](../scripts/guest-domain-poc/policy-candidate.txt)는 전용 process 타입, 전용 실행 파일 타입과 그 파일의 entrypoint 후보만 담는다. 기존 Host 도메인의 규칙을 수정하는 후보는 포함하지 않는다. 공용 attribute 상속의 전역 영향은 미확인이다.
- [런처](../src/bin/ssal-guest-domain-poc.rs)는 정책이나 라벨을 설정하지 않는다. 기존 [identity reporter](../src/bin/ssal-selinux-identity.rs)를 exec하고 결과를 확인한다. 서비스, Guest init, Zygote, Framework, Binder, property socket 및 인증 HAL은 실행하지 않는다.

```sh
# 해당 플랫폼용으로 빌드한 런처에서 인자 생략 시에도 dry-run
ssal-guest-domain-poc
ssal-guest-domain-poc --dry-run
```

무전환 대조군은 같은 런처와 Reporter를 사용하되 `setexec`/도메인 전환을 하지 않는다. 실행 파일은 해시만 검증하므로 별도 Guest 라벨이나 정책을 준비하지 않는다.

```sh
ssal-guest-domain-poc --control /path/to/ssal-selinux-identity --sha256 REPORTER_HASH
```

Android NDK 및 Rust 빌드에서 런처와 진단 Reporter를 생성했다. `cargo test --locked --bin ssal-guest-domain-poc`의 6개 테스트, Android AArch64 `cargo check` 및 release build가 통과했다. 실기기에서 무전환 대조군은 통과했고 전환군은 `execveat`/ELF 진입 전후 구간에서 SIGSEGV가 재현됐다.

승인 후 실행 구문은 아래와 같다. `--run-after-approval`은 기술적 실행 가드이며 사용자 승인을 대신하지 않는다. 실제 명령에는 검토한 identity helper의 절대 경로와 승인된 SHA-256을 지정한다. 런처는 열린 파일의 해시를 실행 전후 검사한다. 그 사이의 수정 가능성은 남으므로 helper는 실행 도중 수정되지 않는 전용 파일이어야 한다.

```sh
ssal-guest-domain-poc --run-after-approval /절대경로/ssal-selinux-identity --sha256 승인된_SHA256
```

런처는 시작과 종료 시 전역 Enforcing을 요구하고 source가 `u:r:ksu:s0`인지 확인한다. 열린 helper의 실제 `security.selinux`가 `u:object_r:ssal_guest_probe_exec:s0`이어야 한다. 커널 `selinuxfs/access`에서 source의 `process:setexec`, source→target `process:transition`, target→helper `file:entrypoint`, source→helper 파일 접근의 AV를 조회하고 모두 허용되어야 한다. 동일 정책 sequence 및 대상 permissive flag도 검사한다. 기본 실행은 대상 permissive면 중단하고, 진단 옵션은 관측값이 permissive인 경우에만 허용한다. `ksu`는 현재 permissive인 관리 도메인이므로 그 실행 성공은 source 측 SELinux 집행 증명이 아니다.

통과 시 일회용 child에서 `/proc/thread-self/attr/exec`에 고정 target을 쓰고 열린 helper FD로 `execveat`한다. fork 이후 child는 async-signal-safe libc syscall과 고정 크기 trace write만 수행한다. 부모는 fork PID, wait status, setexec/execveat syscall errno를 기록하고 Reporter `main` 진입 표식을 별도 pipe에서 확인한다. 표준 입출력을 제외한 기존 FD는 exec 시 닫으며 입력은 `/dev/null`이다. helper가 보고한 PID, 실제 context, 실행 파일 device/inode 및 정상 종료를 비교하고, 3초 timeout 시 child를 종료·회수한다. 전환 전후 전역 Enforcing, 대상 permissive flag와 AV sequence가 다르면 실패한다. 대상 permissive 상태는 항상 거부하며 permissive 진단 옵션은 없다. 출력 pipe와 표준 스트림은 남으므로 완전한 FD 격리 시험이 아니다. SID 문자열 확인은 도메인 구별의 증거 후보이며 Host 자원 차단 증거가 아니다. UID/GID·namespace는 reporter가 보고하지만 런처는 이들의 격리를 보증하거나 비교하지 않는다.

## 실기기에서 확인한 것

2026-10-31 21:30 KST, SM-S937N, fingerprint `samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`: 전역 Enforcing, root 셸 `u:r:ksu:s0`, `ksud samsung-v2.2 (uapi: 5)`. `selinuxfs/context` 조회에서 `u:r:ssal_guest_probe:s0`는 `EINVAL`이었다. 이는 전체 라벨 유효성 실패이며 타입 부재만을 증명하지 않는다. 조회 전후 Enforcing이었다. 커널 전체 정책 해시가 없는 기존 한계가 남는다.

설치된 `ksud sepolicy check`는 `type ssal_guest_probe domain`, `type ssal_guest_probe_exec file_type`, `allow ssal_guest_probe ssal_guest_probe_exec file entrypoint`, `permissive ssal_guest_probe`, `enforce ssal_guest_probe`를 각각 exit 0으로 파싱했고, 잘못된 문장은 exit 1이었다. 별도로 `allow ksu ssal_guest_probe process transition`의 문법도 확인했으나 Host 도메인 변경 제약 때문에 후보에 넣지 않았다. `check`는 파서 검사이며 타입 생성·attribute 존재·AV·실제 적용의 증거가 아니다.

## 2026-11-01 승인 계측 시험

승인된 기존 네 정책 문장으로 시험했으며 추가 `allow`나 permissive 설정은 하지 않았다. 동일 런처의 Rust 대조군, 정적 C 대조군, libc 없는 bare ELF 대조군은 KSU context에서 통과했다. 각 전환군은 `setexec_open`과 `setexec_write` errno 0 이후 같은 SIGSEGV를 냈다. 3개 무-runtime ELF probe와 `exit_group(42)` probe로 실패가 Reporter `main` 이후가 아님을 확인했다. fault PC와 backtrace는 crash buffer/tombstone 미생성으로 확인하지 못했다. 전체 기록은 [SIGSEGV 분석 보고서](guest-selinux-sigsegv-analysis.md)에 있다.

시험 중 `adb reboot` 또는 그 밖의 재부팅 명령은 실행하지 않았다. 런타임 정책 patch는 현재 boot의 live policy에 남아 있다. 안전한 무재부팅 rollback은 확인하지 못했으며, 이 보고서 작업에서 재부팅을 요청하지 않는다.

고정된 [삼성 KernelSU 포크 커널 구현](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/kernel/selinux/sepolicy.c#L803)은 타입 추가와 attribute 연결, `permissive`/`enforce`의 per-type permissive map 조작 경로를 구현한다. [userspace 파서](https://github.com/diabl0w/KernelSU/blob/b38f4096f33632ad5871dc3fff0ec426e23c9358/userspace/ksud/src/sepolicy.rs)에도 해당 문법이 있다. 이것은 소스상 기능이며 설치된 바이너리와 정확한 커널 코드의 동일성, 실제 적용 및 실패 시 원자성을 보장하지 않는다. 타입 생성은 role 및 attribute 관련 데이터에도 영향을 줄 수 있다. 일부 규칙 실패가 발생하면 CLI 성공만으로 완전 적용을 판단하지 않는다.

## 승인 후 수행할 검증 절차

1. 정책 적용 **이전**에 부팅 ID, 시간, fingerprint, 전역 enforce, 주요 Host 프로세스의 PID/start time/context와 실행 파일, 기존 모듈 정책 및 자동 재적용 상태를 기록한다. `u:r:ssal_guest_probe:s0`와 `u:object_r:ssal_guest_probe_exec:s0` 유효성 및 이름 충돌을 조회한다. 이미 존재하거나 출처가 불명확하면 중단한다. policy export 불가 시 hash와 전체 AV 차분은 unknown으로 남긴다.
2. 별도 정책 복사본에서 후보의 기존 attribute·role·MLS·constraint 및 `neverallow` 영향을 분석한다. 파일 타입의 attribute와 reporter 및 dynamic linker가 요구하는 `read/open/map/execute`, 디렉터리 탐색, proc 및 pipe/FD 접근은 현재 미확정이다. 필요한 최소 권한만 별도로 검토한다. Host `ksu`의 기존 `setexec`, transition과 파일 접근 AV가 부족하면 **중단**한다. Host 도메인을 수정하거나 wildcard allow로 우회하지 않는다.
3. 사용자에게 정확한 정책 문장, 예상 전역 영향, helper 해시·전용 임시 파일·라벨링과 실행 단계 및 복구 계획을 제시하고 승인받는다. 적용 단계마다 결과와 실제 context/AV를 조회한다. 이 PoC는 `ksud patch/apply`, `chcon` 또는 `setenforce`를 호출하지 않는다. 자동 재적용 규칙을 설치하지 않는다. 타입 생성은 실패 시 일부 반영될 수 있으므로 불확실하면 진행하지 않는다.
4. 승인된 전용 임시 helper에만 라벨을 설정하고 파일 해시·inode·라벨을 확인한다. 런처의 AV/sequence/Enforcing 확인을 통과한 경우에만 실행한다. target permissive는 기본적으로 차단하며, 별도 승인된 진단에서만 사용한다. 전환 후 실제 SID, PID, 재회수, global Enforcing 및 permissive flag를 기록한다. permissive 결과는 Host 접근 차단이나 enforcing 동작의 증거로 사용하지 않는다.
5. 시험 전후 주요 Host PID/start time/context, global enforce, 가능한 정책 sequence, 전용 파일·프로세스 잔존 여부를 비교한다. 확인 가능한 범위만 보고하며 전체 Host 불변성으로 일반화하지 않는다. 개별 제한 접근은 전용 enforcing 도메인과 정확한 대상 SID에서 별도 음성 시험이 필요하다.
6. 프로세스 종료·회수와 전용 파일 삭제 후 잔존 자원을 확인한다. 동적 커널 정책을 이 PoC가 안전하게 되돌리는 기능은 없다. 이번 SIGSEGV 조사는 재부팅 없이 종료했고, 재부팅을 요청하지 않는다. 현재 boot의 live policy patch 상태와 남은 위험은 [분석 보고서](guest-selinux-sigsegv-analysis.md)에 기록했다. `enforce ssal_guest_probe`만으로 타입·allow가 제거되지는 않는다.

## Property Area 연결 계약

현 오프라인 [Property Area 프로토타입](guest-property-area-prototype.md)은 Windows 시험이며 이 도메인과 연결돼 있지 않다. 향후 별도 Guest writer/client 도메인, area 디렉터리·`property_info`·context area·serial·socket·persist 파일 타입, 실제 filesystem SID와 tmpfs mount 조건을 정의해야 한다. 생성에는 부모 dir 탐색/생성, inode create 및 `filesystem:associate`, relabel에는 `relabelfrom`/`relabelto`와 associate가 필요하다. client별 file open/read/getattr/map, socket 연결과 `property_service:set`은 정확한 SID별로 검증해야 한다. 12개 invalid context, 입력 매칭, Host area/socket/FD 차단과 독립 userdata는 별도 차단 요소다. 본 후보에는 이런 property 권한을 추가하지 않았다.
