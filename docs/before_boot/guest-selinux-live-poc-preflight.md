# Guest SELinux Live PoC 승인 전 사전 점검

2026-10-31 21:44 KST에 빌드와 읽기 전용 검사만 수행했다. 정책 적용, 파일 전송·라벨 변경, 시험 프로세스 실행 및 재부팅은 **not_run**이다. 실행 계획과 네 정책 문장은 [Live PoC 계획](guest-selinux-live-poc-plan.md)에 있다.

- 대상: ADB serial `R5CY52JC03H`, SM-S937N, fingerprint `samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`, boot ID `c0f129b3-1ba5-4b78-8246-58dae210994e`.
- 전역 SELinux는 Enforcing, 조회 주체는 `u:r:ksu:s0`, `ksud samsung-v2.2 (uapi: 5)`다. `u:r:ssal_guest_probe:s0`, `u:object_r:ssal_guest_probe_exec:s0` context 조회는 각각 `EINVAL`이었다. 이는 타입 부재 자체를 증명하지 않는다.
- 기존 AV 조회의 sequence는 1이다. `ksu → ksu process:setexec`는 allowed이고 source permissive flag는 1, `shell → servicemanager binder:call`은 allowed, `servicemanager → servicemanager process:getattr`의 source permissive flag는 0이다. 신규 타입의 AV는 아직 질의할 수 없다.
- 주요 Host 프로세스의 PID, start time, context, exe는 [원본 관측](../out/guest-domain-live/baseline.json)에 기록했다. init 이름은 PID 1 외 vendor_init도 포함한다. 시점의 One UI 정상 동작 및 전체 Host 불변성은 이 관측만으로 입증하지 않는다.
- `/sys/fs/selinux/policy` 읽기는 `EINVAL`로 실패해 실효 정책 해시와 전체 차분은 unknown이다. `/data`는 `f2fs`, `seclabel`, `nosuid`이며 `noexec`는 관측되지 않았다. 신규 도메인에 대한 `nosuid_transition`, 실제 실행 경로·파일시스템 SID 및 per-inode relabel 성공은 미확인이다.
- 기존 `/data/adb/modules/ssal/sepolicy.rule` SHA-256은 `0f6b0e1c3e4217f685826d6a46ff7150667aa0a5be612c554964bfe3e5b3d39b`, `zygisksu/sepolicy.rule`은 `0763d21b08857c62e74170b14d54e508a037ce707c24aa859a90001bc32e7e19`이다. 두 모듈의 `disable`, `remove` 표시는 확인되지 않았다. 파일이 존재한다는 사실만으로 실행 중 적용 여부나 재부팅 후 모든 동작을 확정할 수 없다. 이 파일은 변경하지 않는다.

## 승인 대상의 고정 산출물

기존 WSL `ssal-dev`의 Android NDK와 `cargo build --locked --release --target aarch64-linux-android`로 현재 소스에서 두 바이너리를 빌드했다. 둘 다 ELF64 AArch64이며 `/system/bin/linker64`, `libc.so`, `libdl.so`에 의존한다.

| 바이너리 | SHA-256 |
|---|---|
| `out/guest-domain-live/launcher` | `885ea174c6c9e777d5fd470334b521f5483479761b4e5faac12a2b4a91e6743b` |
| `out/guest-domain-live/identity` | `155709304ee012e9d803b4dfe02da4cfd5d9a0bba2cd5588f36a5a66604dba9c` |

후보 파일 `scripts/guest-domain-poc/policy-candidate.txt`의 SHA-256은 `22da591be41b4ee26ed7c500af1fbedbc0fb5932448da045bca7735c4a117214`이다. 승인을 받으면 `/data/local/tmp/ssal-guest-domain-poc` 전용 임시 디렉터리를 새로 만들고 두 바이너리와 기존 읽기 전용 SELinux 조회 helper만 사용한다. 이미 경로가 있거나 해시·라벨·부팅 ID가 달라지면 중단한다. 기존 Host 파일이나 모듈 규칙은 수정하지 않는다.

승인 범위는 네 문장을 순서대로 일회성 적용해 각 단계의 실제 결과를 확인하고, 전용 identity 파일에만 라벨을 지정해 고정 launcher를 한 번 실행하는 것이다. 예상 밖 거부·실패·부분 적용이나 Host 이상이 생기면 추가 정책 없이 중단한다. 동적 정책은 커널 전역에 남을 수 있으며 역패치는 제공되지 않는다. 실험 후 계획된 하드 재부팅과 재부팅 후 context·Host 서비스·One UI 확인이 필요하다. 하드 재부팅은 실행 중 작업을 중단하며 복구 성공은 아직 입증되지 않았다.
