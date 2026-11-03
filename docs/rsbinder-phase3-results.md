# SSAL rsbinder Phase 3 결과

## 상태

**PASS — 재현된 SELinux 거부를 단일 Binder permission으로 해소한 동안 Callback과 Binder Death/Restart가 통과했고, 시험 종료 직후 정책을 정확히 원복했습니다.**

Guest 부팅, SSAL 전체 전환, HAL proxy 실행은 하지 않았습니다. Phase 4 구현을 진행할 수 있지만, 그 작업의 runtime 검증은 별도입니다.

## 환경과 범위

- 기기: Samsung SM-S937N, Android 17 / SDK 37. SELinux 전역 모드는 계속 `Enforcing`이었습니다.
- Guest image: Android 16 / SDK 36. `rsbinder 0.12.0`, `rsbinder-aidl 0.12.0`.
- 기존 C++ Test B helper는 기기에 설치된 바이너리(SHA-256 `99fcdb1ef7d8e28e8af010d28a550114f44995951b3ceb5fcf232eb667ba9`)를 사용했습니다. C++ 시험 서버의 등록·descriptor·echo 확인 뒤 시험 서버만 종료하고 같은 Guest service name으로 Rust 시험을 했습니다.
- Host ServiceManager, properties, installed module, production daemons에는 변경을 가하지 않았습니다. 임시 바이너리와 규칙 파일은 `/data/local/tmp`의 테스트 stage에만 두고 마지막에 제거했습니다.

## 최초 실패와 원인

정책을 바꾸지 않은 상태에서 Callback 실패를 재현했습니다. 외부 supervisor가 실제 프로세스를 관찰한 값은 다음과 같습니다.

| 항목 | 값 |
|---|---|
| `scontext` | `u:r:aidl_lazy_test_server:s0` |
| `tcontext` | `u:r:shell:s0` |
| `tclass` / 권한 | `binder` / `call` |
| 요청 mask | `0x2` (`call`) |
| 기존 allowed mask | `0x8` (`transfer`만 해당) |
| SELinux 상태 | Enforcing |
| 실패 | `AIDL callback transaction #0: TransactionFailed / FailedTransaction` |

client는 실제 `u:r:shell:s0`, UID/GID 1000, 별도 mount namespace, private Binder FD 3으로 관찰됐습니다. 서버는 `u:r:aidl_lazy_test_server:s0`, UID/GID 1000, Binder FD 3이었습니다. 서비스 등록·조회·descriptor·`add(17,25)=42`·`echo("ssal-phase3")`는 Callback 전까지 통과했습니다.

`dmesg`와 `logcat -b kernel`에서 이 시도에 대응하는 `avc: denied` 원문은 찾지 못했습니다. 따라서 AVC 문장을 근거로 삼지는 않습니다. 실제 프로세스 컨텍스트, SELinux `access`의 커널 실효 AV 응답, 동일 시험의 정책 미적용/적용/원복 결과로 원인을 확인했습니다. 권한이 없는 기준 실행에서는 Callback이 실패했고, `call` 한 비트를 추가한 실행에서는 성공했으며, 원복 뒤 AV는 다시 거부로 돌아왔습니다.

기존 `module/sepolicy.rule`에는 다음과 같은 server↔shell `transfer`가 이미 있었습니다.

```selinux
allow shell aidl_lazy_test_server binder transfer
allow aidl_lazy_test_server shell binder transfer
```

이 규칙은 Binder 객체 전달을 허용하지만 동기 Callback에 필요한 server→shell `binder call`은 허용하지 않습니다.

## SELinux 최소 정책과 원복

### 충돌 검토

- AOSP Android 17 `android17-release`의 platform `public`/`private` SELinux 소스에서 Binder `neverallow`를 검토했습니다. `aidl_lazy_test_server → shell : binder call`을 막는 적용 규칙은 발견하지 못했습니다. [`aidl_lazy_test_server.te`](https://android.googlesource.com/platform/system/sepolicy/+/android17-release/private/aidl_lazy_test_server.te), [`shell.te`](https://android.googlesource.com/platform/system/sepolicy/+/android17-release/private/shell.te), [`domain.te`](https://android.googlesource.com/platform/system/sepolicy/+/android17-release/public/domain.te).
- `aidl_lazy_test_server`는 AOSP platform-private domain입니다. Samsung vendor policy 소스는 읽지 않았습니다. KernelSU의 `ksud sepolicy check`는 statement 문법 검사이며 `neverallow` 컴파일 검사가 아니므로, 충돌 검토는 위 AOSP 소스에 대한 별도 검토입니다.
- 기기에서 확인한 KernelSU는 `ksud samsung-v2.2 (uapi: 5)`이고 `sepolicy apply` 및 `check` 명령을 지원했습니다. 구현은 rule별 runtime allow/deny를 제공합니다. [`ksud sepolicy` 구현](https://github.com/tiann/KernelSU/blob/main/userspace/ksud/src/sepolicy.rs), [KernelSU runtime rule 처리](https://github.com/tiann/KernelSU/blob/main/kernel/selinux/sepolicy.c).

### 적용

테스트 stage 파일에는 다음 한 줄만 넣고 parser check 뒤 runtime 적용했습니다.

```selinux
allow aidl_lazy_test_server shell binder call
```

```sh
ksud sepolicy check policy-allow.rule
ksud sepolicy apply policy-allow.rule
```

`ksud check`의 성공은 문법 검증으로만 취급했습니다. 적용 직후 AV를 다시 조회해 아래 변경을 확인했습니다.

이 규칙은 PID가 아니라 `aidl_lazy_test_server` 도메인 전체에 적용됩니다. 따라서 allow가 활성화된 동안 그 도메인의 프로세스는 shell Binder `call` 권한을 가졌고, 시험 종료 직후 동일 권한을 deny로 원복했습니다.

| 방향 / 권한 | 기준 허용 mask | 적용 중 허용 mask | 원복 후 허용 mask |
|---|---:|---:|---:|
| `aidl_lazy_test_server → shell : binder call` | `0x8` (거부) | `0xA` (허용) | `0x8` (거부) |
| `aidl_lazy_test_server → shell : binder transfer` | `0x8` | `0xA` | `0x8` |
| `shell → aidl_lazy_test_server : binder call/transfer` | `0xA` | `0xA` | `0xA` |
| `aidl_lazy_test_server → servicemanager : binder call/transfer` | `0xA` | `0xA` | `0xA` |

`0xA`는 기존 `call`과 `transfer` 두 비트입니다. 적용 중 변경된 권한은 의도한 server→shell `call` 하나였습니다. 기존 `transfer`는 유지됐습니다.

### 원복

테스트 직후 같은 source, target, class, permission에 대해 다음 deny rule을 적용했습니다.

```selinux
deny aidl_lazy_test_server shell binder call
```

```sh
ksud sepolicy check policy-deny.rule
ksud sepolicy apply policy-deny.rule
```

원복 검증:

- 적용 전 policy SHA-256: `577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723`.
- 단일 allow 적용 중: `589ecad0b5eada1d940e678250c3dfd977ee194e315bb4b98e84cc61984f7663`.
- deny 적용 후 SHA-256이 적용 전 값과 정확히 같았습니다.
- 적용 후 `call`은 `0x8` 허용 mask로 다시 거부됐고 기존 `transfer`는 계속 허용됐습니다.
- 작업본 `module/sepolicy.rule`과 설치본 `/data/adb/modules/ssal/sepolicy.rule`의 SHA-256은 모두 `e0d7fc34cb87864689089bcbba45dd44486cb7a28ba7d3ee73f9c2cdade7f389`입니다. 영구 규칙 변경은 없습니다.
- 재부팅 없이 runtime policy를 원복했습니다. SELinux는 계속 Enforcing이었습니다.

## Callback 재검증

최종 자동 실행에서 C++ Test B와 Phase 2C 뒤 다음 순서로 Phase 3를 통과했습니다.

| 단계 | 결과 |
|---|---|
| Service 등록 및 조회 | Guest `aidl_lazy_test_1` 등록·조회 성공 |
| Interface descriptor | `org.ssal.phase3.IPhase3Service` 일치 |
| `add(17,25)` | `42` |
| `echo("ssal-phase3")` | `"ssal-phase3"` |
| Callback 객체 전달 | Binder object 전달 성공 |
| server→client Callback | 두 번 실행: `ssal-phase3 → callback:ssal-phase3`, `ssal-phase3-repeat → callback:ssal-phase3-repeat` |
| 참조 수명 | 동일한 Strong Callback 참조를 유지한 상태에서 두 동기 호출 성공 |

최종 실행의 프로세스 관찰은 다음과 같습니다. Binder FD 번호는 각 프로세스의 Guest/private Binder FD입니다.

| 역할 | PID | SELinux context | UID/GID | mount namespace | Binder FD |
|---|---:|---|---|---|---:|
| Rust 서버 1 | 6226 | `u:r:aidl_lazy_test_server:s0` | 1000/1000 | `mnt:[4026536844]` | 3 |
| 일반 client | 6248 | `u:r:shell:s0` | 1000/1000 | `mnt:[4026536846]` | 3 |
| death client | 6272 | `u:r:shell:s0` | 1000/1000 | `mnt:[4026536846]` | 3 |
| Rust 서버 2 | 6303 | `u:r:aidl_lazy_test_server:s0` | 1000/1000 | `mnt:[4026536844]` | 3 |
| 재연결 client | 6309 | `u:r:shell:s0` | 1000/1000 | `mnt:[4026536928]` | 3 |

Guest SDK는 Phase 2C probe와 Phase 3 service에서 36으로 확인됐습니다.

## Binder Death/Restart

- death client가 `link_to_death`를 등록했습니다.
- 테스트 전용 Rust 서버 PID `6226`만 supervisor가 확인 후 SIGTERM으로 종료했습니다.
- death client가 `death_observed`를 받았고 Guest ServiceManager에서 서비스가 사라졌습니다.
- 종료된 서버의 기존 Binder 참조에 대한 `echo`는 `TransactionFailed / DeadObject`로 실패했습니다.
- 서버를 새 PID `6303`으로 재시작해 service와 descriptor를 재등록했습니다.
- 새 client가 다시 조회하고 `add`, `echo`, callback 2회를 성공했습니다.
- 서버 종료 뒤 최종 서비스 조회는 `service_absent`였습니다.
- client/server 프로세스는 모두 reap됐고, 시험 PID, Guest mount, session loop backing 잔여물이 없었습니다. runner는 55개 loop allocation의 반환을 확인했습니다. Binder driver 내부 refcount 계측은 별도로 하지 않았습니다.

## Host 격리 및 회귀

Host 상태 비교는 C++ baseline 종료, AIDL callback, Binder death, restart/reconnect, 최종 서비스 제거의 5단계에서 모두 `unchanged=true`였습니다.

- Host Binder identity는 `[dev=33, ino=4, rdev=129793]`, Guest private Binder의 `rdev=129797`로 분리됐습니다.
- Host `package` 서비스는 실행 전·후 `found`; `aidl_lazy_test_1` 및 `org.ssal.phase3.IPhase3Service`는 Host에서 끝까지 `not found`였습니다.
- `host_registry_isolation`, `property_host_unchanged`, `cleanup`, `servicemanager` 검사가 모두 통과했습니다. Host mount/process/property snapshot hash는 5단계에서 동일했습니다.
- 종료 후 Host `servicemanager`와 `adbd`는 계속 `running`이었습니다. 운영 데몬을 종료하거나 재시작하지 않았습니다.
- 임시 test stage와 recovery 잔여물은 제거됐고 `/data/local/ssal/mnt`는 비어 있었습니다.
- 설치된 SELinux rule file은 작업본과 같은 hash였습니다. SELinux 정책 hash도 기준값으로 복귀했습니다.

| 회귀 항목 | 결과 |
|---|---|
| 기존 C++ Test B 및 Phase 1 완료 게이트 | 통과 (`test_b_passed=true`, `phase1_complete=true`) |
| Phase 2C rsbinder | 통과: Guest SDK 36, `aidl_lazy_test_1` 조회, `BBinder` descriptor |
| Phase 3A/B/C 및 Host 격리 | 통과 (`phase3.passed=true`, 관련 checks 모두 `passed`) |
| Root host unit tests | 25 통과 |
| Phase 2 crate unit tests | 1 통과 |
| Phase 3 crate unit tests | 테스트 없음, `cargo test` 성공 |
| Root/Phase 2/Phase 3 Android AArch64 release build | 모두 통과 |
| Rust format checks | 통과 |

## 남은 문제와 다음 단계

Phase 3 범위에서 확인된 Binder transport 또는 rsbinder 구현 결함은 없습니다. 최초 실패는 test server에서 shell client로 가는 SELinux `binder call` 권한 부족이었고, 정확히 그 권한을 적용했을 때 callback이 통과했습니다. Death/restart와 재연결도 성공했습니다.

Phase 4 진행이 가능합니다. 다만 HAL proxy, 실제 Guest boot, 전체 SSAL switching은 이 검증에 포함되지 않았습니다. AVC 원문이 없다는 기록 한계와 Binder driver 내부 refcount를 직접 계측하지 않았다는 범위도 유지합니다.
