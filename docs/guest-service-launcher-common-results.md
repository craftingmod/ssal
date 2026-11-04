# 공통 Guest Service Launcher — 2026-11-04

Phase 5B는 **PASS로 종료**한다. 기존 cgroup/libprocessgroup PASS는 확정하며, cgroup·PID namespace·SELinux 아키텍처를 재설계하거나 광범위하게 재조사하지 않았다. Phase 6A는 같은 런처에서 installd/artd 초기 실행과 Private Binder 등록 확인까지 진행했다.

## 공통 경로

`guest_mounts::verify`의 기존 rootfs, profile userdata, APEX, GuestCgroups mount/cleanup과 `binder_probe::Session`의 private binderfs를 재사용한다. `guest_launcher::command`는 기존 root 전환·FD 정리 함수를 사용하고 Guest cgroup 배치, 환경 초기화, UID/GID·보조 그룹 설정, 선택한 Guest domain exec 전환을 공통으로 처리한다.

- `--guest-service-worker`: shell/property/FD/Private Binder AIDL 기본 검증.
- `--guest-child-worker`: 과거 POC 전용 분기를 제거하고 같은 공통 런처로 연결했다. 기존 `SSAL_GUEST_CHILD_*` 입력 대신 ssald 옆의 아래 helper를 사용한다. 독립 `ssal-guest-domain-poc` 진단 바이너리는 유지한다.
- `--guest-processgroup-worker`: 기존 실제 Guest libprocessgroup helper와 설정을 유지하고 exec 경계를 공통 `command`로 통합했다. 기존 자격·관리 context 시험 범위는 유지한다.
- `--guest-services-6a-worker`: 기본 검증 후 installd/artd를 실행하고, 실제 Private Binder `INTERFACE_TRANSACTION`으로 descriptor를 읽는다.

배포 파일은 `ssald`, 기존 Phase 2 `guest_probe`, Phase 3 `phase3-ipc`, 기존 `ssal-phase2-log.so`다. helper는 세션 tmpfs에 read-only bind한다. `scripts/run-guest-launcher.sh`가 실행 전후 Host Enforcing, boot ID, PID 1 mountinfo, 핵심 프로세스 PID/starttime/SID/UID/GID/capability/NNP/seccomp/root/exe/mount namespace, Host Binder/property/socket identity와 표본 property, Host registry의 진단 서비스 부재를 비교한다. Host userdata 전체 내용의 무변경을 증명하는 검사는 아니다.

## 실기기 결과

SM-S937N, Android 17 Host / Android 16 Guest, 기존 `phase5a-bringup-20261104` profile directory userdata 사용.

| 확인 | 결과 |
|---|---|
| 실제 Guest `/system/bin/sh` | exit 0, UID 1000, `u:r:ssal_guest_probe:s0` |
| Guest property area | 기존 rsproperties serializer/area initializer 재사용. Guest build.prop SDK 36, Bionic getprop 36, Host serial property 없음 |
| Guest property 초기값 | SDK, codename, ARM64 ABI, dex2oat64, servicemanager.ready만 로컬 seed. Host property 복사 없음 |
| Host control/property socket | Guest `/dev/socket` 비어 있음; `setprop ctl.start ssal_must_not_reach_host_init` exit 1 |
| Host FD 상속 | 부모의 Host `/data` FD를 CLOEXEC 없이 열어 주입. 실제 shell exec 후 FD 0=/dev/null, 1/2=세션 pipe뿐 |
| Guest userdata | profile identity 일치·Host `/data` identity와 다름, Guest shell 고유 marker write/read/unlink 성공 |
| Private Binder AIDL | Guest 507:5, Host 507:1. 등록·descriptor·add(17,25)=42·echo·동기 callback 2회 PASS |
| AIDL 실제 FD/SID | server/client의 Binder FD는 private 507:5; SDK 36, UID 1000, Guest SID 관측 |
| installd | 생존 및 Private Binder descriptor `android.os.IInstalld` 응답 PASS |
| artd | 생존 및 Private Binder descriptor `com.android.server.art.IArtd` 응답 PASS |
| Host 전후 | snapshot byte-identical, global Enforcing 유지, boot ID `f7900911-c061-4570-8f65-900571a55c11` 유지 |
| 정리 | 추적한 Guest process group만 종료·reap, binderfs·rootfs 잔여 mount 없음, loop 55개 해제 |

Guest 전용 permissive domain을 활용했다. Host 전체 permissive 전환, Host 기존 domain 권한 추가, 정책 변경, Host init 요청 전달, 재부팅은 하지 않았다. 공유 PID 및 Host `/proc` 가시성은 승인된 전제이며 NO-GO로 재분류하지 않았다.

## 실제 실패와 수정

1. 최초 Guest servicemanager SIGABRT: 기존 stderr logger를 연결해 `selinux_status_open(true) >= 0` 검사 실패를 확인했다. 기존 servicemanager 실행 경로와 동일하게 selinuxfs root는 libselinux가 발견할 수 있는 RW bind로 두고, 모든 제어 파일/디렉터리는 각각 RO bind했다. 기존 AV/context query 파일만 RW다. global enforce는 바꾸지 않았다.
2. logger를 `/run/ssal`에서 로드할 때 Guest linker namespace가 접근을 거부해 exit 1. Guest-only LD_LIBRARY_PATH에 세션 경로를 추가했다.
3. ADB 재복사 후 ssald exec exit 126/EACCES: 복사 파일의 executable bit를 복구했다.
4. Phase 6A 최초 installd SIGSEGV/fault address 0: 기존 daemon 경로의 `ASEC_MOUNTPOINT`, storage/I18N/tzdata 환경을 보존한 후 해당 SIGSEGV가 사라졌다. backtrace로 단일 getenv 호출을 확정한 것은 아니다.
5. 이어 installd `mkdir(/data/misc/user/0)` ENOENT(2), exit 1: Guest 전용 `/data/misc/user`, `/data/misc/installd` 부모만 준비하고 재실행했다.

servicemanager의 ready property 쓰기는 property service가 없어 실패 로그를 남긴다. 로컬 area에 읽기용 ready 값을 seed했으며 실제 등록·AIDL 호출은 성공했다. artd trace 파일 ENOENT(2)는 관측된 비차단 로그다. 이 둘을 SELinux 완성 조건이나 cgroup 회귀로 분류하지 않는다.

## 범위와 재현

Phase 6A는 **초기 실행·등록·descriptor IPC**까지다. 이번 installd/artd는 실험용 UID/GID 0, Guest permissive domain이며 최종 RC의 서비스별 UID/capability 구성을 인증하지 않는다. 앱 설치·삭제, dex2oat, 실제 Guest boot, full Guest property service, 장기 생존 및 하드 재부팅 복구는 이번 실행 범위가 아니다.

WSL은 AGENTS.md대로 sandbox 밖에서 사용한다. Android helper 빌드:

```sh
bash scripts/build-guest-launcher.sh
```

helper 2개와 기존 logger를 ssald 옆에 배치하고, 실기기에서 `sh scripts/run-guest-launcher.sh --guest-services-6a-worker`에 해당하는 업로드 경로를 실행한다. 이 스크립트는 문서에 기록한 기존 이미지/profile을 사용한다. 생성된 Guest userdata의 installd layout 디렉터리와 layout_version은 유지한다.

## 최종 검증 기록

- sandbox 밖 WSL: `cargo fmt --check` 및 두 experiment crate의 fmt PASS, `cargo test --locked` **81 PASS, 특권 테스트 3 ignored**, Android AArch64 release 빌드 PASS.
- [legacy child alias → 공통 런처 최종 로그](guest-launcher-common-device.log): worker exit 0, Host snapshot 동일, loop 55개 해제.
- [Phase 6A 최종 로그](guest-launcher-phase6a-device.log): installd PID 17965, artd PID 17974, 두 descriptor transaction exit 0, worker exit 0, Host snapshot 동일, loop 55개 해제.
- [기존 libprocessgroup 호출부 통합 회귀](guest-launcher-processgroup-regression.log): 새 공통 exec 함수로 한 번 실행해 `createProcessGroup=0`, 기존 세 profile true, worker exit 0 확인. cgroup 설정·경로의 광범위한 추가 조사는 하지 않았다.
- 최종 SHA-256: ssald `1cc2bbd3f22f3c2dba3d12bb9310a9bea6aedd83eae54cd5916fee714c89ea79`, property initializer `b32d4e3d8fcc384119f5d5be4af02d1b5ae0f10cffb252ba93616fa08eabac45`, AIDL helper `d08565d8c965bb7e8ca628a251242a0dd5e8258f50beaf6b8ba5852999ca1d28`.
- 최종 5B/6A Host snapshot 4개는 로컬 `out/guest-launcher-final/{5b,6a}-{before,after}.txt`에 보존했다. 모두 3302 bytes, SHA-256 `5e197890b106a1c3ada0b05fd39b5165539e2abcb87c728526f4d266f47c488b`로 동일하다. `scripts/build-guest-launcher.sh` 실행도 exit 0으로 검증했다.
