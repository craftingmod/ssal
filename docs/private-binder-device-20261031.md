# Private Binder 실기기 구현·정책 실험 — 2026-10-31

SM-S937N에서 설치 데몬을 교체하지 않고 임시 워커와 진단 도구로 실행했다. [원시 증거](private-binder-device-20261031.json).

## 변경과 결과

`Session`이 새 binderfs의 원본 `binder`를 선택하도록 변경했다. 기본 노드가 없을 때만 `BINDER_CTL_ADD(name=binder)`를 수행한다. alias 연결 전에 원본 라벨·inode·생성 경로를 기록하고, control FD와 mount ID 일치·Host rdev 불일치 검사를 유지한다. 이미 올바른 라벨인 경우 불필요한 fsetxattr/context 재마운트를 생략한다.

| 시험 | 결과 | 범위 |
|---|---|---|
| 원본 binder | binder_device | kernel_mount_default, private 507:5 / Host 507:1 |
| enforcing servicemanager, UID 1000 | open / mmap / VERSION 성공 | 실제 exec 후 context와 UID를 출력한 별도 helper |
| BINDER_WRITE_READ | 빈 요청 성공 | ioctl dispatch 성공이며 transaction/IPC 성공은 아님 |
| BINDER_SET_CONTEXT_MGR_EXT | 성공 | 해당 세션의 private 장치에만 호출 |
| Guest libbinder echo IPC | 성공 | 서버·클라이언트 ksu 도메인; helper와 Guest 라이브러리 해시 확인 |
| runtime preflight SELinux 라벨 호환성 | passed | 이전 binderfs 라벨 접근 차단 해소 |
| 정식 servicemanager / enforcing IPC / service_contexts | 미실행 | 전체 정책 무변경 성공으로 판정하지 않음 |

runtime preflight에서 target servicemanager의 조회 AV flags는 0이며 해당 도메인의 permissive 예외를 추가하지 않았다. 전역 Enforcing을 유지했으며 기존 관리 도메인 ksu의 permissive 상태와 구분한다. 단독 ioctl helper는 Host 라이브러리 환경에서 실행한 작은 Rust 프로그램이고, Guest dynamic loader 전체 검증은 아니다.

## context 마운트 실험

별도 mount namespace에서 propagation을 private으로 바꾸고 `/mnt`에 임시 tmpfs를 구성했다. default binderfs와 두 가지 옵션을 각기 새 mount로 검사했다.

| 옵션 | mount 결과 | association AV |
|---|---|---|
| `max=4` | 성공 | 기본 genfs 라벨 사용 |
| `context=binder_device` | EACCES(13) | binder_device → binder_device 거부 |
| `context=binder_device,fscontext=tmpfs` | 성공 | binder_device → tmpfs 허용 |

단일 context와 fscontext 분리의 차이는 association 가설을 강하게 지지한다. 그러나 dmesg와 제한된 logcat 수집에서 대응 AVC를 확보하지 못했다. 실제 실패 분기를 확정했다고 기록하지 않는다. user namespace 링크도 커널에서 제공되지 않아 null/unavailable로 남겼다. 동일 환경의 기본 mount와 fscontext 옵션 mount 성공은 적어도 모든 context 옵션이 일괄 거부된다는 해석과 맞지 않는다.

context mount의 root도 binder_device가 되므로 원래 binderfs 디렉터리 경유 접근은 target에서 실패했다. private 노드를 tmpfs 부모 아래의 `/mnt/binder`에 bind한 뒤에는 두 성공 mount 모두 target ioctl 시험이 통과했다. 이 결과는 장치 라벨과 경로 탐색 권한을 따로 다뤄야 함을 보여 준다.

**새 allow·genfscon·permissive 규칙은 적용하지 않았다.** 현재 검사 범위는 기존 실효 정책으로 통과했고, 원인 불명 EACCES에 임의 규칙을 넣지 않는 조건을 따랐다. 모듈 sepolicy.rule과 부팅 자동 적용 설정도 변경하지 않았다. 따라서 이번 실험에서 재부팅 시 재적용될 새 정책은 없다.

## 재현 도구와 제한

`scripts/build-android.sh`가 `out/bin/ssal-binder-access`를 생성한다. `scripts/probe-binder-labels.sh`는 다음과 같이 **일회성 unshare**로 실행하는 개발용 도구다. 설치/자동 실행 스크립트가 아니다.

```sh
unshare -m /system/bin/sh /TEMP/probe-binder-labels.sh /TEMP/ssal-binder-access
```

스크립트는 임시 helper에만 servicemanager_exec 라벨을 적용하고 UID 1000으로 runcon 실행한다. Host Binder에는 metadata 조회만 하며 ioctl은 검증된 다른 rdev에 보낸다. fd의 dev/inode/rdev를 다시 비교한다. 대상 장치는 UID 1000 소유 0600이다. mount errno 및 각 ioctl errno를 개별 출력한다. 결과 JSON의 scope를 유지하며 빈 WRITE_READ를 IPC로 승격하지 않는다.

스크립트는 현재 기기의 기본 binder 노드가 존재하는 개발 환경용이다. runtime과 같은 전체 FD/capability/namespace 실행 명세를 구현한 서비스 런처가 아니며, 출력의 각 syscall 결과를 확인해야 한다. 정식 서비스 기동 조건은 계속 차단된다.

정리 결과: 진단 스크립트 CLEANUP_PASSED, runtime/IPC 워커의 정상 mount 해제와 각각 loop 55개 반환 확인. 관측한 Host 주요 프로세스 PID, Binder 정체성·DAC·라벨, Enforcing 전후 동일. 이는 전체 Host 디스크 내용이나 모든 중간 상태 불변성의 증명은 아니다. Host 부팅 파티션을 쓰는 작업은 수행하지 않았다.

검증: cargo fmt, clippy -D warnings, 23 tests passed / 3 privileged tests ignored, shellcheck, Android release 빌드, WebUI/모듈 ZIP 패키징. 설치된 모듈·데몬은 갱신하지 않았다.

남은 작업은 target 도메인에서 실제 Binder transaction과 서비스 등록/조회, service_contexts 타입 호환성, 양방향 레지스트리 비노출이다. PID/proc·Guest property/logging·task profile 차단도 유지한다. `launch_enabled=false`다.
