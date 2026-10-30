# SELinux exec 전환 시험

`ssal probe-selinux-transition PROFILE_NAME`은 임시 Guest rootfs에서 기존 8개 권한을 조회하고, 별도 `ssal-selinux-identity` 실행 파일로 명시적 exec 전환을 시험한다. 실제 servicemanager는 실행하지 않는다. `launch_enabled=false`는 유지한다.

## 동작과 결과 범위

- 전역 Enforcing, source `ksu` permissive 플래그, target `servicemanager` permissive 플래그를 독립 기록한다.
- `selinuxfs/access`로 현재 커널 클래스/권한 번호를 조회해 요청한다. 각 결과에 API, class index, requested/allowed mask, flags, raw response, policy sequence를 남긴다. 이는 커널이 계산한 실효 AV이며 정적 allow 규칙 분석 결과는 아니다. 특히 source permissive를 정책 집행 검증으로 바꾸지 않는다.
- `selinuxfs/create`의 process class로 자동 전환의 정책 예측을 기록한다. 자동 exec는 수행하지 않는다. 명시적 target 지정 결과와 별도다. 인터페이스는 [libselinux AV 구현](https://github.com/SELinuxProject/selinux/blob/main/libselinux/src/compute_av.c), [create 구현](https://github.com/SELinuxProject/selinux/blob/main/libselinux/src/compute_create.c)을 따른다.
- Guest servicemanager 파일과 시험용 helper의 실제 라벨은 열린 FD에서 읽기만 한다. helper는 데몬과 같은 디렉터리의 `ssal-selinux-identity`다. 복사 후 라벨 변경, chcon, 정책 변경을 수행하지 않는다.
- helper에 대한 target `file:entrypoint`와 source 실행 접근을 추가 검사한다. entrypoint 거부, target permissive, 권한/시퀀스 불확실, setexec 지정 실패는 실제 exec 전에 차단한다. source permissive 자체는 시험을 막지 않으며 별도 사실로 보고한다.
- 일회용 자식에서만 `/proc/thread-self/attr/exec`를 기록한다. 이 setexeccon 커널 인터페이스 시험의 PID·errno·회수 결과를 남긴다.
- 사전 검사를 통과하면 두 번째 일회용 자식의 pre-exec에서 target을 지정하고, 열린 helper FD를 `/proc/self/fd/N` 경로로 exec한다. 이 단계는 호스트 root/현재 워커 namespace에서 helper만 실행하며 Guest 서비스 자격·환경의 완성 여부는 검증하지 않는다.
- helper는 exec 후 자신의 context, PID, UID/EUID/GID/EGID, 제공되는 모든 namespace 링크, 실행 파일 경로·device/inode, proc status를 보고하고 종료한다. Binder, property, mount, 자식 생성 기능이 없다. 부모는 PID, 예상 target, 자격, namespace, pinned executable identity와 정상 종료를 비교한다.
- 자식은 PID로 추적하고 3초 timeout에 kill/wait한다. 상속 FD는 exec 시 닫히도록 처리한다. 불확실한 실패에는 성공 판정을 하지 않는다.

`policy_permission_check`, `source_domain_permissive`, `target_domain_enforcing`, `setexeccon`, `exec_transition`, `post_exec_identity`, `host_unchanged`, `cleanup`을 분리한다. `cleanup`은 자식/FD, Guest rootfs, system/userdata mount 및 loop 정리 결과로 나눠 기록하며 모든 범위가 passed여야 정리 완료다.

Host init/servicemanager/zygote/SurfaceFlinger의 PID·start time·실행 파일·컨텍스트·생존 여부와 부모 컨텍스트/namespace, 전역 enforce 및 AV sequence를 전후 비교한다. 이는 관찰한 프로세스 상태의 비교이며 모든 호스트 상태 불변성의 증명은 아니다. 정책 원본 해시는 읽을 수 있을 때만 비교한다. 실패하면 오류와 null을 보존한다.

## 빌드 및 독립 워커

Android 빌드는 `out/bin/ssald`, `out/bin/ssal`, `out/bin/ssal-selinux-identity`를 만들며 패키지에도 helper가 포함된다. 새 CLI 명령에는 갱신된 데몬이 필요하다. 기기 시험은 설치 데몬을 교체하지 않고 동일 디렉터리의 임시 데몬/helper로 실행했다.

```sh
ssald --selinux-probe-worker SYSTEM_IMG USERDATA SESSION_DIR
```

SESSION_DIR은 새 전용 디렉터리이며 빈 system/data 하위 디렉터리를 준비한다. 직접 호출자는 워커 종료 후 mount 부재를 확인하고 scratch를 제거한다. 일반 CLI는 prepare 감독 경로가 정리한다.

## 2026-10-31 SM-S937N 결과

[실제 exec 단계 시험 결과](selinux-exec-device-20261031.json), [이전 pending-exec 검사](selinux-transition-device-20261031.json).

| 항목 | 결과 |
|---|---|
| 전역 SELinux | Enforcing |
| source_domain_permissive | true (`ksu`, flags=1) |
| target_domain_enforcing | true (`servicemanager`, flags=0), 전후 확인 |
| 기존 Guest 8개 권한 | 모두 커널 AV allowed |
| 자동 전환 예측 | Guest servicemanager/helper 모두 `u:r:ksu:s0` 유지 |
| 시험용 helper 라벨 | `u:object_r:shell_data_file:s0` |
| policy_permission_check | failed: target → helper entrypoint 거부 |
| setexeccon | passed: errno 0, 일회용 자식 회수 |
| exec_transition | blocked |
| post_exec_identity | not_run |
| host_unchanged | passed: 관찰한 주요 프로세스 및 부모 상태 유지 |
| cleanup | 자식/FD·Guest rootfs·mount/loop 정리 모두 passed |

거부된 질의는 `u:r:servicemanager:s0 → u:object_r:shell_data_file:s0`, class file index 6, permission entrypoint, requested mask `0x04000000`, allowed mask `0x00000000`, flags `0x0`, sequence 1이다. raw response는 `0 ffffffff 0 ffffffff 1 0`이다.

실제 exec를 강행하지 않았으며, 정책/라벨을 자동 수정하지 않았다. 명시적 컨텍스트 지정 성공은 실제 전환 성공의 증거가 아니다. 다음 결정에는 현재 제약 안에서 허용된 entrypoint 라벨을 갖는 무해한 시험 실행 파일을 마련할 수 있는지 검토가 필요하다. 현재 파일에 라벨이나 allow를 임의 추가하는 우회는 수행하지 않았다.

기기에서 helper를 일반 ksu로 실행하는 대조군은 JSON identity 보고 후 정상 종료했다. 이는 reporter의 동작 확인이며 servicemanager 도메인 전환 증거가 아니다. 전환 성공·도메인 변경 후의 reporter 접근 및 timeout 경로는 실제 기기에서 미검증이다. 정책 원본 읽기는 EINVAL이어서 SHA-256은 미확인이다. loop backing 55개 해제와 scratch 제거, 전역 Enforcing 및 주요 Host PID 유지도 확인했다.
