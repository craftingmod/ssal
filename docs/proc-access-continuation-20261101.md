# Proc 접근 재분석 — 2026-11-01

후속 완료: [FD 격리와 Property Area Live 성공](property-fd-area-success-20261101.md). 기존 Proc 성공 경로를 유지하고 새 정책 없이 Parent FD 검증과 실제 Property Area 생성·매핑·add/find까지 통과했다. 아래 내용은 당시 Proc 단계 기록이다.

## 승인 후 실기기 결과

사용자 승인 후 위 세 권한에 해당하는 `ksud sepolicy patch` 세 문장만 현재 boot의 live 정책에 적용했다. 적용 전후 읽기 전용 AV 질의에서 `dir:search`, `file:open`, `file:read`가 각각 DENIED에서 ALLOWED로 바뀌었고 Guest permissive flag는 0이었다. [적용 기록](../out/proc-policy-patch-20261101.txt), [적용 후 preflight](../out/proc-policy-post-preflight-20261101.txt). 정책 sequence가 1로 유지된 것은 정책 불변의 증거가 아니다.

Proc-Only child를 한 번 실행했다. Parent exec-stop의 Guest SID, task SID, executable dev/inode, mount namespace 및 Enforcing 검사가 통과했고, Guest가 세 `attr/current` 경로 모두에서 open/read/close errno 0으로 `u:r:ssal_guest_probe:s0`를 직접 읽었다. Child는 정상 종료 및 회수됐다. 실행 전후 init, servicemanager, zygote, system_server, surfaceflinger의 PID/starttime/context/exe, Host property 디렉터리 및 mount identity와 파일 metadata는 동일했고 전역 Enforcing이 유지됐다. Host property 내용은 확인하지 않았다. [실행 기록](../out/proc-policy-verified-device-20261101.txt).

이는 해당 세 권한을 함께 추가하면 기존 self context 조회가 성공함을 보여준다. 각 권한이 개별적으로 필수인지는 각각 제거하는 시험을 하지 않아 확정하지 않는다. 별도 component `stat`는 여전히 EACCES다. `file:getattr`도 실효 AV 거부이며 해당 `stat`의 원인 후보이나 정확한 반환 훅은 미확정이다. 출력의 `proc_failure_class=NO_FAILURE`는 세 identity open/read 결과에 대한 분류이지 모든 component stat의 성공을 의미하지 않는다. stderr의 `sched_getscheduler` EACCES도 별도로 관찰되었으며 원인과 영향은 미확정이다.

Property Area의 읽기 전용 preflight는 Guest → tmpfs dir:write/add_name 및 file:create/open/read/write/relabelfrom, Guest → vendor_ctl_port-bridge_prop file:relabelto/open/read/write/map/getattr의 필수 AV 거부로 child 생성 전에 중단됐다. [기록](../out/property-preflight-after-proc-fix-20261101.txt). 이는 후보 타입을 사용하는 현재 PoC의 결과이며 실제 Guest 전체에 필요한 최소 정책 집합은 아니다. Property Live, mount, 추가 정책 변경은 수행하지 않았다. 이후 [최종 preflight](../out/proc-policy-final-preflight-20261101.txt)에서도 Host identity 및 Enforcing 검사가 통과했다.

적용된 allow는 커널의 현재 live 정책에 남아 있으며 안전한 무재부팅 rollback을 확인하지 못했다. 자동 재적용 설정은 추가하지 않았다. 재부팅은 수행하지 않았고 재부팅 후 복구도 이번에 검증하지 않았다. 아래의 적용 전 기록은 당시 상황을 보존한다.

## 확인된 차단과 한계

기존 Proc-Only 실행은 exec-stop에서 Guest SID와 executable inode, 동일 mount namespace, 전역 Enforcing 및 Guest enforcing을 확인했다. Child의 세 `attr/current` open은 모두 EACCES이고 `/proc` stat과 self 링크 readlink는 성공했다. Parent가 관찰한 두 attr 파일 라벨은 `u:r:ssal_guest_probe:s0`였다. 실행 전후 Host 프로세스와 property mount identity는 동일했고 child는 회수됐다. [원본 기록](../out/proc-only-device-20261101.txt).

현재 실효 정책을 다시 조회한 결과, Guest → `u:object_r:proc:s0`의 `dir:search`, `lnk_file:read`는 허용이고 Guest → `u:r:ssal_guest_probe:s0`의 `dir:search`, `file:open`, `file:read`, `file:getattr`은 모두 거부다. Guest permissive flag는 0, policy sequence는 1이다. 읽기 전용 preflight는 통과했고 Host 프로세스, property 디렉터리와 파일 metadata는 전후 동일하다. Property 파일 내용은 비교하지 않았다. [재조회 기록](../out/proc-only-preflight-continuation-20261101.txt).

따라서 현재 정책에는 self 경로 탐색과 파일 읽기에 각각 독립적인 필수 차단이 존재한다. 이는 정책 변경 없이 현재 방식의 Guest self-context 조회가 성공할 수 없다는 구체적인 원인이다. 다만 기존 stat은 대상 inode의 `getattr`도 검사하므로 stat EACCES만으로 **첫 반환이 정확히 어느 구성요소의 어느 훅인지** 확정하지 않는다. `/proc/<pid>` 디렉터리 자체의 Guest label 및 `dir:getattr`은 해당 child에 대해 별도로 측정하지 않았다. AVC가 없다는 것은 SELinux 거부가 없다는 뜻이 아니다. `dontaudit`, audit 제한 및 로그 상관관계 누락은 구별되지 않았다. AV 응답만으로 dontaudit 존재를 확정하지 않는다.

기기의 `/proc` mount는 `rw,relatime,gid=3009,hidepid=invisible`이다. 관찰한 KSU 자기 PID 디렉터리는 `0555`, attr/current는 `0666`이고 객체 라벨은 KSU 도메인이었다. 이는 Guest inode의 DAC를 직접 검증한 결과가 아니다. [Android common 6.6 proc 코드](https://android.googlesource.com/kernel/common/+/refs/tags/android15-6.6-2025-01_r13/fs/proc/base.c)는 hidepid 검사 뒤 generic DAC를 사용하며 보이지 않는 PID 거부에 ENOENT를 사용한다. 이 동작은 이번 EACCES와 맞지 않지만 삼성 변경 사항을 배제하지 못한다. [SELinux 훅](https://android.googlesource.com/kernel/common/+/refs/tags/android15-6.6-2024-10_r2/security/selinux/hooks.c)은 inode permission/getattr과 task-to-inode 훅을 등록한다. 실행 커널은 Samsung `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k`이며 정확히 일치하는 Samsung 소스를 확보하지 못해 common과의 차이는 검증하지 않았다.

## 검토용 정책 후보 — 적용되지 않음

현재 허용 여부와 별개로 다음 세 권한이 self context 조회의 후보이다. SELinux rule의 `self`는 같은 타입을 의미하며 같은 PID만을 뜻하지 않는다.

```te
allow ssal_guest_probe self:dir search;
allow ssal_guest_probe self:file { open read };
```

source 및 target은 모두 `u:r:ssal_guest_probe:s0`다. 같은 도메인으로 라벨된 다른 객체와 다른 프로세스의 객체에도 적용될 수 있으므로, 같은 PID로 범위가 제한된 규칙이 아니다. 다른 DAC, hidepid, LSM 및 SELinux constraint도 적용될 수 있다. `dir:getattr`과 `file:getattr`은 stat 기반 진단을 위한 별도 후보이지 open/read 자체를 위한 확정 최소 권한이라고 단정하지 않는다. `process:getattr`은 관측상 거부지만 self attr getter에 필요하다고 가정하지 않는다. 후속 실기기 성공, 정책 constraints와 범위 검토 전에는 충분한 정책이라고 주장할 수 없다. 기존 module 정책 및 Host 정책에 이 후보를 추가하지 않았다.

정책 적용 승인이 없으면 재실행해도 같은 필수 AV 거부가 남으므로 이번에는 추가 Guest child를 실행하지 않았다. 승인 후에는 정책 적용 전후 Host AV와 복구 경로를 별도로 검토하고, 변경을 적용한 뒤 동일 프로세스·mount·Enforcing 검증과 세 경로의 open/read를 재시험한다. 필요한 경우 실제 `/proc/<pid>`, `task`, `attr`, `current`의 라벨·DAC를 exec-stop에서 측정하고 `O_PATH`와 단계별 openat으로 getattr과 search를 구별한다. Property Area Live 실행은 별도 승인이다.

## 독립 Property 검증과 대체 경로 설계

Property 합성 fixture의 AOSP serializer exact/prefix lookup과 Bionic area add/find/remap, 별도 sentinel 불변 시험이 통과했다. 기존 입력 검증 및 snapshot·정책 후보 테스트 12개와 Rust 런처 테스트 20개도 통과했다. 이는 실제 Guest property service, Android SELinux 접근, Host FD/socket 차단 또는 전체 부팅 성공을 증명하지 않는다. 이전 Property preflight에서 Guest tmpfs 생성·쓰기·relabel 및 property 파일 접근에 복수 거부가 확인되어 있으며, 실제 inode·filesystem label과 client별 접근 모델을 확정한 뒤 별도 정책 분석이 필요하다. 기존 Property Live의 필수 AV 및 Guest self SID gate는 변경하지 않았다.

만약 self 접근을 당장 허용하지 않는 별도 PoC가 필요하다면 명시적 실험 모드만 사용한다. Parent는 `PTRACE_EVENT_EXEC`에서 PID/starttime, process와 task SID, executable dev/inode, namespace, 전역 Enforcing, Guest enforcing 및 불변 정책 sequence를 모두 검사하고 어느 하나라도 불명확하거나 불일치하면 child를 재개하지 않는다. 검사한 SID는 exec-stop 시점의 Parent 관찰일 뿐, 이후 Guest 자체 SID 확인이나 후속 전환 부재를 보장하지 않는다. 해당 모드는 일반 모드 또는 Property Area Live의 SID gate를 대체하지 않으며 아직 구현하지 않았다.

Staging 디렉터리는 root 소유 `0777`에서 `0711`로 강화했다. 기존 파일 inode와 `ssal_guest_probe_exec` label은 유지되고 로컬·기기 SHA-256이 일치한다. 새 코드 또는 Android 바이너리는 만들지 않았다. 기존 문서의 잘못된 62자리 helper hash 네 곳을 실제 hash `f19b8b416c30060f0f058418503365a1ac09fe7befeefe0167ef9b642d97ff08`로 수정했다.
