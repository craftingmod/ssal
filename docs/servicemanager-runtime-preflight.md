# servicemanager 런타임 사전 검사

후속 구현은 임시 Guest 라벨/DAC 변경과 UID 1000 시험 워커를 추가했다. 현재 명령의 확장 범위와 최신 결과는 [실행 환경 검증](servicemanager-execution-environment.md)을 참고한다. 아래는 최초 읽기 전용 조사 당시의 결과다.

`ssal probe-servicemanager-runtime-preflight PROFILE_NAME`을 추가했다. `launch_enabled=false`를 유지하며 실제 Android 서비스, setexeccon, context manager 설정, Binder transaction, property 요청을 실행하지 않는다. 기존 prepare의 linkerconfig 생성과 shell/rootfs 검사 이후 전용 검사를 수행한다. SELinux 정책, permissive 상태, Host/Guest 파일 라벨은 변경하지 않는다.

```sh
ssal probe-servicemanager-runtime-preflight profile1
# 설치 데몬을 교체하지 않는 직접 검사:
ssald --servicemanager-runtime-preflight-worker SYSTEM_IMG USERDATA NEW_SESSION_DIR
```

직접 워커 호출자는 새 세션 디렉터리와 빈 system/data 하위 디렉터리를 준비한다. 워커는 Binder FD/mount → Guest rootfs → system/userdata mount와 loop를 정리하고 범위별 결과를 출력한다. 직접 호출의 scratch 제거는 호출자가 mount·프로세스·loop 잔여 여부를 확인한 뒤 수행한다. 일반 CLI는 기존 prepare 감독 경로로 scratch도 제거한다. 진단 단계가 정상적으로 끝나도 실행 준비가 부족하므로 종료 코드 1을 반환한다. 진단 실패와 차단은 JSON의 `failed`/`blocked`로 구분한다.

## 기기 결과

2026-10-31 SM-S937N, Android 16 Guest profile1의 [원시 증거](servicemanager-runtime-preflight-device-20261031.json)를 기록했다. 설치 데몬과 정책 파일을 교체하지 않고 임시 Android 워커로 검증했다.

| 단계 | 결과 | 근거 |
|---|---|---|
| private_binder | passed | 기존 probe-binder의 공통 Session으로 독립 binderfs 생성, BINDER_CTL_ADD, FD mount ID 및 ioctl 반환 major/minor 검증, Guest 기본 경로의 dev/inode/rdev 일치 확인 |
| selinux_labels | blocked | 실제 생성 노드 및 linkerconfig 파일에 대한 target AV 거부 |
| execution_spec | blocked | 명세 작성 및 읽기 전용 선행 검사 완료, 자격/격리 적용은 미실행 |
| host_protection | blocked | proc magic link로 Host Binder 관찰, property 영역·kmsg 공유 |
| host_protection.media | passed | Host/Guest media 디렉터리 inode가 다르고 Guest media 내부 추가 mount 없음 |
| host_unchanged | passed | 주요 Host 프로세스 PID/start time/실행 파일/context/생존, Host Binder 정체성, Enforcing 및 AV sequence 일치 |
| cleanup | passed | private FD/mount, rootfs, system/userdata mount, loop 55개 해제, 소유 실행 프로세스·Host namespace mount 잔여 부재와 scratch 삭제 확인 |
| service_launch / domain_transition | not_run | servicemanager와 다른 실제 Android 서비스 실행 없음 |

Guest Binder는 **507:8**, Host Binder는 **507:1**이며 protocol은 8이다. Guest `/dev/binder`는 Android symlink를 Guest root 기준으로 해석한 뒤 private 노드를 bind한다. private FD는 CLOEXEC다. `BINDER_VERSION`만 조회하고 context-manager ioctl은 호출하지 않는다.

현재 userdata는 directory 형식으로 Host `/data`와 같은 파일시스템에 있다. 따라서 media의 st_dev가 같다는 사실은 공유 디렉터리의 증거가 아니다. Host media inode 164와 Guest media inode 204403의 차이 및 mount topology를 검사했다. 이는 해당 디렉터리 경계 검사이며 기존 모든 파일의 hard link나 전체 콘텐츠 독립성 감사는 아니다.

## SELinux 정책 차단과 라벨 후보

- Guest linkerconfig 파일은 `tmpfs`이며 `servicemanager → tmpfs:file`의 open/read/getattr/map이 모두 거부된다. 디렉터리 search/getattr는 허용된다.
- 실제 private 노드는 `binderfs`이며 `servicemanager → binderfs:chr_file`의 open/read/write/getattr/ioctl/map이 모두 거부된다. context-manager 자체 권한의 허용과 별개다.
- Host의 `linkerconfig_file:file`에는 위 파일 권한이 허용되고 `binder_device:chr_file`에도 조사한 권한이 허용된다. 두 타입은 **재사용 검토 후보**다. `linkerconfig_file:dir`은 search가 허용되지만 getattr는 거부되므로 파일·디렉터리를 같은 판정으로 묶지 않는다. 디렉터리 getattr 거부만으로 필수 loader 접근 차단이라고 단정하지 않는다.
- 기존 타입을 쓴 private Binder도 별도 드라이버 객체라 레지스트리는 분리할 수 있다. 하지만 동일 servicemanager 도메인/타입 재사용은 Guest/Host 사이의 별도 MAC 경계를 만들지 않는다. 강한 MAC 구분이 필요하면 Guest 도메인·타입의 정책 설계가 필요하다. 파일시스템의 라벨 지원과 타입 의미를 검토하지 않고 안전한 재사용으로 확정할 수 없다.

조사 범위는 관찰한 Host/Guest 타입에 대한 현재 커널 실효 AV다. 전체 정책의 모든 접근 가능한 타입 열거, ioctl xperm, 전체 loader 의존성 접근 증명은 아니다. 정책 원본 읽기는 EINVAL로 해시를 얻지 못했다. AV sequence는 1로 유지됐다. 이미 KernelSU가 적용된 현재 정책의 결과이며 변경 전 순정 삼성 정책만으로 가능하다는 증거는 아니다. 정책 수정과 chcon은 수행하지 않았다.

## 런타임 환경 차단

`ServiceExecutionSpec` v1은 UID/GID 1000/1000, 보조 그룹 [3009], 모든 capability set 0, stdio만 허용하는 FD 명세, nofile 1024/1024·core 0/0 및 나머지 worker limit snapshot 유지, 환경 초기화, mount/PID/net/UTS/IPC/root/cgroup 요구사항, ProcessCapacityHigh를 정의한다. 실제 rc의 system/system readproc와 일치한다.

다음 선행 조건이 남았다.

1. private Binder는 root:root 0600이다. 명세 자격에는 읽기·쓰기 DAC가 없다. private 노드의 소유권/권한을 준비하는 단계가 필요하며 이번 검사에서는 chmod/chown하지 않았다. SELinux 거부와 독립적인 문제다.
2. 워커의 SETUID/SETGID/SETPCAP/SYS_CHROOT/SYS_ADMIN capability 비트는 존재하며 nofile hard limit도 충분하다. 하지만 UID/GID/groups/capability drop, FD allowlist, root/namespace, rlimit의 실제 적용 및 적용 후 검증은 not_run이다. 워커의 stdio는 상속 socket이며 서비스용 명세를 만족하지 않는다.
3. ProcessCapacityHigh는 Guest JSON에서 `JoinCgroup(cpuset, foreground)`로 해석됐다. Guest 소유 cgroup 목적지가 준비되지 않았다. 공유 Host cpuset에 작업을 적용하지 않았다.
4. mount namespace는 Host init과 다르지만 net/UTS는 같다. PID/IPC namespace 항목은 Host와 워커의 proc namespace 목록에 없으며 namespace 생성은 시험하지 않았다. 필요한 커널 지원/대체 proc 접근 차단 가능성을 별도 검증해야 한다.
5. privileged worker가 Guest proc mount의 `/proc/1/root/dev/binder`를 커널 magic link로 따라가면 Host Binder와 동일한 객체가 보인다. 일반 Android symlink resolver로 이 경로를 해석하면 잘못된 결과가 나므로 직접 커널 경로 관찰을 분리했다. 이것은 target 도메인의 접근 허용 증명이 아니지만, 경로 제거·FD 정리·target 자격 검증 전에는 격리를 통과시킬 수 없다. Guest 기본 Binder의 private 연결만으로 전체 fallback 차단을 증명하지 않는다.
6. property_service 및 property_service_for_system 경로는 ENOENT지만 `/dev/__properties__`와 `/dev/kmsg`는 Host 객체와 같다. 정확한 바이너리의 property/FD 우회 경로는 미검증이며 Guest property 서비스·영역은 준비되지 않았다. rc의 `/dev/kmsg w` FD를 제공하지 않았으며 대체 Guest logging backend가 필요하다.

현재 **실제 servicemanager 실행 가능한 상태가 아니다**. private Binder 생성·기본 경로 연결은 해결 가능함을 확인했지만, SELinux 파일/장치 접근과 DAC·자격·namespace·property·logging·task-profile 차단이 남았다. 어떤 결과도 `launch_enabled=false`를 해제하지 않는다.

검증은 cargo fmt, clippy `-D warnings`, 단위 테스트 21개 통과(특수 권한 3개 제외), Android release 빌드와 모듈 패키징이다. 임시 워커 실행 후 주요 Host 상태가 일치했고 정책 파일 해시와 관찰한 Host 라벨도 전후 같았다. 이 비교를 전체 중간 상태 불변성으로 확대하지 않는다.
