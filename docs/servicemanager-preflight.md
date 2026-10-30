# 정식 servicemanager 실행 사전 검사

`ssal probe-servicemanager-preflight PROFILE_NAME`은 정식 Guest 바이너리의 SELinux AV, rc, 실행 환경과 호스트 노출 경로를 조사한다. 기존 helper 전환 시험과 별도 명령이며, 이번 검사에는 setexeccon, 서비스 exec, Binder open/ioctl, property socket connect가 없다. `launch_enabled=false`를 유지한다. 설치 데몬을 교체하지 않고 임시 워커로 기기를 검사했다.

```sh
ssald --servicemanager-preflight-worker SYSTEM_IMG USERDATA SESSION_DIR
```

SESSION_DIR에는 새 전용 system/data 디렉터리를 준비한다. mount/loop 정리 후 호출자가 mount 부재를 확인하고 scratch를 제거한다. 일반 CLI의 기존 prepare 감독 경로는 scratch도 정리한다. 검사에 성공해도 현재 실행·격리 선행 조건이 준비되지 않았으므로 명령은 실패 상태로 종료한다. 진단 결과와 자원 정리 결과를 각각 출력한다.

## 2026-10-31 결과

SM-S937N의 Android 16 Guest profile1에서 [원시 결과](servicemanager-preflight-device-20261031.json)를 기록했다.

| 필드 | 결과 | 범위 |
|---|---|---|
| policy_permissions | passed | 정식 파일에 대한 기존 8개 커널 실효 AV 조회 |
| entrypoint | passed | 실제 `servicemanager_exec` 라벨 및 target entrypoint 허용 |
| domain_transition | not_run | 실제 exec 및 도메인 전환 미실행 |
| execution_prerequisites | blocked | 아래 실행 조건 부족 |
| host_isolation | blocked | Host Binder/property 영역/kmsg 공유 및 차단 증명 부족 |
| cleanup | passed | 검사 FD, Guest mount, system/userdata mount, loop, 임시 파일 정리 |

### 정식 실행 파일 권한

실제 Guest `/system/bin/servicemanager`의 라벨은 `u:object_r:servicemanager_exec:s0`다. API는 `/sys/fs/selinux/access`의 `security_compute_av_flags_raw` 프로토콜이다. 커널 class/permission 번호를 런타임에 조회하고 원문 응답과 시퀀스도 보존했다.

| 질의 | requested mask | allowed mask | flags |
|---|---|---|---|
| ksu → ksu process:setexec | 0x00020000 | 0xffffffff | 1 |
| ksu → servicemanager process:transition | 0x00000002 | 0xffffffff | 1 |
| ksu → servicemanager_exec file:execute | 0x00004000 | 0xffffffff | 1 |
| servicemanager → servicemanager_exec file:entrypoint | 0x04000000 | 0x04044412 | 0 |

open/read/getattr/map에 대한 source 접근도 허용됐다. 전역 Enforcing, ksu permissive, servicemanager enforcing을 별도로 확인했다. 자동 전환의 커널 create 조회 결과는 `u:r:ksu:s0` 유지다. 명시적 전환에 필요한 조회 권한이 허용된 것과 자동 전환 준비 여부는 다르다.

실행 파일의 mount는 ro,nosuid,nodev다. `nnp_nosuid_transition` policy capability는 1이고, source → target의 process2:nosuid_transition/nnp_transition AV는 둘 다 allowed mask 0xffffffff, flags 1이었다. 워커 NoNewPrivs는 0이다. 이 추가 조회도 실제 exec의 nosuid/자격 처리 결과를 대체하지 않는다.

**현재 로드된 실효 정책에서는 정식 파일의 명시적 전환에 필요한 조회 권한이 부족하다는 증거가 없다. 실제 전환 성공은 미검증이다.** KernelSU와 permissive ksu가 있는 현재 정책을 변경 전 순정 삼성 정책과 동일하다고 단정할 수 없다. 정책 원본 읽기도 EINVAL이라 해시는 미확인이다. 따라서 “순정 삼성 정책만으로 가능”은 이번 결과로 확정할 수 없다. 새로운 allow 규칙이 필요하다고 전환 권한 조회만으로 결론 내릴 근거도 없다.

### 확인된 실행 조건과 부족한 부분

실제 Guest rc의 사용자/그룹 설정은 Android 16 기준과 일치한다. UID/GID는 1000/1000, 보조 그룹은 readproc(3009)이다. rc는 kmsg 쓰기 FD와 ProcessCapacityHigh task profile도 요구한다. 이번 워커의 UID/GID는 0이며, 서비스용 자격·capability 정리·FD allowlist·rlimit·task profile 적용 및 적용 후 검증은 아직 갖추지 않았다. init의 restart 동작은 SSAL에 가져오거나 실행하지 않는다.

구체적인 SELinux/격리 차단 근거는 다음과 같다.

1. 생성된 `/linkerconfig/ld.config.txt`가 `tmpfs` 라벨이다. servicemanager → tmpfs:file의 open/read/getattr/map이 모두 거부된다. allowed mask 0, flags 0이다. 실제 loader 실행은 하지 않았지만 설정 파일 접근의 구체적인 사전 차단 요인이다.
2. 현재 Guest `/dev/binder`는 Host와 동일한 객체다. major/minor 507:1, device/inode/rdev가 모두 같다. mode 0666이고 target의 chr_file 접근 및 binder:set_context_mgr AV는 허용되지만, 이 장치를 Guest context manager용으로 사용할 수는 없다. 기존 Test A의 독립 Binder 성공은 이 preflight에 private 장치가 준비됐다는 뜻이 아니다.
3. 이전 Test A에서 관측한 private 노드 라벨 `binderfs`를 후보로 질의하면 servicemanager → binderfs:chr_file의 open/read/write/getattr/ioctl/map이 모두 거부된다. allowed mask 0, flags 0이다. 이번에는 private 노드를 새로 만들거나 열지 않았으므로, 이는 그 후보 라벨에 대한 정책 판단이며 실제 새 노드의 검증 결과가 아니다.
4. Guest의 property_service 및 property_service_for_system 경로는 ENOENT로 가려져 있다. 그러나 `/dev/__properties__`는 Host와 같은 dev/inode이며 Guest 전용 property 영역·서비스가 없다. 경로 부재만으로 정확한 Guest 바이너리의 모든 FD/namespace/접속 경로 차단을 통과시키지 않았다. property 요청은 전송하지 않았다.
5. `/dev/kmsg`는 Host와 동일 객체다. rc의 logging FD 정책을 그대로 구현하면 공유 커널 로그로 쓰는 경로가 생긴다. logdw 소켓은 가려져 있다.
6. 새 mount namespace와 proc mount는 있지만 prepare는 별도 PID/net namespace를 생성하지 않는다. 실제 서비스 root 전환, 상속 FD/환경 정리, linker 의존성 전체·컨텍스트 파일·SELinux status 접근, ioctl 확장 권한 등은 대상 자격으로 검증되지 않았다. 대표 파일의 AV 조회는 전체 런타임 검증이 아니다.

추가 탐색에서 linkerconfig 및 property 디렉터리의 open/read도 거부됐다. search/getattr는 별도 허용됐다. 디렉터리 open/read가 항상 pathname 탐색에 필요한 것은 아니므로 이 거부를 모두 필수 실행 권한 누락으로 간주하지 않는다. 파일 읽기 거부와 분리해 원시 결과에 남겼다.

### 소스 근거와 해석 범위

공식 [Android 16 rc](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r2/cmds/servicemanager/servicemanager.rc)를 실제 Guest rc와 대조했다. [main.cpp](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r2/cmds/servicemanager/main.cpp)는 기본 Binder 경로를 선택하고 context manager를 설정하며 ready property를 쓰는 경로가 있다. [ProcessState.cpp](https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r2/libs/binder/ProcessState.cpp)는 지정 드라이버의 읽기 access 실패 시 기본 Binder로 fallback하므로, 나중에 private 경로 인자만 전달하는 것은 충분한 격리 증명이 아니다. [bionic property 클라이언트](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/bionic/system_property_set.cpp)는 pathname UNIX 소켓을 사용하며 power-control 속성에 별도 시스템 소켓 경로가 있다.

이는 해당 AOSP 태그의 소스 동작이다. Guest 바이너리의 정확한 소스 대응/변경 여부와 런타임 우회 경로 전부를 입증한 것은 아니므로 host_isolation은 blocked로 유지했다.

정책·라벨·시스템 파일을 변경하지 않았다. 설치 데몬도 교체하지 않았다. 주요 Host PID·start time·컨텍스트·실행 파일·생존 상태 전후 일치, 전역 Enforcing과 AV 시퀀스 1 유지, rootfs 잔여 mount 없음, loop backing 55개 해제 및 임시 파일 제거를 확인했다. 관찰한 Host 상태의 동일성을 모든 중간 상태/전체 시스템 불변성으로 확대하지 않는다.

검증: cargo fmt, clippy, 단위 테스트 20개 통과(특수 권한 테스트 3개 제외), Android 빌드 및 패키징. 실제 servicemanager exec, Binder 서비스 등록, Property 초기화, 정책 패치는 수행하지 않았다.
