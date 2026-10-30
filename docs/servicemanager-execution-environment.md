# Servicemanager 실행 환경 검증 — 2026-10-31

기존 `probe-servicemanager-runtime-preflight`를 확장했다. 기존 명령으로 임시 Guest 객체의 라벨/DAC 준비와 **고정된 시험용 워커**의 실행 자격·실제 접근을 검증한다. `launch_enabled=false`와 전역 Enforcing을 유지한다. servicemanager, Android 서비스, setexeccon, Binder context-manager 설정, Binder transaction 및 property 요청은 실행하지 않았다. 설치 데몬·Host 파일·전역 정책은 교체하거나 수정하지 않았다.

SM-S937N의 Android 16 Guest profile1에서 임시 바이너리로 검증했다. [원시 증거](servicemanager-execution-environment-device-20261031.json)는 최종 실행의 모든 단계, 세 시험 프로세스의 PID/자격/context/접근 결과, Host 전후 상태와 범위별 정리를 포함한다. 종료 코드 1은 남은 차단에 따른 의도된 결과다.

| 필드 | 결과 | 실제 검사 범위 |
|---|---|---|
| selinux_label_compatibility | blocked | linkerconfig 변경·AV는 성공, Binder 라벨 변경·context mount는 차단 |
| binder_dac | passed | private 객체만 1000:1000 0600으로 설정, 해당 자격에서 open 및 BINDER_VERSION 성공 |
| binder_isolation | passed | 최소 dev/빈 proc 시험 뷰의 양성·음성 대조군; 실제 libbinder/service 실행은 미검증 |
| execution_credentials | passed | 실제 UID/GID/groups/capabilities/FD/rlimit/환경/root 적용 후 측정 |
| namespace_isolation | blocked | 새 mount/net/UTS는 성공, PID/IPC 생성 EINVAL, 기능하는 private proc·안전한 task profile 미준비 |
| property_isolation | passed | 시험 뷰의 Host 영역 제거·명시한 경로 접근 차단; Guest property 초기화 성공은 아님 |
| media_isolation | passed | 다른 디렉터리 inode 및 Guest media 내부 추가 mount 부재 |
| host_unchanged | passed | 주요 프로세스 정체성/생존, Host Binder mode/owner/label, 관련 Host 객체 및 init mountinfo 전후 일치 |
| cleanup | passed | 시험 프로세스 회수, FD·임시 뷰·Binder·rootfs·system/data mount·loop 55개 해제와 scratch 삭제 |

통과의 범위는 시험 워커다. 모든 시험에서 실제 도메인은 **u:r:ksu:s0**였다. UID 1000과 capability 0이 적용됐어도 이를 **u:r:servicemanager:s0**에서의 성공으로 확대하지 않는다. 해당 서비스 도메인은 AV 조회에서 enforcing이며 Binder 접근을 여전히 거부한다.

## 기존 타입으로 해결한 부분

Guest가 생성한 `/linkerconfig/ld.config.txt`를 FD로 열고, 전용 Guest tmpfs의 일반 파일인지, 단일 링크인지, 부모와 같은 파일시스템인지, Host 원본과 다른 dev/inode인지 확인했다. 그 FD에만 `security.selinux`를 설정했다. Host 파일이나 공유 source의 라벨을 바꾸지 않는다.

실제 `tmpfs` → `linkerconfig_file` 변경이 성공했다. 변경 후 servicemanager의 file open/read/getattr/map AV가 모두 허용됐다. UID 1000 시험 워커도 파일을 실제로 열어 1바이트 읽기와 read-only mmap/munmap에 성공했다. 내용은 로그에 남기지 않았다. 전체 Guest loader 의존성이나 실제 서비스 도메인에서의 loader 실행을 검증한 것은 아니다. Guest linkerconfig 디렉터리 라벨은 tmpfs로 유지하며 search/getattr 허용을 별도로 조회했다.

## 기존 타입 재사용만으로 해결되지 않은 부분

기존 Session의 BINDER_CTL_ADD 장치와 그 FD mount ID, major/minor, Host rdev 불일치를 확인한 뒤에만 변경을 시도했다. 관찰한 Host는 507:1, Guest는 507:8이다. 번호를 고정값으로 사용하지 않는다.

- private Binder FD의 `binder_device` 라벨 설정: **EOPNOTSUPP(95)**.
- 기존 private mount를 정상 해제한 뒤 새 독립 binderfs에 `context=u:object_r:binder_device:s0` 적용: **EACCES(13)**.
- 실패한 임시 시도는 정리하고 기본 private binderfs를 새로 구성했다. 실제 라벨은 계속 `binderfs`다. servicemanager의 chr_file open/read/write/getattr/ioctl/map AV가 모두 거부된다.

따라서 현재 시험한 방법에서는 기존 `binder_device` 타입을 private binderfs에 적용해 차단을 해결하지 못했다. context mount EACCES 하나만으로 누락된 SELinux 규칙을 특정하지는 않는다. mount labeling의 커널/파일시스템 제약과 감사 근거가 더 필요하다. 임의 mknod로 Binder 객체를 복제하거나 Host Binder를 대체 장치로 사용하지 않았다.

후속 [Enforcing 접근 조사](private-binder-enforcing-research.md)에서 현재 코드가 `ssal-probe`를 원본 `/dev/binderfs/binder` 위에 bind한다는 점을 확인했다. 따라서 위 결과는 alias 이전의 원본 `binder` genfs 라벨을 검증한 것이 아니다. 정책 무변경 원본 노드 검사와 `context`/`fscontext` 분리 후보가 남아 있으며, 새 기기 시험으로 확인해야 한다.

현재 `binderfs` 라벨을 유지한다면 실제 servicemanager 접근에는 정책 허용 확장이 필요하다. 또는 별도 타입을 적용할 수 있는 장치 라벨링 방법과 정책을 함께 마련해야 한다. 이번 작업은 어느 정책도 추가하지 않았다. 정책 원본 읽기는 EINVAL이며, 실효 AV sequence와 Enforcing을 비교했다. 현재 KernelSU 실효 정책 결과를 변경 전 순정 삼성 정책의 결과로 간주하지 않는다.

| 방식 | 장점 | 보안상 제한·선행 조건 |
|---|---|---|
| 기존 linkerconfig_file/binder_device 재사용 | 기존 servicemanager 허용 규칙을 활용할 가능성 | 기존 Host 타입과 MAC 구분이 없음. private Binder 객체 자체의 레지스트리 분리는 가능하지만 같은 domain/type의 객체 접근을 구분하지 못함. binderfs의 실제 라벨 적용은 이번 기기에서 차단 |
| servicemanager → binderfs 접근 허용 확장 | 관찰한 private 노드 라벨을 유지할 수 있음 | Host servicemanager에도 같은 허용이 적용될 수 있어 범위 검토 필요. ioctl/xperm와 디렉터리 권한도 별도 검토 |
| SSAL 전용 domain/type 설계 | Guest 실행 주체·자원을 별도 MAC 경계로 제한 가능 | 정책 확장과 전환·entrypoint 규칙, 실제 자원 라벨 적용 지원이 모두 필요. 새 타입 이름만 추가해서는 binderfs 라벨링 제한이 해결되지 않음 |

## 실제 충족한 실행 명세

ServiceExecutionSpec을 v2로 확장하고 `ssald --runtime-credentials-worker`라는 고정된 진단 분기를 추가했다. 임의 Guest 실행 파일을 받지 않으며, 호스트에서 로드된 시험 바이너리가 새 mount namespace와 Guest root에 들어가 측정한다. Guest dynamic linker 실행 시험과 구분한다.

실제로 적용하고 측정한 조건은 다음과 같다.

- real/effective/saved/fs UID/GID 1000/1000, 보조 그룹은 [3009].
- inheritable/permitted/effective/ambient/bounding capability 모두 0, NoNewPrivs=1. 실제 서비스 전환과의 호환성은 미검증이다.
- 상속 환경 초기화 후 PATH=/system/bin, ANDROID_ROOT=/system, ANDROID_DATA=/data만 설정.
- FD 0은 읽기 전용 /dev/null, FD 1·2는 쓰기 전용 수집 pipe. 모두 CLOEXEC. proc 진단용 FD는 측정 후 닫았고, limit보다 큰 FD도 포함한 기존 FD 목록에서 추가 FD 부재를 확인했다. private Binder FD도 별도로 CLOEXEC다.
- nofile 1024/1024, core 0/0 적용 후 getrlimit로 확인. 나머지는 상위 워커 snapshot을 유지하는 명세다.
- 새 mount namespace, recursive private propagation, chroot와 chdir(/), 실제 root dev/inode 일치. 새 net/UTS namespace 생성 성공.

private Binder의 DAC는 **1000:1000 0600**으로 한정했다. 세계 읽기·쓰기를 허용하지 않았다. 최소 dev 뷰에서 해당 자격으로 private 장치를 실제 open하고 protocol 8을 확인했다. ksu 도메인의 결과이며, 위의 enforcing servicemanager AV 거부를 무효화하지 않는다.

## privileged 관찰과 서비스 자격 접근의 차이

첫 시험은 기존 composed root 뷰를 UID 1000/capability 0으로 조사했다. Host init의 `/proc/1/root/dev/binder`는 **EACCES**였다. 이전 privileged 관찰에서 같은 경로가 Host Binder로 보인 것과 구분된다. `/proc/self/root/dev/binder`는 이 시험 프로세스의 Guest root로 연결되므로 보인다는 사실만으로 Host 노출이라고 판정하지 않는다.

하지만 기존 뷰에서 UID 1000/ksu는 Host property 영역의 `properties_serial`을 O_PATH로 열 수 있었고 **Host kmsg를 write-open할 수 있었다**. property 값을 읽거나 kmsg에 쓰지 않았다. property service 두 소켓은 ENOENT였다. 기존 composed 뷰를 그대로 서비스에 넘기면 안 된다.

두 번째 시험은 새 tmpfs `/dev`에 검증한 private Binder FD의 bind와 /dev/null만 제공했다. property/socket 디렉터리는 새 빈 디렉터리이고 kmsg는 mode 000의 임시 일반 파일이다. `/proc`에는 비어 있는 read-only tmpfs를 덮었다. 다음을 실제 UID 1000으로 확인했다.

- 두 property service 소켓 및 Host property 파일: ENOENT.
- `/proc/1/root/dev/binder`, `/proc/self/root/dev/binder`: ENOENT.
- hwbinder/vndbinder/binderfs 별칭: ENOENT.
- kmsg write-open: EACCES. 시험 로그는 stdout/stderr pipe로 수집했다.
- private 기본 Binder 경로: 실제 open 및 BINDER_VERSION 성공.

세 번째 음성 대조군에서는 기본 Binder 경로를 mode 000의 Guest 임시 파일로 가렸다. 시험 워커의 장치 정체성 검사가 이를 거부했고 Host open 시도는 없었다. 이 프로그램은 fallback을 구현하지 않는다. **실제 libbinder의 fallback 코드를 실행한 결과는 아니며**, 시험 뷰의 Host 경로 제거·FD 제한과 함께 기록한 제한된 근거다.

현재 최소 뷰에서도 Host `/sys/fs/cgroup/cgroup.procs`와 `/sys/fs/bpf` 메타데이터에 대한 O_PATH 접근은 가능했다. 이 결과는 내용 읽기나 쓰기 권한의 증명이 아니다. cgroup/BPF 쓰기·task profile 적용은 하지 않았다. 이 공유 sysfs 영역의 실제 서비스용 접근 정책과 Guest 목적지가 남은 설계 과제다.

## probe-servicemanager 전 필수 조건

1. enforcing 서비스 도메인에서 실제 private Binder 라벨에 접근할 수 있도록 승인된 정책/라벨링 방안을 결정하고 검증해야 한다. 필요한 ioctl/xperm 및 context-manager 권한도 검증해야 한다.
2. PID/IPC unshare는 실제 **EINVAL(22)**이었다. 빈 proc는 접근 차단용 대조 환경이지 기능하는 Android proc가 아니다. 커널 제약 아래에서 필요한 proc 기능과 안전한 PID 접근 제한을 함께 만족하는 설계가 필요하다.
3. Guest ProcessCapacityHigh의 `JoinCgroup(cpuset, foreground)`를 Host 공용 목적지에 적용해서는 안 된다. 최소 dev에는 기존 /dev/cpuset도 없다. Guest 소유 목적지 및 profile 적용/검증을 마련해야 한다.
4. Host property 경로 차단을 유지하면서 Guest의 property 영역·서비스/ready 쓰기 요구사항을 해결해야 한다. stdout/stderr 수집과 별개로 실제 servicemanager의 kmsg logging 요구사항을 안전한 backend로 조정해야 한다.
5. 실제 서비스 전환·정확한 Guest loader/라이브러리·service_contexts 접근, FD/환경/rlimit 적용 순서를 검증하고, 이후 별도 Test B에서만 레지스트리와 양방향 격리를 평가해야 한다. 이번 시험에서 통과한 자격을 서비스 도메인 실행 성공으로 대체하면 안 된다.

임시 뷰는 매번 해제했으며, 검사 종료 후 준비 상태가 기기에 남아 있는 것은 아니다. 실제 서비스 실행기는 검증한 준비 절차를 재현하고 identity를 다시 확인해야 한다. 전체 실행 가능 판정은 계속 **blocked**다.

검증: cargo fmt, clippy `-D warnings`, 단위 테스트 **23 passed / 3 ignored**, Android release 빌드, 모듈 ZIP 패키징, git diff 공백 검사. 추가 테스트는 미확인 errno를 접근 차단으로 통과시키지 않는 판정과 UID/FD 누출의 통과 거부다. 기존 특수 권한 테스트 3개는 이 단위 테스트 실행에서 제외했고 기기 시험 결과를 별도로 기록했다.

임시 바이너리와 모든 세션 scratch를 삭제했다. Host 주요 프로세스와 관찰한 파일 정체성·모드·소유권·라벨·init mountinfo가 일치했다. 정책 파일 해시와 관찰한 Host 라벨의 외부 전후 snapshot도 같다. 이 결과를 전체 Host 콘텐츠나 모든 중간 상태의 불변성 증명으로 확대하지 않는다.
