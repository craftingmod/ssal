# Enforcing Binder IPC 및 Service Registry 격리 — 2026-10-31

SM-S937N의 기존 실효 정책과 전역 Enforcing을 유지한 실기기 결과다. [원시 JSON](enforcing-binder-device-20261031.json)에 syscall, errno, Binder 반환 명령, 실제 도메인, AV, 실행 자격, 라이브러리 해시와 정리를 기록했다. 설치된 모듈/데몬을 교체하지 않고 임시 워커만 사용했다.

**기존 정책으로 enforcing 도메인 간 Private Binder IPC와 Android 16 Guest libbinder IPC가 성공했다. `service_contexts`의 9개 context는 커널에서 거부되어 전체 선행 조건 충족은 blocked다.** 정식 servicemanager, zygote, system_server 및 다른 Framework 서비스는 실행하지 않았다. `launch_enabled=false`다.

| 완료 기준 | 판정 | 검증한 범위 |
|---|---|---|
| `private_binder_identity` | passed | 새 binderfs 원본 binder, binder_device, control과 mount ID 일치, inode/rdev/DAC, 기본 경로와 열린 FD 재검증 |
| `servicemanager_domain_transition` | passed | 임시 servicemanager_exec helper의 명시적 exec 후 실제 servicemanager context, AV flags=0 |
| `enforcing_binder_open` | passed | 해당 프로세스에서 Private Binder 직접 open, VERSION, mmap |
| `enforcing_binder_transaction` | passed | enforcing shell → servicemanager의 빈 transaction, 시험 등록·조회·부재 응답·echo |
| `private_context_manager` | passed | 세션의 Private Binder에서 SET_CONTEXT_MGR_EXT 성공; Host에는 호출하지 않음 |
| `guest_libbinder_ipc` | passed | Guest linker/Bionic/libbinder, 실제 FD, 교차 도메인 echo와 Binder 객체 왕복 전달 |
| `service_contexts_compatibility` | blocked | 고유 context 519개 중 9개가 커널 context 검증과 AV 조회에서 EINVAL |
| `host_binder_nonexposure` | passed | 시험 자격의 열거한 alias 접근 차단, 상속 FD 부재, 기본 장치 음성 대조군; 양방향 Host 레지스트리 조회는 not_run |
| `host_unchanged` | passed | 관측한 주요 프로세스/벤더 데몬, Host 자원 metadata/init mountinfo, Enforcing/AV sequence, 정책 파일 해시·라벨 비교 |
| `cleanup` | passed | 소유 프로세스 회수, 정상 unmount, 매 회 loop 55개 반환, rootfs 잔여 부재, 모든 시험 scratch 삭제 |

## 장치와 실행 환경

`Session::provision`이 새 binderfs의 커널 기본 `binder`를 선택했다. 기본 노드가 없을 때만 `BINDER_CTL_ADD(name=binder)`를 사용하며 `ssal-probe`를 원본 위에 bind하지 않는다. 최종 세션은 Private **507:5**, Host **507:1**이었다. 원본 `binder_device` 라벨을 유지했고 Binder fsetxattr/context mount는 실행하지 않았다. 새 control FD의 mount ID와 원본 FD, alias의 dev/inode/rdev를 각각 검증했다. 숫자는 세션 관측값이며 고정 장치 번호가 아니다.

`ServiceExecutionSpec` v2의 UID/GID 1000/1000, 보조 그룹 [3009], effective/permitted/inheritable/bounding/ambient capabilities 0, nofile 1024/1024, core 0/0, 초기화한 환경과 stdio allowlist를 적용했다. exec 이후 실제 도메인·자격·root·FD·rlimit를 다시 검사했다. 관측용 FD는 현재 프로세스의 attr/current, status와 SELinux enforce를 읽는 세 개뿐이며 Binder를 열기 전에 닫았다. Host root/Binder/property/kmsg/socket FD는 전달하지 않았다. raw 서버·클라이언트는 각각 별도 exec이며 서로 Binder FD를 넘기지 않았다.

Guest userdata 루트가 root:root 0700이라 초기 경로 시험은 execve EACCES(13)로 중단됐다. 영구 DAC 변경 없이 Binder 실험에만 `/data`를 세션 전용 tmpfs로 가렸다. 실행 파일은 이 tmpfs에 새로 복사하고 servicemanager_exec 또는 클라이언트용 shell_exec를 적용했다. 생성된 Guest linkerconfig 파일에만 기존 linkerconfig_file 타입을 적용했다. Host 파일 라벨을 바꾸지 않았다.

최소 `/dev`에는 Private Binder와 null만 연결하고 kmsg는 mode 000 일반 파일로 막았다. Host property 영역·소켓, hw/vnd Binder와 binderfs 원본 경로는 노출하지 않았다. `/proc`는 빈 읽기 전용 tmpfs로 제한했다. `/proc/1/root/dev/binder`, `/proc/self/root/dev/binder`, `/proc/1/fd`, `/proc/self/fd`와 장치 alias는 실제 시험 자격에서 ENOENT였다. kmsg 쓰기 open은 EACCES였다. 기본 `/dev/binder`를 mode 000 임시 파일로 가린 대조군은 stat 단계 EACCES로 중단됐고 Host open/ioctl은 수행하지 않았다.

NoNewPrivs를 exec **전** 적용한 시험은 실제 target context에서 값 1을 확인했다. 별도의 exec **후** 적용 시험은 exec 직후 값 0을 기록하고 1로 설정·검증한 뒤에만 Binder를 열었다. 운영 경로로 선택한 교차 도메인 시험은 exec 전 적용을 사용했다. net/UTS namespace 생성은 성공했고 IPC namespace는 EINVAL(22)이었다. 빈 proc는 기능하는 Guest proc/PID namespace의 구현이 아니다. Guest property 초기화·서버와 cgroup/task profile도 여전히 미구현이다.

## 정상 IPC와 접근 거부

정상 시험의 서버는 실제 `u:r:servicemanager:s0`, 클라이언트는 실제 `u:r:shell:s0`다. 클라이언트의 UID도 1000이며 관리 도메인 ksu가 아니다. 두 도메인의 조회 AV permissive flags는 0이고 sequence는 1로 유지됐다. `shell → servicemanager`의 binder call/transfer와 응답 방향 transfer, context-manager 권한을 따로 기록했다.

raw helper는 빈 WRITE_READ dispatch와 **실제 빈 BC_TRANSACTION**을 구분한다. 실제 transaction은 서버 수신과 BR_REPLY payload까지 확인한다. `ssal.enforcing.private.echo`라는 고정 시험 이름을 메모리 레지스트리에 등록하고 조회했으며, 다른 이름의 not_found와 nonce echo도 확인했다. 이 레지스트리는 고정 시험 프로토콜이며 AOSP IServiceManager나 SELinux service_manager add/find 실행을 구현하지 않는다.

의도적인 거부 대조군에서는 서버와 클라이언트를 모두 servicemanager 도메인으로 실행했다. `servicemanager → servicemanager:binder call`은 AV allowed=false, mask=0xc, flags=0이다. WRITE_READ syscall 자체는 **rc=0, errno=null**이지만 write_consumed=68 뒤 **BR_FAILED_REPLY(0x7211)**를 받았다. GET_EXTENDED_ERROR는 rc=0으로 같은 명령과 **param=-1(EPERM)**을 반환했다. 이것을 syscall errno=EPERM이나 IPC 성공으로 바꾸어 쓰지 않는다. 대응 AVC는 제한한 dmesg/logcat 구간에서 확보하지 못했다. AV 거부와 extended error가 일치하지만 AVC로 원인을 확정했다는 주장은 하지 않는다. 이 대조군을 통과시키려고 servicemanager self-call allow를 추가하지 않았다.

Guest libbinder에서도 동일 도메인 대조군은 status_t=-2147483646(FAILED_TRANSACTION)이었다. 별도의 enforcing shell → servicemanager 시험은 **status_t=0**, nonce/서버 PID 확인 및 **실제 Binder 객체 왕복 전달 status_t=0**으로 성공했다. call, 객체 transfer와 context-manager 권한을 한 결과로 합치지 않았다.

libbinder helper/manifest와 Guest libbinder.so, libutils.so, libc++.so, linker의 해시를 기록했다. 런타임 `dladdr`는 `/system/lib64/libbinder.so`를 가리켰고 실제 열린 FD의 dev/inode/rdev가 Private Binder와 일치했다. Rust raw helper도 Guest linker/Bionic으로 실행하지만 libbinder를 사용하지 않는다. 이전 보고서의 Host 라이브러리 기반 단독 ioctl과 구별한다.

AOSP Android 16 ProcessState는 지정 driver의 access 실패 시 `/dev/binder`로 fallback할 수 있다. 두 경로를 호출 전에 같은 Private inode로 검사하고 init 후 실제 FD를 다시 검사했다. 기본 경로가 없거나 잘못되면 라이브러리를 초기화하지 않는다. becomeContextManager의 EXT→legacy 내부 fallback과 개별 errno는 libbinder의 bool 반환만으로 구분할 수 없으며, 이번 개별 ioctl/xperm 증거는 raw helper의 실제 EXT/VERSION/WRITE_READ/GET_EXTENDED_ERROR 결과다. 모든 ioctl xperm의 전체 allowlist를 증명한 것은 아니다.

## service_contexts 차단

Guest system/system_ext/product/vendor/odm 경로 중 실제 존재하는 파일을 읽고 고유 context **519개**를 검사했다. **510개는 커널에서 유효했고 다음 9개는 `write(/sys/fs/selinux/context)`와 add/find AV 조회에서 EINVAL(22)**이었다.

- `adbroot_service`
- `fingerprint_hidl_service`
- `lineage_globalactions_service`
- `lineage_hardware_service`
- `lineage_health_interface_service`
- `lineage_livedisplay_service`
- `lineage_profile_service`
- `lineage_trust_service`
- `qcrilam_service`

각 이름은 `u:object_r:이름:s0` 형태다. 검증 syscall의 실행 주체는 관리 도메인 ksu이며 AV의 source는 명시한 servicemanager다. EINVAL은 유효하지 않은 context에 대한 결과로, 일반 접근 거부의 EACCES나 ioctl xperm 거부가 아니다. 나머지 context의 add/find AV도 원시 JSON에 그대로 남겼다. context가 유효하다는 사실은 모든 서비스 도메인의 add/find 허용을 의미하지 않는다.

## 격리 및 복구 판정의 범위

Private 장치의 정체성에 더해 실제 context manager·transaction·응답을 확인했다. Host Binder는 metadata만 관찰했으며 context-manager 설정, 등록, 시험 transaction을 보내지 않았다. Host 레지스트리에 Guest 이름이 보이지 않는지, Guest에 실제 Host 고유 서비스가 보이지 않는지의 **양방향 실제 레지스트리 검증은 not_run**이다. 시험 레지스트리의 not_found나 차단된 alias를 그 증명으로 대신하지 않는다. `host_binder_nonexposure=passed`는 명시한 프로세스 자격과 최소 뷰의 경로/FD/fallback 범위다.

Host init/servicemanager/zygote/system_server/surfaceflinger 및 관측한 Vendor 프로세스의 PID/starttime/context/생존, Host Binder/property/kmsg/media/user/system/misc/linkerconfig metadata와 init mountinfo가 전후 일치했다. 전역 Enforcing, AV sequence=1, target flags=0과 설치된 sepolicy.rule SHA-256 및 관측한 Host 라벨도 같았다. 커널 policy 파일 읽기는 기존과 같이 EINVAL이라 전체 실효 정책 해시를 확보하지 못했다. 전체 Host 디스크와 모든 중간 상태의 불변성을 주장하지 않는다.

소유 서버 프로세스 그룹만 종료·wait했고 모든 직접 시험 프로세스를 회수했다. Private/임시 뷰를 lazy unmount 없이 해제한 뒤 rootfs 잔여 부재, 매 회 loop 55개 반환을 확인했다. 추가로 Host namespace mount·scratch loop backing·소유 실행 파일 프로세스의 잔여를 검사하고 7개 시험 디렉터리를 삭제했다. 정리/관측 결과에서 복구가 필요한 전역 변경은 발견하지 않았다.

## 권고와 재현

권고는 **최소 SELinux 정책 확장 검토**다. 기존 정책으로 Binder device/전이/실제 교차 도메인 IPC는 가능하므로 동일 도메인 거부 대조군을 위한 권한 추가는 필요하지 않다. 우선 위 9개 Guest context와 서비스별 필요한 add/find 주체를 검토해야 한다. 검토는 정책 적용 승인이 아니며 이번에는 allow/type/permissive 추가, 자동 패치, sepolicy.rule 변경을 하지 않았다. 정책은 공유 커널 전체에 영향을 주므로 범위와 복구·자동 재적용 여부를 별도 설계해야 한다. PID/proc/property/cgroup 조건도 해결되기 전에는 정식 서비스 제한 실행 준비 완료로 판단할 수 없다.

직접 워커의 재현 형식은 다음과 같다. ssald와 고정 helper, Guest libbinder helper 및 manifest를 같은 임시 디렉터리에 둔다. 서로 다른 비어 있는 SESSION 디렉터리를 쓰며 설치 데몬은 교체하지 않는다.

```sh
mkdir -p SESSION/system SESSION/data
TEMP/ssald --enforcing-binder-worker SYSTEM_IMG GUEST_USERDATA SESSION
# stdout의 Enforcing Binder summary 및 뒤따르는 두 resource summary를 확인한다.
# exit 1은 launch 차단 유지에 따른 결과다. 개별 판정은 JSON으로 확인한다.
sh cleanup-enforcing-binder.sh /data/local/tmp/ssal-enforcing-고유시험이름
```

정리 스크립트는 canonical path가 일치하는 전용 prefix만 허용하고 잔여 mount/loop/실행 파일 프로세스가 있으면 삭제를 거부한다. 워커의 프로세스 회수·정상 unmount 결과와 함께 확인해야 한다.

검증 결과: cargo fmt --check, clippy --all-targets -D warnings, **단위 테스트 24 passed / 3 privileged ignored**, shellcheck, aarch64 Android release 빌드, Android 16 Guest 라이브러리 대상 C++ helper 빌드, WebUI 빌드 및 모듈 ZIP 패키징 모두 passed다. 원시 JSON의 validation에 산출물 해시와 명령을 기록했다. ZIP은 설치하지 않았다.

**이번 결과는 Android 부팅 성공, 정식 servicemanager 실행 성공 또는 `launch_enabled=true` 전환을 뜻하지 않는다.**
