# 초기 마운트 프로필

`initial-shared-dev`는 기존 profile metadata와의 호환성을 위해 유지한 식별자다. 현재 구성은 `ssal prepare PROFILE_NAME`에서 마운트를 조립하지만, 검증되지 않은 Host proc/root, exec-FD, signal/ptrace 경계 때문에 Guest GSI 바이너리 실행 직전에 fail-closed로 중단하고 마운트를 해제한다. 따라서 현재 `prepare`는 성공하지 않으며 chroot·pivot_root 검사도 실행하지 않는다. 게스트 Android 서비스 시작과 hot-switch는 수행하지 않는다.

정의는 [`initial.json`](../module/profiles/mounts/initial.json), 구현은 [`guest_mounts.rs`](../src/guest_mounts.rs)에 있다. JSON은 빌드 시 바이너리에 포함하고 모듈에도 참고용으로 배포한다. 설치된 JSON만 바꾸면 실행 설정이 변경되는 구조는 아니며 재빌드가 필요하다. 새 게스트 `profile.json`에는 `mount_profile` 이름을 기록한다. userdata는 버전 3 프로필의 `userdata.img`만 지원하며 이전 프로필은 삭제 후 재생성한다.

## 마운트 표

대상은 root 전환 후 사용할 경로다. 준비 단계에서는 세션 `rootfs/` 아래에 구성한다.

| 대상 | 원본·방식 | 정책 |
|---|---|---|
| `/` | 새 tmpfs + system 이미지 항목별 RO bind | system-as-root와 system-only 이미지를 구분. system loop/ext4는 RO,noload,nosuid,nodev. 조립용 루트 tmpfs는 RW |
| `/data` | 프로필 `userdata.img` → 세션 `data/` RW loop/ext4 → 일반 bind | RW,nosuid,nodev. Host `/data`와 다른 filesystem. backing 이미지와 loop 노드는 Guest에 노출하지 않음 |
| `/data/{adb,apex,media,...}` | 게스트 userdata 내부 | 호스트 데이터 브리지 없음. 필요한 디렉터리는 게스트 서비스가 추가 생성 |
| `/dev` | Guest 전용 4 MiB tmpfs, nosuid,noexec | `/dev/null`, `zero`, `random`, `urandom`만 개별 bind. 각 원본의 character-device major/minor, root:root 0666 권한과 Guest mount ID를 검사 |
| `/dev/socket`, `/dev/block`, `/dev/binderfs` | Guest `/dev` tmpfs 내부 빈 디렉터리 | Host socket, block, `binder-control`, Binder, property area, kmsg, input, DRM, HAL 노드는 전달하지 않음. private Binder probe만 독립 binderfs를 임시 구성 |
| `/proc` | 새 proc | nosuid,nodev,noexec. PID namespace는 분리하지 않음 |
| `/sys` | 새 sysfs | RO,nosuid,nodev,noexec |
| `/sys/fs/selinux` | 존재하는 호스트 경로 일반 bind | 게스트 뷰 RO |
| `/sys/fs/cgroup`, `/sys/fs/bpf` | Host 경로 bind 없음 | cgroup/BPF의 Host RW 경로를 Guest에 직접 연결하지 않음. fresh sysfs와 공유 커널의 나머지 노출은 별도 기기 검사 필요 |
| `/vendor`, `/odm`, `/vendor_dlkm` | 존재하는 호스트 디렉터리 일반 bind | 게스트 뷰만 RO로 재마운트 |
| `/mnt`, `/storage`, `/data_mirror` | 각각 새 tmpfs | 호스트 저장소 mount를 상속하지 않음 |
| `/tmp` | 전용 RW tmpfs, root:root, 1777 | 이미지 내부 RO 디렉터리를 재사용하지 않음 |
| `/cache` | 전용 RW tmpfs, system:cache, 0770 | 초기 검증용 휘발성 저장소. ROM이 영속 cache를 요구하면 별도 정책 필요 |
| `/metadata`, `/config` | 각각 빈 RO tmpfs | 이미지 디렉터리를 제외하고 호스트 metadata·configfs도 공유하지 않음. 게스트 metadata 영속화·암호화와 configfs 장치 제어는 미구현 |
| 네 emulated 경로 | 게스트 `/data/media` 일반 bind | `/storage/emulated`, `/mnt/user/0/emulated`, `/mnt/installer/0/emulated`, `/mnt/androidwritable/0/emulated` |
| `/data/data`, `/data_mirror/*` | 게스트 `user/0`, `user_de/0`, `misc/profiles/{cur,ref}` bind | 사용자 0 기본 mirror. FBE·CE 잠금 해제 구현은 아님 |
| `/apex` | 새 tmpfs + payload RO loop/ext4 | 게스트 system/system_ext/product와 선택한 vendor의 사전 설치 패키지. 호스트 `/apex`·`/data/apex` 공유 없음 |
| `/linkerconfig` | 새 tmpfs | Guest `linkerconfig`를 실행하기 직전 경계 gate가 항상 거부한다. 현재 `prepare`는 이 단계에서 실패 후 앞선 mount를 정리한다. |
| `/run/ssal/{ssal,ssald}` | 설치된 CLI/daemon 파일 RO bind | 호스트 모듈 디렉터리 전체나 관리 소켓을 노출하지 않음 |

`/mnt/runtime/{default,read,write,full}`, `/mnt/pass_through`, `/mnt/appfuse`, `/mnt/media_rw`, `/mnt/expand`, `/mnt/secure`, `/mnt/asec`, `/mnt/obb`의 기본 디렉터리도 준비한다. 호스트 볼륨을 연결하지 않으며 `/mnt/vendor/*` 예외도 아직 없다.

미디어 경로에는 `/data/media/0`이 아니라 `/data/media`를 bind한다. `/storage/emulated/0`과 `/storage/self/primary`가 게스트 사용자 0의 같은 디렉터리를 가리키고 `/0/0` 중첩을 만들지 않는다. 게스트 `media`와 `media/0`은 UID/GID 1023:1023, 모드 0770으로 설정한다. 재귀 chmod는 하지 않는다. 앱별 접근 제어는 아직 구현되지 않았다.

## APEX와 선택적 패치

APEX 추출은 Android `/system/bin/unzip`, KernelSU BusyBox, PATH의 `unzip` 순서로 사용 가능한 실행 파일을 선택한다. `.capex`는 `original_apex`를 먼저 추출한다. 임시 추출 공간이 호스트 `/data`에 필요하다.

이름·버전은 `apex_manifest.pb`에서 읽으며 ZIP과 payload의 manifest가 일치하는지 확인한다. `<name>@<version>`과 `<name>` 경로, 준비한 패키지의 `apex-info-list.xml`을 만든다. 원본 APK 파싱용 패키지는 `/apex/.packages/`에 RO bind한다. Android에서는 payload backing 파일에 기존 `ssal_image_file` 라벨을 적용한다.

정식 apexd 활성화·서명 검증·업데이트는 구현하지 않는다. ext4 payload만 지원한다. EROFS/flattened APEX, 중복 모듈 선택과 공유 라이브러리 APEX의 추가 구성은 지원하지 않으며 호스트 APEX로 자동 대체하지 않는다.

선택적 패치는 호스트 `/data/local/ssal/guests/PROFILE_NAME/patches/`에 둔다. 존재하는 항목만 적용하며 대상 누락·형식 불일치는 실패로 보고한다.

| 원본 | 대상 |
|---|---|
| `services_patched.jar`, `framework_patched.jar`, `framework-res_patched.apk` | 대응하는 게스트 system framework 파일 |
| `libaudio_aidl_conversion_common_cpp_patched.so`, `libaudioclient_aidl_conversion_patched.so` | 대응하는 게스트 system/lib64 파일 |
| `PermissionController_patched.apk` | permission APEX에서 찾은 APK. 활성·버전 경로에 적용 |
| `extservices_permissions/` | extservices APEX의 권한 디렉터리. 활성·버전 경로에 적용 |
| `su` | 명시적으로 제공한 바이너리만 `/system/xbin/su`에 RO bind. xbin에 새 tmpfs 사용 |

패치를 자동 생성하거나 호스트 미디어 DB·ADB 인증 정보를 복사하지 않는다. `su`와 CLI는 코드 경로를 제공하는 단계이며 KernelSU 권한·관리 연결 동작은 미검증이다.

## 실행과 검증

```sh
ssal doctor PROFILE_NAME
ssal prepare PROFILE_NAME
ssal logs
```

worker는 새 namespace를 만든 직후 `/` 전체를 재귀 private으로 바꾼다. userdata 이미지의 배타 잠금과 기존 loop 연결 부재를 확인하고 `e2fsck -p`가 0 또는 1로 종료한 경우에만 RW 마운트한다. userdata 쓰기/읽기와 system loop mount를 검사한 뒤 위 구조를 구성한다. Android의 절대 symlink는 준비 중인 게스트 root 안에서 해석한다. userdata·미디어의 device/inode, primary 저장소 경로, 실제 mountinfo를 확인한다.

커널이 할당한 loop 번호에 대응하는 호스트 `/dev/block/loopN`·`/dev/loopN` 노드가 없으면 세션 `loop-devices/`의 private tmpfs에 노드를 만든다. 이 tmpfs는 장치 접근을 위해 nodev를 지정하지 않고 nosuid,noexec,mode=0700으로 구성하며 게스트 root에는 노출하지 않는다. major/minor는 `/sys/block/loopN/dev`에서 읽고 실제 노드의 rdev를 확인한다. Android에서는 기존 loop 블록 노드의 SELinux 라벨을 복사한다. 호스트 `/dev`에 mknod하거나 기존 노드를 삭제·변경하지 않는다. 모든 이미지 mount 해제 후 이 tmpfs도 일반 unmount한다.

성공·실패 모두 역순으로 일반 unmount하며 Guest `/dev`와 선택 device bind를 포함해 mount를 추적한다. 정리 실패는 오류로 보고하고 lazy unmount로 성공 처리하지 않는다. rootfs의 data bind들을 해제한 뒤 외부 ext4 mount와 loop를 해제한다. worker 종료 후 전용 scratch만 삭제한다. userdata에 생성한 기본 미디어·앱·mirror 디렉터리는 유지한다.

## 게스트 실행 검사와 서비스 기동 조건

현재 `linkerconfig`를 포함한 Guest GSI 실행은 모두 차단되어 있다. `prepare`는 mount를 구성한 뒤 linkerconfig 실행 gate에서 실패하고 앞선 mount를 역순으로 정리한다. 따라서 아래 `guest_probe.rs` 검사는 현재 실행되지 않으며, 다시 실행을 허용하기 전에 Host proc/root, exec-FD, signal/ptrace 경계의 실제 음성 시험이 필요하다.

1. 조립한 rootfs로 chroot한 `/system/bin/sh`와 외부 동적 바이너리 toybox를 실행한다.
2. 별도 자식에서 다시 mount namespace를 분리하고 `/`를 private으로 바꾼 뒤 `pivot_root`한다. 이전 root는 이 자식에서만 `MNT_DETACH`로 분리한다. 이는 상속한 호스트 하위 mount를 포함하는 이전 root의 의도적인 분리이며, worker의 게스트 mount를 lazy unmount하는 정리 우회와 구분한다.
3. 실행이 재허용되면 두 검사 모두 `/`의 device/inode가 준비한 rootfs인지 확인한다. Guest exec helper는 snapshot 시점의 상속 FD 번호와 inode identity를 기록하고 allowlist 밖 descriptor를 `pre_exec`에서 닫는다. command pipe 번호가 재사용된 경우 identity가 달라서 보존한다. 다중 스레드 실행 중 snapshot 이후 열리는 FD에 대한 admission은 미구현이며, Guest service의 exec-stop FD 목록도 관측되지 않았다. 이전 root 경로가 사라졌는지, system/vendor/APEX/data와 linkerconfig 파일을 확인한다.
4. `/data`, `/tmp`, `/cache`에 충돌하지 않는 임시 표식을 쓰고 읽는다. worker가 프로필 userdata의 표식 내용을 읽어 실제 기록 위치를 확인하고 모든 표식을 지운다.
5. 각 실행은 최대 20초 대기하며 시간 초과 시 전용 프로세스 그룹을 종료한다. 검사에서는 init이나 Android 서비스를 시작하지 않는다.

실행이 재허용될 때의 진단 출력은 게스트 디렉터리의 UID/GID/mode·SELinux 라벨과 실제 shell 프로세스 컨텍스트를 포함한다. shell 컨텍스트에는 `validation_scope=probe_only`를 붙이며 `ksu` 등의 관리 도메인 실행을 Android 서비스 도메인 통과로 판정하지 않는다. 현재 이 출력은 생성되지 않는다.

fscrypt는 호스트 `/data`와 게스트 `/data`, `media`, `user/0`, `user_de/0`의 정책 버전·모드·플래그를 조회한다. 메모리 안에서 키 식별자를 포함한 정책을 비교하되 원문·해시·키 식별자는 출력하지 않는다. `policy_same`, `key_identifier_same`은 true/false/미확인(null)으로 기록한다. 동일 정책이라도 해당 키의 CE/DE 소속·잠금 해제 수명주기나 게스트 FBE 구현을 의미하지 않는다. 정책·라벨은 변경하지 않는다.

실행 gate가 해제된 뒤 linkerconfig 검사는 생성된 `ld.config.txt`들을 순회해 파일·section·namespace·디렉터리 매핑을 요약한다. 메인 설정에 section·default namespace·디렉터리 매핑이 없으면 준비를 실패시킨다. default namespace가 다른 namespace에 링크만 하는 구성도 허용한다. 이는 구조 검사이며 모든 서비스의 라이브러리 해석을 보장하지 않는다.

VINTF 파일 목록은 호환성 결과와 따로 출력한다. `/system/bin/checkvintf`가 있으면 `--check-compat --rootdir /`로 직접 실행한다. 결과는 `passed`(도구 종료 0), `failed`(AOSP EX_DATAERR=65: 비호환), `unavailable`(도구 없음), `error`(EX_USAGE=64·EX_SOFTWARE=70·실행/권한 오류·신호·시간 초과 등)로 구분한다. 파일 나열 성공을 통과로 판정하지 않는다. property·kernel 입력값이 게스트/기기 구성에 맞게 확정되지 않았으므로 도구 통과도 완전한 호환성 인증은 아니다.

실행이 재허용되면 `guest probe summary:` 행은 식별자를 제외한 구조화 JSON으로 root probe 컨텍스트·설정 요약·CE/DE 정책 비교·VINTF 상태를 포함한다. `android_service_domains_verified`와 `guest_fbe_verified`는 현재 false다.

Guest `/dev` 구성은 Host 장치 전체를 bind하지 않고 allowlist의 네 pseudo-device만 identity·권한·mount ID를 확인한다. Host property area와 두 property socket은 Guest 경로에서 빠지지만, Android 16 Bionic용 Guest property area/service와 property context·SELinux 권한은 구현되지 않았다. Guest property access는 아직 지원되지 않는다. 서비스 기동 전에는 private framework Binder·servicemanager와 Host HAL 연결 방식, Guest property service, Guest installd/artd/vold, FUSE 접근 제어, Host proc/signal/ptrace 경계, 파일·프로세스 SELinux 정책과 FBE 호환성을 확정해야 한다. 일반 Android init을 실행하는 기능은 이 단계에 포함하지 않는다.

선택한 목표 구성·서비스별 조건·시작 및 종료·복구 규칙은 [서비스 실행 계약](service-execution-contract.md)에 정의한다. `launch_enabled=false`다. 현재 Guest 실행 gate 때문에 `prepare`는 서비스 계약 확인 단계에 도달하지 않으며, gate 해제 뒤에도 계약상 Android 서비스는 별도 허가 전까지 시작하지 않는다.

정리는 worker의 rootfs 하위 mountinfo가 비었는지와 각 세션 loop 장치의 `LOOP_GET_STATUS64`를 확인한다. 다른 backing으로 재사용된 장치는 해제하지 않으며 같은 세션 backing이 남으면 실패한다. daemon도 worker 종료 후 자기 namespace의 세션 경로 아래 잔여 mount를 확인한 뒤 scratch를 삭제한다. 이 검사는 세션 경로와 추적한 loop에 한정되며 호스트 전체 상태의 무변경이나 모든 namespace 참조 소멸을 증명하지 않는다.

일반 검사는 `scripts/dev.ps1 check`, Android 빌드는 `scripts/dev.ps1 build`로 수행한다. 실제 mount/umount 회귀 테스트는 Linux CAP_SYS_ADMIN이 있는 폐기 가능한 테스트 컨테이너에서 실행한다. Android 대상 교차 빌드만으로 Guest 실행 경계가 검증되지는 않는다.

```sh
cargo test --locked --bin ssald real_mounts_preserve_host_and_cleanup_recursively -- --ignored --test-threads=1
```

이 테스트는 private namespace의 일반 재귀 bind 해제 경로, 네 미디어 뷰, 쓰기 경로, RO bind와 원본 쓰기 보존, mount 실패 후 정리를 확인한다. 현재 기본 profile은 Host `/dev` 재귀 bind를 사용하지 않는다. 기본 WSLc 컨테이너에는 해당 capability가 없고 privileged 옵션도 없어 테스트를 실행할 수 없다. 단위 테스트·교차 빌드 통과를 실제 mount나 기기 부팅 검증으로 간주하지 않는다.

별도의 무시된 `real_chroot_probe_closes_host_directory_fds` 회귀 테스트는 CAP_SYS_CHROOT만 필요하다. 이 검사는 테스트 전용 chroot의 상속 FD 정리만 검증하며 production Guest exec gate나 조립된 Android rootfs를 검증하지 않는다. 현재 환경에서는 실행하지 않았다.

`real_pivot_probe_detaches_old_root`는 CAP_SYS_ADMIN이 있는 폐기 가능한 Linux 컨테이너용 회귀 테스트다. 작은 tmpfs 루트에서 동적 shell을 실행하고 이전 root 분리와 worker root 보존을 확인한다. 기본 WSLc 환경에서는 실행하지 못했다.

참고: [AOSP init.rc](https://android.googlesource.com/platform/system/core/+/refs/heads/android14-gsi/rootdir/init.rc), [APEX manifest 형식](https://android.googlesource.com/platform/system/apex/+/refs/heads/main/proto/apex_manifest.proto).

## ext4 userdata 검증

`ssal create`는 8 GiB 이미지를 미리 할당하고 journal을 포함한 고정 ext4 feature 집합으로 포맷한다. backing 파일은 root:root 0600, SELinux `ssal_userdata_image_file`이며 kernel의 backing 쓰기는 이 Guest 전용 타입에 한정한다. 프로필 디렉터리의 `profile.json`과 `patches/`는 이미지 바깥에 유지한다. 신규 데이터 검사는 빈 `lost+found`만 예외로 허용한다. 암호화된 Host 저장소 안의 이미지라는 사실은 Guest FBE·CE/DE 키 수명주기 구현을 의미하지 않는다.

기본 Rust 테스트는 실제 32 MiB ext4 포맷·오프라인 검사, 덮어쓰기 거부, 파일 잠금, 실패 후 이미지 보존·생성 정리, 구버전 거부 및 사용 중 삭제 거부를 확인한다. 재마운트 영속성 검사는 폐기 가능한 CAP_SYS_ADMIN 환경에서 실행한다.

```sh
cargo test --locked --bin ssald real_ext4_remount_preserves_data_and_releases_loops -- --ignored --test-threads=1
```

실기기에서는 새 프로필로 mount/unmount 및 기존 launcher 회귀를 먼저 확인하고, 그 다음 하드 재부팅 후 One UI 복귀와 이미지 재마운트를 검증한다. 기존 실측 문서의 directory-backed 결과는 새 이미지 경로의 통과 증거가 아니다.
