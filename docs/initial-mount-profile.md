# 초기 마운트 프로필

`initial-shared-dev`는 `ssal prepare PROFILE_NAME`에서 마운트를 구성하고, 임시 자식 프로세스의 chroot·pivot_root 실행 검사 후 해제하는 프로필이다. 게스트 Android 서비스 시작과 hot-switch는 수행하지 않는다. 준비 성공과 Android 부팅 성공은 구분한다.

정의는 [`initial.json`](../module/profiles/mounts/initial.json), 구현은 [`guest_mounts.rs`](../src/guest_mounts.rs)에 있다. JSON은 빌드 시 바이너리에 포함하고 모듈에도 참고용으로 배포한다. 설치된 JSON만 바꾸면 실행 설정이 변경되는 구조는 아니며 재빌드가 필요하다. 새 게스트 `profile.json`에는 `mount_profile` 이름을 기록한다. 이 필드가 없는 기존 디렉터리 프로필에도 같은 기본값을 사용한다.

## 마운트 표

대상은 root 전환 후 사용할 경로다. 준비 단계에서는 세션 `rootfs/` 아래에 구성한다.

| 대상 | 원본·방식 | 정책 |
|---|---|---|
| `/` | 새 tmpfs + system 이미지 항목별 RO bind | system-as-root와 system-only 이미지를 구분. system loop/ext4는 RO,noload,nosuid,nodev. 조립용 루트 tmpfs는 RW |
| `/data` | 프로필 `userdata/` 일반 bind | RW,nosuid,nodev. 호스트 `/data` 전체 연결이나 역방향 bind 없음 |
| `/data/{adb,apex,media,...}` | 게스트 userdata 내부 | 호스트 데이터 브리지 없음. 필요한 디렉터리는 게스트 서비스가 추가 생성 |
| `/dev` | 호스트 재귀 bind, 재귀 private | 장치·Binder·property 영역·기존 devpts/cgroup 등 공유 |
| `/dev/socket`, `/dev/block` | 새 tmpfs로 덮음 | 호스트 소켓 디렉터리와 해당 블록 경로를 가림. 다른 경로의 장치까지 차단하는 보안 경계는 아님 |
| `/proc` | 새 proc | nosuid,nodev,noexec. PID namespace는 분리하지 않음 |
| `/sys` | 새 sysfs | RO,nosuid,nodev,noexec |
| `/sys/fs/selinux` | 존재하는 호스트 경로 일반 bind | 게스트 뷰 RO |
| `/sys/fs/cgroup`, `/sys/fs/bpf` | 존재하는 호스트 경로 일반 bind | RW. 커널 전역 실행 환경 공유 |
| `/vendor`, `/odm`, `/vendor_dlkm` | 존재하는 호스트 디렉터리 일반 bind | 게스트 뷰만 RO로 재마운트 |
| `/mnt`, `/storage`, `/data_mirror` | 각각 새 tmpfs | 호스트 저장소 mount를 상속하지 않음 |
| `/tmp` | 전용 RW tmpfs, root:root, 1777 | 이미지 내부 RO 디렉터리를 재사용하지 않음 |
| `/cache` | 전용 RW tmpfs, system:cache, 0770 | 초기 검증용 휘발성 저장소. ROM이 영속 cache를 요구하면 별도 정책 필요 |
| `/metadata`, `/config` | 각각 빈 RO tmpfs | 이미지 디렉터리를 제외하고 호스트 metadata·configfs도 공유하지 않음. 게스트 metadata 영속화·암호화와 configfs 장치 제어는 미구현 |
| 네 emulated 경로 | 게스트 `/data/media` 일반 bind | `/storage/emulated`, `/mnt/user/0/emulated`, `/mnt/installer/0/emulated`, `/mnt/androidwritable/0/emulated` |
| `/data/data`, `/data_mirror/*` | 게스트 `user/0`, `user_de/0`, `misc/profiles/{cur,ref}` bind | 사용자 0 기본 mirror. FBE·CE 잠금 해제 구현은 아님 |
| `/apex` | 새 tmpfs + payload RO loop/ext4 | 게스트 system/system_ext/product와 선택한 vendor의 사전 설치 패키지. 호스트 `/apex`·`/data/apex` 공유 없음 |
| `/linkerconfig` | 새 tmpfs + 게스트 linkerconfig 실행 | `/apex/com.android.runtime/bin/linkerconfig` 우선, `/system/bin/linkerconfig` 대체 경로 지원. 실패·빈 `ld.config.txt`는 준비 실패 |
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

worker는 새 namespace를 만든 직후 `/` 전체를 재귀 private으로 바꾼다. userdata 쓰기/읽기와 system loop mount를 검사한 뒤 위 구조를 구성한다. Android의 절대 symlink는 준비 중인 게스트 root 안에서 해석한다. userdata·미디어의 device/inode, primary 저장소 경로, 실제 mountinfo를 확인한다.

커널이 할당한 loop 번호에 대응하는 호스트 `/dev/block/loopN`·`/dev/loopN` 노드가 없으면 세션 `loop-devices/`의 private tmpfs에 노드를 만든다. 이 tmpfs는 장치 접근을 위해 nodev를 지정하지 않고 nosuid,noexec,mode=0700으로 구성하며 게스트 root에는 노출하지 않는다. major/minor는 `/sys/block/loopN/dev`에서 읽고 실제 노드의 rdev를 확인한다. Android에서는 기존 loop 블록 노드의 SELinux 라벨을 복사한다. 호스트 `/dev`에 mknod하거나 기존 노드를 삭제·변경하지 않는다. 모든 이미지 mount 해제 후 이 tmpfs도 일반 unmount한다.

성공·실패 모두 역순으로 일반 unmount하며 `/dev` 재귀 bind의 하위 mount도 추적한다. 정리 실패는 오류로 보고하고 lazy unmount로 성공 처리하지 않는다. worker 종료 후 전용 scratch만 삭제한다. userdata에 생성한 기본 미디어·앱·mirror 디렉터리는 유지한다.

## 게스트 실행 검사와 서비스 기동 조건

linkerconfig 생성 후 `guest_probe.rs`가 아래 검사를 수행한다. shell과 경로·쓰기 검사가 실패하면 prepare도 실패한다.

1. 조립한 rootfs로 chroot한 `/system/bin/sh`와 외부 동적 바이너리 toybox를 실행한다.
2. 별도 자식에서 다시 mount namespace를 분리하고 `/`를 private으로 바꾼 뒤 `pivot_root`한다. 이전 root는 이 자식에서만 `MNT_DETACH`로 분리한다. 이는 상속한 호스트 하위 mount를 포함하는 이전 root의 의도적인 분리이며, worker의 게스트 mount를 lazy unmount하는 정리 우회와 구분한다.
3. 두 검사 모두 `/`의 device/inode가 준비한 rootfs인지 확인한다. cwd를 `/`로 바꾸고 상속한 FD는 exec 때 닫히도록 설정한다. 이전 root 경로가 사라졌는지, system/vendor/APEX/data와 linkerconfig 파일을 확인한다. product/system_ext는 게스트 안에서 실제 해석되는 경로를 출력한다.
4. `/data`, `/tmp`, `/cache`에 충돌하지 않는 임시 표식을 쓰고 읽는다. worker가 프로필 userdata의 표식 내용을 읽어 실제 기록 위치를 확인하고 모든 표식을 지운다.
5. 각 실행은 최대 20초 대기하며 시간 초과 시 전용 프로세스 그룹을 종료한다. 검사에서는 init이나 Android 서비스를 시작하지 않는다.

진단 출력은 게스트 디렉터리의 UID/GID/mode·SELinux 라벨과 실제 shell 프로세스 컨텍스트를 포함한다. shell 컨텍스트에는 `validation_scope=probe_only`를 붙이며 `ksu` 등의 관리 도메인 실행을 Android 서비스 도메인 통과로 판정하지 않는다.

fscrypt는 호스트 `/data`와 게스트 `/data`, `media`, `user/0`, `user_de/0`의 정책 버전·모드·플래그를 조회한다. 메모리 안에서 키 식별자를 포함한 정책을 비교하되 원문·해시·키 식별자는 출력하지 않는다. `policy_same`, `key_identifier_same`은 true/false/미확인(null)으로 기록한다. 동일 정책이라도 해당 키의 CE/DE 소속·잠금 해제 수명주기나 게스트 FBE 구현을 의미하지 않는다. 정책·라벨은 변경하지 않는다.

linkerconfig는 생성된 `ld.config.txt`들을 순회해 파일·section·namespace·디렉터리 매핑을 요약한다. 메인 설정에 section·default namespace·디렉터리 매핑이 없으면 준비를 실패시킨다. default namespace가 다른 namespace에 링크만 하는 구성도 허용한다. 이는 구조 검사이며 모든 서비스의 라이브러리 해석을 보장하지 않는다.

VINTF 파일 목록은 호환성 결과와 따로 출력한다. `/system/bin/checkvintf`가 있으면 `--check-compat --rootdir /`로 직접 실행한다. 결과는 `passed`(도구 종료 0), `failed`(AOSP EX_DATAERR=65: 비호환), `unavailable`(도구 없음), `error`(EX_USAGE=64·EX_SOFTWARE=70·실행/권한 오류·신호·시간 초과 등)로 구분한다. 파일 나열 성공을 통과로 판정하지 않는다. property·kernel 입력값이 게스트/기기 구성에 맞게 확정되지 않았으므로 도구 통과도 완전한 호환성 인증은 아니다.

`guest probe summary:` 행은 식별자를 제외한 구조화 JSON이다. 실제 root probe 컨텍스트·설정 요약·CE/DE 정책 비교·VINTF 상태를 포함하며 `android_service_domains_verified`와 `guest_fbe_verified`는 현재 false다.

Binder 장치와 property 영역의 호스트 원본 일치 여부, property service 소켓이 가려졌는지도 출력한다. 서비스 기동 전에는 framework Binder·servicemanager와 호스트 HAL 연결 방식, property service와 공유 메모리의 일관성, 게스트 installd/artd/vold, FUSE 접근 제어, 파일·프로세스 SELinux 정책과 FBE 호환성을 확정해야 한다. 일반 Android init을 실행하는 기능은 이 단계에 포함하지 않는다.

선택한 목표 구성·서비스별 조건·시작 및 종료·복구 규칙은 [서비스 실행 계약](service-execution-contract.md)에 정의한다. prepare는 계약과 기동 차단 사유를 확인하지만 실제 Android 서비스는 실행하지 않는다. 현재 공유 Binder/property를 private 환경으로 바꿨다는 뜻은 아니다.

정리는 worker의 rootfs 하위 mountinfo가 비었는지와 각 세션 loop 장치의 `LOOP_GET_STATUS64`를 확인한다. 다른 backing으로 재사용된 장치는 해제하지 않으며 같은 세션 backing이 남으면 실패한다. daemon도 worker 종료 후 자기 namespace의 세션 경로 아래 잔여 mount를 확인한 뒤 scratch를 삭제한다. 이 검사는 세션 경로와 추적한 loop에 한정되며 호스트 전체 상태의 무변경이나 모든 namespace 참조 소멸을 증명하지 않는다.

일반 검사는 `scripts/dev.ps1 check`, Android 빌드는 `scripts/dev.ps1 build`로 수행한다. 실제 mount/umount 회귀 테스트는 Linux CAP_SYS_ADMIN이 있는 폐기 가능한 테스트 컨테이너에서 실행한다.

```sh
cargo test --locked --bin ssald real_mounts_preserve_host_and_cleanup_recursively -- --ignored --test-threads=1
```

이 테스트는 private namespace에서 재귀 `/dev` bind 해제, 네 미디어 뷰, 쓰기 경로, RO bind와 원본 쓰기 보존, mount 실패 후 정리를 확인한다. 기본 WSLc 컨테이너에는 해당 capability가 없고 privileged 옵션도 없어 실행할 수 없다. 단위 테스트·교차 빌드 통과를 실제 mount나 기기 부팅 검증으로 간주하지 않는다.

별도의 `real_chroot_probe_closes_host_directory_fds` 회귀 테스트는 CAP_SYS_CHROOT만 필요하며 기본 Linux 빌드 컨테이너에서 실행 가능하다. 이 검사는 chroot 실행 헬퍼와 상속 FD 정리만 검증한다. 조립한 Android rootfs와 pivot_root 검사는 실제 기기 prepare에서 확인해야 한다.

`real_pivot_probe_detaches_old_root`는 CAP_SYS_ADMIN이 있는 폐기 가능한 Linux 컨테이너용 회귀 테스트다. 작은 tmpfs 루트에서 동적 shell을 실행하고 이전 root 분리와 worker root 보존을 확인한다. 기본 WSLc 환경에서는 실행하지 못했다.

참고: [AOSP init.rc](https://android.googlesource.com/platform/system/core/+/refs/heads/android14-gsi/rootdir/init.rc), [APEX manifest 형식](https://android.googlesource.com/platform/system/apex/+/refs/heads/main/proto/apex_manifest.proto).
