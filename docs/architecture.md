# ssal / ssald 아키텍처 구상

작성일: 2026-10-30  
상태: 구현 전 설계 초안

구현 진행: `prepare`에 적용한 초기 mount 구성과 현재 제약은 [초기 마운트 프로필](initial-mount-profile.md)에 정리한다. 아래 hot-switch·서비스 분리 항목은 목표 설계다.

서비스 분리의 선택한 목표와 시작·중지·복구 조건은 [서비스 실행 계약](service-execution-contract.md)에 정의한다. 계약의 형식 검사와 기동 차단은 구현했으며 private property/Binder·HAL 중계·서비스 런처는 아직 구현하지 않았다.

FreeSam의 LineageOS hot-switch를 KernelSU 모듈과 CLI 중심으로 재구성한다. 이 문서는 목표 구조와 구현 순서, 기기에서 검증해야 할 경계를 정의한다. 아래 내용은 구현 완료나 기기 호환성을 보장하는 명세가 아니다.

## 1. 목표와 전제

다음 네 가지를 기본 요구사항으로 한다.

1. `ssal`은 LineageOS 세션을 시작하고 OneUI로 복귀하는 CLI다. `ssald`는 Zygote 종료 이후에도 살아남으며 호스트와 게스트의 mount 환경을 각각 보존하는 관리 데몬이다.
2. `ssal`과 `ssald`는 하나의 KernelSU 모듈로 배포한다.
3. LineageOS의 `/data`는 호스트 OneUI와 데이터를 공유하지 않는다. `/data/media`, `/data/adb`, 앱 데이터, 설정, ADB 인증 정보까지 게스트에서 독립적으로 관리한다.
4. 배포 바이너리와 스크립트는 호스트 `/data/adb/modules/ssal/`에 두고, 등록한 시스템 이미지·설정·사용자 데이터 이미지·실제 마운트 지점·로그는 호스트 `/data/local/ssal/` 아래에서 용도별로 나눈다.

이미지 다운로드는 사용자가 외부 도구로 수행한다. 사용자는 압축 해제된 `system.img`를 `/sdcard/Download/` 등 접근 가능한 위치에 준비하고 `ssal add <image_name> <경로>`로 등록한다. ssal은 로컬 파일을 관리 저장소로 복사하며 다운로드·URL 입력·압축 해제 기능은 구현 범위에 포함하지 않는다.

여기서 부팅은 커널 재부팅이나 부팅 슬롯 전환이 아니다. 호스트 커널을 유지한 상태에서 OneUI 프레임워크를 중지하고 LineageOS 프레임워크를 시작하는 hot-switch다. OneUI 복귀 시에도 기존 앱 프로세스가 그대로 재개되는 것은 아니며, 프레임워크와 앱을 다시 시작할 수 있다.

데이터 독립은 호스트 데이터 디렉터리를 게스트에 연결하지 않는다는 의미다. 커널, 물리 저장장치, 일부 하드웨어 서비스는 공유한다. 게스트 root를 적대적인 주체로 가정하는 보안 격리는 mount namespace만으로 달성하지 못한다.

## 2. 구성 요소와 프로세스

```text
KernelSU
 └─ service.sh
     └─ ssald                         호스트 환경에서 계속 생존
         ├─ 관리 소켓 / 상태 머신 / 복구 journal
         ├─ host namespace FD / root FD
         └─ guest supervisor          별도 mount namespace
             ├─ guest namespace FD / root FD
             ├─ LineageOS 전용 /data
             ├─ 게스트 시스템 서비스
             └─ zygote → system_server → 앱

ssal ── 관리 소켓 ──> ssald
```

| 구성 요소 | 책임 |
| --- | --- |
| `ssal` | 명령 전달, 진행 상황 표시, 상태와 로그 조회 |
| `ssald` | 이미지 관리, namespace 보존, 전환과 복구, 세션 및 프로세스 감독 |
| guest supervisor | 게스트 mount 구성, root 전환, 서비스 시작과 종료 |
| 기기 프로파일 | 서비스 의존성, 정지·복원 순서, HAL 연결, 호환성 패치 |

CLI는 전환 스크립트를 직접 실행하지 않는다. 데몬에 작업을 요청하고 작업 ID로 상태를 조회한다. CLI, 터미널, ADB 연결이 끊겨도 이미 접수한 전환 작업은 데몬에서 계속 진행한다.

`ssald`는 Zygote나 앱의 자식으로 시작하지 않고 KernelSU 부팅 단계에서 시작한다. 부모 관계뿐 아니라 cgroup과 Android 프로세스 그룹 정리 대상도 확인하여 호스트 프레임워크 종료 시 함께 제거되지 않게 한다. `setsid`만으로 생존을 보장한다고 가정하지 않는다.

데몬 본체는 호스트 환경에 남는다. namespace 진입과 게스트 실행은 별도 worker 프로세스에서 수행하여, 다중 스레드 데몬에서 `setns`와 root 변경을 섞지 않는다.

## 3. 호스트 디렉터리 구성

```text
/data/adb/modules/ssal/
├─ module.prop
├─ skip_mount
├─ customize.sh
├─ post-fs-data.sh
├─ service.sh
├─ uninstall.sh
├─ sepolicy.rule
├─ bin/
│  ├─ ssal
│  └─ ssald
├─ libexec/
│  └─ guest-init
└─ profiles/
   └─ <device>/
      ├─ services.toml
      └─ patches/

/data/local/ssal/
├─ config/
│  └─ ssal.toml
├─ images/
│  └─ <image-id>/
│     ├─ system.img
│     └─ manifest.json
├─ guests/
│  └─ <profile-name>/
│     ├─ profile.json
│     └─ userdata/
├─ mnt/
│  └─ <session-id>/
│     ├─ system/
│     ├─ userdata/
│     └─ rootfs/
├─ state/                             복구 journal과 영속 상태
├─ logs/
└─ run/                               소켓·lock 등 부팅별 상태
```

이 트리의 경로는 모두 호스트 기준이다. `mnt/`는 마운트 지점의 명명 규칙이며, 게스트 namespace에서 구성한 실제 마운트가 호스트 namespace에도 보인다는 뜻은 아니다. 진단은 해당 namespace에서 수행한다.

모듈 경로는 배포 코드 전용으로 사용하고 실행 중 이미지·설정·로그를 쓰지 않는다. `/data/adb/modules/ssal/` 자체가 파일시스템 수준의 RO인 것은 아니다. 필요한 경우 게스트에 노출하는 코드 뷰를 별도로 RO 마운트한다.

`/data/local/ssal/`과 관리 소켓의 상위 디렉터리는 root 소유로 관리한다. `run/`은 부팅마다 초기화하되 `state/`와 사용자 이미지는 보존한다. 영속 journal과 실행 중 임시 상태를 혼동하지 않는다.

## 4. 게스트 `/data` 독립

초기 구현은 프로필별 userdata 디렉터리를 게스트 `/data`에 bind mount한다.

```text
호스트 /data/local/ssal/guests/<profile-name>/userdata/
                       │ bind mount
                       ▼
게스트 /data
       ├─ adb/
       ├─ app/
       ├─ media/
       ├─ misc/
       ├─ system/
       ├─ user/
       └─ user_de/
```

- 호스트 `/data`, `/data/adb`, `/data/media`를 게스트에 bind하지 않는다.
- 게스트 앱 디렉터리를 호스트 `/data/app`, `/data/user*` 등에 역으로 bind하지 않는다.
- 호스트 ADB 인증 키를 자동 복사하지 않는다. 게스트 ADB 키와 인증 정책은 별도로 관리한다.
- 게스트의 `/data/local/ssal`은 존재하더라도 게스트 이미지 내부 디렉터리다. 호스트 관리 디렉터리에 연결하지 않는다.
- 호스트 `/data/apex`의 가변 상태도 공유하지 않는다. 게스트 APEX 구성과 활성화 방식은 별도로 설계한다.
- 호스트 `/mnt`를 재귀 bind하지 않는다. 호스트 저장소 마운트가 함께 유입될 수 있다.

이 구성은 호스트 `/data` 파일시스템과 여유 공간을 공유하며 독립 파일시스템이나 용량 제한을 제공하지 않는다. 게스트 서비스에 필요한 SELinux 라벨, 접근 권한과 용량 관리 정책은 별도로 검증해야 한다.

호스트 저장소의 암호화에 더해 게스트 자체 FBE, 잠금 화면, KeyMint 연동까지 제공할지는 별도 결정 사항이다. 새 ext4 이미지를 만드는 것만으로 일반 Android의 CE/DE 암호화 동작이 완성되지는 않는다.

## 5. namespace와 mount 수명 관리

`ssald`는 mount 목록과 실제 환경을 모두 관리한다.

```text
HostContext
  mount_namespace_fd
  root_directory_fd
  service_state_before_switch
  changed_global_state

GuestSession
  session_id
  mount_namespace_fd
  root_directory_fd
  supervisor_pidfd
  managed_processes
  loop_devices
  mount_operations
  transition_state
```

`mountinfo`는 관찰 및 진단용 기록이다. 텍스트를 저장했다고 같은 mount 환경을 다시 얻을 수 있는 것은 아니다. namespace FD를 열어 두어 환경을 보존하고, root 디렉터리 FD를 별도로 관리한다. FD를 통한 namespace 참조는 해당 namespace를 사용하던 프로세스가 종료되어도 유지할 수 있다.

권장 순서는 다음과 같다.

1. Zygote를 중지하기 전에 호스트 namespace와 root FD를 확보한다. KernelSU에서 상속한 namespace가 기대한 호스트 서비스의 뷰인지 검증한다.
2. guest worker에서 `unshare(CLONE_NEWNS)`를 실행한다.
3. 상속한 mount 전파를 끊도록 `/`를 재귀적으로 private으로 변경한다.
4. 이 namespace 안에서 시스템 이미지, userdata, 게스트 rootfs를 구성한다.
5. supervisor가 게스트 namespace와 root를 확보한 뒤 root 전환을 수행한다.
6. 이전 호스트 root를 분리하고 게스트에 필요 없는 FD와 경로 참조를 닫는다.
7. 데몬은 전달받은 namespace와 root FD로 세션을 관리한다.

`setns`만으로 실행 파일 경로, root, cwd가 모두 게스트로 바뀐다고 가정하지 않는다. worker가 명시적으로 root와 cwd를 설정해야 한다. supervisor가 죽어도 namespace FD가 남을 수 있으므로 namespace 생존과 서비스 정상 상태도 구분한다.

FD는 재부팅 후 복원할 수 없다. 디스크에는 FD 번호 대신 작업 journal, 이미지 ID, 세션 ID, boot ID, 복구에 필요한 상태를 남긴다. 데몬 재시작 후 기존 supervisor를 재연결하는 기능은 별도 프로토콜로 구현하며, journal만으로 namespace를 복구했다고 처리하지 않는다.

## 6. 게스트 서비스와 저장소 뷰

`/data`만 바꾸고 호스트 데이터 서비스를 그대로 사용하면 독립성이 깨진다. `/data`에 접근하는 서비스의 실행 환경까지 게스트로 맞춰야 한다.

| 대상 | 설계 방향 |
| --- | --- |
| `installd`, `artd` | 게스트 namespace에서 실행하여 게스트 앱 데이터와 ART 상태만 사용 |
| `vold` | 게스트 전용 저장소 관리. 호스트 물리 볼륨을 건드리지 않도록 범위 제한 |
| MediaProvider/FUSE | 게스트 `/data/media`에 기반한 전용 저장소 뷰 구성 |
| `/data_mirror` | 게스트 `/data`에서 새로 구성 |
| `/storage`, `/mnt/user`, `/mnt/runtime` | 호스트 뷰를 상속하지 않고 게스트용으로 구성 |
| ADB | 호스트 관리용 ADB와 게스트 ADB의 데이터·인증·연결 경로를 구분 |
| vendor HAL | 필요한 호스트 하드웨어 서비스 연결을 기기 프로파일로 정의 |

`vold`를 새로 실행하는 것만으로 안전한 저장소 구성이 완성되지는 않는다. fstab, 블록 장치 접근, uevent 처리와 볼륨 소유권을 제한해야 한다. 초기에는 게스트 내부 emulated storage를 우선하고 외부 SD/USB 저장소는 별도 기능으로 다룬다.

게스트 `/dev`도 호스트 전체를 무조건 재귀 bind하지 않는다. 필요한 장치와 소켓, property 영역, Binder 장치를 명시적으로 선택한다. `/proc`, `/sys`, 장치 노출은 mount 경로 외의 호스트 접근 경로이므로 데이터 독립 검사에 포함한다.

KernelSU 모듈 설치와 기동은 호스트가 담당한다. 게스트 `/data/adb`를 독립시킨다고 그 안에 같은 모듈을 다시 설치할 필요는 없다. 게스트에서 관리 기능이 필요하면 `/run/ssal` 같은 별도 경로에 CLI 코드의 RO 뷰와 제한된 관리 인터페이스를 제공한다. 게스트의 `su` 동작과 소켓 접근 권한은 별도로 검증한다.

## 7. Binder, property와 HAL 경계

mount namespace 분리는 Android 시스템 서비스의 자동 분리를 의미하지 않는다. 다음 항목은 hot-switch 구현 전에 확정해야 한다.

- 게스트와 호스트 Binder 서비스 이름 충돌 방지 방식
- 게스트 framework Binder 컨텍스트 분리 여부
- 분리한 framework와 호스트 vendor HAL 사이의 연결 방식
- property 메모리 영역과 property service의 공유 범위
- 호스트 `init`에 전달하는 `ctl.*` 요청의 통제 방식
- 호스트 `init`의 서비스 재시작 및 `onrestart` 연쇄 동작

장기적으로는 게스트 framework Binder를 분리하고 필요한 HAL 연결을 명시하는 구성이 경계를 설명하기 좋다. 하지만 Binder 장치를 따로 만드는 것만으로 호스트 HAL 접근이 해결되지는 않는다. 서비스 검색과 Binder 객체 전달까지 고려한 연결 방식이 필요하며 기기별 구현과 검증이 선행되어야 한다.

초기 호환성 검증에서 FreeSam처럼 공유 Binder를 사용한다면, 충돌하는 호스트 서비스를 중지하고 게스트 서비스가 독점 등록하는 전환 절차가 필요하다. 이는 완전한 서비스 격리가 아니며, 호스트 `installd`로 우회하는 식으로 데이터 독립 요구사항을 완화해서는 안 된다.

property도 같은 원칙을 적용한다. 게스트 전용 property 환경을 구현하지 않은 상태에서 `setprop`을 호출하면 호스트 상태를 바꿀 수 있다. 필요한 전역 변경은 `ssald`가 허용 목록과 복원 기록을 통해 수행한다. 일반 Android `init`을 게스트에서 실행하면 이 문제가 자동 해결된다고 가정하지 않는다.

SELinux는 커널 전역 정책을 공유한다. 기기 프로파일에 필요한 정책과 라벨을 정의하고, 전역 permissive 전환이나 재귀 `chmod 777`을 정상 운영 방식으로 삼지 않는다.

## 8. 전환 상태 머신과 복구

```text
HOST_ACTIVE
    ↓
PREPARING          이미지 검증, userdata mount, guest namespace 구성
    ↓
GUEST_READY        마운트와 서비스 사전 검사
    ↓
SWITCHING          호스트 서비스 정지, 게스트 서비스 시작
    ↓
GUEST_ACTIVE
    ↓
RETURNING         게스트 종료, 호스트 서비스 복원
    ↓
HOST_ACTIVE

실패 → ROLLING_BACK → HOST_ACTIVE
                   └→ RECOVERY_REQUIRED
```

전환 작업은 하나씩 실행하고 각 단계의 완료와 보상 작업을 journal에 기록한다.

1. 이미지 무결성, 기기 프로파일, 저장 공간과 필수 자산을 검증한다.
2. 호스트 Zygote 중지 전에 게스트 준비를 최대한 끝낸다.
3. 호스트 서비스 상태와 변경할 전역 상태를 기록한다.
4. 기기 프로파일의 의존성 순서에 따라 호스트 서비스를 중지한다.
5. 게스트 서비스를 시작하고 제한 시간 안에 프레임워크와 필수 기능의 정상 동작을 확인한다.
6. 실패하면 시작한 게스트 서비스와 mount를 정리하고 호스트 상태를 복원한다.

정상 복귀에서도 게스트의 쓰기를 멈추고 프로세스 종료를 확인한 뒤 mount를 의존성 역순으로 해제한다. 이름 기반 `pkill` 대신 세션에서 추적한 프로세스와 프로세스 그룹을 대상으로 한다. pidfd를 지원하지 않는 커널의 대체 경로는 PID 재사용 검사를 포함해야 한다.

사용 중인 mount를 무조건 lazy unmount하여 정리가 끝났다고 처리하지 않는다. mount 참조와 프로세스가 남으면 원인을 기록하고 loop 장치도 성급하게 해제하지 않는다.

호스트 namespace 보존은 서비스와 전역 상태의 자동 복원을 뜻하지 않는다. 서비스·property·장치 상태 복구는 mount 복구와 별도로 구현한다. 복구할 수 없는 실패는 `RECOVERY_REQUIRED`로 보고하며 반복 전환을 막는다.

다음 재부팅은 기본적으로 OneUI로 시작한다. 실패한 게스트 자동 실행은 해제한다. 초기 구현에서는 게스트 자동 실행을 제공하지 않고 수동 전환부터 검증하는 것이 좋다.

## 9. KernelSU 모듈 수명 주기

| 파일 | 책임 |
| --- | --- |
| `customize.sh` | 바이너리·기기 조건 검증, 배포 권한 설정 |
| `post-fs-data.sh` | 관리 디렉터리와 최소 상태 준비 |
| `service.sh` | `ssald` 실행 |
| `skip_mount` | 모듈 `system/` 자동 마운트를 사용하지 않음을 표시 |
| `sepolicy.rule` | 데몬과 게스트 실행에 필요한 정책 정의 |
| `uninstall.sh` | 가능한 세션 정리와 제거 정책 적용 |

이미지 복사나 게스트 시작을 `post-fs-data.sh`에서 수행하지 않는다. 호스트 `/system` 오버레이가 필요 없다면 KernelSU의 시스템 오버레이에 의존하지 않고 자체 namespace에서 게스트 mount를 구성한다. 선택한 KernelSU 버전과 포크에서 부팅 단계 및 정책 동작을 확인한다.

사용자 이미지와 설정은 모듈 업데이트 시 보존한다. 실행 중 세션이 참조하는 코드와 자산의 교체는 제한하고, 초기 구현은 호스트 복귀 후 업데이트를 적용한다. 모듈 삭제 시에도 기본적으로 사용자 데이터를 보존하며 데이터 삭제는 별도의 명시적 작업으로 제공한다.

## 10. CLI와 관리 프로토콜

CLI 인터페이스 초안은 다음과 같다.

```sh
ssal doctor
ssal add <image_name> /sdcard/Download/system.img
ssal switch <image_name>
ssal status
ssal logs --follow
ssal return
```

`doctor`는 기기 프로파일, namespace·loop 지원, 필수 서비스와 자산, SELinux 조건, 여유 공간을 점검한다. `add <image_name> <경로>`는 사용자가 준비한 시스템 이미지를 복사·검증하고 지정한 이름으로 등록한다. 이미지 이름은 영문 대소문자, 숫자, `_`, `-`로 구성된 1~64자다. 최초 등록 시 userdata 크기 등은 `ssal.toml`의 설정을 사용하고, 실제 userdata 생성은 최초 준비 단계에서 수행한다. `switch`는 작업을 데몬에 접수하며 재연결 가능한 작업 ID를 반환한다. `status`는 현재 상태와 마지막 실패·복구 결과를 제공한다.

관리 소켓은 root 소유로 두고 peer 자격을 검사한다. 게스트에 소켓을 제공할 경우 허용 명령을 분리한다. 임의 shell 실행을 기본 RPC로 제공하지 않는다. CLI와 데몬의 프로토콜 버전을 명시하고, 이미지 등록·교체·전환 간 충돌을 직렬화한다.

이미지 등록은 다음 순서로 처리한다.

1. 호스트가 활성 상태일 때 원본 경로를 열고 일반 파일인지, 지원하는 이미지 형식인지, 복사할 공간이 충분한지 검사한다. `/sdcard` 경로는 호출자의 저장소 뷰에서 접근 가능해야 하므로 CLI가 연 파일 FD를 Unix 소켓의 `SCM_RIGHTS`로 데몬에 전달한다. 데몬은 전달받은 FD도 검증한다.
2. `images/` 아래 임시 파일로 복사한다. 원본을 이동하거나 수정하지 않으며, 원본 경로의 symlink나 bind mount를 등록 결과로 사용하지 않는다.
3. 복사한 파일의 형식·내용을 검증하고 해시를 계산한다. 등록 해시는 이후 변경 감지용이며 배포처의 진위 확인을 대신하지 않는다. 초기 지원 형식은 압축 해제된 raw ext4 `system.img`로 한정하고, 압축 파일과 Android sparse 이미지는 사용자가 외부에서 변환하도록 안내한다.
4. 복사와 검증을 완료한 파일을 `images/<image-id>/system.img`로 확정하고 manifest와 게스트의 이미지 참조를 갱신한다. 실패 시 기존 등록과 userdata를 유지하고 임시 파일을 정리한다.

등록 후에는 원본 파일을 삭제하거나 이동해도 세션 실행에 영향을 주지 않는다. 같은 이미지 이름으로 다시 등록하면 호스트 활성 상태에서 시스템 이미지 참조만 교체하고 기존 userdata는 보존한다. 실행 중인 세션의 이미지와 userdata는 덮어쓰지 않는다. 새 시스템 이미지와 기존 userdata의 호환성은 별도로 검사하고, userdata 초기화는 명시적인 별도 작업으로 취급한다.

이미지 manifest에는 해시, 이미지 형식, 확인 가능한 Android 버전, 필요한 호환성 자산과 프로파일 정보를 기록한다. 다운로드 주소나 다운로드 진행 상태는 관리하지 않는다.

## 11. FreeSam에서 변경할 부분

FreeSam은 기기 호환성 자료와 동작 참고용으로 활용한다. 기존 스크립트를 경로만 바꾸어 그대로 실행하는 방식은 이 설계의 데이터 독립 조건을 충족하지 못한다.

| 기존 처리 | 새 구조에서의 방향 |
| --- | --- |
| `master_prepare.sh`의 게스트 앱 디렉터리 → 호스트 `/data` 역방향 bind | 제거하고 게스트 `installd`·`artd` 구성 |
| 호스트 `/mnt` 재귀 bind | 제거하고 게스트 저장소 뷰 생성 |
| 호스트 `/data/adb`, `/data/media` 연결 | 제거하고 userdata 내부 디렉터리 사용 |
| 호스트 ADB 키 복사 | 제거하고 게스트 독립 인증 |
| 실행 스크립트를 staged `/data`로 복사 | 모듈 코드 또는 게스트용 RO 코드 뷰 사용 |
| 이름 기반 프로세스 종료와 다수의 shell watchdog | 데몬의 세션별 프로세스 감독으로 통합 |
| 전역 mount를 해제하는 복귀 스크립트 | namespace 정리와 서비스 복구를 분리 |

관련 로컬 참고 자료:

- [FreeSam 아키텍처](../FreeSam/docs/ARCHITECTURE.md)
- [게스트 준비 스크립트](../FreeSam/app/src/main/assets/master_prepare.sh)
- [게스트 시작 스크립트](../FreeSam/app/src/main/assets/master_inner.sh)
- [LineageOS 전환 스크립트](../FreeSam/app/src/main/assets/switch_to_lineage.sh)
- [OneUI 복귀 스크립트](../FreeSam/app/src/main/assets/return_to_oneui.sh)

## 12. 구현 순서와 검증 기준

### 단계 1: 모듈과 데몬

모듈 설치, 데몬 기동, RPC, `doctor`, `status`, 작업 journal을 구현한다. CLI 연결이 끊겨도 작업을 조회할 수 있는지 확인한다.

### 단계 2: 독립 userdata와 namespace

`ssal add <image_name> <경로>`로 로컬 이미지를 복사·등록하고 원본 파일 삭제 후에도 등록 이미지가 유효한지 확인한다. 복사 실패와 공간 부족 시 기존 등록 및 userdata가 보존되는지도 확인한다. OneUI를 실행한 채 게스트 rootfs와 userdata를 구성한다. 호스트 mount가 변하지 않는지, 게스트 `/data`가 프로필의 userdata 디렉터리에서 제공되는지 확인한다. 호스트 전용 표식 파일과 게스트 전용 표식 파일로 일반 경로에서 상호 노출과 역방향 쓰기가 없는지 확인한다. 이 검사는 root에 대한 보안 격리 증명과 구분한다.

### 단계 3: 게스트 데이터 서비스

Binder·property 방식을 확정하고 게스트 `installd`, `artd`, 저장소 서비스를 연결한다. 앱 설치·삭제·dexopt·재시작과 미디어 저장이 게스트 userdata에만 기록되는지 확인한다. 호스트 `/data` 변경 여부를 함께 관찰한다.

### 단계 4: 기기별 hot-switch와 복귀

디스플레이, 입력, 오디오, 네트워크, HAL 의존성을 프로파일로 정의한다. 정상 전환과 복귀, 게스트 부팅 실패, supervisor 종료, CLI 연결 종료, 데몬 재시작, 전환 중 재부팅을 검증한다. 지원하지 않는 복구 경로는 상태와 제한을 명시한다.

최초 지원 범위는 단일 기기·단일 GSI 조합으로 제한한다. 자동 부팅, 복수 게스트, 외부 저장소, 게스트 FBE와 잠금 화면, 게스트 KernelSU 연동은 기본 전환과 데이터 독립이 확인된 뒤 확장한다.

## 참고 문서

- [KernelSU 모듈 가이드](https://kernelsu.org/guide/module.html): 모듈 파일 구성과 부팅 스크립트 단계
- [Linux mount_namespaces(7)](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html): mount namespace 복제와 전파 속성
- [Linux setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html): namespace FD를 통한 진입과 권한 조건
