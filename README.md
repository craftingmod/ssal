# ssal

SSAL — System Switching Abstraction Layer.
> The name came first. The acronym came later.

## AGENT

KernelSU 모듈과 Android arm64 CLI의 초기 구현입니다. `ssald`가 root 전용 소켓을 제공하며 `ssal doctor`, `ssal status`, `ssal logs`, `ssal add <image_name> <raw-ext4-image>`를 지원합니다. 이미지 이름은 영문 대소문자, 숫자, `_`, `-`로 1~64자까지 지정합니다. 이름별로 이미지를 등록하며 `ssal status`에서 목록과 백그라운드 작업 결과를 확인합니다. 기존 `lineage` 등록은 업데이트 후 그대로 유지됩니다. 원본은 변경하지 않고 복사하며, 재등록 시 기존 userdata는 건드리지 않습니다.

`ssal create IMAGE_NAME [PROFILE_NAME]`은 등록된 이미지의 현재 ID를 고정하고 기기 정보와 프로필별 8 GiB raw ext4 `userdata.img`를 생성합니다. 이미지 공간을 미리 할당하며 Host 여유 공간 256 MiB를 추가로 요구합니다. Android의 `/system/bin/mke2fs`, `/system/bin/e2fsck`와 새 `ssal_userdata_image_file` 정책이 필요합니다. 이름을 생략하면 사용하지 않는 `profile1`, `profile2` 등을 선택합니다. 기존 프로필은 덮어쓰지 않습니다. 프로필은 `ssal status`에서 확인하고, 데이터와 설정은 `/data/local/ssal/guests/PROFILE_NAME/`에 보존됩니다. 프로필 형식은 버전 3만 지원합니다. 이전 버전의 directory/image 프로필은 자동 변환하지 않으며 `ssal remove PROFILE_NAME` 후 다시 생성해야 합니다.

`ssal remove PROFILE_NAME`은 프로필과 그 안의 userdata를 영구적으로 삭제합니다. 연결된 system 이미지와 다른 프로필은 삭제하지 않습니다. 이전 형식의 프로필도 삭제할 수 있습니다. 실행 중이거나 loop에 연결된 userdata 이미지는 삭제하지 않습니다.

`ssal doctor PROFILE_NAME`은 이미지 해시와 크기, ext4 매직, userdata 이미지의 크기·소유권·권한·형식, 기기 fingerprint 및 사용 가능한 마운트 장치와 기본 마운트 프로필을 확인합니다. `ssal prepare PROFILE_NAME`은 별도 mount namespace에서 userdata 파일을 배타 잠금하고 오프라인 `e2fsck -p` 검사 후 RW loop/ext4로 마운트합니다. 복구 실패 시 이미지를 보존하고 중단하며 자동 재포맷하지 않습니다. userdata 쓰기/읽기와 system RO loop mount를 검사한 뒤, [초기 마운트 프로필](docs/initial-mount-profile.md)에 따라 rootfs, Guest 전용 `/dev`와 소켓·블록 경로, `/proc`·`/sys`, vendor, 게스트 `/mnt`·미디어·data mirror, APEX와 linkerconfig를 구성합니다. APEX 추출·마운트 또는 linkerconfig 생성이 실패하면 준비도 실패합니다. 실제 mountinfo는 명령 결과와 `ssal logs`에 기록하고 작업 종료 시 마운트를 해제합니다. 이미지 해시와 APEX 추출에는 시간과 임시 공간이 필요하며 실제 기기에서는 SELinux 조건을 검증해야 합니다.

모듈의 `sepolicy.rule`은 loop backing 파일용 `ssal_image_file` 타입과 커널 읽기 권한을 정의합니다. 새로 등록하는 system 이미지와 prepare 중 추출하는 APEX payload에 해당 SELinux 라벨을 적용하며, 정책이 로드되지 않거나 라벨 적용에 실패하면 작업도 실패합니다. 기존 system 이미지는 자동으로 변경하지 않으므로 개발 중 초기화 후 다시 등록해야 합니다. 모듈 설치 후 정책이 로드된 상태에서 등록하고, `ssal doctor PROFILE_NAME`에서 라벨을 확인하세요. 이 정책은 게스트 서비스의 SELinux 권한이나 호환성을 보장하지 않습니다.

현재 이미지 검사는 ext4 매직과 복사 크기 및 SHA-256에 한정됩니다. 파일시스템의 완전성, Android 버전 및 기기 호환성은 확인하지 않습니다. 프로필에 기록한 기기 정보는 감지된 값이며 전환에 필요한 기기 설정은 아직 구현되지 않았습니다. 준비용 mount namespace와 마운트 구성은 구현했지만 게스트 서비스와 hot-switch는 구현되지 않아 `switch`와 `return`은 거부됩니다. 준비 성공은 Android 부팅 성공을 의미하지 않으며 실제 기기에서 검증되지 않았습니다.

`prepare`는 linkerconfig 생성 이후 게스트 chroot·별도 자식의 `pivot_root`에서 동적 shell과 경로·userdata 쓰기/읽기를 검사합니다. `/tmp`·`/cache`는 RW tmpfs, `/metadata`·`/config`는 빈 RO tmpfs로 구성합니다. SELinux·fscrypt·VINTF와 Binder/property 공유 상태를 진단하고 정리 후 잔여 mount·세션 loop backing을 확인합니다. 진단 결과는 Android 서비스·FUSE·암호화·HAL 호환성이나 부팅 성공을 보장하지 않습니다.

서비스 실행의 목표와 기동·종료·복구 조건은 [서비스 실행 계약](docs/service-execution-contract.md)에 정의했습니다. prepare는 linkerconfig 구조 요약, 식별자를 노출하지 않는 CE/DE 경로 정책 비교, shell 전용 SELinux 관찰과 VINTF의 `passed/failed/unavailable/error`를 출력하고 서비스별 기동 차단 사유를 확인합니다. [실험용 Guest property server](docs/guest-property-service.md)는 private area 쓰기·읽기와 Android protobuf `/data/property/persistent_properties` 저장·복구를 구현했습니다. 전용 production 도메인 검증과 전체 서비스 supervisor 통합은 남아 있으며 prepare에서 Android 서비스를 시작하지 않습니다.

`ssal probe-binder PROFILE_NAME`은 별도 [독립 Binder 시험](docs/binder-probe.md)을 실행합니다. 새 binderfs 장치 생성·열기·최소 IPC·정리를 각각 기록하며 AOSP servicemanager나 HAL은 실행하지 않습니다. IPC 헬퍼는 게스트 플랫폼 라이브러리와 별도 빌드하고 이미지 일치 해시를 검사합니다. 일반 prepare와 Android 서비스 기동 차단은 유지합니다.

## CLI 사용법

`ssal --help` (`-h`)로 명령 목록을, `ssal COMMAND --help` 또는 `ssal help COMMAND`로 개별 사용법을 확인합니다. `ssal --version` (`-V`)은 버전을 출력합니다. 도움말과 버전 조회에는 root나 실행 중인 데몬이 필요하지 않습니다.

```sh
ssal prepare profile1 --regen --native
ssal add lineage /data/local/tmp/system.img
ssal add -- -image ./-system.img
ssal status >status.txt
ssal doctor profile1 2>error.txt
```

일반 명령의 옵션은 피연산자 앞뒤에서 사용할 수 있습니다. `--` 뒤의 값은 옵션으로 해석하지 않으므로 `-`로 시작하는 이름이나 경로에는 `--`를 사용하거나 경로에 `./`를 붙입니다. `probe`의 실행 옵션과 위험 확인 조건은 기존 전용 파서를 유지하며 `ssal probe --help`에서 확인합니다.

정상 결과와 도움말은 stdout으로, 입력 오류·파일 오류·연결 실패·데몬이 거부한 결과는 `ssal:` 접두사와 함께 stderr로 출력합니다. 종료 코드는 성공 `0`, 실행 실패 `1`, 일반 명령의 사용법 오류 `2`입니다. 기존에 실패 결과를 stdout에서 읽던 스크립트는 stderr를 읽거나 `2>&1`로 합쳐야 합니다. 인자 없이 실행하면 사용법 오류로 종료하며, 백그라운드 이미지 등록의 성공 코드는 작업 접수만 의미합니다. 완료 여부는 `ssal status`로 확인합니다.

## 독립 Guest Shell

root에서 `ssal shell [PROFILE_NAME]`은 대화형 PTY를, `ssal exec [PROFILE_NAME] -- COMMAND [ARG]...`는 단일 명령을 실행합니다. 프로필이 하나면 이름을 생략할 수 있습니다. 실행 파일 옆의 `ssald`, `ssal-property-service`, `ssal-context-map.so`를 사용하며 데몬 소켓이나 Android 부팅 완료를 요구하지 않습니다.

```sh
ssal shell y702
ssal exec -- /system/bin/id
ssal exec y702 -- /system/bin/sh -c 'getprop ro.build.version.sdk; exit 37'
printf 'id\ngetprop ro.build.version.sdk\n' | ssal exec -- /system/bin/sh
```

기존 공용 환경이 준비돼 있으면 해당 mount/network namespace와 Property/APEX를 재사용합니다. Android worker가 환경을 준비하는 중이면 준비 완료 또는 실패 후 lock 해제까지 기다립니다. 사용할 환경이 없으면 기존 mount 준비 경로로 독립 환경을 만들고 `/system/bin/sh`를 실행합니다. 독립 Shell은 Binder, Zygote, SystemServer를 시작하지 않습니다. 준비 상세 로그는 `/data/local/ssal/logs/shell-PID.log`에 남습니다.

Shell은 프로필별 mapped `shell` SID와 UID/GID 2000, 빈 supplementary groups 및 capability 집합을 사용합니다. exec는 입출력 파이프를 중계하므로 Host 파일 FD를 Guest에 상속하지 않습니다. PTY는 Guest 전용 devpts를 사용하며 창 크기 변경·Ctrl-C·작업 제어를 지원합니다. 명령의 종료 코드를 그대로 반환합니다.

Android 서비스 종료·실패 시 열린 Shell의 lease가 해제될 때까지 공용 mount와 Property 서비스를 유지합니다. 마지막 Shell 종료 후 자식을 회수하고 기존 mount/loop 정리를 실행합니다. PID namespace 지원 커널은 별도 PID namespace를 사용합니다. `CONFIG_PID_NS`가 없는 순정 커널은 PID를 공유하며 SELinux, UID/GID, private proc mount와 FD 제한으로 격리합니다. 이 경우 `/proc`의 PID 번호까지 숨기는 보장은 없습니다. 강제 `SIGKILL`·전원 차단 뒤 scratch 디렉터리 회수는 일반 종료 정리와 별개입니다.

로컬 PTY 회귀는 `python3 tests/shell_transport.py /build/target/debug/ssal`, 기기 회귀는 `scripts/test-guest-shell.sh`, Android 실패 시 수명 분리 검증은 `scripts/test-shell-android-lifecycle.sh`를 사용합니다. 수명 분리 검증 스크립트는 지정 프로필의 mapped SID를 가진 Guest 서비스에만 실패를 주입합니다.

### Guest init.rc 실험

일회용 Guest userdata 복제본과 빈 worker 디렉터리를 준비한 뒤, 기기의 root 셸에서 기존 Zygote worker에 `SSAL_GUEST_INITRC=1`을 붙여 실행합니다.

```sh
SSAL_GUEST_INITRC=1 /path/to/ssald --guest-zygote-7a-worker SYSTEM_IMG DISPOSABLE_USERDATA WORKER_DIR
```

Guest 시스템 파티션의 rc와 Guest property 기반 import를 읽습니다. `early-init`·`init`에서 `servicemanager`를 시작하고, private Binder 준비 확인 후 `late-init`에서 이어지는 트리거로 Zygote를 시작합니다. 시작과 생략 로그에 rc 파일과 행 번호가 표시됩니다.

부팅 이벤트에 붙은 property 조건은 해당 부팅 단계의 Guest 스냅샷에서 평가합니다. Property Service는 `servicemanager.ready=true`에서 순수 `on property:...` 액션을 한 번 평가한 뒤, Guest property가 생성되거나 값이 바뀔 때 관련 액션을 실행합니다. 여러 조건은 모두 만족해야 하며, 부팅 이벤트가 붙은 액션은 property 변경으로 다시 실행되지 않습니다.

실시간 액션은 명시적으로 등록된 Guest 서비스의 `start`·`class_start`, `trigger`, Guest init SELinux 권한이 있는 비영속 `setprop`을 지원합니다. 등록 서비스는 이름·실행 파일·인수가 일치하는 rc 선언의 `oneshot`과 `restart_period`를 상속합니다. Property Service의 `services` 설정에서 두 옵션을 덮어쓸 수 있습니다. rc 선언과 일치하지 않는 등록 서비스는 `"oneshot": false` 또는 초 단위 `"restart_period"`를 지정하면 자동 재시작합니다.

재시작 간격은 직전 기동 시각을 기준으로 하며 기본값은 5초입니다. 비정상 종료에는 최소 5초를 적용합니다. 명시적 `ctl.stop`은 대기 중인 자동 재시작도 취소합니다. 현재 Zygote worker가 직접 감독하는 `servicemanager`와 Zygote에는 기존 진단 수명주기를 적용합니다. Vendor/ODM HAL, APEX rc, `onrestart` 훅과 재부팅 동작은 이 경로의 실행 범위 밖입니다. SystemServer 시작에는 기존 `SSAL_START_SYSTEM_SERVER=1`과 APEX Binder 준비 검사가 필요합니다.

## 빌드

WSLc, Bun과 네트워크가 필요합니다. PowerShell에서 실행합니다.

```powershell
bun run setup:windows
./scripts/dev.ps1 check
./scripts/dev.ps1 build
```

개별 Cargo 명령은 실행 중인 개발 컨테이너에서 사용할 수 있습니다.

```powershell
wslc exec --workdir /src ssal-dev cargo test --locked --lib
```

결과는 `out/ssal-module.zip`과 `out/bin/`에 생성됩니다. 설치 후 root 셸에서 `export PATH="/data/adb/modules/ssal/bin:$PATH"`를 실행하면 해당 셸에서 `ssal`을 사용할 수 있습니다. 또는 `/data/adb/modules/ssal/bin/ssal`을 직접 실행합니다. 사용자 이미지와 상태는 모듈 업데이트 및 제거 시 보존됩니다. 빌더 이미지를 다시 빌드하고 기존 `ssal-dev`를 교체하려면 `bun run update:windows`를 실행합니다. 기존 컨테이너가 실행 중이면 중지한 뒤 삭제하고 새 컨테이너를 생성합니다. 다른 작업공간이나 이미지에 연결된 동명의 컨테이너는 교체하지 않습니다.

WebUI 소스는 `frontend/`에 있으며 `bun run build:web`으로 `out/webroot/`에 빌드합니다. `bun run package`는 빌드된 바이너리와 WebUI를 모듈 ZIP으로 묶습니다. KernelSU 모듈 WebUI의 버튼으로 데몬을 재시작할 수 있으며, 이미지 등록 중에는 재시작이 거부됩니다.

상세 목표와 남은 단계는 [아키텍처](docs/architecture.md)를 참고하세요.

SELinux 전환 사전 검사는 `ssal probe-selinux-transition PROFILE_NAME`으로 실행합니다. [검사 범위와 기기 결과](docs/selinux-transition-probe.md)를 참고하세요.

PC에서 `bun run selinux:check`를 실행하면 adb의 root 접근과 실행 중인 `ssal-dev`를 사용해 SELinux를 조회합니다. 기본 프로필은 `profile1`이며 `--profile NAME`, `--serial ADB_SERIAL`로 선택할 수 있습니다. 등록된 raw ext4 이미지의 해시를 검증해 `.cache/selinux-images/`에 보관하고, 마운트 없이 Guest 정책을 추출해 기기의 vendor/odm과 비교합니다. Debian 컴파일러가 처리하지 못하는 CIL은 기기 컴파일러로 임시 복사본만 컴파일합니다. 현재 커널의 context·AV 조회, 컴파일 결과와 정리는 `out/selinux-check/<run>/report.json`에 기록하며 최신 위치는 `out/selinux-check/latest.json`에 남깁니다. 정책 로드·라벨 변경·서비스 기동은 하지 않습니다. 종료 코드 0은 조회 완료를 뜻하며 호환 여부는 JSON의 `overall`과 세부 결과를 확인해야 합니다. [기기 점검 결과](docs/selinux-check-device-20261031.md)를 참고하세요.

정식 Guest servicemanager의 실행 없는 권한·환경·격리 검사는 `ssal probe-servicemanager-preflight PROFILE_NAME`으로 실행합니다. [실행 선행 조건과 기기 결과](docs/servicemanager-preflight.md)를 참고하세요.

`selinux:check`는 진단 후 같은 디렉터리에 적용 없는 `patch-plan.json`도 생성합니다. 기기 없이 저장된 진단을 다시 분석하려면 `bun run selinux:plan` 또는 `bun run selinux:plan --report out/selinux-check/<run>/report.json`을 실행합니다. 실행 중인 `ssal-dev`와 로컬 참고 정책 소스가 필요합니다. 계획에는 선언·매핑·사용 참조, attribute 영향과 검증 한계를 기록하며, 부팅 필수성·실제 사용 여부·Host 보안 영향은 입증 전까지 미확인으로 둡니다. JSON 안의 KernelSU 선언 후보는 구문·적용 검증 전의 검토 자료이며 실행 가능한 정책 파일이나 allow 규칙을 생성하지 않습니다. 기존 진단의 `blocked` 판정도 해제하지 않습니다.

실제 private Binder를 연결하고 라벨 호환성·실행 명세·Host 노출 경로를 조사하는 후속 검사는 `ssal probe-servicemanager-runtime-preflight PROFILE_NAME`으로 실행합니다. 실제 서비스는 실행하지 않습니다. [런타임 차단 요인과 기기 결과](docs/servicemanager-runtime-preflight.md)를 참고하세요.

이 검사는 임시 Guest 라벨/DAC 적용과 UID 1000 시험 워커 검증도 수행합니다. [실행 환경 검증 결과와 남은 차단](docs/servicemanager-execution-environment.md)을 참고하세요. 실제 servicemanager 실행은 계속 차단됩니다.

Private Binder의 Enforcing 접근 방안은 [후속 조사](docs/private-binder-enforcing-research.md)에 정리했습니다. 현재 alias bind에 가려진 원본 `binder` 노드 검사, `context`/`fscontext` 분리와 최소 정책 후보를 다룹니다. 새 기기 검증 결과는 아닙니다.

후속 [구현·기기 실험](docs/private-binder-device-20261031.md)에서는 원본 binder_device 선택과 enforcing servicemanager/UID 1000의 제한된 ioctl 검사를 통과했습니다. 추가 정책은 적용하지 않았으며, enforcing IPC·service_contexts와 정식 서비스 기동은 미검증입니다.

최신 [Enforcing Binder IPC·레지스트리 시험](docs/enforcing-binder-device-20261031.md)은 기존 정책에서 shell → servicemanager의 실제 transaction, Guest libbinder echo와 Binder 객체 전달을 확인했습니다. 같은 도메인의 거부 대조군을 구분했으며, service_contexts의 9개 context가 차단됩니다. 정식 Android 서비스 실행과 launch_enabled 해제는 수행하지 않았습니다.

Phase 2 데이터 격리 검사는 `ssal probe-guest-data PROFILE_NAME`으로 실행합니다. **새로 만든 빈 프로필**과 기존 Permissive 상태가 필요하며, 검사 자체는 SELinux 모드를 변경하지 않습니다. 디렉터리 bind `/data`에서 private `installd` 생성·삭제와 `artd` 컴파일, Host 불변성 및 역순 정리를 확인합니다. [실기기 결과와 실행 조건](docs/phase2-data-isolation.md)을 참고하세요. `switch`와 운영 서비스 `launch_enabled=false`는 유지합니다.
