# ssal

SSAL — System Switching Abstraction Layer.
> The name came first. The acronym came later.

## AGENT

KernelSU 모듈과 Android arm64 CLI의 초기 구현입니다. `ssald`가 root 전용 소켓을 제공하며 `ssal doctor`, `ssal status`, `ssal logs`, `ssal add <image_name> <raw-ext4-image>`를 지원합니다. 이미지 이름은 영문 대소문자, 숫자, `_`, `-`로 1~64자까지 지정합니다. 이름별로 이미지를 등록하며 `ssal status`에서 목록과 백그라운드 작업 결과를 확인합니다. 기존 `lineage` 등록은 업데이트 후 그대로 유지됩니다. 원본은 변경하지 않고 복사하며, 재등록 시 기존 userdata는 건드리지 않습니다.

`ssal create IMAGE_NAME [PROFILE_NAME]`은 등록된 이미지의 현재 ID를 고정하고 기기 정보와 프로필별 userdata 디렉터리를 생성합니다. 이름을 생략하면 사용하지 않는 `profile1`, `profile2` 등을 선택합니다. 기존 프로필은 덮어쓰지 않습니다. 프로필은 `ssal status`에서 확인하고, 데이터와 설정은 `/data/local/ssal/guests/PROFILE_NAME/`에 보존됩니다. 이전 userdata 이미지 방식의 프로필은 지원하지 않으며 자동 변환하지 않습니다.

`ssal remove PROFILE_NAME`은 프로필과 그 안의 userdata를 영구적으로 삭제합니다. 연결된 system 이미지와 다른 프로필은 삭제하지 않습니다. 이전 userdata 이미지 방식의 프로필도 삭제할 수 있습니다.

`ssal doctor PROFILE_NAME`은 이미지 해시와 크기, ext4 매직, userdata 디렉터리, 기기 fingerprint 및 사용 가능한 마운트 장치와 기본 마운트 프로필을 확인합니다. `ssal prepare PROFILE_NAME`은 별도 mount namespace에서 userdata 쓰기/읽기와 system RO loop mount를 검사한 뒤, [초기 마운트 프로필](docs/initial-mount-profile.md)에 따라 rootfs, 공유 `/dev`와 전용 소켓·블록 경로, `/proc`·`/sys`, vendor, 게스트 `/mnt`·미디어·data mirror, APEX와 linkerconfig를 구성합니다. APEX 추출·마운트 또는 linkerconfig 생성이 실패하면 준비도 실패합니다. 실제 mountinfo는 명령 결과와 `ssal logs`에 기록하고 작업 종료 시 마운트를 해제합니다. 이미지 해시와 APEX 추출에는 시간과 임시 공간이 필요하며 실제 기기에서는 SELinux 조건을 검증해야 합니다.

모듈의 `sepolicy.rule`은 loop backing 파일용 `ssal_image_file` 타입과 커널 읽기 권한을 정의합니다. 새로 등록하는 system 이미지와 prepare 중 추출하는 APEX payload에 해당 SELinux 라벨을 적용하며, 정책이 로드되지 않거나 라벨 적용에 실패하면 작업도 실패합니다. 기존 system 이미지는 자동으로 변경하지 않으므로 개발 중 초기화 후 다시 등록해야 합니다. 모듈 설치 후 정책이 로드된 상태에서 등록하고, `ssal doctor PROFILE_NAME`에서 라벨을 확인하세요. 이 정책은 게스트 서비스의 SELinux 권한이나 호환성을 보장하지 않습니다.

현재 이미지 검사는 ext4 매직과 복사 크기 및 SHA-256에 한정됩니다. 파일시스템의 완전성, Android 버전 및 기기 호환성은 확인하지 않습니다. 프로필에 기록한 기기 정보는 감지된 값이며 전환에 필요한 기기 설정은 아직 구현되지 않았습니다. 준비용 mount namespace와 마운트 구성은 구현했지만 게스트 서비스와 hot-switch는 구현되지 않아 `switch`와 `return`은 거부됩니다. 준비 성공은 Android 부팅 성공을 의미하지 않으며 실제 기기에서 검증되지 않았습니다.

`prepare`는 linkerconfig 생성 이후 게스트 chroot·별도 자식의 `pivot_root`에서 동적 shell과 경로·userdata 쓰기/읽기를 검사합니다. `/tmp`·`/cache`는 RW tmpfs, `/metadata`·`/config`는 빈 RO tmpfs로 구성합니다. SELinux·fscrypt·VINTF와 Binder/property 공유 상태를 진단하고 정리 후 잔여 mount·세션 loop backing을 확인합니다. 진단 결과는 Android 서비스·FUSE·암호화·HAL 호환성이나 부팅 성공을 보장하지 않습니다.

서비스 실행의 목표와 기동·종료·복구 조건은 [서비스 실행 계약](docs/service-execution-contract.md)에 정의했습니다. prepare는 linkerconfig 구조 요약, 식별자를 노출하지 않는 CE/DE 경로 정책 비교, shell 전용 SELinux 관찰과 VINTF의 `passed/failed/unavailable/error`를 출력하고 서비스별 기동 차단 사유를 확인합니다. 계약 검증은 구현했지만 private property/Binder·HAL 중계·서비스 런처는 아직 없으며 Android 서비스를 시작하지 않습니다.

`ssal probe-binder PROFILE_NAME`은 별도 [독립 Binder 시험](docs/binder-probe.md)을 실행합니다. 새 binderfs 장치 생성·열기·최소 IPC·정리를 각각 기록하며 AOSP servicemanager나 HAL은 실행하지 않습니다. IPC 헬퍼는 게스트 플랫폼 라이브러리와 별도 빌드하고 이미지 일치 해시를 검사합니다. 일반 prepare와 Android 서비스 기동 차단은 유지합니다.

## 빌드

WSLc, Bun과 네트워크가 필요합니다. PowerShell에서 실행합니다.

```powershell
bun run setup:windows
./scripts/dev.ps1 check
./scripts/dev.ps1 build
```

결과는 `out/ssal-module.zip`과 `out/bin/`에 생성됩니다. 설치 후 root 셸에서 `export PATH="/data/adb/modules/ssal/bin:$PATH"`를 실행하면 해당 셸에서 `ssal`을 사용할 수 있습니다. 또는 `/data/adb/modules/ssal/bin/ssal`을 직접 실행합니다. 사용자 이미지와 상태는 모듈 업데이트 및 제거 시 보존됩니다. 빌더 이미지 변경 후에는 기존 `ssal-dev`를 제거하고 setup을 다시 실행해야 합니다.

WebUI 소스는 `frontend/`에 있으며 `bun run build:web`으로 `out/webroot/`에 빌드합니다. `bun run package`는 빌드된 바이너리와 WebUI를 모듈 ZIP으로 묶습니다. KernelSU 모듈 WebUI의 버튼으로 데몬을 재시작할 수 있으며, 이미지 등록 중에는 재시작이 거부됩니다.

상세 목표와 남은 단계는 [아키텍처](docs/architecture.md)를 참고하세요.

SELinux 전환 사전 검사는 `ssal probe-selinux-transition PROFILE_NAME`으로 실행합니다. [검사 범위와 기기 결과](docs/selinux-transition-probe.md)를 참고하세요.

정식 Guest servicemanager의 실행 없는 권한·환경·격리 검사는 `ssal probe-servicemanager-preflight PROFILE_NAME`으로 실행합니다. [실행 선행 조건과 기기 결과](docs/servicemanager-preflight.md)를 참고하세요.

실제 private Binder를 연결하고 라벨 호환성·실행 명세·Host 노출 경로를 조사하는 후속 검사는 `ssal probe-servicemanager-runtime-preflight PROFILE_NAME`으로 실행합니다. 실제 서비스는 실행하지 않습니다. [런타임 차단 요인과 기기 결과](docs/servicemanager-runtime-preflight.md)를 참고하세요.

이 검사는 임시 Guest 라벨/DAC 적용과 UID 1000 시험 워커 검증도 수행합니다. [실행 환경 검증 결과와 남은 차단](docs/servicemanager-execution-environment.md)을 참고하세요. 실제 servicemanager 실행은 계속 차단됩니다.

Private Binder의 Enforcing 접근 방안은 [후속 조사](docs/private-binder-enforcing-research.md)에 정리했습니다. 현재 alias bind에 가려진 원본 `binder` 노드 검사, `context`/`fscontext` 분리와 최소 정책 후보를 다룹니다. 새 기기 검증 결과는 아닙니다.

후속 [구현·기기 실험](docs/private-binder-device-20261031.md)에서는 원본 binder_device 선택과 enforcing servicemanager/UID 1000의 제한된 ioctl 검사를 통과했습니다. 추가 정책은 적용하지 않았으며, enforcing IPC·service_contexts와 정식 서비스 기동은 미검증입니다.

최신 [Enforcing Binder IPC·레지스트리 시험](docs/enforcing-binder-device-20261031.md)은 기존 정책에서 shell → servicemanager의 실제 transaction, Guest libbinder echo와 Binder 객체 전달을 확인했습니다. 같은 도메인의 거부 대조군을 구분했으며, service_contexts의 9개 context가 차단됩니다. 정식 Android 서비스 실행과 launch_enabled 해제는 수행하지 않았습니다.
