# ssal

KernelSU 모듈과 Android arm64 CLI의 초기 구현입니다. `ssald`가 root 전용 소켓을 제공하며 `ssal doctor`, `ssal status`, `ssal logs`, `ssal add <image_name> <raw-ext4-image>`를 지원합니다. 이미지 이름은 영문 대소문자, 숫자, `_`, `-`로 1~64자까지 지정합니다. 이름별로 이미지를 등록하며 `ssal status`에서 목록과 백그라운드 작업 결과를 확인합니다. 기존 `lineage` 등록은 업데이트 후 그대로 유지됩니다. 원본은 변경하지 않고 복사하며, 재등록 시 기존 userdata는 건드리지 않습니다.

`ssal create IMAGE_NAME [PROFILE_NAME]`은 등록된 이미지의 현재 ID를 고정하고 기기 정보와 프로필별 2 GiB sparse ext4 userdata 이미지를 생성합니다. 이름을 생략하면 사용하지 않는 `profile1`, `profile2` 등을 선택합니다. 기존 프로필은 덮어쓰지 않습니다. 프로필은 `ssal status`에서 확인하고, 데이터와 설정은 `/data/local/ssal/guests/PROFILE_NAME/`에 보존됩니다. 생성에는 기기의 `/system/bin/mke2fs`가 필요합니다.

현재 이미지 검사는 ext4 매직과 복사 크기 및 SHA-256에 한정됩니다. 파일시스템의 완전성, Android 버전 및 기기 호환성은 확인하지 않습니다. 프로필에 기록한 기기 정보는 감지된 값이며 전환에 필요한 기기 설정은 아직 구현되지 않았습니다. namespace, 게스트 서비스와 hot-switch도 구현되지 않아 `switch`와 `return`은 거부됩니다. 실제 기기에서 검증되지 않았습니다.

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
