# ssal

## WSLc 빌드 환경

WSLc와 네트워크가 필요합니다. PowerShell에서 순서대로 실행합니다.

```powershell
bun run setup:windows
./scripts/dev.ps1 check
./scripts/dev.ps1 build
./scripts/dev.ps1 userdata -Size 256M
```

`setup:windows`는 빌더 이미지가 없으면 만들고, `ssal-dev`가 없으면 생성하며, 중지된 컨테이너는 시작합니다. 이미 실행 중이면 그대로 사용합니다. 이미지와 컨테이너가 이미 존재할 때 Containerfile 변경을 자동 감지하지 않습니다. 빌더 이미지를 다시 만든 후에는 기존 `ssal-dev`를 제거하고 setup을 다시 실행해야 새 이미지가 적용됩니다.

결과는 `out/ssal-module-mock.zip`, `out/bin/`, `out/userdata-test.img`에 생성됩니다. userdata 명령은 기존 이미지를 덮어쓰지 않습니다. 사용한 컨테이너는 `./scripts/dev.ps1 stop`으로 중지합니다.

현재 바이너리와 모듈은 빌드 검증용 mock이며 hot-switch 기능을 제공하지 않습니다. 생성한 ext4 이미지는 개발 실험용이며 Android userdata 초기화, SELinux 라벨 및 기기 호환성 설정을 포함하지 않습니다. 실제 시스템 이미지는 사용자가 별도로 준비합니다.


## GSI Test Image

* [Vanilla](https://downloads.sourceforge.net/project/misterztr-gsi/LineageOS/Android%2016/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.7z?use_mirror=autoselect)
* [Gapps variant](https://downloads.sourceforge.net/project/misterztr-gsi/LineageOS/Android%2016/LineageOS-23.2-20260524-GAPPS-EXT4-GSI.7z?use_mirror=autoselect)
