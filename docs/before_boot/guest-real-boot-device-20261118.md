# Lenovo 실기기 Guest 기동 검증 — 2026-11-18 KST

Lenovo TB320FC(ADB `HA1WAQ7P`, Android 15/ZUI)에서 `2b9717b`의 LineageOS Guest를 실행했다. **Guest Zygote 단독 기동은 통과했고, SystemServer 경로는 `apexservice` 등록 전 SIGSEGV로 차단됐다.** 삼성 커널, 잠긴 부트로더 및 One UI 복구는 이번 검증 범위에서 제외했다.

`ssald`, Property Service와 Rust `apexservice`(`rsbinder 0.13.0`)를 `ssal-dev`에서 Android arm64 release로 다시 빌드했다. 기기에 별도로 배치한 바이너리와 `y702`의 기존 LineageOS 시스템 이미지를 사용했다. 8 GiB userdata는 원본과 내용이 같고 inode가 다른 임시 복제본 `.userdata-apexservice.img`로 두 번의 실행을 진행했다. 비교와 기동에 사용한 명령은 [등록·기동 스크립트](../scripts/run-apexservice.sh)와 [관찰 스크립트](../out/guest-real-boot-20261118/observe-device.sh)에 있다. 배치 바이너리의 해시는 [검증 기록](../out/guest-real-boot-20261118/binaries.sha256)에 보관했다.

## 기동 결과

| 항목 | 판정 | 관찰 |
| --- | --- | --- |
| Guest Property Service | 통과 | Guest SDK 36과 별도 Property 영역 및 소켓을 확인했다. worker SID는 `u:r:ssal_p0001_init:s0`다. [등록 로그 179행](../out/guest-real-boot-20261118/check.log#L179) |
| Guest servicemanager와 private Binder | 통과 | Guest Context Manager와 Binder `234:5`에서 `aidl_lazy_test_1` 조회, 실제 AIDL transaction과 callback을 확인했다. [등록 로그 226행](../out/guest-real-boot-20261118/check.log#L226) |
| 실제 `apexservice` 등록·조회 | 실패 | 15:11:32 KST, PID `17146`이 `u:r:ssal_p0001_apexd:s0`로 실행된 직후 SIGSEGV로 종료했다. 등록 및 조회 성공 기록은 없으며 등록 단계는 종료 코드 `1`을 반환했다. [등록 로그 231행](../out/guest-real-boot-20261118/check.log#L231) [종료 기록 3086행](../out/guest-real-boot-20261118/check.log#L3086) |
| Guest Zygote 단독 기동 | 통과 | 15:12:10–15:13:39 KST, PID `17901`이 `u:r:ssal_p0001_zygote:s0`, UID/GID 0으로 preload를 완료했다. 별도 mount·network namespace와 다섯 cgroup 계층의 `/ssal_guest` membership을 확인했다. 동일 PID와 시작 시각으로 30초간 유지됐고 종료 코드 `0` 및 Zygote 소켓 제거를 확인했다. [Zygote 로그 337행](../out/guest-real-boot-20261118/zygote.log#L337) [프로세스 신원](../out/guest-real-boot-20261118/zygote-identity.txt) |
| SystemServer 및 Android 부팅 완료 | 차단 | `apexservice` 등록·조회가 선행 조건이어서 SystemServer worker 실행 단계에 진입하지 못했다. Framework 진입, PackageManager의 APEX 호출, Guest `sys.boot_completed=1`은 검증하지 못했다. [기동 게이트](../scripts/run-apexservice.sh#L40) |

PID와 시각으로 좁힌 logcat/dmesg에는 `apexservice`의 fault PC, backtrace, tombstone 또는 exec 이후 enforcing Guest AVC가 없었다. exec 전 `u:r:ksu:s0`의 AVC는 `permissive=1`로 기록됐고 launcher가 새 Guest SID를 관찰했다. SIGSEGV의 원인은 확인하지 못했다. [필터링한 진단](../out/guest-real-boot-20261118/luna-filtered-logs.txt)

Zygote 실행에서는 15:13:06.485 KST에 Guest 도메인의 `vendor_file:dir search` 거부가 기록됐지만, Zygote preload와 30초 유지 검사를 통과했다. [Zygote 진단](../out/guest-real-boot-20261118/luna-zygote-filtered-logs.txt)

실행 중인 Guest의 `property-service.json`에는 `services` 키가 없었다. 프로덕션 설정은 빈 서비스 목록으로 역직렬화되고, 현재 launcher는 `apexservice`를 `BinderService::start`에서 직접 실행한다. 따라서 이번 시험은 실제 서비스의 `ctl.interface_start=aidl/apexservice` 수명주기 연동까지 검증하지 못했다. [기기 설정 확인](../out/guest-real-boot-20261118/zygote-property-config.txt) [설정 기본값](../src/guest/properties/mod.rs#L43) [launcher 호출](../src/guest/launcher/mod.rs#L942)

## Host 전후 비교

- 세 시점의 Host boot ID, SELinux Enforcing 및 active policy 해시, PID 1 mountinfo, APEX 목록 해시, Host `apexd` 상태 및 원본 userdata·system 이미지의 size/mtime/inode가 동일했다. [기동 전](../out/guest-real-boot-20261118/host-before.txt) [등록 시도 후](../out/guest-real-boot-20261118/host-after-check.txt) [Zygote 종료 후](../out/guest-real-boot-20261118/host-after-zygote.txt)
- 선정한 9개 Host 서비스의 PID·starttime·cgroup과 loop 목록은 전후 바이트 단위로 동일했다. Host `system_server`는 PID `2280`이었다. 호스트 재부팅은 없었다. [서비스 기록](../out/guest-real-boot-20261118/after-zygote.services)
- Host Property 1,934개 중 등록 시도 전후에 바뀐 값은 없었다. Zygote 단독 실행까지 마친 뒤 `cache_key.system_server.account_user_data` 한 개가 `-7659458767717428333`에서 `-7659458767717428331`로 바뀌었으며 원인은 확인하지 못했다. `sys.lmk.killcnt`와 `persist.debug.killcnt`는 모두 `800:3,900:337`로 동일했다.

두 worker 종료 후 Guest 프로세스, 공개된 environment, mount, loop backing, 다섯 Guest cgroup이 남아 있지 않음을 확인했다. 임시 userdata 복제본과 이 실행의 기기 staging 디렉터리를 제거했다. 원본 Guest userdata, system 이미지와 프로필의 파일 메타데이터는 정리 전후 동일했다. [정리 증거](../out/guest-real-boot-20261118/cleanup-proof.txt)
