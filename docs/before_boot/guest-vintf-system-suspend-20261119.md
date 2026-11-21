# Guest VINTF 및 SystemSuspend 실기기 검증 · 2026-11-19

Lenovo TB320FC (ADB `HA1WAQ7P`, Android 15/ZUI, SELinux Enforcing)에서 `y702`의 LineageOS Android 16 이미지를 실행했다. 검증은 기존 KernelSU 정책과 Guest 프로필을 사용했다. 삼성·One UI 및 하드 재부팅 복구는 미검증이다.

Android 16 libvintf는 `apex.all.ready`가 true일 때 `/apex/apex-info-list.xml`을 선택한다. Guest 목록에 각 APEX의 파티션을 기록하고, 이미지에서 찾은 패키지 전체의 활성 경로·버전 경로·원본 패키지 bind mount가 읽기 전용임을 확인한 뒤에만 Guest property service가 해당 값을 게시한다. ART, i18n, runtime, SDK extensions, tzdata는 명시적으로 존재를 확인한다. 등록 전에 실제 Guest Binder에서 VINTF 선언을 조회한다. [Android 16 libvintf](https://android.googlesource.com/platform/system/libvintf/+/refs/heads/android16-release/Apex.cpp)

| 단계 | 결과 | 근거 |
| --- | --- | --- |
| Guest APEX 목록·마운트 | PASS | 활성 패키지 44개. SYSTEM 36개, SYSTEM_EXT 8개. 목록 XML과 registry가 일치하고 APEX tmpfs 및 패키지별 bind mount가 읽기 전용이다. [목록](../out/guest-vintf-20261119/apex-info-list.xml) · [mountinfo](../out/guest-vintf-20261119/apex-mountinfo.txt) |
| Guest 속성 및 실제 servicemanager의 목록 선택·읽기 | PASS | PID 6749, `u:r:ssal_p0001_servicemanager:s0`, `mnt:[4026534936]`, 목록 dev 234/inode 135. 같은 PID의 libvintf가 `Loaded APEX Infos from /apex/apex-info-list.xml` 및 framework manifest 처리 성공을 기록했다. [기동 기록](../out/guest-vintf-20261119/run-1.txt) |
| Guest framework VINTF 선언 → HAL 등록 | PASS | Guest Binder의 `isDeclared`가 true를 반환했고 `android.system.suspend.ISystemSuspend/default`가 등록됐다. [기동 기록](../out/guest-vintf-20261119/run-1.txt) |
| Guest SystemServer 30초 유지 | PASS | Guest SID의 PID 6890이 framework 진입 후 30초 유지됐다. worker 종료 코드 0. 서비스 출력은 supervisor 정리 시 기록되지만 선언 조회와 등록 완료를 기다린 뒤 Zygote를 시작한다. [기동 기록](../out/guest-vintf-20261119/run-1.txt) |
| Guest → Unix socket → Host broker → SystemSuspend wakelock | PASS | Host `suspend_control_internal`에서 이 실행의 broker PID 6791이 소유한 `SSAL:VirtualWakeLock`이 01:26:21 KST에 Active였다. Guest 종료 후 01:26:51에 Inactive로 바뀌었다. 별도 Host broker 프로브는 동일 배포 바이너리의 명시적 ACQUIRE·RELEASE 응답(ACK 3)과 Active → Inactive 전환을 확인했다. Guest 실행의 RELEASE 메시지 자체는 미검증이다. [Host 관측](../out/guest-vintf-20261119/host-wakelock-observed.txt) · [broker PID](../out/guest-vintf-20261119/run-1-detail.txt) · [프로토콜 확인](../out/guest-vintf-20261119/host-broker-protocol.txt) |
| Host 전원·격리·원본 userdata | PASS | Host 전원 스냅샷, boot ID, SystemServer/servicemanager PID, SELinux 정책·APEX 목록·PID 1 mountinfo 해시, 원본 userdata의 inode·크기·mtime·SHA-256 일치. Guest private Binder는 234:5였다. [기동 전](../out/guest-vintf-20261119/run-1-before.txt) · [기동 후](../out/guest-vintf-20261119/run-1-after.txt) |
| `SSAL_GUEST_SYSTEM_SUSPEND=0` 회귀 | PASS | Guest SystemServer PID 8253이 framework 진입 후 30초 유지됐고 worker 종료 코드는 0이었다. Guest HAL과 Host broker가 기동되지 않았으며 Host 스냅샷은 일치했다. [기동 기록](../out/guest-vintf-20261119/run-0.txt) · [확인](../out/guest-vintf-20261119/run-0-checks.txt) |
| 정리 | PASS | 두 실행에서 Guest cgroup·mount·loop 잔여물이 없음을 확인했다. 이번 실행의 userdata 복제본 두 개를 삭제했고 원본 inode·크기·mtime은 일치했다. [정리 기록](../out/guest-vintf-20261119/cleanup.txt) |

## 오류와 AVC

수정 전 Guest HAL 등록은 `IllegalArgument / Ok: VINTF declaration error`로 끝났다. 당시 framework manifest의 최초 차단은 `/bootstrap-apex/apex-info-list.xml` 조회의 `-13/EACCES`였다. 11-18 23:57:39.372 KST AVC 293205는 `{ search }`, `u:r:ssal_p0001_servicemanager:s0` → `u:object_r:apex_mnt_dir:s0`, `tclass=dir`, `name="bootstrap-apex"`, `permissive=0`이었다.

수정 후에도 부수적인 device manifest 조회는 `/vendor/etc/vintf/manifest.xml`에서 `-13/EACCES`를 반환했다. 같은 실행의 framework manifest 조회 및 등록은 성공했다. 해당 시각·PID의 enforcing AVC는 수집한 logcat/dmesg에서 확인되지 않았다. 수정 전 같은 vendor 조회의 AVC 293206은 `{ search }`, `u:r:ssal_p0001_servicemanager:s0` → `u:object_r:vendor_file:s0`, `tclass=dir`, `name="/"`, `permissive=0`이었다. 이번 실행에서 Guest XML을 만들 때의 기존 KSU `{ relabelfrom }`, `{ relabelto }` AVC 294321·294322는 `permissive=1`로 기록됐다. 이번 변경은 기존 Host 정책·파일 라벨과 vendor 접근을 그대로 유지했다. [VINTF 오류](../out/guest-vintf-20261119/run-1-detail.txt) · [AVC 원문](../out/guest-vintf-20261119/avc-logcat-1.txt)

## 실제 배포 바이너리 SHA-256

| 파일 | SHA-256 |
| --- | --- |
| `ssald` | `813f0367d6b06d1c5b8631c3bed89b53061b52c14fdd7ae2ac1f9078cbcf57b1` |
| `ssal-property-service` | `794798c9cdcae846d2802d7185ebc1831f380ee2424107ebccc897f82726d992` |
| `ssal-system-suspend` | `4b1759b073e4e17ef273f6f1cb5494a55a6ae3d78de34273cc026d59157536a4` |
| `ssal-apexservice` | `7651bcb59f75d973d9471b8fa8fa7ac14c7c7b4dd7b99420bdb11e6f5e413c26` |
| `ssal-context-map.so` | `74b86d03ffd6492c28fd27ce6332023aae8d0bbe922d419f040037f48d7df466` |

WSLc Android arm64 release 빌드가 성공했다. 직렬 Rust 테스트는 141개 통과, 8개 fixture 의존 테스트 제외였다. 첫 병렬 실행에서는 기존 persistent-property flock 테스트가 `EAGAIN(11)`로 실패했고 직렬 재실행에서 통과했다. 바이너리는 기기 임시 경로에 별도로 배치했다. [실기기 전체 해시](../out/guest-vintf-20261119/deployed.sha256) · [테스트 기록](../out/guest-vintf-20261119/tests.txt)
