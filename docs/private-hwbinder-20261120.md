# SSAL Private HwBinder 실기기 검증

2026-11-20 00:33:43–00:34:36 KST, Lenovo TB320FC `HA1WAQ7P`의 Android 15 호스트에서 `y702` LineageOS Android 16 GSI로 검증했다. 최종 worker는 코드 0으로 종료했다. [실행 시각과 배포 해시](../out/guest-hwbinder-20261120/run-5-result.txt)

| 단계 | 결과 | 확인한 내용 |
| --- | --- | --- |
| 1. Private Binder 재사용 | PASS | 별도 `--guest-hwbinder-worker`가 기존 binderfs 세션, Guest property service, linkerconfig, 서비스 supervisor를 사용했다. Guest init, SurfaceFlinger, 기기 HAL 기동 없이 실행했다. |
| 2. 장치 생성과 Context 격리 | PASS | 커널의 새 binderfs 인스턴스가 만든 기본 `hwbinder` 노드를 Guest `/dev/hwbinder`에 연결했다. Guest는 `234:6`, Host는 `234:2`였고 프로토콜은 8이었다. Host 매니저가 실행 중인 상태에서 Guest 시작 전에는 Guest 조회가 대기했고, Guest 매니저 종료 뒤에는 같은 장치에서 `DEAD_OBJECT`가 반환됐다. [실행 로그 172–214행](../out/guest-hwbinder-20261120/run-5-evidence.txt) |
| 3. AOSP 매니저와 의존성 | PASS | GSI 원본 `/system_ext/bin/hwservicemanager`가 `u:r:ssal_p0001_hwservicemanager:s0`으로 실행됐다. Guest의 platform·system_ext·product `hwservice_contexts`, APEX 목록과 framework VINTF를 읽고 Guest property service에 `hwservicemanager.ready=true`를 게시했다. [실행 로그 189–210행](../out/guest-hwbinder-20261120/run-5-evidence.txt) |
| 4. Context Manager 및 HIDL | PASS | Guest UID 2000과 mapped shell SID로 handle 0을 통해 `IServiceManager/default`와 AOSP 내장 `ITokenManager/default`를 조회하고 두 객체에 `IBase::debug`를 호출했다. 매니저와 서비스 객체는 GSI의 AOSP 바이너리가 등록했다. [실행 로그 190–214행](../out/guest-hwbinder-20261120/run-5-evidence.txt) |
| 5. Enforcing, Host 경계, 정리 | PASS | 실행 전후 Host 서비스 PID·시작 시각·SID·cgroup, binder 장치, 부팅 ID, PID 1 mountinfo, APEX 목록 및 매니저 준비 상태 스냅샷이 동일했다. Guest 프로세스, binderfs, cgroup과 루프 장치가 정리됐고 임시 userdata와 배포 디렉터리를 삭제했다. 원본 userdata와 GSI는 각각 실행 전후 SHA-256이 일치했다. [Host 대조](../out/guest-hwbinder-20261120/host-run-5-verification.txt) · [정리](../out/guest-hwbinder-20261120/cleanup.txt) · [이미지 대조](../out/guest-hwbinder-20261120/original-images-verification.txt) |

## 의존성과 SELinux

Guest worker는 Host의 vendor·odm·vendor_dlkm 마운트를 생략한다. 이번 GSI에서는 device manifest 부재 시 libvintf가 FCM을 미지정으로 처리하고, Guest framework manifest의 매니저 및 토큰 선언을 사용할 수 있었다. `apex.all.ready` 게시 이후 Guest `/apex/apex-info-list.xml`이 실제로 선택됐다. [AOSP 매니저 시작 코드](https://android.googlesource.com/platform/system/hwservicemanager/+/refs/tags/android-16.0.0_r3/service.cpp) · [Android 16 libvintf](https://android.googlesource.com/platform/system/libvintf/+/refs/tags/android-16.0.0_r2/VintfObject.cpp)

정책은 Guest 장치 SID의 binderfs 연결, Guest 매니저의 SELinux AV 조회와 supervisor 파이프, mapped shell의 내장 HIDL 서비스 조회를 허용한다. 00:31:30.592 KST의 enforcing AVC 354713에서 Guest 매니저의 Guest shell 파이프 FD `use`가 차단됐다. 최종 실행에서 두 Guest SID 사이의 FD `use`와 FIFO `write`를 추가했다. 사전 시험에서 추가한 Guest `hidl_base_hwservice:find`는 최종 소스에서 제거했다. KernelSU의 라이브 정책은 추가만 지원하므로 해당 사전 규칙은 현재 부팅 동안 남아 있다. [AVC](../out/guest-hwbinder-20261120/run-4-focused-avc.txt) · [최종 정책 델타](../out/guest-hwbinder-20261120/guest-policy-run-5.delta) · [최종 필터링 AVC](../out/guest-hwbinder-20261120/run-5-focused-avc.txt)

초기 Host 기준선 수집에서는 Host 쪽에서 읽기 전용 `lshal` 호출을 한 차례 실행했다. 최종 검증의 HIDL 호출은 Guest 전용 장치에서 수행했다. 삼성 순정 커널, One UI, 하드 재부팅 복구는 연결된 기기에서 검증할 수 없었다.

초기 실행에서 `getprop` 직접 실행은 mapped shell 진입 시 `EACCES`를 반환했다. 기존 `/system/bin/sh` 진입 경로를 재사용했다. `lshal list`는 프로세스별 binder 로그를 읽지 못한 뒤 신호 11로 끝났으므로 두 내장 인터페이스를 지정하는 `lshal debug`로 검증했다. 트랜잭션 오류가 종료 코드 0으로 잘리는 경우를 잡기 위해 종료 코드와 표준 오류를 모두 검사한다. [실행 2](../out/guest-hwbinder-20261120/run-2.log) · [실행 3](../out/guest-hwbinder-20261120/run-3.log) · [실행 4](../out/guest-hwbinder-20261120/run-4.log)

## 재현

샌드박스 밖에서 `wslc exec ssal-dev bash scripts/build-android.sh`를 실행한다. 생성된 `ssald`, `ssal-property-service`, `ssal-context-map.so`, `ssal-phase2-log.so`, `ssal-hwbinder-probe.sh`를 기기의 같은 임시 디렉터리에 배치한다. 기존 프로필 아래에 별도 inode의 `.userdata-*.img`를 만들고 userdata 이미지 라벨을 적용한다. 이 GSI에서는 256 MiB가 오버레이 복사 중 고갈됐고 4 GiB로 통과했다.

```sh
mkdir -p "$stage/system" "$stage/data"
timeout -s TERM -k 30 200 "$bin/ssald" --guest-hwbinder-worker "$system_img" "$scratch_userdata_img" "$stage"
```

기기에서 `root`로 실행한다. 출력에서 장치 비교, Guest SID, 두 HIDL 호출, 종료 후 `DEAD_OBJECT`, mount·cgroup·loop 정리를 확인한다. 원본 이미지와 분리된 테스트용 userdata를 실행 후 삭제한다. [재현 wrapper](../out/guest-hwbinder-20261120/run-worker.sh) · [최종 실기기 로그](../out/guest-hwbinder-20261120/run-5.log)

Android arm64 release 빌드와 shellcheck를 통과했다. Rust 직렬 테스트는 186개 통과, 환경 의존 테스트 8개 제외였다. [테스트 로그](../out/guest-hwbinder-20261120/rust-tests.txt)
