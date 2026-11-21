# Y702 부팅 잔여 문제 · 2026-11-21

## 원인과 재현

기기의 `/data/adb/modules/ssal/bin`에 `ssal-lmkd`, `ssal-vold`, `ssal-netd`가 없었다. 구현과 로컬 빌드 산출물은 존재했지만, launcher가 파일이 있는 경우에만 실행하여 누락을 조기에 감지하지 못했다. `netd`와 `vold`는 모듈 패키징 목록에도 없었고, 빌드 스크립트는 이름 변경 전 `experiments/` 경로를 참조했다.

재현 실행의 worker는 PID 28030, SystemServer는 PID 28855였다. Guest 로그 시간 `11-20 16:32`에 `StartNetworkManagementService`와 `Connecting native netd service` 이후 메인 스레드에서 null `INetd` 경고가 반복되며 시작 단계가 반환되지 않았다. LMKD 재접속과 vold 오류는 별도 스레드에서 발생했다. 따라서 주된 정지 원인은 누락된 Guest netd로 판단한다. [분석과 원본 행 번호](../out/boot-residual-20261121/log-findings.md)

현재 ANR은 메인 스레드가 15초 막힌 `pre_watchdog` 덤프다. 이전 실행에는 65초 `watchdog` 덤프도 있다. tombstoned가 없어 Java 스택을 수집하지 못했으므로 정확한 Java 프레임이나 Watchdog의 실제 kill은 이 자료로 확정하지 않는다. SurfaceFlinger는 등록을 통과했다.

## 변경과 검증

- `prepare`와 `start`는 기본 Guest 서비스 바이너리 12개의 일반 파일 여부와 실행 권한을 먼저 검사한다. 누락 목록과 모듈 재설치 안내를 반환한다. 진단용 probe 경로에는 이 검사를 추가하지 않았다.
- services workspace를 현재 경로에서 빌드하고 `vold`, `netd`를 설치·패키징 목록에 포함했다.
- 누락, 실행 권한 없음, 디렉터리를 거부하는 단위 테스트와 Android 서비스 workspace/daemon 빌드가 통과했다.
- 실기기에서 파일 보충 전 `prepare`와 `start`가 모두 세 파일의 누락을 정확히 보고했다. 이후 빌드한 세 바이너리와 새 daemon을 배포했다.
- 세 바이너리 보충 후 `prepare`는 파일 검사를 통과했으나 Guest overlay 생성 중 userdata의 `ENOSPC`로 중단됐다. 비정상 종료 후 남은 overlay와 빈 Guest cgroup은 별도 정리 대상이다.
- 종료된 세션의 overlay와 빈 Guest cgroup만 정리한 후 userdata의 사용량은 81,352 KiB, 여유는 8,093,680 KiB였다. 이후 `prepare y702`가 정상 완료됐고 mount·loop 정리 검사를 통과했다. [prepare 실행 결과](../out/boot-residual-20261121/prepare-after-deploy.txt)
- 세 서비스 배포 후 실행에서 `StartNetworkManagementService`는 4ms에 완료됐다 (`fixed/stderr.log:22101`). 다음 정지 지점은 `StartAudioService`였다 (`:22592-22596`). AudioPolicy와 AudioFlinger가 null이었다 (`:22709-22711`, `:22785-22786`). 기존 `ssal-virtual-audio`, `ssal-audio-host`도 기기와 패키징 목록에서 빠져 있었다. 두 바이너리의 빌드·패키징·사전 검사를 추가하고 빌드 및 기기 배포를 완료했다. [해당 실행 로그](../out/boot-residual-20261121/fixed/stderr.log)
- 오디오 보충 후에는 AudioService가 10,122ms에 완료되고 SystemReady가 반환됐다. 이후 phase 1000에서 `IApexService.markBootCompleted()`가 `UnsupportedOperationException`을 반환해 SystemServer가 종료됐다 (`final/stderr.log:40197-40221`). 현재 소스는 이 호출에 성공을 반환하며 ApexService 테스트 5개가 통과했다. 기기의 오래된 ApexService 바이너리를 현재 소스로 빌드한 파일로 교체했다. [예외 스택](../out/boot-residual-20261121/final/stderr.log)

모듈 ZIP 생성은 기존 Binder helper의 `build_script_sha256` 불일치 검사로 중단됐다. 해당 검사를 우회하거나 오래된 ZIP을 배포하지 않았다.

## 최종 실기기 결과와 남은 문제

ApexService 교체 후 worker 13588 / SystemServer 14624 실행에서 `GUEST_SYSTEM_READY`와 `GUEST_BOOT_COMPLETED`가 모두 `phase_returned=true`였다 (`verified-guest-y702.log:471,474,482-483`). BOOT_COMPLETED 브로드캐스트 완료도 확인했다 (`verified/stderr.log:47080`). 저장한 stderr에는 SystemServer fatal이 없었다. virtual-composer는 `presenter=true`로 레이어 프레임을 전달했다. [최종 실행 로그](../out/boot-residual-20261121/verified-guest-y702.log) · [분석](../out/boot-residual-20261121/log-findings.md)

현재 launcher의 기존 관찰 루프는 부팅 완료를 감지하면 종료한다. 따라서 이번 실행의 종료를 부팅 실패로 해석하면 안 된다. 이후 `Guest control socket directory is not empty`가 발생하고, 자손 프로세스 검증 및 mount·cgroup 정리가 실패했다 (`verified-guest-y702.log:6595`). 상주 실행과 종료 정리는 아직 해결하지 않았다. SurfaceFlinger의 invalid present fence 경고도 남아 있다. 실제 장시간 화면 표시와 입력 동작은 검증하지 않았다.

최종 실행 종료 후에는 해당 세션의 stale overlay와 빈 Guest cgroup만 정리했다. 임시 `.userdata-*.img`는 없고, 정상 userdata는 보존했다. Host SystemServer PID 2191, 부팅 ID `0bd95db0-89ba-4bdd-88d4-3b8e1f7b832d`, SELinux Enforcing은 조사 전후 동일했다. 재부팅하지 않았다.
