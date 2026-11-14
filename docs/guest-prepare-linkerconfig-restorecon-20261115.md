# Guest 준비 helper / restorecon 수정 및 Y702 검증

후속 [동적 shell probe 검증](guest-prepare-shell-probe-20261115.md)에서 고정 진단 경로를 수정하고 전체 prepare 완료를 확인했다. 아래는 수정 전 실행 기록이며, 첫 부팅은 여전히 미검증이다.

2026-11-15 00:47–00:51 KST, Lenovo TB320FC (`HA1WAQ7P`), `y702`에서 재부팅 없이 검증했다.

## 변경

- 일반 prepare의 고정 linkerconfig helper만 기존 root command 경로를 사용한다. 자동 서비스와 동적 shell probe의 admission gate는 유지한다.
- Android 16 libselinux는 읽기 전용 selinuxfs를 활성 마운트로 등록하지 않는다. 기존 Guest context-map preload에서 실제 selinuxfs magic을 확인하고 `set_selinuxmnt`로 등록하며 enabled/Enforcing을 확인한다. libselinux를 링크하지 않은 helper에는 적용하지 않는다.
- mapped Guest의 selinuxfs에서 `context` 질의 파일만 Host의 쓰기 가능한 파일로 bind한다. 이 파일은 context 유효성 질의에 사용하며 정책을 수정하지 않는다. `load`, `enforce` 등 나머지 제어 파일은 읽기 전용이다.
- restorecon에 기존 preload를 적용한다. Guest userdata에 충돌 없이 시험 파일을 만들고, 실제 라벨이 매핑된 `system_data_file`로 변경돼야 성공으로 인정한다. 시험 파일을 삭제하고 기존 시스템 overlay 라벨 보존 검사도 수행한다.

## 관측

`out/guest-prepare-fix-20261115/prepare.log:175`에서 시험 파일이 `unlabeled`에서 `ssal_p0001_system_data_file`로 변경됐다. 재실행 `prepare-repeat.log:175`에서는 `ssal_p0001_system_data_root_file`에서 같은 목표로 변경됐다.

두 실행 모두 linkerconfig 생성과 구조 검사를 통과하고 다음 `chroot dynamic shell probe` 단계의 기존 admission gate에서 중단됐다. 전체 prepare와 첫 부팅 성공을 주장하지 않는다. 실기기에는 백업 후 최종 ssald/context-map을 설치했고 로컬 `out/bin`에도 반영했다.

두 실행 모두 시스템 overlay 라벨 보존, 세션 mount 잔여 없음, loop 46개 해제를 확인했다. Host Enforcing, boot ID `c6de69a6-5ab5-4ed0-9c14-cd1eab6fea35`, `sys.boot_completed=1`, system_server PID 2247 및 활성 정책 SHA-256 `f2ae794aa9d57c8639f206b1950534e6379a808caa2e3b8b420d6b099d0d8f1e`가 전후 동일했다.

숨긴 `.ssal-overlay-*` tmpfs에서 `setxattr failed` 경고가 남는다. Android libselinux `android_device.c`의 `RESTORECON_PARTIAL_MATCH_DIGEST` 저장 경로에서 발생하는 캐시 xattr 경고다. 시스템 overlay 라벨 변경이나 userdata 시험 파일 relabel 실패로 해석하지 않는다. 파일별 모든 userdata 라벨의 완전성은 별도 검증하지 않았다.

검증: mount 회귀 12개 통과(특권 mount 테스트 1개 제외), Guest 정책 회귀 19개 통과(외부 fixture 2개 제외), 기존 native context-map self-check, Android AArch64 release 빌드. WSL의 기존 `out/bin` 파일 교체 권한 문제는 별도 빌드 디렉터리와 Windows 복사로 처리했다.

원인 참고: [Android 16 libselinux 탐지](https://android.googlesource.com/platform/external/selinux/+/android-16.0.0_r2/libselinux/src/init.c), [restorecon 및 digest 구현](https://android.googlesource.com/platform/external/selinux/+/android-16.0.0_r2/libselinux/src/android/android_device.c).
